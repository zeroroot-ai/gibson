// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	jobpb "github.com/zeroroot-ai/sdk/api/gen/gibson/job/v1"
)

// bankMemberLookup resolves which member a callback is coming from, over the
// bank store (ADR-0019, gibson#1711).
//
// It is a daemon type rather than a harness one because the harness must not
// import the bank store: the harness is the callback surface and the store is
// platform state, and the seam between them is the interface the harness
// declares.
type bankMemberLookup struct {
	banks bank.Store
}

var _ harness.MemberLookup = (*bankMemberLookup)(nil)

// MemberByRun returns the member and bank a mission run belongs to. An error
// means the run is not a member's, which is all a caller may learn.
func (l *bankMemberLookup) MemberByRun(ctx context.Context, tenantID, missionRunID string) (memberID, bankID string, err error) {
	m, err := l.banks.MemberByRun(ctx, tenantID, missionRunID)
	if errors.Is(err, bank.ErrNotFound) {
		return "", "", harness.ErrNotAMember
	}
	if err != nil {
		return "", "", fmt.Errorf("resolve the member of run %s: %w", missionRunID, err)
	}
	return m.ID, m.BankID, nil
}

// The three seams below are read lazily.
//
// The data-plane pool and the capability-grant signing key are both built
// during Start, after the callback service's options are assembled, so a seam
// captured at option time would capture nothing. Each resolves per call and
// answers a clear refusal while its dependency is absent, which is what a
// member sees on a daemon that serves no banks.

// lazyJobSurface resolves the job store per call.
type lazyJobSurface struct {
	daemon *daemonImpl
	// stores overrides where the job store comes from. Tests set it; the
	// daemon leaves it nil and reads the pool.
	stores func() (job.Store, error)
}

var _ harness.JobSurface = (*lazyJobSurface)(nil)

func (l *lazyJobSurface) store() (job.Store, error) {
	if l.stores != nil {
		return l.stores()
	}
	if l.daemon.pool == nil {
		return nil, errUnavailable("the data-plane pool is not up, so this daemon serves no jobs")
	}
	return job.NewPostgresStore(l.daemon.pool), nil
}

func (l *lazyJobSurface) Open(ctx context.Context, tenantID string, in job.OpenInput) (*job.Job, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	j, err := s.Open(ctx, tenantID, in)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return j, nil
}

func (l *lazyJobSurface) Send(ctx context.Context, tenantID string, in job.SendInput) (*job.Input, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	sent, err := s.Send(ctx, tenantID, in)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return sent, nil
}

func (l *lazyJobSurface) Events(ctx context.Context, tenantID, jobID string, since int64, limit int32) ([]*job.Event, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	events, err := s.Events(ctx, tenantID, jobID, since, limit)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return events, nil
}

func (l *lazyJobSurface) Claim(ctx context.Context, tenantID, bankID, memberID string) (*job.Job, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	j, err := s.Claim(ctx, tenantID, bankID, memberID)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return j, nil
}

func (l *lazyJobSurface) Get(ctx context.Context, tenantID, id string) (*job.Job, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	j, err := s.Get(ctx, tenantID, id)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return j, nil
}

func (l *lazyJobSurface) PendingInputs(ctx context.Context, tenantID, memberID string, limit int32) ([]*job.Input, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	in, err := s.PendingInputs(ctx, tenantID, memberID, limit)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return in, nil
}

func (l *lazyJobSurface) Acknowledge(ctx context.Context, tenantID, inputID string) error {
	s, err := l.store()
	if err != nil {
		return err
	}
	if err := s.Acknowledge(ctx, tenantID, inputID); err != nil {
		return fmt.Errorf("job store: %w", err)
	}
	return nil
}

func (l *lazyJobSurface) SetState(ctx context.Context, tenantID, jobID string, state job.State, claudeSessionID string) (*job.Job, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	j, err := s.SetState(ctx, tenantID, jobID, state, claudeSessionID)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return j, nil
}

func (l *lazyJobSurface) AddDeliverable(ctx context.Context, tenantID, jobID string, d *jobpb.Deliverable) (*job.Job, error) {
	s, err := l.store()
	if err != nil {
		return nil, err
	}
	j, err := s.AddDeliverable(ctx, tenantID, jobID, d)
	if err != nil {
		return nil, fmt.Errorf("job store: %w", err)
	}
	return j, nil
}

// lazyMemberLookup resolves the bank store per call.
type lazyMemberLookup struct {
	daemon *daemonImpl
	// banks overrides where the bank store comes from. Tests set it.
	banks func() (bank.Store, error)
}

var _ harness.MemberLookup = (*lazyMemberLookup)(nil)

func (l *lazyMemberLookup) MemberByRun(ctx context.Context, tenantID, missionRunID string) (memberID, bankID string, err error) {
	var store bank.Store
	switch {
	case l.banks != nil:
		store, err = l.banks()
		if err != nil {
			return "", "", err
		}
	case l.daemon.pool == nil:
		return "", "", errUnavailable("the data-plane pool is not up, so this daemon serves no banks")
	default:
		store = bank.NewPostgresStore(l.daemon.pool)
	}
	return (&bankMemberLookup{banks: store}).MemberByRun(ctx, tenantID, missionRunID)
}

// lazyTurnGrantMinter resolves the capability-grant minter per call.
type lazyTurnGrantMinter struct{ daemon *daemonImpl }

var _ harness.TurnGrantMinter = (*lazyTurnGrantMinter)(nil)

func (l *lazyTurnGrantMinter) Mint(req capabilitygrant.MintRequest) (string, error) {
	if l.daemon.cgMinter == nil {
		return "", errUnavailable("the daemon has no signing key, so it cannot mint a turn grant")
	}
	token, err := l.daemon.cgMinter.Mint(req)
	if err != nil {
		return "", fmt.Errorf("mint a turn grant: %w", err)
	}
	return token, nil
}

// errUnavailable is a refusal a member can act on: the daemon is not serving
// this surface yet, and retrying later is the right response.
func errUnavailable(reason string) error {
	return status.Error(codes.Unavailable, reason)
}
