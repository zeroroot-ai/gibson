// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/platform/bank"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	bankpb "github.com/zeroroot-ai/sdk/api/gen/gibson/bank/v1"
)

// memberEvents is where a member's console lines and its heartbeat land
// (ADR-0019 decision 13, gibson#1716). One type serves both seams because both
// resolve the same thing: which live run a member id names.
//
// The bank store is read per call because the data-plane pool is built during
// Start, after the callback service and the gRPC server are assembled.
type memberEvents struct {
	daemon *daemonImpl
	// stores overrides where the bank store comes from. Tests set it; the
	// daemon leaves it nil and reads the pool.
	stores func() (bank.Store, error)
}

var (
	_ harness.MemberEventSink    = (*memberEvents)(nil)
	_ component.MemberStatusSink = (*memberEvents)(nil)
)

func (e *memberEvents) store() (bank.Store, error) {
	if e.stores != nil {
		return e.stores()
	}
	if e.daemon.pool == nil {
		return nil, errors.New("the data-plane pool is not up, so this daemon serves no banks")
	}
	return bank.NewPostgresStore(e.daemon.pool), nil
}

// PublishMemberEvent appends one line to the member's live stream. A member
// with no live stream, or a daemon with no banks, drops the line with a debug
// record: the line is for a viewer, and the work that produced it stands.
func (e *memberEvents) PublishMemberEvent(ctx context.Context, tenantID, memberID string, line []byte) {
	store, err := e.store()
	if err != nil {
		e.daemon.logger.Debug(ctx, "member console line dropped", "member_id", memberID, "reason", err.Error())
		return
	}
	m, err := store.GetMember(ctx, tenantID, memberID)
	if err != nil {
		e.daemon.logger.Debug(ctx, "member console line dropped: no such member", "member_id", memberID, "error", err.Error())
		return
	}
	if err := e.daemon.liveAgents.Publish(tenantID, m.AgentRunID, line); err != nil {
		e.daemon.logger.Debug(ctx, "member console line dropped: no live run", "member_id", memberID, "run_id", m.AgentRunID)
	}
}

// ReportMemberStatus stores what a member reported on its heartbeat and puts a
// member_status line on its stream.
func (e *memberEvents) ReportMemberStatus(ctx context.Context, tenantID, memberID string, st *bankpb.MemberStatus) error {
	store, err := e.store()
	if err != nil {
		return err
	}
	updated, err := store.UpdateMemberStatus(ctx, tenantID, memberID, bank.MemberStatus{
		State:         memberStateFromProto(st.GetState()),
		JobsInFlight:  st.GetJobsInFlight(),
		JobCap:        st.GetCap(),
		ActiveJobIDs:  st.GetActiveJobIds(),
		ClaudeVersion: st.GetClaudeVersion(),
	})
	if err != nil {
		return fmt.Errorf("record member status: %w", err)
	}
	line, _ := json.Marshal(map[string]any{
		"type": "member_status", "state": string(updated.State),
		"jobs_in_flight": updated.JobsInFlight, "cap": updated.JobCap,
		"claude_version": updated.ClaudeVersion,
	})
	if perr := e.daemon.liveAgents.Publish(tenantID, updated.AgentRunID, append(line, '\n')); perr != nil {
		e.daemon.logger.Debug(ctx, "member status line dropped: no live run", "member_id", memberID, "run_id", updated.AgentRunID)
	}
	return nil
}

// memberStateFromProto maps the wire state a member may report. Anything a
// member may not claim maps to the empty state, which the store refuses by
// name.
func memberStateFromProto(s bankpb.MemberState) bank.MemberState {
	switch s {
	case bankpb.MemberState_MEMBER_STATE_IDLE:
		return bank.MemberIdle
	case bankpb.MemberState_MEMBER_STATE_BUSY:
		return bank.MemberBusy
	case bankpb.MemberState_MEMBER_STATE_NEEDS_SIGN_IN:
		return bank.MemberNeedsSignIn
	case bankpb.MemberState_MEMBER_STATE_LAUNCHING, bankpb.MemberState_MEMBER_STATE_DRAINING,
		bankpb.MemberState_MEMBER_STATE_DEAD, bankpb.MemberState_MEMBER_STATE_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

// lazyMemberSource resolves the bank store per call for the agent console.
type lazyMemberSource struct{ daemon *daemonImpl }

func (l *lazyMemberSource) MemberByRun(ctx context.Context, tenantID, runID string) (*bank.Member, error) {
	if l.daemon.pool == nil {
		return nil, bank.ErrNotFound
	}
	m, err := bank.NewPostgresStore(l.daemon.pool).MemberByRun(ctx, tenantID, runID)
	if err != nil {
		return nil, fmt.Errorf("read the bank member for mission run %q: %w", runID, err)
	}
	return m, nil
}
