// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package bank holds the reconciler that keeps a bank's members running
// (ADR-0019 decision 1, gibson#1709).
//
// A bank is declarative: it says how many members should run. The reconciler is
// what makes the running count match. It owns the POLICY — how many, which one
// to drain, when a member counts as dead — and nothing else. Launching a
// sandbox, originating the member's mission and killing it are MECHANISM, and
// they live behind MemberLauncher, which the daemon implements. That split is
// what lets the policy be tested without a cluster, and it is why the hard
// parts of a controller (the counting and the choosing) are readable here.
package bank

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	bankstore "github.com/zeroroot-ai/gibson/internal/platform/bank"
)

// MemberLauncher is the mechanism half: what it takes to make one member exist
// or stop existing. The daemon implements it over the mission manager and the
// sandboxed agent launcher; a test fakes it.
type MemberLauncher interface {
	// LaunchMember starts one member of the bank and returns what the daemon
	// needs to find it again. A member backs no mission of its own: the bank
	// is its origin, its grant is scoped to the bank, and the jobs it serves
	// are the missions' work (ADR-0019). The implementation launches the
	// agent in member mode with the base grant.
	//
	// memberID is chosen by the reconciler, not the launcher: a relaunch keeps
	// the id so the member's jobs and its console history stay one member's.
	LaunchMember(ctx context.Context, tenantID string, b *bankstore.Bank, memberID string) (LaunchedMember, error)

	// StopMember ends a member's sandbox. It is called after the member has
	// drained, so it is a teardown, not an interruption.
	StopMember(ctx context.Context, tenantID string, m *bankstore.Member) error
}

// LaunchedMember is what a launch produced: the mission that backs the member
// and the sandbox it runs in.
type LaunchedMember struct {
	MissionID    string
	MissionRunID string
	AgentRunID   string
	SandboxID    string
}

// JobReleaser hands a dead member's jobs back to its bank's queue. The daemon
// backs it with the job store.
//
// It is required, not optional: a job a dead member held would otherwise wait
// on that member forever, and the next PullJob of any member of the bank is
// how the job comes back with its claude_session_id set (gibson#1710).
type JobReleaser interface {
	// ReleaseMember clears the member from every job it holds that is not
	// closed, and reports how many it released.
	ReleaseMember(ctx context.Context, tenantID, memberID string) (int64, error)
}

// Events reports what the reconciler did, so a console and the Timeline see a
// bank move. A nil sink is allowed: the reconciler still reconciles.
type Events interface {
	MemberLaunched(ctx context.Context, tenantID string, m *bankstore.Member)
	MemberDead(ctx context.Context, tenantID string, m *bankstore.Member)
	MemberDraining(ctx context.Context, tenantID string, m *bankstore.Member)
	MemberRemoved(ctx context.Context, tenantID string, m *bankstore.Member)
}

// Config is the constructor input.
type Config struct {
	Store    bankstore.Store
	Launcher MemberLauncher
	Jobs     JobReleaser
	Events   Events
	Logger   *slog.Logger
	// HeartbeatTimeout is how long a member may go without reporting before it
	// counts as dead. Zero takes DefaultHeartbeatTimeout.
	HeartbeatTimeout time.Duration
	// Now is the clock. Tests replace it; production leaves it nil.
	Now func() time.Time
}

// DefaultHeartbeatTimeout is three heartbeat intervals. A member reports every
// ten seconds, so a single missed report is a hiccup and three is a death.
const DefaultHeartbeatTimeout = 30 * time.Second

// Reconciler keeps each bank's running member count equal to its desired count.
type Reconciler struct {
	store     bankstore.Store
	launcher  MemberLauncher
	jobs      JobReleaser
	events    Events
	logger    *slog.Logger
	heartbeat time.Duration
	now       func() time.Time
}

// New builds a Reconciler. The store and the launcher are required: a
// reconciler with neither would report success having done nothing, which is
// the worst thing a controller can do.
func New(cfg Config) (*Reconciler, error) {
	if cfg.Store == nil {
		return nil, errors.New("bank: New: Store is required")
	}
	if cfg.Launcher == nil {
		return nil, errors.New("bank: New: Launcher is required")
	}
	if cfg.Jobs == nil {
		return nil, errors.New("bank: New: Jobs is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HeartbeatTimeout <= 0 {
		cfg.HeartbeatTimeout = DefaultHeartbeatTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Reconciler{
		store: cfg.Store, launcher: cfg.Launcher, jobs: cfg.Jobs, events: cfg.Events,
		logger:    cfg.Logger.With("component", "bank_reconciler"),
		heartbeat: cfg.HeartbeatTimeout, now: cfg.Now,
	}, nil
}

// ReconcileTenant brings every bank of one tenant to its desired state.
//
// One bank's failure does not stop the others: a tenant with a broken bank
// still gets the rest reconciled, and the failure is returned so a caller can
// see it. Returning at the first error would let one bad bank freeze a tenant.
func (r *Reconciler) ReconcileTenant(ctx context.Context, tenantID string) error {
	banks, err := r.store.ListAll(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("bank reconcile: list banks of %s: %w", tenantID, err)
	}
	var failures []error
	for _, b := range banks {
		if rerr := r.ReconcileBank(ctx, tenantID, b); rerr != nil {
			failures = append(failures, fmt.Errorf("bank %s: %w", b.ID, rerr))
		}
	}
	return errors.Join(failures...)
}

// ReconcileBank brings one bank to its desired state, in three passes that must
// happen in this order:
//
//  1. Mark the dead. A member whose heartbeat stopped is not running, so it
//     must not count toward the desired total — otherwise a bank of five with
//     two dead members stays at three forever.
//  2. Drain the excess. Idle members first: draining a busy member would
//     abandon work that is nearly done while an idle one sits there.
//  3. Launch the missing, including replacements for the dead.
func (r *Reconciler) ReconcileBank(ctx context.Context, tenantID string, b *bankstore.Bank) error {
	members, err := r.allMembers(ctx, tenantID, b.ID)
	if err != nil {
		return err
	}

	var failures []error
	live := make([]*bankstore.Member, 0, len(members))
	for _, m := range members {
		if r.isDead(m) {
			if derr := r.markDead(ctx, tenantID, m); derr != nil {
				failures = append(failures, derr)
			}
			continue
		}
		if m.State == bankstore.MemberDraining {
			// A drained member is one with no jobs left. Until then it keeps
			// its slot but does not count as live capacity.
			if m.JobsInFlight == 0 {
				if serr := r.removeMember(ctx, tenantID, m); serr != nil {
					failures = append(failures, serr)
				}
			}
			continue
		}
		live = append(live, m)
	}

	// A bank holds tens of members, never more than int32 can count, so the
	// narrowing cannot overflow; it is spelled once so the comparisons read.
	running := int32(len(live)) //nolint:gosec // bounded by the bank's desired count, an int32
	switch {
	case running > b.DesiredCount:
		if derr := r.drain(ctx, tenantID, live, running-b.DesiredCount); derr != nil {
			failures = append(failures, derr)
		}
	case running < b.DesiredCount:
		if lerr := r.launch(ctx, tenantID, b, b.DesiredCount-running); lerr != nil {
			failures = append(failures, lerr)
		}
	}
	return errors.Join(failures...)
}

// allMembers reads every member of a bank, following the pages.
func (r *Reconciler) allMembers(ctx context.Context, tenantID, bankID string) ([]*bankstore.Member, error) {
	var out []*bankstore.Member
	token := ""
	for {
		page, next, err := r.store.ListMembers(ctx, tenantID, bankID, bankstore.Page{Token: token})
		if err != nil {
			return nil, fmt.Errorf("bank reconcile: list members of %s: %w", bankID, err)
		}
		out = append(out, page...)
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// isDead reports whether a member has stopped reporting.
//
// A member that has never reported is judged from when it was created, so a
// launch that never came up is found rather than waited on forever. A DEAD
// member stays dead until it is replaced.
func (r *Reconciler) isDead(m *bankstore.Member) bool {
	if m.State == bankstore.MemberDead {
		return true
	}
	last := m.LastHeartbeat
	if last.IsZero() {
		last = m.CreatedAt
	}
	return r.now().Sub(last) > r.heartbeat
}

func (r *Reconciler) markDead(ctx context.Context, tenantID string, m *bankstore.Member) error {
	if m.State != bankstore.MemberDead {
		updated, err := r.store.SetMemberState(ctx, tenantID, m.ID, bankstore.MemberDead)
		if err != nil {
			return fmt.Errorf("mark member %s dead: %w", m.ID, err)
		}
		r.logger.WarnContext(ctx, "bank member stopped reporting",
			"member_id", m.ID, "bank_id", m.BankID, "last_heartbeat", m.LastHeartbeat)
		if r.events != nil {
			r.events.MemberDead(ctx, tenantID, updated)
		}
	}
	// The sandbox may still exist even though the process stopped answering,
	// so it is killed before the row is removed. A best-effort stop: a sandbox
	// that is already gone must not block the replacement.
	if err := r.launcher.StopMember(ctx, tenantID, m); err != nil {
		r.logger.WarnContext(ctx, "could not stop a dead member's sandbox",
			"member_id", m.ID, "error", err)
	}
	// Its jobs go back to the queue BEFORE the row goes: a job that still named
	// a member with no row would be held by nobody and pulled by nobody.
	released, err := r.jobs.ReleaseMember(ctx, tenantID, m.ID)
	if err != nil {
		return fmt.Errorf("release the jobs of dead member %s: %w", m.ID, err)
	}
	if released > 0 {
		r.logger.InfoContext(ctx, "a dead member's jobs went back to the queue",
			"member_id", m.ID, "bank_id", m.BankID, "released", released)
	}
	return r.removeMember(ctx, tenantID, m)
}

func (r *Reconciler) removeMember(ctx context.Context, tenantID string, m *bankstore.Member) error {
	if m.State == bankstore.MemberDraining {
		if err := r.launcher.StopMember(ctx, tenantID, m); err != nil {
			return fmt.Errorf("stop drained member %s: %w", m.ID, err)
		}
	}
	if err := r.store.RemoveMember(ctx, tenantID, m.ID); err != nil {
		return fmt.Errorf("remove member %s: %w", m.ID, err)
	}
	if r.events != nil {
		r.events.MemberRemoved(ctx, tenantID, m)
	}
	return nil
}

// drain marks the n members that should go. Idle first, then the least busy:
// draining a member that is nearly finished throws away more work than draining
// one that is doing nothing.
func (r *Reconciler) drain(ctx context.Context, tenantID string, live []*bankstore.Member, n int32) error {
	ordered := drainOrder(live)
	var failures []error
	for i := int32(0); i < n && int(i) < len(ordered); i++ {
		m := ordered[i]
		updated, err := r.store.SetMemberState(ctx, tenantID, m.ID, bankstore.MemberDraining)
		if err != nil {
			failures = append(failures, fmt.Errorf("drain member %s: %w", m.ID, err))
			continue
		}
		r.logger.InfoContext(ctx, "bank member draining",
			"member_id", m.ID, "bank_id", m.BankID, "jobs_in_flight", m.JobsInFlight)
		if r.events != nil {
			r.events.MemberDraining(ctx, tenantID, updated)
		}
		// A member with nothing in flight is done draining at once. Waiting a
		// whole pass to remove it would leave a bank above its desired count
		// for no reason.
		if m.JobsInFlight == 0 {
			updated.State = bankstore.MemberDraining
			if rerr := r.removeMember(ctx, tenantID, updated); rerr != nil {
				failures = append(failures, rerr)
			}
		}
	}
	return errors.Join(failures...)
}

// drainOrder sorts members by how much work draining them would interrupt:
// fewest jobs in flight first, and among equals the oldest first, so the choice
// is deterministic and a test can state it.
func drainOrder(live []*bankstore.Member) []*bankstore.Member {
	ordered := make([]*bankstore.Member, len(live))
	copy(ordered, live)
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && lessDrainable(ordered[j], ordered[j-1]); j-- {
			ordered[j], ordered[j-1] = ordered[j-1], ordered[j]
		}
	}
	return ordered
}

func lessDrainable(a, b *bankstore.Member) bool {
	if a.JobsInFlight != b.JobsInFlight {
		return a.JobsInFlight < b.JobsInFlight
	}
	return a.CreatedAt.Before(b.CreatedAt)
}

// launch starts n new members.
//
// A member starts in NEEDS_SIGN_IN when the bank signs in on a person's
// subscription, because it cannot take a job until its owner completes the
// in-sandbox login, and in LAUNCHING otherwise. The daemon sets both: a member
// cannot report a state it has not reached.
func (r *Reconciler) launch(ctx context.Context, tenantID string, b *bankstore.Bank, n int32) error {
	var failures []error
	for range n {
		memberID := newMemberID()
		launched, err := r.launcher.LaunchMember(ctx, tenantID, b, memberID)
		if err != nil {
			failures = append(failures, fmt.Errorf("launch a member of bank %s: %w", b.ID, err))
			continue
		}
		m := &bankstore.Member{
			ID: memberID, BankID: b.ID,
			MissionID: launched.MissionID, MissionRunID: launched.MissionRunID,
			AgentRunID: launched.AgentRunID, SandboxID: launched.SandboxID,
			State:  initialState(b),
			JobCap: b.MaxJobsInFlight,
		}
		if err := r.store.AddMember(ctx, tenantID, m); err != nil {
			// The sandbox exists but no row names it, so nothing would ever
			// reach or reap it. Stop it rather than leak it.
			if serr := r.launcher.StopMember(ctx, tenantID, m); serr != nil {
				r.logger.ErrorContext(ctx, "a launched member could not be recorded or stopped",
					"member_id", memberID, "record_error", err, "stop_error", serr)
			}
			failures = append(failures, fmt.Errorf("record member %s: %w", memberID, err))
			continue
		}
		r.logger.InfoContext(ctx, "bank member launched",
			"member_id", memberID, "bank_id", b.ID, "state", string(m.State))
		if r.events != nil {
			r.events.MemberLaunched(ctx, tenantID, m)
		}
	}
	return errors.Join(failures...)
}

// newMemberID returns the id a launch is recorded under. It is generated here
// rather than by the launcher, because a relaunch has to be able to KEEP an id:
// the member's jobs and its console history belong to one member across a
// restart, and an id the launcher minted would change under them.
func newMemberID() string {
	return string(types.NewID())
}

// initialState is where a member starts. A subscription bank holds its members
// at needs-sign-in: the person has to complete the login inside the sandbox
// before the member can take work, and the platform never holds the token.
func initialState(b *bankstore.Bank) bankstore.MemberState {
	if b.LoginShape == bankstore.LoginShapeSubscription {
		return bankstore.MemberNeedsSignIn
	}
	return bankstore.MemberLaunching
}
