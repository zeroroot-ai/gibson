// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// destructive_authz.go implements ADR-0028's per-action destructive-proof
// authorization gate (gibson#336): a concrete DestructiveProofAuthorizer
// (declared in bet_settlement.go, NOT modified here) that queues a pending
// request and blocks ONLY the one goroutine attempting that one destructive
// settlement, until a human decision lands or its context ends.
//
// Identity is HypothesisID — the SAME identifier BetSettlement uses
// (bet_settlement.go) — because a destructive demonstration attempt is 1:1
// with one bet's settlement attempt: SettleBetTrue's own terminal-settlement
// check already prevents a second attempt once one succeeds, so there is
// never more than one outstanding destructive request per hypothesis.
//
// Two concerns are kept deliberately separate:
//   - The in-memory pending map is the live hand-off: a channel per
//     outstanding HypothesisID, registered by Authorize and signalled by
//     Decide. It has no durability and needs none — it only ever matters
//     while the requesting goroutine (SettleBetTrue's off-tick caller) is
//     still alive and waiting.
//   - The DestructiveAction World component (via DestructiveActionRequested /
//     DestructiveActionDecided, folded through the normal Reduce path,
//     ADR-0007) is the durable, replayable audit record ListPending reads —
//     restart-durable, independent of whether any goroutine is still
//     waiting on it.
//
// ADR-0028 decision 2 ("the gate is per-action, not per-mission") holds
// structurally here: Authorize is invoked from SettleBetTrue's own call
// stack — an off-tick call, per ADR-0027's evaluation model — so blocking
// inside it blocks nothing but that one caller. The tick loop, and every
// other hypothesis's settlement attempt, is untouched.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/mlange-42/ark/ecs"
)

// DestructiveAction is the per-bet destructive-proof authorization record
// (ADR-0028). Identity is HypothesisID.
type DestructiveAction struct {
	HypothesisID  string
	Tenant        string
	ScopeID       string
	MissionID     string
	Technique     string
	PredicateType string
	// RequestedAtUnixMS is when the request was queued, captured by the live
	// caller (Authorize) — never derived from wall-clock inside the reducer,
	// so replay reproduces the exact recorded value (the same pattern
	// observation.go's ObservedAt uses).
	RequestedAtUnixMS int64

	// Decided, Approved, UserID, DecidedAtUnixMS are set only once a
	// DestructiveActionDecided event folds (terminal: the first decision
	// wins, mirroring BetSettlement's own terminal-settlement rule).
	Decided         bool
	Approved        bool
	UserID          string
	DecidedAtUnixMS int64
}

// DestructiveActionRequested records that a destructive proof-of-demonstration
// attempt is awaiting human authorization (ADR-0028). It folds through the
// normal Observe-shaped reducer path (ADR-0007), so it is replayable like any
// other event.
type DestructiveActionRequested struct {
	HypothesisID      string
	Tenant            string
	ScopeID           string
	MissionID         string
	Technique         string
	PredicateType     string
	RequestedAtUnixMS int64
}

// Kind identifies the destructive_action.requested brain event.
func (DestructiveActionRequested) Kind() string { return "destructive_action.requested" }

// applyDestructiveActionRequested folds a DestructiveActionRequested event
// into the World. An empty HypothesisID records nothing — there would be no
// action to authorize. A HypothesisID that already has a DestructiveAction is
// left untouched (idempotent: a retried Authorize call for a still-pending
// hypothesis, e.g. after a daemon restart, must not reset the original
// request's timestamp or duplicate the entity).
func applyDestructiveActionRequested(w *World, e DestructiveActionRequested) {
	if e.HypothesisID == "" {
		return
	}

	q := ecs.NewFilter1[DestructiveAction](w.ecs).Query()
	for q.Next() {
		a := q.Get()
		if a.HypothesisID == e.HypothesisID {
			q.Close()
			return
		}
	}
	// Query exhausted → world unlocked.

	w.destructiveActions.NewEntity(&DestructiveAction{
		HypothesisID:      e.HypothesisID,
		Tenant:            e.Tenant,
		ScopeID:           e.ScopeID,
		MissionID:         e.MissionID,
		Technique:         e.Technique,
		PredicateType:     e.PredicateType,
		RequestedAtUnixMS: e.RequestedAtUnixMS,
	})
}

// DestructiveActionDecided records a human's approve/deny verdict for one
// pending destructive action (ADR-0028 decision 3). It folds through the
// normal reducer path, so replay reproduces the decision exactly — replay
// re-applies this already-decided fact, it never re-runs Authorize/Decide.
type DestructiveActionDecided struct {
	HypothesisID    string
	Approved        bool
	UserID          string
	DecidedAtUnixMS int64
}

// Kind identifies the destructive_action.decided brain event.
func (DestructiveActionDecided) Kind() string { return "destructive_action.decided" }

// applyDestructiveActionDecided folds a DestructiveActionDecided event into
// the World. An empty HypothesisID decides nothing. A HypothesisID with no
// matching DestructiveAction records nothing — there is no pending action to
// decide. Terminal: an already-decided action is left untouched, so
// whichever decision lands first for a HypothesisID wins, regardless of a
// racing second Decide call (see DestructiveAuthorizationQueue.Decide).
func applyDestructiveActionDecided(w *World, e DestructiveActionDecided) {
	if e.HypothesisID == "" {
		return
	}

	q := ecs.NewFilter1[DestructiveAction](w.ecs).Query()
	for q.Next() {
		a := q.Get()
		if a.HypothesisID != e.HypothesisID {
			continue
		}
		if a.Decided {
			q.Close()
			return
		}
		a.Decided = true
		a.Approved = e.Approved
		a.UserID = e.UserID
		a.DecidedAtUnixMS = e.DecidedAtUnixMS
		q.Close()
		return
	}
	// Query exhausted → world unlocked.
}

// DestructiveActionSnapshot is a stable, comparable view of a DestructiveAction.
type DestructiveActionSnapshot struct {
	HypothesisID      string
	Tenant            string
	ScopeID           string
	MissionID         string
	Technique         string
	PredicateType     string
	RequestedAtUnixMS int64
	Decided           bool
	Approved          bool
	UserID            string
	DecidedAtUnixMS   int64
}

// DestructiveActionSnapshot returns destructive actions in deterministic
// (HypothesisID) order — pending and decided alike; callers that want only
// the pending subset filter on !Decided (see
// DestructiveAuthorizationQueue.Pending).
func (w *World) DestructiveActionSnapshot() []DestructiveActionSnapshot {
	var out []DestructiveActionSnapshot
	q := ecs.NewFilter1[DestructiveAction](w.ecs).Query()
	for q.Next() {
		a := q.Get()
		out = append(out, DestructiveActionSnapshot{
			HypothesisID:      a.HypothesisID,
			Tenant:            a.Tenant,
			ScopeID:           a.ScopeID,
			MissionID:         a.MissionID,
			Technique:         a.Technique,
			PredicateType:     a.PredicateType,
			RequestedAtUnixMS: a.RequestedAtUnixMS,
			Decided:           a.Decided,
			Approved:          a.Approved,
			UserID:            a.UserID,
			DecidedAtUnixMS:   a.DecidedAtUnixMS,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HypothesisID < out[j].HypothesisID })
	return out
}

// DestructiveActionSnapshot returns the current destructive-action snapshots
// (read-locked, safe to call concurrently with the tick loop — the same
// read-accessor contract every other Engine method offers).
func (e *Engine) DestructiveActionSnapshot() []DestructiveActionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.DestructiveActionSnapshot()
}

// destructiveDecision is the payload sent over a pending action's channel
// when Decide resolves it.
type destructiveDecision struct {
	approved bool
	userID   string
}

// DestructiveAuthorizationQueue is a concrete DestructiveProofAuthorizer
// (ADR-0028, gibson#336). Wire it into SettleBetTrue by passing its Authorize
// method:
//
//	q := brain.NewDestructiveAuthorizationQueue(engine)
//	settled, err := engine.SettleBetTrue(ctx, registry, q.Authorize, req)
//
// A human decides through Decide (the daemon RPC handler's job — see
// gibson#336's ApproveDestructiveAction/DenyDestructiveAction), and reads the
// outstanding queue through Pending (ListPendingDestructiveActions).
//
// Thread safety: all public methods are safe for concurrent use.
type DestructiveAuthorizationQueue struct {
	engine *Engine

	mu      sync.Mutex
	pending map[string]chan destructiveDecision

	// now is an injectable clock, defaulting to time.Now, so tests can pin
	// timestamps deterministically without sleeping.
	now func() time.Time
}

// NewDestructiveAuthorizationQueue constructs a queue bound to engine. engine
// must not be nil: the queue submits Timeline events through it and reads its
// World snapshot for Pending.
func NewDestructiveAuthorizationQueue(engine *Engine) *DestructiveAuthorizationQueue {
	if engine == nil {
		panic("brain: NewDestructiveAuthorizationQueue requires a non-nil engine")
	}
	return &DestructiveAuthorizationQueue{
		engine:  engine,
		pending: make(map[string]chan destructiveDecision),
		now:     time.Now,
	}
}

// DestructiveAuthorizationQueue returns e's queue, constructing it on first
// call (most engines never see a destructive proof request, so this is
// deliberately lazy rather than a field every Engine pays for up front). The
// daemon's DestructiveAuthorizationService handlers and whatever eventually
// wires SettleBetTrue's authorize parameter both call this to reach the SAME
// queue instance for a given engine.
func (e *Engine) DestructiveAuthorizationQueue() *DestructiveAuthorizationQueue {
	e.destructiveAuthzOnce.Do(func() {
		e.destructiveAuthz = NewDestructiveAuthorizationQueue(e)
	})
	return e.destructiveAuthz
}

// Authorize implements DestructiveProofAuthorizer (bet_settlement.go). It
// enqueues req as a pending destructive action (folded onto the engine's
// Timeline, so ListPendingDestructiveActions and replay both see it) and
// blocks the calling goroutine — and only it — until Decide is called for
// req.HypothesisID, or ctx ends first.
func (q *DestructiveAuthorizationQueue) Authorize(ctx context.Context, tenant string, req BetSettlementRequest) (bool, error) {
	if req.HypothesisID == "" {
		return false, errors.New("brain: destructive authorization requires a hypothesis id")
	}

	ch := make(chan destructiveDecision, 1)
	q.mu.Lock()
	if _, exists := q.pending[req.HypothesisID]; exists {
		q.mu.Unlock()
		return false, fmt.Errorf("brain: destructive proof for hypothesis %q is already awaiting authorization", req.HypothesisID)
	}
	q.pending[req.HypothesisID] = ch
	q.mu.Unlock()

	q.engine.Submit(DestructiveActionRequested{
		HypothesisID:      req.HypothesisID,
		Tenant:            tenant,
		ScopeID:           req.ScopeID,
		MissionID:         req.MissionID,
		Technique:         string(req.Technique),
		PredicateType:     string(req.PredicateType),
		RequestedAtUnixMS: q.now().UnixMilli(),
	})

	select {
	case dec := <-ch:
		return dec.approved, nil
	case <-ctx.Done():
		q.mu.Lock()
		delete(q.pending, req.HypothesisID)
		q.mu.Unlock()
		return false, ctx.Err()
	}
}

// Pending returns every destructive action still awaiting a decision, in
// deterministic (HypothesisID) order — the backing read for
// ListPendingDestructiveActions.
func (q *DestructiveAuthorizationQueue) Pending() []DestructiveActionSnapshot {
	all := q.engine.DestructiveActionSnapshot()
	out := make([]DestructiveActionSnapshot, 0, len(all))
	for _, a := range all {
		if !a.Decided {
			out = append(out, a)
		}
	}
	return out
}

// Decide records a human's approve/deny verdict for hypothesisID (ADR-0028
// decision 3): ApproveDestructiveAction/DenyDestructiveAction's backing call.
//
// It checks the live, in-memory pending map first (authoritative and
// immediate — no dependency on the async Timeline fold having landed yet).
// If a goroutine is still waiting in Authorize for this action, Decide
// unblocks it and records the decision. If no goroutine is waiting — the
// action settled via a different path, or the daemon restarted after the
// request was persisted but before it was decided — Decide falls back to the
// durable World record: an already-decided action is refused (terminal,
// first-decision-wins), an unknown one is refused, and a known-but-orphaned
// pending one still gets its decision recorded for the audit trail even
// though there is no longer anyone to unblock.
//
// A benign race is possible if two Decide calls race for the same
// hypothesisID: the losing caller's decision is recorded on the Timeline but
// the reducer drops it (first-decision-wins), so Decide can return nil for a
// decision that did not actually take effect — callers that need to confirm
// the effective verdict should read Pending()/the World snapshot afterward,
// the same caveat every other settlement path in this package documents.
func (q *DestructiveAuthorizationQueue) Decide(hypothesisID, userID string, approved bool) error {
	if hypothesisID == "" {
		return errors.New("brain: decide requires a hypothesis id")
	}

	q.mu.Lock()
	ch, ok := q.pending[hypothesisID]
	if ok {
		delete(q.pending, hypothesisID)
	}
	q.mu.Unlock()

	decidedAt := q.now().UnixMilli()

	if !ok {
		found := false
		for _, a := range q.engine.DestructiveActionSnapshot() {
			if a.HypothesisID != hypothesisID {
				continue
			}
			found = true
			if a.Decided {
				return fmt.Errorf("brain: destructive action for hypothesis %q was already decided", hypothesisID)
			}
			break
		}
		if !found {
			return fmt.Errorf("brain: no pending destructive action for hypothesis %q", hypothesisID)
		}
		// Known to the World but no live waiter (e.g. after a daemon
		// restart): still record the decision for the audit trail.
		q.engine.Submit(DestructiveActionDecided{
			HypothesisID:    hypothesisID,
			Approved:        approved,
			UserID:          userID,
			DecidedAtUnixMS: decidedAt,
		})
		return nil
	}

	ch <- destructiveDecision{approved: approved, userID: userID}
	q.engine.Submit(DestructiveActionDecided{
		HypothesisID:    hypothesisID,
		Approved:        approved,
		UserID:          userID,
		DecidedAtUnixMS: decidedAt,
	})
	return nil
}
