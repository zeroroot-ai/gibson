// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// destructive_authz.go implements ADR-0132's per-action destructive-proof
// authorization gate (gibson#336), wired the way ADR-0132 (gibson#390)
// corrects it: the gate sits BEFORE the destructive act, not at settlement.
//
// Originally (ADR-0132's first wiring) Authorize queued a pending request
// and blocked the ONE goroutine attempting that one destructive settlement
// until a human decision landed. That gated *accepting the proof*, which is
// too late — the irreversible act had already happened by the time
// SettleBetTrue ran. ADR-0132 splits the single blocking call into two
// non-blocking halves:
//
//   - Request (called from the RequestDestructiveAuthorization RPC,
//     internal/engine/harness) enqueues the pending request and returns
//     immediately, BEFORE the agent performs the destructive act. The fleet
//     keeps working while the decision is pending (ADR-0132's own intent).
//   - Verify (SettleBetTrue's DestructiveProofAuthorizer, bet_settlement.go)
//     reads back the recorded decision at settlement time — by then the
//     agent has already performed the act and read back an approval, so
//     this is a check of an existing fact, never a live ask.
//
// Decide (the dashboard's ApproveDestructiveAction/DenyDestructiveAction
// backing call, gibson#342) is the one thing both halves share (ADR-0132,
// "one authorization path"): it folds a DestructiveActionDecided
// fact that Verify later reads. There is no live in-memory hand-off left to
// coordinate — nothing blocks anymore — so Decide operates purely off the
// durable DestructiveAction World record (via DestructiveActionRequested /
// DestructiveActionDecided, folded through the normal Reduce path,
// ADR-0107): restart-durable, replayable, and the single source of truth
// for both Verify and ListPendingDestructiveActions.
//
// Identity is HypothesisID — the SAME identifier BetSettlement uses
// (bet_settlement.go) — because a destructive demonstration attempt is 1:1
// with one bet's settlement attempt: SettleBetTrue's own terminal-settlement
// check already prevents a second attempt once one succeeds, so there is
// never more than one outstanding destructive request per hypothesis.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/mlange-42/ark/ecs"
)

// Reversibility states whether a destructive action can be undone after it
// runs. The agent reports it with the request, and the approver reads it
// (ADR-0132). The numbers match the wire enums of the harness callback and
// of DestructiveAuthorizationService, so a stored event keeps its meaning.
type Reversibility int32

const (
	// ReversibilityUnspecified means that the agent reported no signal.
	ReversibilityUnspecified Reversibility = 0
	// ReversibilityReversible means that the action can be undone.
	ReversibilityReversible Reversibility = 1
	// ReversibilityIrreversible means that the action cannot be undone.
	ReversibilityIrreversible Reversibility = 2
)

// DestructiveAction is the per-bet destructive-proof authorization record
// (ADR-0132). Identity is HypothesisID.
type DestructiveAction struct {
	HypothesisID  string
	Tenant        string
	ScopeID       string
	MissionID     string
	Technique     string
	PredicateType string
	// BlastRadius states, in plain words, what the action would reach. The
	// agent reports it. Empty means that the agent reported no signal.
	BlastRadius string
	// Reversibility states whether the action can be undone.
	Reversibility Reversibility
	// RequestedAtUnixMS is when the request was queued, captured by the live
	// caller (Request) — never derived from wall-clock inside the reducer,
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
// attempt is awaiting human authorization (ADR-0132). It folds through the
// normal Observe-shaped reducer path (ADR-0107), so it is replayable like any
// other event.
type DestructiveActionRequested struct {
	HypothesisID      string
	Tenant            string
	ScopeID           string
	MissionID         string
	Technique         string
	PredicateType     string
	RequestedAtUnixMS int64
	// BlastRadius and Reversibility are what the agent reported about the
	// action. They are part of the event, so they survive a restart and a
	// replay. An event from before these fields decodes with zero values.
	BlastRadius   string        `json:",omitempty"`
	Reversibility Reversibility `json:",omitempty"`
}

// Kind identifies the destructive_action.requested brain event.
func (DestructiveActionRequested) Kind() string { return "destructive_action.requested" }

// applyDestructiveActionRequested folds a DestructiveActionRequested event
// into the World. An empty HypothesisID records nothing — there would be no
// action to authorize. A HypothesisID that already has a DestructiveAction is
// left untouched (idempotent: a retried Request call for a still-pending
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
		BlastRadius:       e.BlastRadius,
		Reversibility:     e.Reversibility,
		RequestedAtUnixMS: e.RequestedAtUnixMS,
	})
}

// DestructiveActionDecided records a human's approve/deny verdict for one
// pending destructive action (ADR-0132). It folds through the
// normal reducer path, so replay reproduces the decision exactly — replay
// re-applies this already-decided fact, it never re-runs Request/Decide.
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
	BlastRadius       string        `json:",omitempty"`
	Reversibility     Reversibility `json:",omitempty"`
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
			BlastRadius:       a.BlastRadius,
			Reversibility:     a.Reversibility,
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

// ErrDestructiveActionPending means Verify found no recorded human decision
// yet for the named hypothesis — a pending request with no decision, or no
// request at all. SubmitProof (internal/engine/harness/callback_submit_proof.go)
// treats this specially (ADR-0132): it is the caller's routine cue that the
// bet stays open, never a system failure.
var ErrDestructiveActionPending = errors.New("brain: destructive proof authorization is still pending")

// ErrDestructiveActionDenied means Verify found a recorded human decision
// that refused authorization for the named hypothesis. Unlike
// ErrDestructiveActionPending, this is terminal: the bet can never settle
// this way, and SubmitProof reports it in-band rather than retrying.
var ErrDestructiveActionDenied = errors.New("brain: destructive proof authorization was denied")

// DestructiveAuthorizationQueue is the concrete ADR-0132
// implementation split across three roles, all reading and writing the SAME
// durable DestructiveAction World record (decision 4, "one authorization
// path"):
//
//   - Request (the RequestDestructiveAuthorization RPC's backing call,
//     internal/engine/harness) enqueues a pending action and returns
//     immediately, BEFORE the agent performs the destructive act.
//
//   - Decide (the dashboard's ApproveDestructiveAction/DenyDestructiveAction
//     backing call, gibson#342) records a human's verdict.
//
//   - Verify is SettleBetTrue's DestructiveProofAuthorizer (bet_settlement.go):
//     wire it in by passing this method —
//
//     q := brain.NewDestructiveAuthorizationQueue(engine)
//     settled, err := engine.SettleBetTrue(ctx, registry, q.Verify, req)
//
// Pending (ListPendingDestructiveActions) reads the same record for the
// dashboard's queue view.
//
// Thread safety: all public methods are safe for concurrent use. There is no
// live in-memory hand-off to protect — every method reads or writes the
// engine's own Timeline/World, which is already safe for concurrent use.
type DestructiveAuthorizationQueue struct {
	engine *Engine

	// now is an injectable clock, defaulting to time.Now, so tests can pin
	// timestamps deterministically without sleeping.
	now func() time.Time
}

// NewDestructiveAuthorizationQueue constructs a queue bound to engine. engine
// must not be nil: the queue submits Timeline events through it and reads its
// World snapshot for Pending/Verify.
func NewDestructiveAuthorizationQueue(engine *Engine) *DestructiveAuthorizationQueue {
	if engine == nil {
		panic("brain: NewDestructiveAuthorizationQueue requires a non-nil engine")
	}
	return &DestructiveAuthorizationQueue{
		engine: engine,
		now:    time.Now,
	}
}

// DestructiveAuthorizationQueue returns e's queue, constructing it on first
// call (most engines never see a destructive proof request, so this is
// deliberately lazy rather than a field every Engine pays for up front). The
// daemon's DestructiveAuthorizationService handlers, the
// RequestDestructiveAuthorization RPC's tenant-routing adapter, and
// SettleBetTrue's wired-in verifier all call this to reach the SAME queue
// instance for a given engine.
func (e *Engine) DestructiveAuthorizationQueue() *DestructiveAuthorizationQueue {
	e.destructiveAuthzOnce.Do(func() {
		e.destructiveAuthz = NewDestructiveAuthorizationQueue(e)
	})
	return e.destructiveAuthz
}

// DestructiveAuthorizationRequest carries what Request (the
// RequestDestructiveAuthorization RPC's backing call, ADR-0132,
// gibson#390) needs to enqueue a pending destructive action BEFORE the agent
// performs it — the same identifying facts DestructiveActionRequested folds.
type DestructiveAuthorizationRequest struct {
	HypothesisID  string
	ScopeID       string
	MissionID     string
	Technique     string
	PredicateType string
	// BlastRadius and Reversibility are what the agent reported about the
	// action, for the approver.
	BlastRadius   string
	Reversibility Reversibility
}

// Request enqueues req as a pending destructive action and returns
// immediately (ADR-0132): the fleet keeps working while a human
// decides, because by construction the agent has not yet performed the
// destructive act — it asks first. This is the non-blocking replacement for
// the superseded blocking Authorize: nothing here waits on a channel, and
// nothing needs to be registered for Decide to unblock later, because Decide
// now operates purely off the durable World record (see Decide).
//
// Folding is idempotent (applyDestructiveActionRequested): a retried Request
// for a still-pending hypothesis — e.g. the agent's RPC call itself retried
// after a network hiccup — never resets the original request's timestamp or
// duplicates the record, so Request never needs to refuse a duplicate the
// way Authorize's live pending map once did.
//
// Returns the authorization_request_id the caller reads back before
// performing the destructive act, and later names on SubmitProof:
// req.HypothesisID itself — DestructiveAction's own identity (see this
// file's package doc) — because a destructive demonstration attempt is 1:1
// with one bet's settlement attempt.
func (q *DestructiveAuthorizationQueue) Request(tenant string, req DestructiveAuthorizationRequest) (string, error) {
	if req.HypothesisID == "" {
		return "", errors.New("brain: destructive authorization request requires a hypothesis id")
	}

	q.engine.Submit(DestructiveActionRequested{
		HypothesisID:      req.HypothesisID,
		Tenant:            tenant,
		ScopeID:           req.ScopeID,
		MissionID:         req.MissionID,
		Technique:         req.Technique,
		PredicateType:     req.PredicateType,
		BlastRadius:       req.BlastRadius,
		Reversibility:     req.Reversibility,
		RequestedAtUnixMS: q.now().UnixMilli(),
	})
	return req.HypothesisID, nil
}

// Verify implements the ADR-0132 request-then-verify shape of
// DestructiveProofAuthorizer (bet_settlement.go). It reads the durable
// DestructiveActionDecided fact recorded for req.HypothesisID and approves
// settlement only when that decision was an approval; it never blocks and
// never asks a human live — by the time SettleBetTrue calls this, the agent
// has already performed the destructive act and read back an approval
// (ADR-0132), so this is a check of an existing fact.
//
//   - No request was ever made, or one is pending with no decision yet:
//     returns ErrDestructiveActionPending.
//   - A decision was recorded and it denied authorization:
//     returns ErrDestructiveActionDenied.
//   - A decision was recorded and it approved authorization: returns
//     (true, nil).
func (q *DestructiveAuthorizationQueue) Verify(_ context.Context, _ string, req BetSettlementRequest) (bool, error) {
	if req.HypothesisID == "" {
		return false, errors.New("brain: destructive authorization verification requires a hypothesis id")
	}

	for _, a := range q.engine.DestructiveActionSnapshot() {
		if a.HypothesisID != req.HypothesisID {
			continue
		}
		if !a.Decided {
			return false, fmt.Errorf("%w: hypothesis %q has a pending request awaiting decision", ErrDestructiveActionPending, req.HypothesisID)
		}
		if !a.Approved {
			return false, fmt.Errorf("%w: hypothesis %q", ErrDestructiveActionDenied, req.HypothesisID)
		}
		return true, nil
	}
	return false, fmt.Errorf("%w: hypothesis %q: no authorization was ever requested", ErrDestructiveActionPending, req.HypothesisID)
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

// Decide records a human's approve/deny verdict for hypothesisID (ADR-0132):
// ApproveDestructiveAction/DenyDestructiveAction's backing call.
// It reads the durable World record directly: since ADR-0132 moved
// authorization to the non-blocking request-then-verify shape above, there
// is no live goroutine left to unblock the way the superseded blocking
// Authorize needed Decide to find. An unknown hypothesis id is refused, and
// an already-decided one is refused (terminal, first-decision-wins).
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

	q.engine.Submit(DestructiveActionDecided{
		HypothesisID:    hypothesisID,
		Approved:        approved,
		UserID:          userID,
		DecidedAtUnixMS: q.now().UnixMilli(),
	})
	return nil
}
