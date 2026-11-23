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
//
// A tool call of a connector uses the same record and the same two events
// (gibson#1474, ADR-0180). A tool call has no hypothesis, so its identity is a
// key that the daemon derives from the tenant, the mission, the connector, the
// tool and the arguments (ToolCallKey). The ActionKind of the record is
// ActionKindToolCall. A third event, destructive_action.consumed, records that
// an approved call ran, so one approval releases one call.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
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

	// ActionKind states what the request is for. An empty value is a destructive
	// proof. ActionKindToolCall is a call of a connector tool. The fields
	// below it are set only for a tool call.
	ActionKind string
	// CallKey is the key of the call without its sequence number.
	CallKey string
	// Connector, Tool and ArgsHash name the call that the approval covers.
	Connector string
	Tool      string
	ArgsHash  string
	// Consumed is set once the approved call was released. One approval
	// releases one call.
	Consumed bool
	// Withdrawn is set when the node that asked for the approval stopped waiting
	// (its timeout, the end of the mission, a cancel), so a person cannot approve a
	// request whose node is gone (gibson#1469). A withdrawn request is decided and
	// not approved, and a later verdict changes nothing.
	Withdrawn       bool
	WithdrawnReason string
	WithdrawnAtMS   int64

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
	// ActionKind, CallKey, Connector, Tool and ArgsHash identify a request for a
	// tool call. They are empty for a destructive proof.
	ActionKind string `json:",omitempty"`
	CallKey    string `json:",omitempty"`
	Connector  string `json:",omitempty"`
	Tool       string `json:",omitempty"`
	ArgsHash   string `json:",omitempty"`
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
		ActionKind:        e.ActionKind,
		CallKey:           e.CallKey,
		Connector:         e.Connector,
		Tool:              e.Tool,
		ArgsHash:          e.ArgsHash,
	})
	reconcileInputRequired(w, e.MissionID)
}

// reconcileInputRequired sets the state of a mission from its open approval
// requests. A working mission with an open request becomes MissionInputRequired.
// A mission in MissionInputRequired with no open request becomes MissionWorking.
// Another state does not change: a paused mission or a mission that ended keeps
// its state. An empty or unknown mission ID changes nothing. The call must not
// run inside an open query.
func reconcileInputRequired(w *World, missionID string) {
	if missionID == "" {
		return
	}
	ent, ok := findMission(w, missionID)
	if !ok {
		return
	}
	open := false
	q := ecs.NewFilter1[DestructiveAction](w.ecs).Query()
	for q.Next() {
		if a := q.Get(); a.MissionID == missionID && !a.Decided {
			open = true
			q.Close()
			break
		}
	}
	m := w.missions.Get(ent)
	switch {
	case open && m.Status == MissionWorking:
		m.Status = MissionInputRequired
	case !open && m.Status == MissionInputRequired:
		m.Status = MissionWorking
	}
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
		missionID := a.MissionID
		q.Close()
		reconcileInputRequired(w, missionID)
		return
	}
	// Query exhausted → world unlocked.
}

// DestructiveActionConsumed records that the daemon released the call that an
// approval covers (gibson#1474). It makes the approval single use: it folds
// into the same record, so a restart and a replay keep it.
type DestructiveActionConsumed struct {
	HypothesisID     string
	ConsumedAtUnixMS int64
}

// Kind identifies the destructive_action.consumed brain event.
func (DestructiveActionConsumed) Kind() string { return "destructive_action.consumed" }

// applyDestructiveActionConsumed folds a DestructiveActionConsumed event. Only
// an approved tool call that is not yet consumed changes. An event for any
// other record is dropped, so a stray event cannot spend a proof.
func applyDestructiveActionConsumed(w *World, e DestructiveActionConsumed) {
	if e.HypothesisID == "" {
		return
	}
	q := ecs.NewFilter1[DestructiveAction](w.ecs).Query()
	for q.Next() {
		a := q.Get()
		if a.HypothesisID != e.HypothesisID {
			continue
		}
		if a.ActionKind == ActionKindToolCall && a.Decided && a.Approved {
			a.Consumed = true
		}
		q.Close()
		return
	}
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
	ActionKind        string        `json:",omitempty"`
	CallKey           string        `json:",omitempty"`
	Connector         string        `json:",omitempty"`
	Tool              string        `json:",omitempty"`
	ArgsHash          string        `json:",omitempty"`
	Consumed          bool          `json:",omitempty"`
	Withdrawn         bool          `json:",omitempty"`
	WithdrawnReason   string        `json:",omitempty"`
	WithdrawnAtMS     int64         `json:",omitempty"`
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
			ActionKind:        a.ActionKind,
			CallKey:           a.CallKey,
			Connector:         a.Connector,
			Tool:              a.Tool,
			ArgsHash:          a.ArgsHash,
			Consumed:          a.Consumed,
			Withdrawn:         a.Withdrawn, WithdrawnReason: a.WithdrawnReason, WithdrawnAtMS: a.WithdrawnAtMS,
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

	// toolMu makes the read of a tool call record and the write that follows
	// one step, so two equal calls cannot both claim one approval.
	toolMu sync.Mutex
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
	if strings.HasPrefix(req.HypothesisID, toolCallIDPrefix) {
		// The prefix names the requests of tool calls. An agent cannot take
		// the identity of a tool call with a proof request.
		return "", fmt.Errorf("brain: hypothesis id %q uses the reserved prefix %q", req.HypothesisID, toolCallIDPrefix)
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
		if a.HypothesisID != req.HypothesisID || a.ActionKind != ActionKindProof {
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

// ActionKindProof is the ActionKind of a destructive proof request. It is the empty
// string, so a record from before the ActionKind field keeps its meaning.
const ActionKindProof = ""

// ActionKindToolCall is the ActionKind of a request for a tool call of a connector
// (gibson#1474).
const ActionKindToolCall = "tool_call"

// toolCallIDPrefix starts the identity of each tool call request. Request
// refuses a proof with this prefix.
const toolCallIDPrefix = "tool-call:"

// ToolCallKey derives the key of a tool call. The key covers the tenant, the
// mission, the run, the work item (the node), the agent, the connector, the tool and the hash of the arguments, so an
// approval of one call does not cover another target, another tool or another
// mission. Each part has a length prefix, so two different calls cannot form the
// same input.
func ToolCallKey(tenant, missionID, runID, workID, agent, connector, tool, argsHash string) string {
	h := sha256.New()
	for _, part := range []string{tenant, missionID, runID, workID, agent, connector, tool, argsHash} {
		_, _ = fmt.Fprintf(h, "%d:%s|", len(part), part) // a hash never fails a write
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ToolCallRequest is one call of a marked tool that waits for the approval of a
// person.
type ToolCallRequest struct {
	MissionID string
	// RunID and WorkID name the run and the node of the call. Two nodes never
	// share one approval, and one approval releases one call (gibson#1469).
	RunID  string
	WorkID string
	// Agent is the identity of the caller. An approval covers the call of one
	// agent, so another agent of the mission cannot spend it (review m16).
	Agent     string
	Connector string
	Tool      string
	// ArgsHash is the hash of the canonical arguments of the call.
	ArgsHash string
	// BlastRadius and Reversibility are for the approver. The manifest of the
	// connector and the arguments of the call give them.
	BlastRadius   string
	Reversibility Reversibility
}

// ToolCallState is the state of one call in the approval queue.
type ToolCallState int

const (
	// ToolCallPending means that a request waits for a decision. The call must
	// not run.
	ToolCallPending ToolCallState = iota + 1
	// ToolCallDenied means that a person refused the call.
	ToolCallDenied
	// ToolCallApproved means that a person approved the call and this check
	// spent the approval. The caller runs the call now, one time.
	ToolCallApproved
)

// AuthorizeToolCall is the one check of the approval queue at tool dispatch. It
// never blocks.
//
//   - A call with no request records one request and returns ToolCallPending
//     with the id of the request.
//   - A call with a request that waits returns ToolCallPending and records
//     nothing new.
//   - A call with a denied request returns ToolCallDenied. The decision is final.
//   - A call with an approved request that is not spent records the spend and
//     returns ToolCallApproved. The next equal call has no approval left and
//     starts a new request.
//
// An error means that the check could not finish. The caller must not run the
// call.
func (q *DestructiveAuthorizationQueue) AuthorizeToolCall(
	ctx context.Context, tenant string, req ToolCallRequest,
) (ToolCallState, string, error) {
	if req.Connector == "" || req.Tool == "" || req.ArgsHash == "" {
		return 0, "", errors.New("brain: a tool call request needs a connector, a tool and an argument hash")
	}
	key := ToolCallKey(tenant, req.MissionID, req.RunID, req.WorkID, req.Agent, req.Connector, req.Tool, req.ArgsHash)

	q.toolMu.Lock()
	defer q.toolMu.Unlock()

	var mine []DestructiveActionSnapshot
	for _, a := range q.engine.DestructiveActionSnapshot() {
		if a.ActionKind == ActionKindToolCall && a.CallKey == key {
			mine = append(mine, a)
		}
	}
	// The sequence number is part of the id, so a numeric order is the order of
	// creation.
	sort.Slice(mine, func(i, j int) bool { return toolCallSeq(mine[i].HypothesisID) < toolCallSeq(mine[j].HypothesisID) })

	for _, a := range mine {
		switch {
		case a.Withdrawn:
			// The node that asked stopped waiting. The request is dead, and a new
			// call of the same arguments starts a new request (gibson#1469).
			continue
		case !a.Decided:
			return ToolCallPending, a.HypothesisID, nil
		case !a.Approved:
			return ToolCallDenied, a.HypothesisID, nil
		case a.Consumed:
			continue
		}
		err := q.engine.SubmitAndWait(ctx, DestructiveActionConsumed{
			HypothesisID:     a.HypothesisID,
			ConsumedAtUnixMS: q.now().UnixMilli(),
		})
		if err != nil {
			return 0, "", fmt.Errorf("brain: record the use of the approval %q: %w", a.HypothesisID, err)
		}
		return ToolCallApproved, a.HypothesisID, nil
	}

	id := toolCallIDPrefix + key + "#" + strconv.Itoa(len(mine))
	err := q.engine.SubmitAndWait(ctx, DestructiveActionRequested{
		HypothesisID:      id,
		Tenant:            tenant,
		MissionID:         req.MissionID,
		Technique:         "mcp:" + req.Connector + ":" + req.Tool,
		PredicateType:     ActionKindToolCall,
		BlastRadius:       req.BlastRadius,
		Reversibility:     req.Reversibility,
		RequestedAtUnixMS: q.now().UnixMilli(),
		ActionKind:        ActionKindToolCall,
		CallKey:           key,
		Connector:         req.Connector,
		Tool:              req.Tool,
		ArgsHash:          req.ArgsHash,
	})
	if err != nil {
		return 0, "", fmt.Errorf("brain: record the approval request of %s:%s: %w", req.Connector, req.Tool, err)
	}
	return ToolCallPending, id, nil
}

// toolCallSeq reads the sequence number at the end of a tool call id.
func toolCallSeq(id string) int {
	i := strings.LastIndexByte(id, '#')
	if i < 0 {
		return 0
	}
	n, err := strconv.Atoi(id[i+1:])
	if err != nil {
		return 0
	}
	return n
}

// DestructiveActionWithdrawn records that the requester stopped waiting for an
// approval (gibson#1469). It folds like a decision that is not an approval: the
// request is decided, it is not approved, and it leaves the queue of the people
// who approve. The first decision wins, so a withdrawal of a request that a person
// decided changes nothing, and a verdict that comes after a withdrawal changes
// nothing.
type DestructiveActionWithdrawn struct {
	HypothesisID string
	Reason       string
	AtUnixMS     int64
}

// Kind identifies the destructive_action.withdrawn brain event.
func (DestructiveActionWithdrawn) Kind() string { return "destructive_action.withdrawn" }

func applyDestructiveActionWithdrawn(w *World, e DestructiveActionWithdrawn) {
	if e.HypothesisID == "" {
		return
	}
	q := ecs.NewFilter1[DestructiveAction](w.ecs).Query()
	for q.Next() {
		a := q.Get()
		if a.HypothesisID != e.HypothesisID {
			continue
		}
		if a.ActionKind != ActionKindToolCall || a.Decided {
			q.Close()
			return
		}
		a.Decided, a.Approved = true, false
		a.Withdrawn, a.WithdrawnReason, a.WithdrawnAtMS = true, e.Reason, e.AtUnixMS
		a.DecidedAtUnixMS = e.AtUnixMS
		missionID := a.MissionID
		q.Close()
		reconcileInputRequired(w, missionID)
		return
	}
}

// Withdraw withdraws the approval request of a node that stopped waiting. It is
// idempotent: a request that is decided already is left as it is.
func (q *DestructiveAuthorizationQueue) Withdraw(ctx context.Context, hypothesisID, reason string) error {
	if hypothesisID == "" {
		return errors.New("brain: withdraw requires a request id")
	}
	if err := q.engine.SubmitAndWait(ctx, DestructiveActionWithdrawn{
		HypothesisID: hypothesisID, Reason: reason, AtUnixMS: q.now().UnixMilli(),
	}); err != nil {
		return fmt.Errorf("brain: withdraw the approval request %q: %w", hypothesisID, err)
	}
	return nil
}
