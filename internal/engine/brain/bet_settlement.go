// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

// bet_settlement.go is proof-of-demonstration (ADR-0027, gibson#278): a bet
// settles TRUE only when a typed success predicate (internal/engine/settlement,
// gibson#297) fires deterministically against recorded evidence — never an
// LLM opinion, and never a bare assertion.
//
// Settlement is folded through the normal Timeline -> Reduce path (ADR-0007),
// so it is replayable like any other event. It records against the bet's own
// HypothesisID (the same identifier PlaceBet's Bet.HypothesisId names,
// callback_place_bet.go), NOT against a brain.Hypothesis World entity: this
// keeps settlement independent of gibson#265 (a parallel slice), the same way
// AgentRun is keyed by an externally-given RunID rather than derived content
// identity. Settlement also does not touch brain.BeliefSubstrate (the
// PlaceBet market-confidence view, gibson#273): that store is still an
// unbacked stub (belief_substrate.go) with no replay story of its own, so
// reconciling "confidence" and "settled" into one substrate is left for a
// later slice, once BeliefSubstrate has a real, replayable implementation to
// reconcile into. For now the two views compose but do not overwrite each
// other: PlaceBet records a stake, settlement records a verdict, both
// addressed by the same HypothesisID.
//
// Settlement is terminal (ADR-0023: "open bets earn nothing" — once
// settled, nothing more happens to that bet): a second settlement event for
// an already-settled HypothesisID is dropped, never overwriting the first
// verdict, mirroring how a stale BeliefScored is dropped rather than
// reopening a decided question.
//
// gibson#279 adds the bounded-exhaustion FALSE path alongside the TRUE path
// above: a bet whose declared attempt budget runs out with no demonstrated
// proof settles FALSE, a real recorded outcome, never silence (ADR-0023).
// Both verdicts share the one BetSettlement component and SettlementVerdict
// type, and both are terminal by the same rule: whichever settlement lands
// first for a HypothesisID wins.
//
// gibson#280 (async HITL verdict) is a separate, later slice that will add
// a third sibling event type (e.g. BetSettledByHITL) folding into the same
// component.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/mlange-42/ark/ecs"
	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
)

// SettlementVerdict is how a bet resolved (ADR-0023). gibson#280 adds the
// HITL verdict as a sibling.
type SettlementVerdict string

const (
	// SettlementVerdictTrue means the fleet demonstrated the claim in a
	// sandbox and a typed predicate fired against the recorded evidence
	// (ADR-0027).
	SettlementVerdictTrue SettlementVerdict = "true"
	// SettlementVerdictFalse means the bet's declared attempt budget was
	// exhausted with no demonstrated proof (ADR-0023, gibson#279) — a real,
	// recorded outcome, not silence.
	SettlementVerdictFalse SettlementVerdict = "false"
)

// BetSettlement records how a bet on a hypothesis resolved. Identity is
// HypothesisID, matching Bet.HypothesisId (callback_place_bet.go) — the same
// externally-given-string-key pattern AgentRun uses for RunID, so settlement
// never depends on a brain.Hypothesis entity existing for that id.
type BetSettlement struct {
	HypothesisID string
	Verdict      SettlementVerdict
	// Technique and PredicateType name which predicate type (from the
	// technique's Domain Pack, internal/engine/settlement) fired, so the
	// verdict is auditable: this is what settled it, and it can be
	// re-evaluated against the same recorded evidence to confirm.
	Technique     string
	PredicateType string
	// EvidenceDigest fingerprints the captured evidence the predicate was
	// evaluated against — the link between the proof and the settled bet
	// (gibson#278's "the proof is evidence on the graph and links to the
	// settled bet" acceptance criterion). Set only for SettlementVerdictTrue.
	EvidenceDigest string
	// AttemptBudget and AttemptsMade record the bet's declared maximum
	// number of demonstration attempts and how many were actually made
	// before settlement. Set only for SettlementVerdictFalse (gibson#279).
	AttemptBudget int
	AttemptsMade  int
	// Reason is a short, human-readable explanation of why the bet settled
	// FALSE (e.g. "sandbox demonstration attempted 3/3 times with no
	// predicate match"). Set only for SettlementVerdictFalse: a FALSE
	// verdict must record why, never settle in silence.
	Reason    string
	ScopeID   string
	MissionID string
}

// BetSettledTrue records that a bet's hypothesis was demonstrated true: a
// typed predicate fired against recorded evidence (ADR-0027). It folds
// through the normal Observe-shaped reducer path (ADR-0007), so replay
// reproduces the settlement exactly — replay re-applies this already-decided
// fact, it never re-evaluates the predicate (the same pattern BeliefScored
// uses: evaluation happens once, off the single-writer path, and only the
// result is folded).
type BetSettledTrue struct {
	HypothesisID   string
	Technique      string
	PredicateType  string
	EvidenceDigest string
	ScopeID        string
	MissionID      string
}

// Kind identifies the bet.settled_true brain event.
func (BetSettledTrue) Kind() string { return "bet.settled_true" }

// applyBetSettledTrue folds a BetSettledTrue event into the World. An empty
// HypothesisID records nothing — there would be no bet to settle. Settlement
// is terminal: a HypothesisID that already has a BetSettlement is left
// untouched, so a later, possibly-differently-evidenced settlement attempt
// can never overwrite a decided verdict.
func applyBetSettledTrue(w *World, e BetSettledTrue) {
	if e.HypothesisID == "" {
		return
	}

	q := ecs.NewFilter1[BetSettlement](w.ecs).Query()
	for q.Next() {
		s := q.Get()
		if s.HypothesisID == e.HypothesisID {
			q.Close()
			return
		}
	}
	// Query exhausted → world unlocked.

	w.betSettlements.NewEntity(&BetSettlement{
		HypothesisID:   e.HypothesisID,
		Verdict:        SettlementVerdictTrue,
		Technique:      e.Technique,
		PredicateType:  e.PredicateType,
		EvidenceDigest: e.EvidenceDigest,
		ScopeID:        e.ScopeID,
		MissionID:      e.MissionID,
	})
}

// BetSettledFalse records that a bet's declared attempt budget was exhausted
// with no demonstrated proof (ADR-0023, gibson#279): a real, recorded
// outcome, not silence. Like BetSettledTrue, it folds through the normal
// reducer path, so replay reproduces the settlement exactly.
type BetSettledFalse struct {
	HypothesisID  string
	AttemptBudget int
	AttemptsMade  int
	Reason        string
	ScopeID       string
	MissionID     string
}

// Kind identifies the bet.settled_false brain event.
func (BetSettledFalse) Kind() string { return "bet.settled_false" }

// applyBetSettledFalse folds a BetSettledFalse event into the World. Settlement
// is terminal, and the rule is shared with applyBetSettledTrue: whichever
// settlement (TRUE or FALSE) lands first for a HypothesisID wins, so a bet
// already settled TRUE can never be flipped FALSE by a later exhaustion
// event, and vice versa.
func applyBetSettledFalse(w *World, e BetSettledFalse) {
	if e.HypothesisID == "" {
		return
	}

	q := ecs.NewFilter1[BetSettlement](w.ecs).Query()
	for q.Next() {
		s := q.Get()
		if s.HypothesisID == e.HypothesisID {
			q.Close()
			return
		}
	}
	// Query exhausted → world unlocked.

	w.betSettlements.NewEntity(&BetSettlement{
		HypothesisID:  e.HypothesisID,
		Verdict:       SettlementVerdictFalse,
		AttemptBudget: e.AttemptBudget,
		AttemptsMade:  e.AttemptsMade,
		Reason:        e.Reason,
		ScopeID:       e.ScopeID,
		MissionID:     e.MissionID,
	})
}

// BetSettlementSnapshot is a stable, comparable view of a BetSettlement.
type BetSettlementSnapshot struct {
	HypothesisID   string
	Verdict        SettlementVerdict
	Technique      string
	PredicateType  string
	EvidenceDigest string
	AttemptBudget  int
	AttemptsMade   int
	Reason         string
	ScopeID        string
	MissionID      string
}

// BetSettlementSnapshot returns settlements in deterministic (HypothesisID)
// order.
func (w *World) BetSettlementSnapshot() []BetSettlementSnapshot {
	var out []BetSettlementSnapshot
	q := ecs.NewFilter1[BetSettlement](w.ecs).Query()
	for q.Next() {
		s := q.Get()
		out = append(out, BetSettlementSnapshot{
			HypothesisID:   s.HypothesisID,
			Verdict:        s.Verdict,
			Technique:      s.Technique,
			PredicateType:  s.PredicateType,
			EvidenceDigest: s.EvidenceDigest,
			AttemptBudget:  s.AttemptBudget,
			AttemptsMade:   s.AttemptsMade,
			Reason:         s.Reason,
			ScopeID:        s.ScopeID,
			MissionID:      s.MissionID,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HypothesisID < out[j].HypothesisID })
	return out
}

// BetSettlements returns the current settlement snapshots (read-locked, safe
// to call concurrently with the tick loop — the same read-accessor contract
// every other Engine method offers).
func (e *Engine) BetSettlements() []BetSettlementSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.BetSettlementSnapshot()
}

// BetSettlementRequest carries everything needed to attempt settling one bet
// TRUE by recorded proof (ADR-0027).
type BetSettlementRequest struct {
	// HypothesisID names the bet being settled — the same identifier
	// PlaceBet's Bet.HypothesisId carries.
	HypothesisID string
	ScopeID      string
	MissionID    string
	// Technique and PredicateType select the registered predicate
	// (internal/engine/settlement): the predicate type must have been
	// registered for Technique by that technique's Domain Pack loader, or
	// evaluation fails closed (the anti-gaming guarantee gibson#297 built).
	Technique       settlement.TechniqueID
	PredicateType   settlement.PredicateType
	PredicateParams any
	// Evidence is what the demonstration captured. The predicate is
	// evaluated against exactly this slice — no LLM, no other input.
	Evidence []finding.EnhancedEvidence
	// Destructive marks this demonstration as destructive or irreversible
	// (ADR-0028). Until a technique's Domain Pack carries its own risk-tier
	// flag, the caller declares it explicitly here. A destructive request is
	// refused unless a DestructiveProofAuthorizer approves it — never
	// auto-approved.
	Destructive bool
}

// DestructiveProofAuthorizer authorizes one specific destructive
// demonstration (ADR-0028): a human sees the action, its blast radius, and
// the predicate it would satisfy — in practice, the dashboard authorization
// queue (gibson#99, tracked as a separate lane) — and approves or denies
// that one action. The bet stays OPEN and the rest of the fleet keeps
// working while this is pending; nothing here pauses a mission.
//
// nil means no authorizer is wired: a destructive request is refused, never
// auto-approved. This is a stub seam, not a finished integration — wiring a
// real authorizer through to the dashboard's authorization queue is a
// follow-up slice.
type DestructiveProofAuthorizer func(ctx context.Context, tenant string, req BetSettlementRequest) (approved bool, err error)

// SettleBetTrue evaluates req's predicate against req's evidence (ADR-0027)
// and, if it fires, settles the named bet TRUE. It returns settled=true only
// when this call caused a new TRUE settlement; settled=false with a nil
// error means the predicate did not fire (the claim stays unproven, not
// refused) or the bet was already settled (a terminal, idempotent no-op). A
// non-nil error means settlement could not even be attempted: no hypothesis
// id, an unregistered predicate type, or a refused/failed destructive-proof
// authorization.
//
// Evaluation is deterministic and synchronous — registry.Evaluate never
// calls an LLM (ADR-0027, decision 2) — but the resulting BetSettledTrue
// event is folded asynchronously through the normal single-writer Submit
// path (ADR-0001), so a caller that needs to observe the settled state
// should read BetSettlements() afterward rather than assume it is visible
// the instant this call returns.
func (e *Engine) SettleBetTrue(ctx context.Context, registry *settlement.Registry, authorize DestructiveProofAuthorizer, req BetSettlementRequest) (bool, error) {
	if req.HypothesisID == "" {
		return false, errors.New("brain: settlement request must name a hypothesis id")
	}

	for _, s := range e.BetSettlements() {
		if s.HypothesisID == req.HypothesisID {
			// Terminal: already settled. Not an error — a caller retrying a
			// settlement attempt after a crash must not fail loudly for
			// something that already succeeded.
			return false, nil
		}
	}

	if req.Destructive {
		if authorize == nil {
			return false, fmt.Errorf(
				"brain: destructive proof for hypothesis %q requires authorization, and no authorizer is wired on this daemon",
				req.HypothesisID)
		}
		approved, err := authorize(ctx, e.World.Tenant, req)
		if err != nil {
			return false, fmt.Errorf("brain: destructive proof authorization for hypothesis %q: %w", req.HypothesisID, err)
		}
		if !approved {
			return false, fmt.Errorf("brain: destructive proof for hypothesis %q was not authorized", req.HypothesisID)
		}
	}

	predicate, err := registry.NewPredicate(req.Technique, req.PredicateType, req.PredicateParams)
	if err != nil {
		return false, fmt.Errorf("brain: settlement predicate for hypothesis %q: %w", req.HypothesisID, err)
	}

	ok, err := registry.Evaluate(ctx, predicate, req.Evidence)
	if err != nil {
		return false, fmt.Errorf("brain: settlement evaluation for hypothesis %q: %w", req.HypothesisID, err)
	}
	if !ok {
		return false, nil
	}

	e.Submit(BetSettledTrue{
		HypothesisID:   req.HypothesisID,
		Technique:      string(req.Technique),
		PredicateType:  string(req.PredicateType),
		EvidenceDigest: settlementEvidenceDigest(req.Evidence),
		ScopeID:        req.ScopeID,
		MissionID:      req.MissionID,
	})
	return true, nil
}

// BetExhaustionRequest carries the facts needed to settle a bet FALSE on
// bounded exhaustion (ADR-0023, gibson#279): the declared attempt budget ran
// out with no demonstrated proof.
type BetExhaustionRequest struct {
	// HypothesisID names the bet being settled — the same identifier
	// PlaceBet's Bet.HypothesisId carries.
	HypothesisID string
	ScopeID      string
	MissionID    string
	// AttemptBudget is the bet's declared maximum number of demonstration
	// attempts. It must be positive: "each bet carries an attempt budget"
	// is not satisfiable by a zero or absent one.
	AttemptBudget int
	// AttemptsMade is how many attempts were actually made. Settlement is
	// refused while AttemptsMade < AttemptBudget: exhaustion cannot be
	// declared early.
	AttemptsMade int
	// Reason is a short, human-readable explanation recorded with the
	// verdict, e.g. "sandbox demonstration attempted 3/3 times with no
	// predicate match". Required: a FALSE verdict must record why it
	// settled, never settle in silence.
	Reason string
}

// SettleBetFalse settles the named bet FALSE once its declared attempt
// budget is exhausted with no demonstrated proof (ADR-0023). This is the
// bounded-exhaustion counterpart to SettleBetTrue: a real, recorded outcome
// — not silence — so the calibration signal learns from misses too.
//
// It returns settled=true only when this call caused a new FALSE
// settlement; settled=false with a nil error means the bet was already
// settled (a terminal, idempotent no-op, by either verdict). A non-nil
// error means settlement could not be attempted: no hypothesis id, a
// non-positive attempt budget, no recorded reason, or the budget is not
// yet actually exhausted.
//
// Like SettleBetTrue, the resulting BetSettledFalse event is folded
// asynchronously through the normal single-writer Submit path (ADR-0001); a
// caller that needs to observe the settled state should read
// BetSettlements() afterward.
func (e *Engine) SettleBetFalse(_ context.Context, req BetExhaustionRequest) (bool, error) {
	if req.HypothesisID == "" {
		return false, errors.New("brain: settlement request must name a hypothesis id")
	}
	if req.AttemptBudget <= 0 {
		return false, fmt.Errorf("brain: bet %q must declare a positive attempt budget, got %d", req.HypothesisID, req.AttemptBudget)
	}
	if req.Reason == "" {
		return false, fmt.Errorf("brain: a FALSE settlement for hypothesis %q must record why", req.HypothesisID)
	}
	if req.AttemptsMade < req.AttemptBudget {
		return false, fmt.Errorf("brain: attempt budget not yet exhausted for hypothesis %q (%d/%d attempts made)",
			req.HypothesisID, req.AttemptsMade, req.AttemptBudget)
	}

	for _, s := range e.BetSettlements() {
		if s.HypothesisID == req.HypothesisID {
			// Terminal: already settled, by either verdict. Not an error —
			// a caller retrying after a crash must not fail loudly for
			// something already decided.
			return false, nil
		}
	}

	e.Submit(BetSettledFalse{
		HypothesisID:  req.HypothesisID,
		AttemptBudget: req.AttemptBudget,
		AttemptsMade:  req.AttemptsMade,
		Reason:        req.Reason,
		ScopeID:       req.ScopeID,
		MissionID:     req.MissionID,
	})
	return true, nil
}

// settlementEvidenceDigest fingerprints the captured evidence a settlement
// decision was made from — the fact recorded on BetSettlement.EvidenceDigest
// (the link from the proof to the settled bet). It is computed once, at
// settlement time; replay never recomputes it, it just re-applies the
// recorded fact, the same evidenceDigest/betEvidenceDigest pattern used
// elsewhere in this codebase (belief.go, callback_place_bet.go).
func settlementEvidenceDigest(evidence []finding.EnhancedEvidence) string {
	b, _ := json.Marshal(evidence)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
