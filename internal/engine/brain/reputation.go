// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// reputation.go is gibson#267 (ADR-0022, ADR-0029 §3): reputation keyed by
// technique × environment, never by agent. Per the issue's own "Reframed as
// a view" comment (grill 2026-09-27), reputation is NOT a separate store —
// it is a VIEW of the belief substrate: belief on a technique×environment
// node (P(technique works here)), updated from settled outcomes. A settled
// bet (bet_settlement.go, gibson#278/#279/#280) updates the reputation of
// the technique it exercised in the scope it ran in; reputation then feeds
// the prior strength on new hypotheses of that technique and the priority
// the fleet gives to pursuing them.
//
// "Environment" is ScopeID: the coordinate every other observation in this
// package already partitions identity by (ADR-0002) — the target the
// mission ran against. This is a deliberate, documented reading; nothing
// else in this codebase defines "environment" as its own concept.
//
// Scope boundary: this file reads settled bets ONLY through
// Engine.BetSettlements()/BetSettlementSnapshot and writes ONLY through
// BeliefSubstrate. All three settlement paths now record a Technique:
// predicate from the proof's own technique, and exhaustion/HITL resolved from
// the bet's Hypothesis by the settle orchestrators (bet_settlement.go). A
// settlement that STILL has no recorded Technique — its Hypothesis is unknown,
// or named none — cannot update any technique's reputation and is skipped, the
// same "surfaced, not hidden" choice calibration.go's Unscored count makes.
//
// The technique×environment node key (TechniqueEnvironmentRef) is exactly what
// voi_plan.go's resolveReputation and ReadReputation build from each
// hypothesis's Technique × ScopeID (gibson#267): the reputation written here is
// read back there as both a new hypothesis's prior and its pursuit-priority
// multiplier. It is tenant-prefixed the same way hypothesisClaimRef scopes a
// claim-node lookup. The write side is driven live by reputation_worker.go,
// which taps a settled bet and calls Engine.UpdateReputation off the tick.
//
// Reputation is exact and recomputed fresh from the full settled-bet
// history on every UpdateReputation call, never blended — this mirrors
// BeliefSubstrate.SetBelief's own "replaces whatever was there before in
// full" contract (node_belief.go), and calibration.go's read-side-
// aggregation pattern. It is also what makes reputation durable across a
// scale-to-zero: it is not BeliefSubstrate itself that persists (still an
// unbacked stub with no durability story of its own) but the fact that
// reputation is always exactly rebuildable from BetSettlement, which IS a
// Timeline-replayable World entity. Recomputing after a restart reproduces
// the identical belief (TestUpdateReputation_RebuildsIdenticallyAfterReset).

// DefaultReputationPrior is the prior strength / pursuit signal for a
// technique×environment pair with no settled bets yet — maximum
// uncertainty, not "never works": a new technique must not be starved of
// pursuit just because it has no track record yet (the same optimism-under-
// uncertainty stance voi_score.go's voiNeutralReputationPrior already takes
// for an unresolvable key).
const DefaultReputationPrior = 0.5

// Reputation is technique × environment's track record (ADR-0022,
// ADR-0029 §3): how often a settled bet on this technique, in this scope,
// came back TRUE.
type Reputation struct {
	Technique string
	ScopeID   string
	// N is how many settled bets contributed. Zero means no track record
	// exists yet — PriorStrength returns DefaultReputationPrior, not 0.
	N int
	// ObservedFrequency is the fraction of the N settled bets whose verdict
	// was TRUE — the belief substrate's own P(technique works here)
	// (belief_substrate.go, NodeKindTechniqueEnvironment).
	ObservedFrequency float64
	// MeanBrierScore is the mean of the contributing bets' own per-bet
	// Brier scores (bet_scoring.go, gibson#277) — how well-calibrated this
	// technique's stakes have been in this environment, not just how often
	// it has won.
	MeanBrierScore float64
}

// PriorStrength is the confidence a NEW hypothesis of this technique, in
// this environment, should start from — and, until the sequential planner
// (gibson#283/#333) can resolve a real technique×environment key, the raw
// signal behind how eagerly the fleet prioritizes pursuing it. A technique
// with no settled bets yet (N == 0) returns DefaultReputationPrior: no
// track record is not the same claim as "never works".
func (r Reputation) PriorStrength() float64 {
	if r.N == 0 {
		return DefaultReputationPrior
	}
	return r.ObservedFrequency
}

// TechniqueEnvironmentRef addresses the technique×environment belief node
// (ADR-0029 §3, NodeKindTechniqueEnvironment) a Reputation is a view of.
// tenant-prefixed the same way hypothesisClaimRef/harness.claimNodeRef scope
// their own NodeRef, since BeliefSubstrate keys purely on (Kind, ID) with no
// tenant dimension of its own.
func TechniqueEnvironmentRef(tenant, technique, scopeID string) NodeRef {
	return NodeRef{Kind: NodeKindTechniqueEnvironment, ID: tenant + "/" + technique + ":" + scopeID}
}

// ComputeReputation aggregates every settlement in settlements for technique
// in scopeID into one Reputation — exact and recomputed fresh each time, the
// same read-side-aggregation pattern calibration.go uses. A settlement for a
// different technique or scope, or with no recorded Technique at all
// (bet_settlement.go's documented gap for the exhaustion/HITL paths today),
// is skipped.
func ComputeReputation(technique, scopeID string, settlements []BetSettlementSnapshot) Reputation {
	rep := Reputation{Technique: technique, ScopeID: scopeID}
	var sumObserved, sumBrier float64
	for _, s := range settlements {
		if s.Technique == "" || s.Technique != technique || s.ScopeID != scopeID {
			continue
		}
		rep.N++
		sumObserved += settlementOutcome(s.Verdict)
		sumBrier += s.BrierScore
	}
	if rep.N > 0 {
		rep.ObservedFrequency = sumObserved / float64(rep.N)
		rep.MeanBrierScore = sumBrier / float64(rep.N)
	}
	return rep
}

// UpdateReputation recomputes technique's reputation in scopeID from
// settlements and writes it to substrate as the technique×environment
// belief (ADR-0029 §3) — the "a settled bet updates the matching
// reputation" acceptance criterion (gibson#267 AC2). It is a full, exact
// overwrite, never a blend: replaying this call with the same settlements
// always reproduces the same write. Returns the Reputation it wrote, so a
// caller can report contributing N/MeanBrierScore without a second read.
func UpdateReputation(ctx context.Context, tenant, technique, scopeID string, settlements []BetSettlementSnapshot, substrate BeliefSubstrate) (Reputation, error) {
	rep := ComputeReputation(technique, scopeID, settlements)
	ref := TechniqueEnvironmentRef(tenant, technique, scopeID)
	nb := NodeBelief{
		Belief: Belief{
			Exploitable: rep.PriorStrength(),
			Model:       "reputation:v1",
		},
		EvidenceDigest: reputationEvidenceDigest(technique, scopeID, settlements),
	}
	if err := substrate.SetBelief(ctx, ref, nb); err != nil {
		return Reputation{}, fmt.Errorf("brain: update reputation for technique %q in scope %q: %w", technique, scopeID, err)
	}
	return rep, nil
}

// ReadReputation reads the current technique×environment belief straight
// from substrate, for a caller that only has BeliefSubstrate at hand (e.g.
// hypothesis creation seeding a new claim's prior, gibson#267 AC3) rather
// than the settlement history. ok is false, matching BeliefSubstrate.Belief
// itself, when nothing has been recorded yet — the caller should treat that
// the same as N == 0 (DefaultReputationPrior), not as a hard failure.
func ReadReputation(ctx context.Context, tenant, technique, scopeID string, substrate BeliefSubstrate) (priorStrength float64, ok bool, err error) {
	ref := TechniqueEnvironmentRef(tenant, technique, scopeID)
	nb, ok, err := substrate.Belief(ctx, ref)
	if err != nil {
		return 0, false, fmt.Errorf("brain: read reputation for technique %q in scope %q: %w", technique, scopeID, err)
	}
	if !ok {
		return DefaultReputationPrior, false, nil
	}
	return nb.Belief.Exploitable, true, nil
}

// reputationEvidenceDigest fingerprints exactly which settled bets (by
// HypothesisID) contributed to a technique×environment reputation write —
// the same evidenceDigest/betEvidenceDigest/settlementEvidenceDigest pattern
// used everywhere else in this package, linking a write back to the
// evidence it was computed from. Sorted so the digest never depends on
// settlements' input order.
func reputationEvidenceDigest(technique, scopeID string, settlements []BetSettlementSnapshot) string {
	ids := make([]string, 0, len(settlements))
	for _, s := range settlements {
		if s.Technique == technique && s.ScopeID == scopeID {
			ids = append(ids, s.HypothesisID)
		}
	}
	sort.Strings(ids)

	b, err := json.Marshal(struct {
		Technique  string   `json:"technique"`
		ScopeID    string   `json:"scope_id"`
		Hypotheses []string `json:"hypotheses"`
	}{technique, scopeID, ids})
	if err != nil {
		// ids is a []string and technique/scopeID are strings: json.Marshal
		// cannot fail on this input. Kept as an explicit, narrow panic
		// rather than silently returning an empty digest, which would look
		// like "no evidence contributed" to a caller.
		panic(fmt.Sprintf("brain: marshal reputation evidence digest: %v", err))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// UpdateReputation recomputes and writes technique's reputation in scopeID
// from the engine's current settled bets (BetSettlements) — the read-only
// accessor a settlement orchestrator or a daemon handler calls after a bet
// settles. substrate is typically a WorldBeliefSubstrate bound to this same
// engine, the same convention Engine.Calibration uses.
func (e *Engine) UpdateReputation(ctx context.Context, technique, scopeID string, substrate BeliefSubstrate) (Reputation, error) {
	return UpdateReputation(ctx, e.World.Tenant, technique, scopeID, e.BetSettlements(), substrate)
}
