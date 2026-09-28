// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"
)

func settledSnapshot(technique, scopeID string, verdict SettlementVerdict, hypothesisID string, brier float64) BetSettlementSnapshot {
	return BetSettlementSnapshot{
		HypothesisID: hypothesisID,
		Verdict:      verdict,
		Method:       SettlementMethodPredicate,
		Technique:    technique,
		ScopeID:      scopeID,
		BrierScore:   brier,
	}
}

func TestComputeReputation_AggregatesMatchingTechniqueAndScope(t *testing.T) {
	settlements := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.04),
		settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-2", 1.0),
		settledSnapshot("t1190", "scope-b", SettlementVerdictTrue, "hyp-3", 0.0), // different scope
		settledSnapshot("t1059", "scope-a", SettlementVerdictTrue, "hyp-4", 0.0), // different technique
	}

	rep := ComputeReputation("t1190", "scope-a", settlements)

	if rep.Technique != "t1190" || rep.ScopeID != "scope-a" {
		t.Fatalf("unexpected key: %+v", rep)
	}
	if rep.N != 2 {
		t.Fatalf("N = %d, want 2", rep.N)
	}
	if want := 0.5; rep.ObservedFrequency != want {
		t.Fatalf("ObservedFrequency = %v, want %v", rep.ObservedFrequency, want)
	}
	if want := 0.52; rep.MeanBrierScore != want {
		t.Fatalf("MeanBrierScore = %v, want %v", rep.MeanBrierScore, want)
	}
}

func TestComputeReputation_SkipsSettlementsWithNoRecordedTechnique(t *testing.T) {
	// bet_settlement.go's own documented gap: the exhaustion/HITL paths
	// carry no Technique today. Such a settlement can never match a named
	// technique and must not be silently folded into some other bucket.
	settlements := []BetSettlementSnapshot{
		settledSnapshot("", "scope-a", SettlementVerdictFalse, "hyp-1", 1.0),
	}

	rep := ComputeReputation("t1190", "scope-a", settlements)

	if rep.N != 0 {
		t.Fatalf("N = %d, want 0 (technique-less settlement must be skipped)", rep.N)
	}
}

func TestComputeReputation_NoSettlements_ZeroTrackRecord(t *testing.T) {
	rep := ComputeReputation("t1190", "scope-a", nil)
	if rep.N != 0 || rep.ObservedFrequency != 0 || rep.MeanBrierScore != 0 {
		t.Fatalf("unexpected non-zero reputation with no settlements: %+v", rep)
	}
}

func TestReputation_PriorStrength_DefaultWhenNoTrackRecord(t *testing.T) {
	rep := Reputation{Technique: "t1190", ScopeID: "scope-a"}
	if got := rep.PriorStrength(); got != DefaultReputationPrior {
		t.Fatalf("PriorStrength() = %v, want DefaultReputationPrior (%v)", got, DefaultReputationPrior)
	}
}

func TestReputation_PriorStrength_UsesObservedFrequency(t *testing.T) {
	rep := Reputation{Technique: "t1190", ScopeID: "scope-a", N: 4, ObservedFrequency: 0.75}
	if got := rep.PriorStrength(); got != 0.75 {
		t.Fatalf("PriorStrength() = %v, want 0.75", got)
	}
}

func TestUpdateReputation_WritesBeliefOnTechniqueEnvironmentNode(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()
	settlements := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.0),
		settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-2", 1.0),
	}

	rep, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", settlements, substrate)
	if err != nil {
		t.Fatalf("UpdateReputation: %v", err)
	}
	if rep.N != 2 || rep.ObservedFrequency != 0.5 {
		t.Fatalf("unexpected returned Reputation: %+v", rep)
	}

	nb, ok, err := substrate.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief: %v", err)
	}
	if !ok {
		t.Fatal("expected a belief to have been written")
	}
	if got, want := nb.Belief.Exploitable, 0.5; got != want {
		t.Fatalf("Belief.Exploitable = %v, want %v", got, want)
	}
	if nb.EvidenceDigest == "" {
		t.Fatal("expected a non-empty EvidenceDigest")
	}
}

func TestUpdateReputation_TenantScopesTheNode(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()
	acmeSettlements := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.0),
	}
	betaSettlements := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-1", 1.0),
	}

	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", acmeSettlements, substrate); err != nil {
		t.Fatalf("UpdateReputation(acme): %v", err)
	}
	if _, err := UpdateReputation(ctx, "beta", "t1190", "scope-a", betaSettlements, substrate); err != nil {
		t.Fatalf("UpdateReputation(beta): %v", err)
	}

	acmeBelief, _, err := substrate.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief(acme): %v", err)
	}
	betaBelief, _, err := substrate.Belief(ctx, TechniqueEnvironmentRef("beta", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief(beta): %v", err)
	}
	if acmeBelief.Belief.Exploitable == betaBelief.Belief.Exploitable {
		t.Fatalf("expected tenants' reputations to differ, both got %v", acmeBelief.Belief.Exploitable)
	}
	if acmeBelief.Belief.Exploitable != 1.0 || betaBelief.Belief.Exploitable != 0.0 {
		t.Fatalf("unexpected values: acme=%v beta=%v", acmeBelief.Belief.Exploitable, betaBelief.Belief.Exploitable)
	}
}

func TestUpdateReputation_IsExactOverwriteNotBlended(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()

	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a",
		[]BetSettlementSnapshot{settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.0)},
		substrate); err != nil {
		t.Fatalf("first UpdateReputation: %v", err)
	}

	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a",
		[]BetSettlementSnapshot{
			settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.0),
			settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-2", 1.0),
			settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-3", 1.0),
		},
		substrate); err != nil {
		t.Fatalf("second UpdateReputation: %v", err)
	}

	nb, _, err := substrate.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief: %v", err)
	}
	// A blended running average across the two calls would land at 0.75 (the
	// mean of 1.0 and 0.5). An exact overwrite recomputed from the FULL
	// settlement list passed on the second call lands at 1/3.
	if want := 1.0 / 3.0; nb.Belief.Exploitable != want {
		t.Fatalf("Belief.Exploitable = %v, want %v (exact overwrite, not a blend)", nb.Belief.Exploitable, want)
	}
}

func TestReadReputation_UnknownReturnsDefaultPriorNotError(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()

	prior, ok, err := ReadReputation(ctx, "acme", "t1190", "scope-a", substrate)
	if err != nil {
		t.Fatalf("ReadReputation: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for an unrecorded technique×environment pair")
	}
	if prior != DefaultReputationPrior {
		t.Fatalf("prior = %v, want DefaultReputationPrior (%v)", prior, DefaultReputationPrior)
	}
}

func TestReadReputation_ReadsWrittenValue(t *testing.T) {
	ctx := context.Background()
	substrate := newFakeBeliefSubstrate()
	settlements := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.0),
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-2", 0.0),
		settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-3", 1.0),
	}
	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", settlements, substrate); err != nil {
		t.Fatalf("UpdateReputation: %v", err)
	}

	prior, ok, err := ReadReputation(ctx, "acme", "t1190", "scope-a", substrate)
	if err != nil {
		t.Fatalf("ReadReputation: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true")
	}
	if want := 2.0 / 3.0; prior != want {
		t.Fatalf("prior = %v, want %v", prior, want)
	}
}

// TestUpdateReputation_RebuildsIdenticallyAfterReset is gibson#267's
// "survives members scaling to zero and back" acceptance criterion.
// BeliefSubstrate is still an unbacked stub with no durability story of its
// own (bet_settlement.go's package doc), so what actually survives a
// substrate restart is the settled-bet history itself (BetSettlement is a
// Timeline-replayable World entity) — reputation survives because it is
// always exactly recomputable from that history, not because the substrate
// cache persisted.
func TestUpdateReputation_RebuildsIdenticallyAfterReset(t *testing.T) {
	ctx := context.Background()
	settlements := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.02),
		settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-2", 0.81),
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-3", 0.09),
	}

	before := newFakeBeliefSubstrate()
	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", settlements, before); err != nil {
		t.Fatalf("UpdateReputation(before): %v", err)
	}
	beforeBelief, _, err := before.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief(before): %v", err)
	}

	// "scaled to zero and back": a brand new substrate, as if the cache was
	// never there. The settlement history (settlements) is what actually
	// persisted, since it lives in the Timeline, not in BeliefSubstrate.
	after := newFakeBeliefSubstrate()
	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", settlements, after); err != nil {
		t.Fatalf("UpdateReputation(after): %v", err)
	}
	afterBelief, _, err := after.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief(after): %v", err)
	}

	if beforeBelief.Belief.Exploitable != afterBelief.Belief.Exploitable {
		t.Fatalf("rebuild diverged: before=%v after=%v", beforeBelief.Belief.Exploitable, afterBelief.Belief.Exploitable)
	}
	if beforeBelief.EvidenceDigest != afterBelief.EvidenceDigest {
		t.Fatalf("evidence digest diverged: before=%v after=%v", beforeBelief.EvidenceDigest, afterBelief.EvidenceDigest)
	}
}

func TestReputationEvidenceDigest_OrderIndependent(t *testing.T) {
	ctx := context.Background()
	a := newFakeBeliefSubstrate()
	b := newFakeBeliefSubstrate()

	forward := []BetSettlementSnapshot{
		settledSnapshot("t1190", "scope-a", SettlementVerdictTrue, "hyp-1", 0.0),
		settledSnapshot("t1190", "scope-a", SettlementVerdictFalse, "hyp-2", 1.0),
	}
	reversed := []BetSettlementSnapshot{forward[1], forward[0]}

	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", forward, a); err != nil {
		t.Fatalf("UpdateReputation(forward): %v", err)
	}
	if _, err := UpdateReputation(ctx, "acme", "t1190", "scope-a", reversed, b); err != nil {
		t.Fatalf("UpdateReputation(reversed): %v", err)
	}

	nbA, _, err := a.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief(a): %v", err)
	}
	nbB, _, err := b.Belief(ctx, TechniqueEnvironmentRef("acme", "t1190", "scope-a"))
	if err != nil {
		t.Fatalf("Belief(b): %v", err)
	}
	if nbA.EvidenceDigest != nbB.EvidenceDigest {
		t.Fatalf("digest depends on input order: forward=%s reversed=%s", nbA.EvidenceDigest, nbB.EvidenceDigest)
	}
}

func TestEngine_UpdateReputation_ReadsSettledBetsFromEngine(t *testing.T) {
	ctx := context.Background()
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	settled, err := e.SettleBetTrue(ctx, registry, nil, BetSettlementRequest{
		HypothesisID:  "hyp-1",
		ScopeID:       "scope-a",
		Technique:     testTechnique,
		PredicateType: testPredicateType,
		PredicateParams: map[string]any{
			"marker": "proof-token-9f3a",
		},
		Evidence:             markerEvidence("proof-token-9f3a"),
		PredictedProbability: 0.9,
	})
	if err != nil {
		t.Fatalf("SettleBetTrue: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true when the predicate fires")
	}
	awaitBetSettlements(t, e, 1)

	substrate := newFakeBeliefSubstrate()
	rep, err := e.UpdateReputation(ctx, string(testTechnique), "scope-a", substrate)
	if err != nil {
		t.Fatalf("Engine.UpdateReputation: %v", err)
	}
	if rep.N != 1 || rep.ObservedFrequency != 1.0 {
		t.Fatalf("unexpected Reputation from engine settlements: %+v", rep)
	}
}
