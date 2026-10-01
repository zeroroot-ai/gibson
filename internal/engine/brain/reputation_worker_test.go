// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"
)

// newReputationTestEngine wires a manually-ticked engine with the reputation
// write loop installed (NewEngine, not the registry's Run loop, so the test
// drives the tick deterministically — the same pattern voiEngine uses). The
// worker's substrate is bound to this same engine, so a write it Submits is
// readable back through a fresh WorldBeliefSubstrate on the same engine.
func newReputationTestEngine(t *testing.T) (*Engine, *ReputationWorker) {
	t.Helper()
	e := NewEngine("acme")
	w := NewReputationWorker(e, NewWorldBeliefSubstrate(e))
	e.Subscribe(w.Tap)
	return e, w
}

// reputationSettle mirrors voiSettle: fold the settlement (fires Tap) -> drain
// off the tick (UpdateReputation recomputes + Submits the write) -> fold the
// NodeBeliefSet write.
func reputationSettle(e *Engine, w *ReputationWorker) {
	e.Tick()
	w.Drain(context.Background())
	e.Tick()
}

// TestReputationWorker_HITLSettledBetUpdatesReputation proves the production
// loop (gibson#267 AC2): a human-settled bet updates the matching
// technique×environment reputation, read back the way a NEW member would —
// through the belief substrate, NOT a direct UpdateReputation call. This is
// what distinguishes a real wiring from the false-liveness trap: nothing here
// calls UpdateReputation itself; the tap + off-tick drain do.
func TestReputationWorker_HITLSettledBetUpdatesReputation(t *testing.T) {
	ctx := context.Background()
	e, w := newReputationTestEngine(t)

	// A hypothesis of technique t1190 in scope-a exists, so the HITL settle path
	// can resolve the technique×environment key from it (the request carries no
	// technique of its own).
	e.Submit(HypothesisObserved{HypothesisID: "hyp-1", ScopeID: "scope-a", Claim: "c", Technique: "t1190"})
	e.Tick()

	if _, err := e.SettleBetByHITL(ctx, BetHITLRequest{
		HypothesisID: "hyp-1", Verdict: VerdictTruePositive, UserID: "reviewer-1",
	}); err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	reputationSettle(e, w)

	prior, ok, err := ReadReputation(ctx, e.World.Tenant, "t1190", "scope-a", NewWorldBeliefSubstrate(e))
	if err != nil {
		t.Fatalf("ReadReputation: %v", err)
	}
	if !ok {
		t.Fatal("want a recorded reputation after a settled bet (AC2) — the write loop did not run")
	}
	if prior != 1.0 {
		t.Fatalf("PriorStrength = %v, want 1.0 (one TRUE settlement)", prior)
	}
}

// TestReputationWorker_ExhaustionSettledBetUpdatesReputation proves the FALSE
// (bounded-exhaustion) path now feeds reputation too (gibson#267 AC2): the
// request carries NO technique and NO scope, yet reputation is updated for
// t1190 in scope-a — which is only possible because SettleBetFalse resolved
// both from the bet's Hypothesis.
func TestReputationWorker_ExhaustionSettledBetUpdatesReputation(t *testing.T) {
	ctx := context.Background()
	e, w := newReputationTestEngine(t)

	e.Submit(HypothesisObserved{HypothesisID: "hyp-1", ScopeID: "scope-a", Claim: "c", Technique: "t1190"})
	e.Tick()

	if _, err := e.SettleBetFalse(ctx, BetExhaustionRequest{
		HypothesisID: "hyp-1", AttemptBudget: 1, AttemptsMade: 1, Reason: "exhausted",
	}); err != nil {
		t.Fatalf("SettleBetFalse: %v", err)
	}
	reputationSettle(e, w)

	prior, ok, err := ReadReputation(ctx, e.World.Tenant, "t1190", "scope-a", NewWorldBeliefSubstrate(e))
	if err != nil {
		t.Fatalf("ReadReputation: %v", err)
	}
	if !ok {
		t.Fatal("an exhaustion settlement must update reputation (AC2 — FALSE path technique resolution)")
	}
	if prior != 0.0 {
		t.Fatalf("PriorStrength = %v, want 0.0 (one FALSE settlement)", prior)
	}
}

// TestReputationWorker_KeyIgnoresAgentIdentity proves AC1 end to end: two bets
// of the SAME technique×environment, settled by two DIFFERENT reviewers,
// accumulate on ONE reputation node — members are interchangeable, the key
// carries no agent identity.
func TestReputationWorker_KeyIgnoresAgentIdentity(t *testing.T) {
	ctx := context.Background()
	e, w := newReputationTestEngine(t)

	e.Submit(HypothesisObserved{HypothesisID: "hyp-1", ScopeID: "scope-a", Claim: "c1", Technique: "t1190"})
	e.Submit(HypothesisObserved{HypothesisID: "hyp-2", ScopeID: "scope-a", Claim: "c2", Technique: "t1190"})
	e.Tick()

	if _, err := e.SettleBetByHITL(ctx, BetHITLRequest{HypothesisID: "hyp-1", Verdict: VerdictTruePositive, UserID: "reviewer-A"}); err != nil {
		t.Fatalf("SettleBetByHITL A: %v", err)
	}
	if _, err := e.SettleBetByHITL(ctx, BetHITLRequest{HypothesisID: "hyp-2", Verdict: VerdictFalsePositive, UserID: "reviewer-B"}); err != nil {
		t.Fatalf("SettleBetByHITL B: %v", err)
	}
	reputationSettle(e, w)

	rep := ComputeReputation("t1190", "scope-a", e.BetSettlements())
	if rep.N != 2 {
		t.Fatalf("N = %d, want 2 — both settlements fold into one technique×environment node, not a per-agent key (AC1)", rep.N)
	}
	prior, ok, err := ReadReputation(ctx, e.World.Tenant, "t1190", "scope-a", NewWorldBeliefSubstrate(e))
	if err != nil {
		t.Fatalf("ReadReputation: %v", err)
	}
	if !ok || prior != 0.5 {
		t.Fatalf("prior = %v (ok=%v), want 0.5 (one TRUE, one FALSE, no agent partitioning)", prior, ok)
	}
}

// TestReputationWorker_TapSkipsTechniquelessSettlement proves a settlement
// whose Hypothesis is unknown (no technique resolvable) keys no
// technique×environment node and is skipped — surfaced, not folded into some
// other bucket.
func TestReputationWorker_TapSkipsTechniquelessSettlement(t *testing.T) {
	e, w := newReputationTestEngine(t)

	if _, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID: "ghost", Verdict: VerdictTruePositive, UserID: "reviewer-1",
	}); err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	e.Tick() // fold the settlement, fire the tap

	if n := w.Drain(context.Background()); n != 0 {
		t.Fatalf("Drain recomputed %d reputations, want 0 (a technique-less settlement keys nothing)", n)
	}
}

// TestReputationWorker_DrainIsQuiescentWithoutSettlements proves the drain does
// no work when no settlement was tapped — the same quiescence VoIWorker.Drain
// guarantees.
func TestReputationWorker_DrainIsQuiescentWithoutSettlements(t *testing.T) {
	e, w := newReputationTestEngine(t)
	e.Tick()
	if n := w.Drain(context.Background()); n != 0 {
		t.Fatalf("Drain recomputed %d reputations, want 0 (nothing settled)", n)
	}
}
