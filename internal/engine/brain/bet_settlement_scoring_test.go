// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"testing"
)

// --- Reducer-level: the score is carried on the event, not recomputed ---

// TestBetSettledTrue_CarriesScore proves the predicate settlement path
// records the staked confidence and its Brier score as already-decided
// event data — Reduce copies it through, it never recomputes it.
func TestBetSettledTrue_CarriesScore(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{
		HypothesisID:         "hyp-1",
		Technique:            "T1190",
		PredictedProbability: 0.8,
		BrierScore:           0.04, // (0.8-1)^2
	})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 settlement, got %d", len(got))
	}
	if !floatsEqual(got[0].PredictedProbability, 0.8) || !floatsEqual(got[0].BrierScore, 0.04) {
		t.Fatalf("score fields not carried through: %+v", got[0])
	}
}

// TestBetSettledFalse_CarriesScore mirrors the TRUE case for the
// bounded-exhaustion path.
func TestBetSettledFalse_CarriesScore(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledFalse{
		HypothesisID:         "hyp-1",
		AttemptBudget:        1,
		AttemptsMade:         1,
		Reason:               "x",
		PredictedProbability: 0.3,
		BrierScore:           0.09, // (0.3-0)^2
	})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 || !floatsEqual(got[0].PredictedProbability, 0.3) || !floatsEqual(got[0].BrierScore, 0.09) {
		t.Fatalf("score fields not carried through: %+v", got)
	}
}

// TestBetSettledByHITL_CarriesScore mirrors the same for the HITL path.
func TestBetSettledByHITL_CarriesScore(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledByHITL{
		HypothesisID:         "hyp-1",
		Verdict:              SettlementVerdictFalse,
		UserID:               "reviewer-1",
		PredictedProbability: 0.6,
		BrierScore:           0.36, // (0.6-0)^2
	})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 || !floatsEqual(got[0].PredictedProbability, 0.6) || !floatsEqual(got[0].BrierScore, 0.36) {
		t.Fatalf("score fields not carried through: %+v", got)
	}
}

// TestBetSettlementScore_ReplayReproducesExactly proves replay carries the
// recorded score forward unchanged (gibson#277 AC3), across all three
// settlement paths in one Timeline.
func TestBetSettlementScore_ReplayReproducesExactly(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(BetSettledTrue{HypothesisID: "hyp-a", Technique: "T1190", PredictedProbability: 0.8, BrierScore: 0.04})
	apply(BetSettledFalse{HypothesisID: "hyp-b", AttemptBudget: 1, AttemptsMade: 1, Reason: "x", PredictedProbability: 0.3, BrierScore: 0.09})
	apply(BetSettledByHITL{HypothesisID: "hyp-c", Verdict: SettlementVerdictTrue, UserID: "r1", PredictedProbability: 0.5, BrierScore: 0.25})

	want := w.BetSettlementSnapshot()
	if len(want) != 3 {
		t.Fatalf("want 3 settlements, got %d", len(want))
	}
	if replayed := Replay("t", tl).BetSettlementSnapshot(); !reflect.DeepEqual(replayed, want) {
		t.Fatalf("replay mismatch:\n got %+v\nwant %+v", replayed, want)
	}
}

// --- Orchestration-level: SettleBetTrue/False/ByHITL compute the score ---

// TestSettleBetTrue_ComputesAndRecordsScore proves the TRUE orchestrator
// computes the Brier score from the caller's declared staked confidence
// against the demonstrated-true outcome, and records both on the
// settlement.
func TestSettleBetTrue_ComputesAndRecordsScore(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	_, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:         "hyp-1",
		Technique:            testTechnique,
		PredicateType:        testPredicateType,
		PredicateParams:      map[string]any{"marker": "tok"},
		Evidence:             markerEvidence("tok"),
		PredictedProbability: 0.8,
	})
	if err != nil {
		t.Fatalf("SettleBetTrue: %v", err)
	}

	got := awaitBetSettlements(t, e, 1)
	if !floatsEqual(got[0].PredictedProbability, 0.8) {
		t.Fatalf("predicted probability not recorded: %+v", got[0])
	}
	if !floatsEqual(got[0].BrierScore, 0.04) { // (0.8-1)^2
		t.Fatalf("brier score = %v, want 0.04: %+v", got[0].BrierScore, got[0])
	}
}

// TestSettleBetTrue_InvalidPredictedProbability_Errors proves an
// out-of-range staked confidence is refused before anything is evaluated or
// settled.
func TestSettleBetTrue_InvalidPredictedProbability_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	_, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:         "hyp-1",
		Technique:            testTechnique,
		PredicateType:        testPredicateType,
		PredicateParams:      map[string]any{"marker": "tok"},
		Evidence:             markerEvidence("tok"),
		PredictedProbability: 1.5,
	})
	if err == nil {
		t.Fatal("want an error for an out-of-range predicted probability")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("an invalid predicted probability must never settle, got %+v", got)
	}
}

// TestSettleBetFalse_ComputesAndRecordsScore mirrors the TRUE case for the
// bounded-exhaustion path: the observed outcome is 0 (FALSE), so a
// confidently-wrong stake scores high.
func TestSettleBetFalse_ComputesAndRecordsScore(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID:         "hyp-1",
		AttemptBudget:        1,
		AttemptsMade:         1,
		Reason:               "exhausted",
		PredictedProbability: 0.9,
	})
	if err != nil {
		t.Fatalf("SettleBetFalse: %v", err)
	}

	got := awaitBetSettlementsFalse(t, e, 1)
	if !floatsEqual(got[0].BrierScore, 0.81) { // (0.9-0)^2
		t.Fatalf("brier score = %v, want 0.81: %+v", got[0].BrierScore, got[0])
	}
}

// TestSettleBetFalse_InvalidPredictedProbability_Errors mirrors the TRUE
// path's same guard.
func TestSettleBetFalse_InvalidPredictedProbability_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID:         "hyp-1",
		AttemptBudget:        1,
		AttemptsMade:         1,
		Reason:               "x",
		PredictedProbability: -0.1,
	})
	if err == nil {
		t.Fatal("want an error for an out-of-range predicted probability")
	}
}

// TestSettleBetByHITL_ComputesAndRecordsScore proves the HITL orchestrator
// scores its verdict the same way as the other two paths.
func TestSettleBetByHITL_ComputesAndRecordsScore(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID:         "hyp-1",
		Verdict:              VerdictFalsePositive,
		UserID:               "reviewer-1",
		PredictedProbability: 0.7,
	})
	if err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}

	got := awaitBetSettlementsHITL(t, e, 1)
	if !floatsEqual(got[0].BrierScore, 0.49) { // (0.7-0)^2, false_positive -> observed 0
		t.Fatalf("brier score = %v, want 0.49: %+v", got[0].BrierScore, got[0])
	}
}

// TestSettleBetByHITL_InvalidPredictedProbability_Errors mirrors the other
// two paths' same guard.
func TestSettleBetByHITL_InvalidPredictedProbability_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID:         "hyp-1",
		Verdict:              VerdictTruePositive,
		UserID:               "reviewer-1",
		PredictedProbability: 2.0,
	})
	if err == nil {
		t.Fatal("want an error for an out-of-range predicted probability")
	}
}
