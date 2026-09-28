// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// --- Reducer-level tests -----------------------------------------------

// TestBetSettledFalse_MarksSettled proves the reducer records a terminal,
// replayable FALSE verdict with the exhaustion reason — a real, recorded
// outcome, not silence (gibson#279).
func TestBetSettledFalse_MarksSettled(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledFalse{
		HypothesisID:  "hyp-1",
		AttemptBudget: 3,
		AttemptsMade:  3,
		Reason:        "sandbox demonstration attempted 3/3 times with no predicate match",
		ScopeID:       "s1",
		MissionID:     "m1",
	})

	got := w.BetSettlementSnapshot()
	want := []BetSettlementSnapshot{{
		HypothesisID:  "hyp-1",
		Verdict:       SettlementVerdictFalse,
		AttemptBudget: 3,
		AttemptsMade:  3,
		Reason:        "sandbox demonstration attempted 3/3 times with no predicate match",
		ScopeID:       "s1",
		MissionID:     "m1",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settlement:\n got %+v\nwant %+v", got, want)
	}
}

// TestBetSettledFalse_EmptyHypothesisIDIsIgnored mirrors the TRUE reducer's
// same guard.
func TestBetSettledFalse_EmptyHypothesisIDIsIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledFalse{HypothesisID: ""})
	if got := w.BetSettlementSnapshot(); len(got) != 0 {
		t.Fatalf("empty hypothesis id must record nothing, got %+v", got)
	}
}

// TestBetSettledFalse_IsTerminal proves a FALSE settlement is just as
// terminal as a TRUE one: a second settlement event for the same hypothesis
// (of either verdict) never overwrites the first.
func TestBetSettledFalse_IsTerminal(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledFalse{HypothesisID: "hyp-1", AttemptBudget: 3, AttemptsMade: 3, Reason: "first"})
	Reduce(w, BetSettledFalse{HypothesisID: "hyp-1", AttemptBudget: 9, AttemptsMade: 9, Reason: "second"})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 settlement, got %d: %+v", len(got), got)
	}
	if got[0].Reason != "first" {
		t.Fatalf("settlement must be terminal, got %+v", got[0])
	}
}

// TestBetSettlement_TrueThenFalseIsTerminal proves the two verdicts share one
// terminal state machine: whichever settlement lands first for a
// HypothesisID wins, regardless of which verdict event arrives second.
func TestBetSettlement_TrueThenFalseIsTerminal(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{HypothesisID: "hyp-1", Technique: "T1190", EvidenceDigest: "d1"})
	Reduce(w, BetSettledFalse{HypothesisID: "hyp-1", AttemptBudget: 3, AttemptsMade: 3, Reason: "too late"})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 || got[0].Verdict != SettlementVerdictTrue {
		t.Fatalf("the first settlement must win regardless of verdict, got %+v", got)
	}
}

// TestBetSettledFalse_ReplayReproducesExactly proves replay dispatches on
// the recorded verdict correctly (gibson#279's determinism criterion) —
// this is the case that would break if RestoreWorld's replay loop always
// re-applied BetSettledTrue regardless of the snapshotted verdict.
func TestBetSettledFalse_ReplayReproducesExactly(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(BetSettledTrue{HypothesisID: "hyp-1", Technique: "T1190", EvidenceDigest: "d1"})
	apply(BetSettledFalse{HypothesisID: "hyp-2", AttemptBudget: 3, AttemptsMade: 3, Reason: "exhausted"})

	want := w.BetSettlementSnapshot()
	if len(want) != 2 {
		t.Fatalf("want 2 settlements, got %d: %+v", len(want), want)
	}
	if replayed := Replay("t", tl).BetSettlementSnapshot(); !reflect.DeepEqual(replayed, want) {
		t.Fatalf("replay mismatch:\n got %+v\nwant %+v", replayed, want)
	}
}

// TestSnapshotRestore_RoundTripsFalseSettlements proves the snapshot/restore
// round trip preserves a FALSE verdict and its exhaustion fields, dispatching
// through BetSettledFalse rather than BetSettledTrue on restore.
func TestSnapshotRestore_RoundTripsFalseSettlements(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{HypothesisID: "hyp-true", Technique: "T1190", EvidenceDigest: "d1"})
	Reduce(w, BetSettledFalse{
		HypothesisID: "hyp-false", AttemptBudget: 5, AttemptsMade: 5,
		Reason: "exhausted", ScopeID: "s1", MissionID: "m1",
	})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.BetSettlementSnapshot(), w.BetSettlementSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("settlements did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}

// TestBetSettledFalse_Kind pins the durable Timeline codec key
// ("bet.settled_false").
func TestBetSettledFalse_Kind(t *testing.T) {
	if got := (BetSettledFalse{}).Kind(); got != "bet.settled_false" {
		t.Fatalf("Kind() = %q, want %q", got, "bet.settled_false")
	}
}

// --- Orchestration-level tests (Engine.SettleBetFalse) ------------------

func awaitBetSettlementsFalse(t *testing.T, e *Engine, want int) []BetSettlementSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []BetSettlementSnapshot
	for time.Now().Before(deadline) {
		got = e.BetSettlements()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d settlements, got %d: %+v", want, len(got), got)
	return nil
}

// TestSettleBetFalse_ExhaustedBudget_Settles proves the core exhaustion path:
// a bet whose declared attempt budget is exhausted with no proof settles
// FALSE, a real recorded outcome (gibson#279).
func TestSettleBetFalse_ExhaustedBudget_Settles(t *testing.T) {
	e := newSettlementTestEngine(t)

	settled, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID:  "hyp-1",
		ScopeID:       "s1",
		MissionID:     "m1",
		AttemptBudget: 3,
		AttemptsMade:  3,
		Reason:        "sandbox demonstration attempted 3/3 times with no predicate match",
	})
	if err != nil {
		t.Fatalf("SettleBetFalse: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true when the attempt budget is exhausted")
	}

	got := awaitBetSettlementsFalse(t, e, 1)
	if got[0].HypothesisID != "hyp-1" || got[0].Verdict != SettlementVerdictFalse {
		t.Fatalf("unexpected settlement: %+v", got[0])
	}
	if got[0].Reason == "" {
		t.Fatal("a FALSE settlement must record why — never silence")
	}
}

// TestSettleBetFalse_BudgetNotExhausted_Refused proves a settlement attempt
// before the budget is actually exhausted is refused, not settled early.
func TestSettleBetFalse_BudgetNotExhausted_Refused(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID:  "hyp-1",
		AttemptBudget: 5,
		AttemptsMade:  2,
		Reason:        "too early",
	})
	if err == nil {
		t.Fatal("want an error when the attempt budget is not yet exhausted")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("an unexhausted budget must never settle, got %+v", got)
	}
}

// TestSettleBetFalse_NonPositiveBudget_Errors proves a bet must declare a
// real attempt budget: "each bet carries an attempt budget" is not
// satisfiable by a zero or negative one.
func TestSettleBetFalse_NonPositiveBudget_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID: "hyp-1", AttemptBudget: 0, AttemptsMade: 0, Reason: "no budget declared",
	})
	if err == nil {
		t.Fatal("want an error for a non-positive attempt budget")
	}
}

// TestSettleBetFalse_MissingReason_Errors proves a FALSE verdict must record
// why — never silence (the issue's own framing).
func TestSettleBetFalse_MissingReason_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID: "hyp-1", AttemptBudget: 1, AttemptsMade: 1, Reason: "",
	})
	if err == nil {
		t.Fatal("want an error when no reason is recorded")
	}
}

// TestSettleBetFalse_MissingHypothesisID_Errors mirrors the TRUE path's
// same guard.
func TestSettleBetFalse_MissingHypothesisID_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		AttemptBudget: 1, AttemptsMade: 1, Reason: "x",
	})
	if err == nil {
		t.Fatal("want an error when hypothesis id is empty")
	}
}

// TestSettleBetFalse_AlreadySettled_IsIdempotentNoOp mirrors the TRUE path's
// terminal, idempotent-retry behavior.
func TestSettleBetFalse_AlreadySettled_IsIdempotentNoOp(t *testing.T) {
	e := newSettlementTestEngine(t)
	req := BetExhaustionRequest{HypothesisID: "hyp-1", AttemptBudget: 1, AttemptsMade: 1, Reason: "exhausted"}
	if _, err := e.SettleBetFalse(context.Background(), req); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	awaitBetSettlementsFalse(t, e, 1)

	settled, err := e.SettleBetFalse(context.Background(), req)
	if err != nil {
		t.Fatalf("second settle: %v", err)
	}
	if settled {
		t.Fatal("want settled=false: an already-settled bet is a no-op, not a re-settlement")
	}
}

// TestSettleBetFalse_AlreadySettledTrue_IsIdempotentNoOp proves a bet already
// settled TRUE (by the sibling gibson#278 path) can never be flipped FALSE by
// a later exhaustion call.
func TestSettleBetFalse_AlreadySettledTrue_IsIdempotentNoOp(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)
	if _, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID: "hyp-1", Technique: testTechnique, PredicateType: testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"}, Evidence: markerEvidence("tok"),
	}); err != nil {
		t.Fatalf("settle true: %v", err)
	}
	awaitBetSettlementsFalse(t, e, 1)

	settled, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID: "hyp-1", AttemptBudget: 1, AttemptsMade: 1, Reason: "too late",
	})
	if err != nil {
		t.Fatalf("SettleBetFalse: %v", err)
	}
	if settled {
		t.Fatal("a bet already settled TRUE must never be settled FALSE")
	}

	got := e.BetSettlements()
	if len(got) != 1 || got[0].Verdict != SettlementVerdictTrue {
		t.Fatalf("the TRUE verdict must stand, got %+v", got)
	}
}
