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

// TestBetSettledByHITL_MarksSettled proves the reducer records a terminal,
// replayable verdict sourced from a human review, with the method and
// reviewer recorded for auditability (gibson#280).
func TestBetSettledByHITL_MarksSettled(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledByHITL{
		HypothesisID: "hyp-1",
		Verdict:      SettlementVerdictTrue,
		UserID:       "reviewer-1",
		ScopeID:      "s1",
		MissionID:    "m1",
	})

	got := w.BetSettlementSnapshot()
	want := []BetSettlementSnapshot{{
		HypothesisID: "hyp-1",
		Verdict:      SettlementVerdictTrue,
		Method:       SettlementMethodHITL,
		UserID:       "reviewer-1",
		ScopeID:      "s1",
		MissionID:    "m1",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settlement:\n got %+v\nwant %+v", got, want)
	}
}

// TestBetSettledByHITL_FalseVerdict proves a HITL settlement can also
// resolve a bet FALSE — HITL is a source of either outcome, not a third
// outcome of its own (ADR-0023 decision 3).
func TestBetSettledByHITL_FalseVerdict(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledByHITL{HypothesisID: "hyp-1", Verdict: SettlementVerdictFalse, UserID: "reviewer-1"})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 || got[0].Verdict != SettlementVerdictFalse || got[0].Method != SettlementMethodHITL {
		t.Fatalf("unexpected settlement: %+v", got)
	}
}

// TestBetSettledByHITL_EmptyHypothesisIDIsIgnored mirrors the TRUE/FALSE
// reducers' same guard.
func TestBetSettledByHITL_EmptyHypothesisIDIsIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledByHITL{HypothesisID: "", Verdict: SettlementVerdictTrue})
	if got := w.BetSettlementSnapshot(); len(got) != 0 {
		t.Fatalf("empty hypothesis id must record nothing, got %+v", got)
	}
}

// TestBetSettlement_AllThreeMethodsAreMutuallyTerminal proves the three
// settlement paths (predicate, exhaustion, HITL) share one terminal state
// machine: whichever lands first for a HypothesisID wins, regardless of
// method or verdict, and no combination of the other two can ever
// overwrite it.
func TestBetSettlement_AllThreeMethodsAreMutuallyTerminal(t *testing.T) {
	tests := []struct {
		name  string
		first Event
		later []Event
	}{
		{
			name:  "predicate then HITL",
			first: BetSettledTrue{HypothesisID: "hyp-1", Technique: "T1190"},
			later: []Event{BetSettledByHITL{HypothesisID: "hyp-1", Verdict: SettlementVerdictFalse, UserID: "r1"}},
		},
		{
			name:  "exhaustion then HITL",
			first: BetSettledFalse{HypothesisID: "hyp-1", AttemptBudget: 1, AttemptsMade: 1, Reason: "x"},
			later: []Event{BetSettledByHITL{HypothesisID: "hyp-1", Verdict: SettlementVerdictTrue, UserID: "r1"}},
		},
		{
			name:  "HITL then predicate",
			first: BetSettledByHITL{HypothesisID: "hyp-1", Verdict: SettlementVerdictTrue, UserID: "r1"},
			later: []Event{BetSettledTrue{HypothesisID: "hyp-1", Technique: "T1190"}},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := NewWorld("t")
			Reduce(w, tc.first)
			for _, ev := range tc.later {
				Reduce(w, ev)
			}
			got := w.BetSettlementSnapshot()
			if len(got) != 1 {
				t.Fatalf("want exactly 1 settlement, got %d: %+v", len(got), got)
			}
		})
	}
}

// TestBetSettledByHITL_ReplayReproducesExactly proves replay dispatches on
// SettlementMethod correctly (gibson#280's determinism criterion).
func TestBetSettledByHITL_ReplayReproducesExactly(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(BetSettledTrue{HypothesisID: "hyp-predicate", Technique: "T1190", EvidenceDigest: "d1"})
	apply(BetSettledFalse{HypothesisID: "hyp-exhausted", AttemptBudget: 3, AttemptsMade: 3, Reason: "x"})
	apply(BetSettledByHITL{HypothesisID: "hyp-hitl", Verdict: SettlementVerdictFalse, UserID: "reviewer-1"})

	want := w.BetSettlementSnapshot()
	if len(want) != 3 {
		t.Fatalf("want 3 settlements, got %d: %+v", len(want), want)
	}
	if replayed := Replay("t", tl).BetSettlementSnapshot(); !reflect.DeepEqual(replayed, want) {
		t.Fatalf("replay mismatch:\n got %+v\nwant %+v", replayed, want)
	}
}

// TestSnapshotRestore_RoundTripsHITLSettlements proves the snapshot/restore
// round trip preserves a HITL verdict, dispatching through BetSettledByHITL
// (not BetSettledTrue/False) on restore.
func TestSnapshotRestore_RoundTripsHITLSettlements(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{HypothesisID: "hyp-predicate", Technique: "T1190"})
	Reduce(w, BetSettledFalse{HypothesisID: "hyp-exhausted", AttemptBudget: 2, AttemptsMade: 2, Reason: "x"})
	Reduce(w, BetSettledByHITL{HypothesisID: "hyp-hitl", Verdict: SettlementVerdictTrue, UserID: "reviewer-1", ScopeID: "s1", MissionID: "m1"})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.BetSettlementSnapshot(), w.BetSettlementSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("settlements did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}

// TestBetSettledByHITL_Kind pins the durable Timeline codec key.
func TestBetSettledByHITL_Kind(t *testing.T) {
	if got := (BetSettledByHITL{}).Kind(); got != "bet.settled_by_hitl" {
		t.Fatalf("Kind() = %q, want %q", got, "bet.settled_by_hitl")
	}
}

// --- Orchestration-level tests (Engine.SettleBetByHITL) ------------------

func awaitBetSettlementsHITL(t *testing.T, e *Engine, want int) []BetSettlementSnapshot {
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

func awaitLabels(t *testing.T, e *Engine, want int) []LabelSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []LabelSnapshot
	for time.Now().Before(deadline) {
		got = e.Labels()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d labels, got %d: %+v", want, len(got), got)
	return nil
}

// TestSettleBetByHITL_TruePositive_SettlesTrue proves a human's
// true_positive verdict settles the bet TRUE without pausing anything
// (ADR-0008) — the call returns immediately; the fold happens on the
// engine's own async single-writer path.
func TestSettleBetByHITL_TruePositive_SettlesTrue(t *testing.T) {
	e := newSettlementTestEngine(t)

	settled, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID: "hyp-1", ScopeID: "s1", MissionID: "m1",
		Verdict: VerdictTruePositive, UserID: "reviewer-1",
	})
	if err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true for a true_positive verdict")
	}

	got := awaitBetSettlementsHITL(t, e, 1)
	if got[0].Verdict != SettlementVerdictTrue || got[0].Method != SettlementMethodHITL || got[0].UserID != "reviewer-1" {
		t.Fatalf("unexpected settlement: %+v", got[0])
	}
}

// TestSettleBetByHITL_FalsePositive_SettlesFalse mirrors the true_positive
// case for the false outcome.
func TestSettleBetByHITL_FalsePositive_SettlesFalse(t *testing.T) {
	e := newSettlementTestEngine(t)

	settled, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID: "hyp-1", Verdict: VerdictFalsePositive, UserID: "reviewer-1",
	})
	if err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true for a false_positive verdict")
	}
	got := awaitBetSettlementsHITL(t, e, 1)
	if got[0].Verdict != SettlementVerdictFalse {
		t.Fatalf("unexpected verdict: %+v", got[0])
	}
}

// TestSettleBetByHITL_AppliesTheSameLabelChannel proves gibson#280's central
// acceptance criterion: the verdict path IS the same label channel
// braintrain and the review UI already consume (label.go), not a second,
// parallel one.
func TestSettleBetByHITL_AppliesTheSameLabelChannel(t *testing.T) {
	e := newSettlementTestEngine(t)

	if _, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID: "hyp-1", Verdict: VerdictTruePositive, UserID: "reviewer-1",
	}); err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}

	labels := awaitLabels(t, e, 1)
	if labels[0].Verdict != VerdictTruePositive {
		t.Fatalf("label verdict: got %q, want %q", labels[0].Verdict, VerdictTruePositive)
	}
	if labels[0].UserID != "reviewer-1" {
		t.Fatalf("label user id: got %q", labels[0].UserID)
	}
	if labels[0].TargetID == "hyp-1" {
		t.Fatal("the bet's label target id must be disambiguated from a raw hypothesis/finding id (namespace collision risk)")
	}
}

// TestSettleBetByHITL_InvalidVerdict_Errors proves a bet's binary
// settlement accepts only true_positive/false_positive — VerdictDismiss (or
// any other value) has no settlement meaning and is refused.
func TestSettleBetByHITL_InvalidVerdict_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)

	_, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID: "hyp-1", Verdict: VerdictDismiss, UserID: "reviewer-1",
	})
	if err == nil {
		t.Fatal("want an error for a non-settlement verdict")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("an invalid verdict must never settle, got %+v", got)
	}
}

// TestSettleBetByHITL_MissingHypothesisID_Errors mirrors the other two
// paths' same guard.
func TestSettleBetByHITL_MissingHypothesisID_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)
	_, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{Verdict: VerdictTruePositive, UserID: "r1"})
	if err == nil {
		t.Fatal("want an error when hypothesis id is empty")
	}
}

// TestSettleBetByHITL_MissingUserID_Errors proves a human verdict must be
// attributable — every write is attributable to who made it.
func TestSettleBetByHITL_MissingUserID_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)
	_, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{HypothesisID: "hyp-1", Verdict: VerdictTruePositive})
	if err == nil {
		t.Fatal("want an error when no reviewer is recorded")
	}
}

// TestSettleBetByHITL_AlreadySettled_IsIdempotentNoOp proves a HITL verdict
// on an already-settled bet (by any of the three paths) is a no-op, never a
// re-settlement.
func TestSettleBetByHITL_AlreadySettled_IsIdempotentNoOp(t *testing.T) {
	e := newSettlementTestEngine(t)
	if _, err := e.SettleBetFalse(context.Background(), BetExhaustionRequest{
		HypothesisID: "hyp-1", AttemptBudget: 1, AttemptsMade: 1, Reason: "exhausted",
	}); err != nil {
		t.Fatalf("settle false: %v", err)
	}
	awaitBetSettlementsHITL(t, e, 1)

	settled, err := e.SettleBetByHITL(context.Background(), BetHITLRequest{
		HypothesisID: "hyp-1", Verdict: VerdictTruePositive, UserID: "reviewer-1",
	})
	if err != nil {
		t.Fatalf("SettleBetByHITL: %v", err)
	}
	if settled {
		t.Fatal("want settled=false: an already-settled bet is a no-op")
	}
	got := e.BetSettlements()
	if len(got) != 1 || got[0].Method != SettlementMethodExhaustion {
		t.Fatalf("the original exhaustion verdict must stand, got %+v", got)
	}
}
