// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/finding"
	"github.com/zeroroot-ai/gibson/internal/engine/settlement"
)

const (
	testTechnique     settlement.TechniqueID   = "T1190"
	testPredicateType settlement.PredicateType = "marker_present"
)

// newMarkerRegistry returns a settlement.Registry with one deterministic
// predicate type registered for testTechnique: true iff any evidence's
// Content equals the configured marker string.
func newMarkerRegistry(t *testing.T) *settlement.Registry {
	t.Helper()
	r := settlement.NewRegistry()
	err := r.Register(testTechnique, testPredicateType, func(params json.RawMessage, evidence []finding.EnhancedEvidence) (bool, error) {
		var p struct {
			Marker string `json:"marker"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return false, fmt.Errorf("decode test predicate params: %w", err)
		}
		for _, e := range evidence {
			if s, ok := e.Content.(string); ok && s == p.Marker {
				return true, nil
			}
		}
		return false, nil
	})
	if err != nil {
		t.Fatalf("register predicate: %v", err)
	}
	return r
}

func markerEvidence(marker string) []finding.EnhancedEvidence {
	return []finding.EnhancedEvidence{
		finding.NewEnhancedEvidence(finding.EvidenceLog, "capture", marker),
	}
}

// --- Reducer-level tests -----------------------------------------------

// TestBetSettledTrue_MarksSettled proves the reducer records a terminal,
// replayable settlement fact for the bet's own hypothesis id (gibson#278) —
// with no dependency on a brain.Hypothesis entity existing for that id
// (gibson#265 is an independent, parallel slice).
func TestBetSettledTrue_MarksSettled(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{
		HypothesisID:   "hyp-1",
		Technique:      "T1190",
		PredicateType:  "marker_present",
		EvidenceDigest: "digest-a",
		ScopeID:        "s1",
		MissionID:      "m1",
	})

	got := w.BetSettlementSnapshot()
	want := []BetSettlementSnapshot{{
		HypothesisID:   "hyp-1",
		Verdict:        SettlementVerdictTrue,
		Method:         SettlementMethodPredicate,
		Technique:      "T1190",
		PredicateType:  "marker_present",
		EvidenceDigest: "digest-a",
		ScopeID:        "s1",
		MissionID:      "m1",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("settlement:\n got %+v\nwant %+v", got, want)
	}
}

// TestBetSettledTrue_EmptyHypothesisIDIsIgnored proves a settlement event
// naming no hypothesis records nothing.
func TestBetSettledTrue_EmptyHypothesisIDIsIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{HypothesisID: ""})
	if got := w.BetSettlementSnapshot(); len(got) != 0 {
		t.Fatalf("empty hypothesis id must record nothing, got %+v", got)
	}
}

// TestBetSettledTrue_IsTerminal proves a second settlement event for an
// already-settled hypothesis is dropped, never overwriting the first
// verdict (ADR-0023: "open bets earn nothing" once settled).
func TestBetSettledTrue_IsTerminal(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{HypothesisID: "hyp-1", Technique: "T1190", EvidenceDigest: "first"})
	Reduce(w, BetSettledTrue{HypothesisID: "hyp-1", Technique: "T9999", EvidenceDigest: "second"})

	got := w.BetSettlementSnapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 settlement, got %d: %+v", len(got), got)
	}
	if got[0].EvidenceDigest != "first" {
		t.Fatalf("settlement must be terminal, got %+v", got[0])
	}
}

// TestBetSettledTrue_ReplayReproducesExactly mirrors the same determinism
// proof every other provenance fold in this package carries.
func TestBetSettledTrue_ReplayReproducesExactly(t *testing.T) {
	tl := &Timeline{}
	w := NewWorld("t")
	apply := func(ev Event) { tl.Append(ev); Reduce(w, ev) }

	apply(BetSettledTrue{HypothesisID: "hyp-1", Technique: "T1190", EvidenceDigest: "d1"})
	apply(BetSettledTrue{HypothesisID: "hyp-2", Technique: "T1059", EvidenceDigest: "d2"})
	apply(BetSettledTrue{HypothesisID: "hyp-1", Technique: "ignored", EvidenceDigest: "ignored"})

	want := w.BetSettlementSnapshot()
	if len(want) != 2 {
		t.Fatalf("want 2 settlements, got %d: %+v", len(want), want)
	}
	if replayed := Replay("t", tl).BetSettlementSnapshot(); !reflect.DeepEqual(replayed, want) {
		t.Fatalf("replay mismatch:\n got %+v\nwant %+v", replayed, want)
	}
}

// TestSnapshotRestore_RoundTripsBetSettlements mirrors the entity/hypothesis
// snapshot round-trip tests.
func TestSnapshotRestore_RoundTripsBetSettlements(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, BetSettledTrue{
		HypothesisID: "hyp-1", Technique: "T1190", PredicateType: "marker_present",
		EvidenceDigest: "d1", ScopeID: "s1", MissionID: "m1",
	})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.BetSettlementSnapshot(), w.BetSettlementSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("settlements did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}

// --- Orchestration-level tests (Engine.SettleBetTrue) -------------------

func newSettlementTestEngine(t *testing.T) *Engine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := NewRegistry(ctx)
	return reg.For("acme")
}

func awaitBetSettlements(t *testing.T, e *Engine, want int) []BetSettlementSnapshot {
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

// TestSettleBetTrue_PredicateFires_Settles proves the default, non-destructive
// proof-of-control path: a fired predicate against captured evidence settles
// the bet TRUE, deterministically, with no LLM in the loop (ADR-0027).
func TestSettleBetTrue_PredicateFires_Settles(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	settled, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:  "hyp-1",
		ScopeID:       "s1",
		MissionID:     "m1",
		Technique:     testTechnique,
		PredicateType: testPredicateType,
		PredicateParams: map[string]any{
			"marker": "proof-token-9f3a",
		},
		Evidence: markerEvidence("proof-token-9f3a"),
	})
	if err != nil {
		t.Fatalf("SettleBetTrue: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true when the predicate fires")
	}

	got := awaitBetSettlements(t, e, 1)
	if got[0].HypothesisID != "hyp-1" || got[0].Verdict != SettlementVerdictTrue {
		t.Fatalf("unexpected settlement: %+v", got[0])
	}
	if got[0].EvidenceDigest == "" {
		t.Fatal("evidence digest must be recorded: it is what links the proof to the settled bet")
	}
}

// TestSettleBetTrue_PredicateDoesNotFire_NotSettled proves an unproven claim
// stays open: no assertion, however confident, ever settles a bet.
func TestSettleBetTrue_PredicateDoesNotFire_NotSettled(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	settled, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:    "hyp-1",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "expected-token"},
		Evidence:        markerEvidence("wrong-token"),
	})
	if err != nil {
		t.Fatalf("SettleBetTrue: %v", err)
	}
	if settled {
		t.Fatal("want settled=false when the predicate does not fire")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("an unproven claim must record no settlement, got %+v", got)
	}
}

// TestSettleBetTrue_UnregisteredPredicate_Errors proves settlement fails
// closed for a predicate type the technique never registered — the same
// anti-gaming guarantee the settlement.Registry itself provides.
func TestSettleBetTrue_UnregisteredPredicate_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := settlement.NewRegistry() // nothing registered

	_, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:  "hyp-1",
		Technique:     testTechnique,
		PredicateType: testPredicateType,
		Evidence:      markerEvidence("x"),
	})
	if err == nil {
		t.Fatal("want an error for an unregistered predicate type")
	}
}

// TestSettleBetTrue_MissingHypothesisID_Errors proves a settlement request
// must name what it is settling.
func TestSettleBetTrue_MissingHypothesisID_Errors(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	_, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		Technique: testTechnique, PredicateType: testPredicateType,
	})
	if err == nil {
		t.Fatal("want an error when hypothesis id is empty")
	}
}

// TestSettleBetTrue_AlreadySettled_IsIdempotentNoOp proves a settled bet
// cannot be re-evaluated or re-settled: settlement is terminal.
func TestSettleBetTrue_AlreadySettled_IsIdempotentNoOp(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)
	req := BetSettlementRequest{
		HypothesisID: "hyp-1", Technique: testTechnique, PredicateType: testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"}, Evidence: markerEvidence("tok"),
	}
	if _, err := e.SettleBetTrue(context.Background(), registry, nil, req); err != nil {
		t.Fatalf("first settle: %v", err)
	}
	awaitBetSettlements(t, e, 1)

	settled, err := e.SettleBetTrue(context.Background(), registry, nil, req)
	if err != nil {
		t.Fatalf("second settle: %v", err)
	}
	if settled {
		t.Fatal("want settled=false: an already-settled bet is a no-op, not a re-settlement")
	}
}

// TestSettleBetTrue_Destructive_RequiresAuthorizer proves a destructive
// demonstration is refused when no authorizer is wired — fail closed, never
// auto-approved (ADR-0028).
func TestSettleBetTrue_Destructive_RequiresAuthorizer(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)

	_, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:    "hyp-1",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        markerEvidence("tok"),
		Destructive:     true,
	})
	if err == nil {
		t.Fatal("want an error: destructive proof with no authorizer wired must be refused")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("a refused destructive proof must never settle, got %+v", got)
	}
}

// TestSettleBetTrue_Destructive_AuthorizerDenies_Refused proves a denial
// from the wired authorizer refuses settlement.
func TestSettleBetTrue_Destructive_AuthorizerDenies_Refused(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)
	deny := func(_ context.Context, _ string, _ BetSettlementRequest) (bool, error) { return false, nil }

	_, err := e.SettleBetTrue(context.Background(), registry, deny, BetSettlementRequest{
		HypothesisID:    "hyp-1",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        markerEvidence("tok"),
		Destructive:     true,
	})
	if err == nil {
		t.Fatal("want an error when the authorizer denies")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("a denied destructive proof must never settle, got %+v", got)
	}
}

// TestSettleBetTrue_Destructive_AuthorizerApproves_Settles proves an
// approved, fired destructive predicate settles — the per-action
// authorization gate is scoped to this one action, not a mission-wide
// pause (ADR-0028).
func TestSettleBetTrue_Destructive_AuthorizerApproves_Settles(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)
	var gotTenant string
	approve := func(_ context.Context, tenant string, _ BetSettlementRequest) (bool, error) {
		gotTenant = tenant
		return true, nil
	}

	settled, err := e.SettleBetTrue(context.Background(), registry, approve, BetSettlementRequest{
		HypothesisID:    "hyp-1",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        markerEvidence("tok"),
		Destructive:     true,
	})
	if err != nil {
		t.Fatalf("SettleBetTrue: %v", err)
	}
	if !settled {
		t.Fatal("want settled=true when the authorizer approves and the predicate fires")
	}
	if gotTenant != "acme" {
		t.Fatalf("authorizer must see the engine's own tenant, got %q", gotTenant)
	}
	awaitBetSettlements(t, e, 1)
}

// TestSettleBetTrue_Destructive_AuthorizerErrors_Refused proves an
// authorizer failure (not just a denial) also refuses settlement.
func TestSettleBetTrue_Destructive_AuthorizerErrors_Refused(t *testing.T) {
	e := newSettlementTestEngine(t)
	registry := newMarkerRegistry(t)
	boom := errors.New("dashboard unreachable")
	fail := func(_ context.Context, _ string, _ BetSettlementRequest) (bool, error) { return false, boom }

	_, err := e.SettleBetTrue(context.Background(), registry, fail, BetSettlementRequest{
		HypothesisID: "hyp-1", Technique: testTechnique, PredicateType: testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"}, Evidence: markerEvidence("tok"), Destructive: true,
	})
	if err == nil {
		t.Fatal("want an error when the authorizer itself fails")
	}
}

// TestBetSettledTrue_Kind pins the durable Timeline codec key
// ("bet.settled_true"). Changing this string would break replay of every
// already-persisted settlement event — see timeline_codec.go's registry.
func TestBetSettledTrue_Kind(t *testing.T) {
	if got := (BetSettledTrue{}).Kind(); got != "bet.settled_true" {
		t.Fatalf("Kind() = %q, want %q", got, "bet.settled_true")
	}
}
