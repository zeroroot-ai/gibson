// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Reducer-level tests
// -----------------------------------------------------------------------

func TestDestructiveActionRequested_RecordsPending(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{
		HypothesisID:      "hyp-1",
		Tenant:            "acme",
		ScopeID:           "s1",
		MissionID:         "m1",
		Technique:         "T1490",
		PredicateType:     "marker_present",
		RequestedAtUnixMS: 1000,
	})

	got := w.DestructiveActionSnapshot()
	want := []DestructiveActionSnapshot{{
		HypothesisID:      "hyp-1",
		Tenant:            "acme",
		ScopeID:           "s1",
		MissionID:         "m1",
		Technique:         "T1490",
		PredicateType:     "marker_present",
		RequestedAtUnixMS: 1000,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("destructive actions:\n got %+v\nwant %+v", got, want)
	}
}

func TestDestructiveActionRequested_EmptyHypothesisIDIsIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{Tenant: "acme"})
	if got := w.DestructiveActionSnapshot(); len(got) != 0 {
		t.Fatalf("want no destructive actions recorded, got %+v", got)
	}
}

func TestDestructiveActionRequested_IsIdempotent(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1", RequestedAtUnixMS: 1000})
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1", RequestedAtUnixMS: 2000})

	got := w.DestructiveActionSnapshot()
	if len(got) != 1 {
		t.Fatalf("want exactly one destructive action, got %+v", got)
	}
	if got[0].RequestedAtUnixMS != 1000 {
		t.Fatalf("want the first request's timestamp preserved, got %d", got[0].RequestedAtUnixMS)
	}
}

func TestDestructiveActionDecided_RecordsDecision(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1", RequestedAtUnixMS: 1000})
	Reduce(w, DestructiveActionDecided{
		HypothesisID:    "hyp-1",
		Approved:        true,
		UserID:          "reviewer-1",
		DecidedAtUnixMS: 2000,
	})

	got := w.DestructiveActionSnapshot()
	want := []DestructiveActionSnapshot{{
		HypothesisID:      "hyp-1",
		RequestedAtUnixMS: 1000,
		Decided:           true,
		Approved:          true,
		UserID:            "reviewer-1",
		DecidedAtUnixMS:   2000,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("destructive actions:\n got %+v\nwant %+v", got, want)
	}
}

func TestDestructiveActionDecided_IsTerminal(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1"})
	Reduce(w, DestructiveActionDecided{HypothesisID: "hyp-1", Approved: true, UserID: "reviewer-1"})
	Reduce(w, DestructiveActionDecided{HypothesisID: "hyp-1", Approved: false, UserID: "reviewer-2"})

	got := w.DestructiveActionSnapshot()
	if len(got) != 1 {
		t.Fatalf("want exactly one destructive action, got %+v", got)
	}
	if !got[0].Approved || got[0].UserID != "reviewer-1" {
		t.Fatalf("want the FIRST decision to win (terminal), got %+v", got[0])
	}
}

func TestDestructiveActionDecided_UnknownHypothesisIDRecordsNothing(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionDecided{HypothesisID: "hyp-nonexistent", Approved: true, UserID: "reviewer-1"})
	if got := w.DestructiveActionSnapshot(); len(got) != 0 {
		t.Fatalf("a decision with no matching request must record nothing, got %+v", got)
	}
}

func TestDestructiveActionDecided_EmptyHypothesisIDIsIgnored(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1"})
	Reduce(w, DestructiveActionDecided{Approved: true, UserID: "reviewer-1"})

	got := w.DestructiveActionSnapshot()
	if len(got) != 1 || got[0].Decided {
		t.Fatalf("an empty-id decision must not decide anything, got %+v", got)
	}
}

func TestSnapshotRestore_RoundTripsPendingDestructiveActions(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{
		HypothesisID: "hyp-1", Tenant: "acme", ScopeID: "s1", MissionID: "m1",
		Technique: "T1490", PredicateType: "marker_present", RequestedAtUnixMS: 1000,
	})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.DestructiveActionSnapshot(), w.DestructiveActionSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("destructive actions did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestSnapshotRestore_RoundTripsDecidedDestructiveActions(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, DestructiveActionRequested{HypothesisID: "hyp-1", RequestedAtUnixMS: 1000})
	Reduce(w, DestructiveActionDecided{HypothesisID: "hyp-1", Approved: true, UserID: "reviewer-1", DecidedAtUnixMS: 2000})

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got, want := restored.DestructiveActionSnapshot(), w.DestructiveActionSnapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("destructive actions did not round-trip:\n got %+v\nwant %+v", got, want)
	}
}

func TestDestructiveActionRequested_Kind(t *testing.T) {
	if got := (DestructiveActionRequested{}).Kind(); got != "destructive_action.requested" {
		t.Fatalf("Kind() = %q, want %q", got, "destructive_action.requested")
	}
}

func TestDestructiveActionDecided_Kind(t *testing.T) {
	if got := (DestructiveActionDecided{}).Kind(); got != "destructive_action.decided" {
		t.Fatalf("Kind() = %q, want %q", got, "destructive_action.decided")
	}
}

// -----------------------------------------------------------------------
// DestructiveAuthorizationQueue — orchestration-level tests
// -----------------------------------------------------------------------

func newDestructiveAuthzTestEngine(t *testing.T) *Engine {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reg := NewRegistry(ctx)
	return reg.For("acme")
}

func awaitDestructiveActions(t *testing.T, e *Engine, want int) []DestructiveActionSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var got []DestructiveActionSnapshot
	for time.Now().Before(deadline) {
		got = e.DestructiveActionSnapshot()
		if len(got) == want {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want %d destructive actions, got %d: %+v", want, len(got), got)
	return nil
}

// awaitDestructiveActionDecided polls until hypothesisID's DestructiveAction
// shows Decided=true (the async Submit->fold path, ADR-0001), or fails the
// test after 2s. A count-only wait (awaitDestructiveActions) is not enough
// here: the pending entity already exists before a decision lands, so its
// count never changes — only Decided does.
func awaitDestructiveActionDecided(t *testing.T, e *Engine, hypothesisID string) DestructiveActionSnapshot {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, a := range e.DestructiveActionSnapshot() {
			if a.HypothesisID == hypothesisID && a.Decided {
				return a
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("destructive action %q was not decided within the deadline", hypothesisID)
	return DestructiveActionSnapshot{}
}

func TestDestructiveAuthorizationQueue_Authorize_BlocksUntilApproved(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	req := BetSettlementRequest{HypothesisID: "hyp-1", Technique: "T1490", PredicateType: "marker_present"}
	resultCh := make(chan bool, 1)
	errCh := make(chan error, 1)
	go func() {
		approved, err := q.Authorize(context.Background(), "acme", req)
		errCh <- err
		resultCh <- approved
	}()

	awaitDestructiveActions(t, e, 1)
	pending := q.Pending()
	if len(pending) != 1 || pending[0].HypothesisID != "hyp-1" {
		t.Fatalf("want hyp-1 pending, got %+v", pending)
	}

	if err := q.Decide("hyp-1", "reviewer-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Authorize returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Authorize did not return after Decide")
	}
	if approved := <-resultCh; !approved {
		t.Fatal("want approved=true")
	}

	got := awaitDestructiveActionDecided(t, e, "hyp-1")
	if !got.Approved || got.UserID != "reviewer-1" {
		t.Fatalf("decision not folded correctly: %+v", got)
	}
	if len(q.Pending()) != 0 {
		t.Fatalf("a decided action must not still be pending, got %+v", q.Pending())
	}
}

func TestDestructiveAuthorizationQueue_Authorize_BlocksUntilDenied(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	req := BetSettlementRequest{HypothesisID: "hyp-1"}
	resultCh := make(chan bool, 1)
	go func() {
		approved, _ := q.Authorize(context.Background(), "acme", req)
		resultCh <- approved
	}()

	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", false); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	select {
	case approved := <-resultCh:
		if approved {
			t.Fatal("want approved=false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Authorize did not return after Decide")
	}
}

func TestDestructiveAuthorizationQueue_Authorize_ContextCanceledUnblocks(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		_, err := q.Authorize(ctx, "acme", BetSettlementRequest{HypothesisID: "hyp-1"})
		errCh <- err
	}()

	awaitDestructiveActions(t, e, 1)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Authorize did not return after context cancellation")
	}
}

func TestDestructiveAuthorizationQueue_Authorize_EmptyHypothesisIDErrors(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	_, err := q.Authorize(context.Background(), "acme", BetSettlementRequest{})
	if err == nil {
		t.Fatal("want an error when the request names no hypothesis id")
	}
}

func TestDestructiveAuthorizationQueue_Authorize_DuplicateRequestErrors(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	go func() { _, _ = q.Authorize(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"}) }()
	awaitDestructiveActions(t, e, 1)

	_, err := q.Authorize(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"})
	if err == nil {
		t.Fatal("want an error: hyp-1 is already awaiting authorization")
	}
}

func TestDestructiveAuthorizationQueue_Pending_ListsOnlyUndecided(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	go func() { _, _ = q.Authorize(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"}) }()
	go func() { _, _ = q.Authorize(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-2"}) }()
	awaitDestructiveActions(t, e, 2)

	if err := q.Decide("hyp-1", "reviewer-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		p := q.Pending()
		if len(p) == 1 && p[0].HypothesisID == "hyp-2" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("want only hyp-2 still pending, got %+v", q.Pending())
}

func TestDestructiveAuthorizationQueue_Decide_UnknownHypothesisIDErrors(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if err := q.Decide("hyp-nonexistent", "reviewer-1", true); err == nil {
		t.Fatal("want an error deciding an unknown action")
	}
}

func TestDestructiveAuthorizationQueue_Decide_AlreadyDecidedErrors(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	go func() { _, _ = q.Authorize(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"}) }()
	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", true); err != nil {
		t.Fatalf("first decide: %v", err)
	}
	awaitDestructiveActionDecided(t, e, "hyp-1")

	if err := q.Decide("hyp-1", "reviewer-2", false); err == nil {
		t.Fatal("want an error re-deciding an already-decided action")
	}
}

func TestEngine_DestructiveAuthorizationQueue_IsMemoized(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q1 := e.DestructiveAuthorizationQueue()
	q2 := e.DestructiveAuthorizationQueue()
	if q1 != q2 {
		t.Fatal("want the same queue instance on repeated calls")
	}
}

func TestDestructiveAuthorizationQueue_DoesNotBlockUnrelatedSettlement(t *testing.T) {
	// ADR-0028 decision 2: the gate is per-action, not per-mission. While
	// hyp-1's destructive proof awaits authorization, an unrelated
	// non-destructive settlement for hyp-2 must complete immediately.
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	go func() { _, _ = q.Authorize(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"}) }()
	awaitDestructiveActions(t, e, 1)

	settled, err := e.SettleBetTrue(context.Background(), registry, nil, BetSettlementRequest{
		HypothesisID:    "hyp-2",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        markerEvidence("tok"),
	})
	if err != nil {
		t.Fatalf("unrelated settlement must not be blocked: %v", err)
	}
	if !settled {
		t.Fatal("want the unrelated, non-destructive settlement to succeed immediately")
	}

	// Clean up the still-pending goroutine so it doesn't leak past the test.
	if err := q.Decide("hyp-1", "reviewer-1", false); err != nil {
		t.Fatalf("cleanup decide: %v", err)
	}
}

// -----------------------------------------------------------------------
// End-to-end: DestructiveAuthorizationQueue wired as SettleBetTrue's
// DestructiveProofAuthorizer (proving the concrete type satisfies the
// existing seam in bet_settlement.go without modifying that file).
// -----------------------------------------------------------------------

func TestSettleBetTrue_Destructive_QueueApproves_Settles(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	settledCh := make(chan bool, 1)
	errCh := make(chan error, 1)
	go func() {
		settled, err := e.SettleBetTrue(context.Background(), registry, q.Authorize, BetSettlementRequest{
			HypothesisID:    "hyp-1",
			Technique:       testTechnique,
			PredicateType:   testPredicateType,
			PredicateParams: map[string]any{"marker": "tok"},
			Evidence:        markerEvidence("tok"),
			Destructive:     true,
		})
		errCh <- err
		settledCh <- settled
	}()

	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("SettleBetTrue: %v", err)
	}
	if !<-settledCh {
		t.Fatal("want settled=true once the queue approves")
	}
	awaitBetSettlements(t, e, 1)
}

func TestSettleBetTrue_Destructive_QueueDenies_Refused(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	errCh := make(chan error, 1)
	go func() {
		_, err := e.SettleBetTrue(context.Background(), registry, q.Authorize, BetSettlementRequest{
			HypothesisID:    "hyp-1",
			Technique:       testTechnique,
			PredicateType:   testPredicateType,
			PredicateParams: map[string]any{"marker": "tok"},
			Evidence:        markerEvidence("tok"),
			Destructive:     true,
		})
		errCh <- err
	}()

	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", false); err != nil {
		t.Fatalf("Decide: %v", err)
	}

	if err := <-errCh; err == nil {
		t.Fatal("want an error: the queue denied authorization")
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("a denied destructive proof must never settle, got %+v", got)
	}
}
