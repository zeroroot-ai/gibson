// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"bytes"
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

// TestDestructiveAction_BlastRadiusAndReversibilitySurviveARestart proves that
// the two fields that the agent reported are part of the durable record
// (gibson#706). A restart reads the World from a snapshot and replays the
// Timeline events after it, so both paths must keep the fields.
func TestDestructiveAction_BlastRadiusAndReversibilitySurviveARestart(t *testing.T) {
	requested := DestructiveActionRequested{
		HypothesisID: "hyp-1", Tenant: "acme", ScopeID: "s1", MissionID: "m1",
		Technique: "T1490", PredicateType: "marker_present", RequestedAtUnixMS: 1000,
		BlastRadius: "one host: db-01", Reversibility: ReversibilityIrreversible,
	}
	want := DestructiveActionSnapshot{
		HypothesisID: "hyp-1", Tenant: "acme", ScopeID: "s1", MissionID: "m1",
		Technique: "T1490", PredicateType: "marker_present", RequestedAtUnixMS: 1000,
		BlastRadius: "one host: db-01", Reversibility: ReversibilityIrreversible,
	}

	// The replay path: the event goes through the Timeline codec, and a new
	// World folds the decoded event.
	encoded, err := EncodeEvent(requested)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	decoded, err := DecodeEvent(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	replayed := NewWorld("t")
	Reduce(replayed, decoded)
	if got := replayed.DestructiveActionSnapshot(); len(got) != 1 || got[0] != want {
		t.Fatalf("after a replay:\n got %+v\nwant %+v", got, want)
	}

	// The snapshot path: the World is written and read back.
	restored, err := RestoreWorld(SnapshotWorld(replayed, "seq-1"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := restored.DestructiveActionSnapshot(); len(got) != 1 || got[0] != want {
		t.Fatalf("after a snapshot restore:\n got %+v\nwant %+v", got, want)
	}
}

// An event that was stored before the two fields existed still decodes, and
// it folds with no signal.
func TestDestructiveActionRequested_AnOlderEventDecodesWithNoSignal(t *testing.T) {
	older, err := EncodeEvent(DestructiveActionRequested{HypothesisID: "hyp-1", RequestedAtUnixMS: 1000})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if bytes.Contains(older, []byte("BlastRadius")) || bytes.Contains(older, []byte("Reversibility")) {
		t.Fatalf("an event with no signal must not write the two keys: %s", older)
	}
	decoded, err := DecodeEvent(older)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	w := NewWorld("t")
	Reduce(w, decoded)
	got := w.DestructiveActionSnapshot()
	if len(got) != 1 || got[0].BlastRadius != "" || got[0].Reversibility != ReversibilityUnspecified {
		t.Fatalf("got %+v; want one action with no signal", got)
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
	reg := NewRegistry(ctx, memStoreFactory())
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
// shows Decided=true (the async Submit->fold path, ADR-0101), or fails the
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

func TestDestructiveAuthorizationQueue_Request_EnqueuesAndReturnsImmediately(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	id, err := q.Request("acme", DestructiveAuthorizationRequest{
		HypothesisID:  "hyp-1",
		ScopeID:       "s1",
		MissionID:     "m1",
		Technique:     "T1490",
		PredicateType: "T1490",
		BlastRadius:   "one tenant bucket",
		Reversibility: ReversibilityReversible,
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if id != "hyp-1" {
		t.Fatalf("want authorization_request_id %q, got %q", "hyp-1", id)
	}

	got := awaitDestructiveActions(t, e, 1)
	want := []DestructiveActionSnapshot{{
		HypothesisID:  "hyp-1",
		Tenant:        "acme",
		ScopeID:       "s1",
		MissionID:     "m1",
		Technique:     "T1490",
		PredicateType: "T1490",
		BlastRadius:   "one tenant bucket",
		Reversibility: ReversibilityReversible,
	}}
	// RequestedAtUnixMS is real wall-clock time here (q.now defaults to
	// time.Now) — compare everything else and only assert it is non-zero.
	if got[0].RequestedAtUnixMS == 0 {
		t.Fatal("want a non-zero RequestedAtUnixMS")
	}
	got[0].RequestedAtUnixMS = 0
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("destructive actions:\n got %+v\nwant %+v", got, want)
	}
}

func TestDestructiveAuthorizationQueue_Request_EmptyHypothesisIDErrors(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{}); err == nil {
		t.Fatal("want an error when the request names no hypothesis id")
	}
}

func TestDestructiveAuthorizationQueue_Request_IsIdempotent(t *testing.T) {
	// A retried Request for a still-pending hypothesis (e.g. the agent's RPC
	// call retried after a network hiccup) must never reset the original
	// request's recorded timestamp or duplicate the record (ADR-0132): Request
	// has no duplicate-detection of its own, it relies entirely on the
	// reducer's idempotent fold (applyDestructiveActionRequested).
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("first Request: %v", err)
	}
	first := awaitDestructiveActions(t, e, 1)[0]

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("second Request: %v", err)
	}
	// Give the (no-op) second fold a moment to land, then confirm nothing
	// changed: still exactly one record, same timestamp.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := e.DestructiveActionSnapshot()
	if len(got) != 1 {
		t.Fatalf("want exactly one destructive action, got %+v", got)
	}
	if got[0].RequestedAtUnixMS != first.RequestedAtUnixMS {
		t.Fatalf("want the first request's timestamp preserved, got %+v want %+v", got[0], first)
	}
}

func TestDestructiveAuthorizationQueue_Verify_EmptyHypothesisIDErrors(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Verify(context.Background(), "acme", BetSettlementRequest{}); err == nil {
		t.Fatal("want an error when the request names no hypothesis id")
	}
}

func TestDestructiveAuthorizationQueue_Verify_NoRequestReturnsPending(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	approved, err := q.Verify(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-never-requested"})
	if approved {
		t.Fatal("want approved=false")
	}
	if !errors.Is(err, ErrDestructiveActionPending) {
		t.Fatalf("want ErrDestructiveActionPending, got %v", err)
	}
}

func TestDestructiveAuthorizationQueue_Verify_UndecidedReturnsPending(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	awaitDestructiveActions(t, e, 1)

	approved, err := q.Verify(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"})
	if approved {
		t.Fatal("want approved=false")
	}
	if !errors.Is(err, ErrDestructiveActionPending) {
		t.Fatalf("want ErrDestructiveActionPending, got %v", err)
	}
}

func TestDestructiveAuthorizationQueue_Verify_DeniedReturnsDenied(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", false); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	awaitDestructiveActionDecided(t, e, "hyp-1")

	approved, err := q.Verify(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"})
	if approved {
		t.Fatal("want approved=false")
	}
	if !errors.Is(err, ErrDestructiveActionDenied) {
		t.Fatalf("want ErrDestructiveActionDenied, got %v", err)
	}
}

func TestDestructiveAuthorizationQueue_Verify_ApprovedReturnsTrue(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	awaitDestructiveActionDecided(t, e, "hyp-1")

	approved, err := q.Verify(context.Background(), "acme", BetSettlementRequest{HypothesisID: "hyp-1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !approved {
		t.Fatal("want approved=true")
	}
}

func TestDestructiveAuthorizationQueue_Pending_ListsOnlyUndecided(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request hyp-1: %v", err)
	}
	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-2"}); err != nil {
		t.Fatalf("Request hyp-2: %v", err)
	}
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

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
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
	// ADR-0132 (still true under the non-blocking wiring):
	// the gate is per-action, not per-mission. A pending, undecided
	// destructive request for hyp-1 must never affect an unrelated
	// non-destructive settlement for hyp-2.
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
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
}

// -----------------------------------------------------------------------
// End-to-end: DestructiveAuthorizationQueue.Verify wired as SettleBetTrue's
// DestructiveProofAuthorizer (proving the concrete type satisfies the
// existing seam in bet_settlement.go without modifying that file's
// signature, ADR-0132).
// -----------------------------------------------------------------------

func TestSettleBetTrue_Destructive_VerifyApproved_Settles(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", true); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	awaitDestructiveActionDecided(t, e, "hyp-1")

	settled, err := e.SettleBetTrue(context.Background(), registry, q.Verify, BetSettlementRequest{
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
		t.Fatal("want settled=true once the recorded decision is approved")
	}
	awaitBetSettlements(t, e, 1)
}

func TestSettleBetTrue_Destructive_VerifyDenied_Refused(t *testing.T) {
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	if _, err := q.Request("acme", DestructiveAuthorizationRequest{HypothesisID: "hyp-1"}); err != nil {
		t.Fatalf("Request: %v", err)
	}
	awaitDestructiveActions(t, e, 1)
	if err := q.Decide("hyp-1", "reviewer-1", false); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	awaitDestructiveActionDecided(t, e, "hyp-1")

	_, err := e.SettleBetTrue(context.Background(), registry, q.Verify, BetSettlementRequest{
		HypothesisID:    "hyp-1",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        markerEvidence("tok"),
		Destructive:     true,
	})
	if err == nil {
		t.Fatal("want an error: the recorded decision denied authorization")
	}
	if !errors.Is(err, ErrDestructiveActionDenied) {
		t.Fatalf("want ErrDestructiveActionDenied, got %v", err)
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("a denied destructive proof must never settle, got %+v", got)
	}
}

func TestSettleBetTrue_Destructive_VerifyNoDecision_Refused(t *testing.T) {
	// The ADR-0132 case that matters most: an agent that calls SettleBetTrue
	// (via SubmitProof) for a destructive proof it never got authorization
	// for at all must be refused, never silently settled.
	e := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(e)
	registry := newMarkerRegistry(t)

	_, err := e.SettleBetTrue(context.Background(), registry, q.Verify, BetSettlementRequest{
		HypothesisID:    "hyp-never-requested",
		Technique:       testTechnique,
		PredicateType:   testPredicateType,
		PredicateParams: map[string]any{"marker": "tok"},
		Evidence:        markerEvidence("tok"),
		Destructive:     true,
	})
	if err == nil {
		t.Fatal("want an error: no authorization was ever requested")
	}
	if !errors.Is(err, ErrDestructiveActionPending) {
		t.Fatalf("want ErrDestructiveActionPending, got %v", err)
	}
	if got := e.BetSettlements(); len(got) != 0 {
		t.Fatalf("an unauthorized destructive proof must never settle, got %+v", got)
	}
}

// A node that stops waiting withdraws its request. The request is decided and not
// approved, it leaves the queue of the people who approve, and a verdict after that
// changes nothing. A new call of the same arguments starts a new request
// (gibson#1469).
func TestDestructiveAuthz_WithdrawnRequestCannotBeApproved(t *testing.T) {
	eng := newDestructiveAuthzTestEngine(t)
	q := NewDestructiveAuthorizationQueue(eng)
	ctx := context.Background()
	state, id, err := q.AuthorizeToolCall(ctx, "acme", ToolCallRequest{MissionID: "m1", Agent: "a", Connector: "c", Tool: "t", ArgsHash: "h"})
	if err != nil || state != ToolCallPending {
		t.Fatalf("state = %v, err = %v", state, err)
	}
	if err := q.Withdraw(ctx, id, "timeout"); err != nil {
		t.Fatal(err)
	}
	var snap DestructiveActionSnapshot
	for _, a := range eng.DestructiveActionSnapshot() {
		if a.HypothesisID == id {
			snap = a
		}
	}
	if !snap.Withdrawn || !snap.Decided || snap.Approved || snap.WithdrawnReason != "timeout" {
		t.Fatalf("snapshot = %+v", snap)
	}
	if err := q.Decide(id, "u1", true); err == nil {
		t.Error("a withdrawn request was approved")
	}
	for _, p := range q.Pending() {
		if p.HypothesisID == id {
			t.Error("a withdrawn request is still pending")
		}
	}
	// Withdrawing again, or after a decision, changes nothing.
	if err := q.Withdraw(ctx, id, "again"); err != nil {
		t.Fatal(err)
	}
	state2, id2, err := q.AuthorizeToolCall(ctx, "acme", ToolCallRequest{MissionID: "m1", Agent: "a", Connector: "c", Tool: "t", ArgsHash: "h"})
	if err != nil || state2 != ToolCallPending || id2 == id {
		t.Fatalf("a new call after a withdrawal must start a new request: state=%v id=%q old=%q err=%v", state2, id2, id, err)
	}
	if err := q.Decide(id2, "u1", true); err != nil {
		t.Fatal(err)
	}
	if err := q.Withdraw(ctx, id2, "late"); err != nil {
		t.Fatal(err)
	}
	for _, a := range eng.DestructiveActionSnapshot() {
		if a.HypothesisID == id2 && (a.Withdrawn || !a.Approved) {
			t.Errorf("a withdrawal changed a decided request: %+v", a)
		}
	}
}

// The withdrawal survives a snapshot and a restore.
func TestDestructiveAuthz_WithdrawalSurvivesARestore(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, DestructiveActionRequested{HypothesisID: "r1", Tenant: "acme", MissionID: "m1", ActionKind: ActionKindToolCall})
	Reduce(w, DestructiveActionWithdrawn{HypothesisID: "r1", Reason: "timeout", AtUnixMS: 5})
	restored, err := RestoreWorld(SnapshotWorld(w, "0"), "acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range restored.DestructiveActionSnapshot() {
		if a.HypothesisID == "r1" && (!a.Withdrawn || a.Approved || a.WithdrawnReason != "timeout") {
			t.Errorf("restored = %+v", a)
		}
	}
	Reduce(restored, DestructiveActionDecided{HypothesisID: "r1", Approved: true, UserID: "u"})
	for _, a := range restored.DestructiveActionSnapshot() {
		if a.HypothesisID == "r1" && a.Approved {
			t.Error("an approval after a restore changed a withdrawn request")
		}
	}
}

// No run continues across a restart. A TOOL node that waited on an approval fails
// with the reason, its request is withdrawn, and a person cannot approve it after
// that. A node of another state and a request of another kind stay as they are
// (gibson#1469).
func TestResumeFailAwaitingApproval_AfterARestart(t *testing.T) {
	factory := memStoreFactory()
	first, stop1 := context.WithCancel(context.Background())
	e1 := NewRegistry(first, factory).For("acme")
	if err := e1.SubmitAndWait(first, DestructiveActionRequested{
		HypothesisID: "req-1", Tenant: "acme", MissionID: "m1", ActionKind: ActionKindToolCall, Connector: "c", Tool: "t", ArgsHash: "h",
	}); err != nil {
		t.Fatal(err)
	}
	for _, wi := range []struct {
		id    string
		state WorkState
		appr  string
	}{{"m1/wait", WorkInputRequired, "req-1"}, {"m1/done", WorkDone, ""}} {
		e1.Submit(WorkDispatched{ID: wi.id, MissionID: "m1", RunID: "run-1", ItemKind: "tool", Target: "mcp:c:t"})
		e1.Submit(WorkCompleted{ID: wi.id, RunID: "run-1", State: wi.state, ApprovalID: wi.appr, Err: "waiting"})
	}
	if err := e1.SubmitAndWait(first, DestructiveActionRequested{
		HypothesisID: "proof-1", Tenant: "acme", MissionID: "m1",
	}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the Engine writes the Timeline
	stop1()

	// The daemon starts again on the same store.
	second, stop2 := context.WithCancel(context.Background())
	defer stop2()
	e2 := NewRegistry(second, factory).For("acme")
	deadline := time.Now().Add(3 * time.Second)
	var wait WorkSnapshot
	for time.Now().Before(deadline) {
		e2.ReadWorld(func(w *World) {
			for _, wi := range w.WorkSnapshot() {
				if wi.ID == "m1/wait" {
					wait = wi
				}
			}
		})
		if wait.State == WorkFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if wait.State != WorkFailed || wait.Err != RestartApprovalReason {
		t.Fatalf("the waiting node = %+v, want failed with the restart reason", wait)
	}
	q := NewDestructiveAuthorizationQueue(e2)
	for _, a := range e2.DestructiveActionSnapshot() {
		switch a.HypothesisID {
		case "req-1":
			if !a.Withdrawn || a.Approved || a.WithdrawnReason != RestartApprovalReason {
				t.Errorf("the request = %+v, want withdrawn with the restart reason", a)
			}
		case "proof-1":
			if a.Withdrawn {
				t.Error("a request of another kind was withdrawn")
			}
		}
	}
	if err := q.Decide("req-1", "u1", true); err == nil {
		t.Error("a person approved a request whose node is gone")
	}
}

// The function reads the World and returns the two events for each waiting node.
func TestResumeFailAwaitingApproval_ReturnsTheWithdrawalAndTheFailure(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, WorkDispatched{ID: "m1/n", MissionID: "m1", RunID: "run-1", ItemKind: "tool", Target: "mcp:c:t"})
	Reduce(w, WorkCompleted{ID: "m1/n", RunID: "run-1", State: WorkInputRequired, ApprovalID: "req-9"})
	evs := ResumeFailAwaitingApproval(w, time.UnixMilli(5))
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want 2", evs)
	}
	if wd, ok := evs[0].(DestructiveActionWithdrawn); !ok || wd.HypothesisID != "req-9" || wd.AtUnixMS != 5 {
		t.Errorf("first = %+v", evs[0])
	}
	if f, ok := evs[1].(WorkCompleted); !ok || f.ID != "m1/n" || f.Err != RestartApprovalReason || f.RunID != "run-1" {
		t.Errorf("second = %+v", evs[1])
	}
}
