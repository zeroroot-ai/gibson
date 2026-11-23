// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 20, 8, 0, 0, 0, time.UTC)

func at(h int) time.Time { return t0.Add(time.Duration(h) * time.Hour) }

// fixedFinding builds a World with one fixed Finding that a check of the given
// kind raised and that was deployed at hour 2.
func fixedFinding(t *testing.T, checkKind string) *World {
	t.Helper()
	w := NewWorld("t1")
	w.clock = func() time.Time { return at(10) }
	Reduce(w, FindingRaised{ID: "f1", CheckKind: checkKind, CheckRef: "ref", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed, At: at(1)})
	Reduce(w, DeployObserved{MergeRequest: "mr-1", DeploymentKey: "dep-1", At: at(2)})
	return w
}

func verify(w *World) { applyAll(w, VerificationSystem(w)) }

func status(t *testing.T, w *World) string {
	t.Helper()
	return findingByID(t, w, "f1").Status
}

// A scan finding is verified after a clean scan that is newer than the deploy.
func TestVerify_CleanScanNewerThanDeployVerifies(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	verify(w)
	if got := status(t, w); got != FindingStatusVerified {
		t.Fatalf("status = %q, want verified", got)
	}
}

// A clean scan does not verify a finding from an attack proof.
func TestVerify_CleanScanDoesNotVerifyAPredicateFinding(t *testing.T) {
	w := fixedFinding(t, "predicate")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	verify(w)
	if got := status(t, w); got != FindingStatusFixed {
		t.Fatalf("status = %q, want fixed", got)
	}
}

// An attack predicate that settles false verifies a scan finding.
func TestVerify_PredicateSettledFalseVerifiesAScanFinding(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "predicate", Found: false, EvidenceAt: at(4)})
	verify(w)
	if got := status(t, w); got != FindingStatusVerified {
		t.Fatalf("status = %q, want verified", got)
	}
}

// A check on evidence that is older than the deploy verifies nothing, and it
// does not reopen the Finding either.
func TestVerify_EvidenceOlderThanTheDeployDecidesNothing(t *testing.T) {
	for _, found := range []bool{false, true} {
		w := fixedFinding(t, "scan")
		Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
		Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: found, EvidenceAt: at(2)}) // the deploy time
		verify(w)
		if got := status(t, w); got != FindingStatusFixed {
			t.Fatalf("found=%v: status = %q, want fixed", found, got)
		}
	}
}

// A check that finds the flaw again sets the Finding to open, and the fix is
// forgotten.
func TestVerify_FoundAgainReopensAndForgetsTheFix(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: true, EvidenceAt: at(4)})
	verify(w)
	f := findingByID(t, w, "f1")
	if f.Status != FindingStatusOpen || f.MergeRequest != "" || !f.DeployedAt.IsZero() {
		t.Fatalf("finding = %+v, want open with no fix", f)
	}
}

// No finding is verified while the health signal has no held event.
func TestVerify_NoHeldHealthSignalNoVerified(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	verify(w)
	if got := status(t, w); got != FindingStatusFixed {
		t.Fatalf("no health event: status = %q, want fixed", got)
	}
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: false, At: at(5)})
	verify(w)
	if got := status(t, w); got != FindingStatusFixed {
		t.Fatalf("failed health: status = %q, want fixed", got)
	}
	// The health signal holds later. The clean check is still there.
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(6)})
	verify(w)
	if got := status(t, w); got != FindingStatusVerified {
		t.Fatalf("held health: status = %q, want verified", got)
	}
}

// A finding with no recorded check counts as the strongest (fail closed,
// review m1): a scan does not verify it, and an attack predicate does.
func TestVerify_NoRecordedCheckIsTheStrongest(t *testing.T) {
	w := fixedFinding(t, "")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	verify(w)
	if got := status(t, w); got != FindingStatusFixed {
		t.Fatalf("a scan verified a finding with no check: status = %q", got)
	}
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "predicate", Found: false, EvidenceAt: at(5)})
	verify(w)
	if got := status(t, w); got != FindingStatusVerified {
		t.Fatalf("status = %q, want verified", got)
	}
}

// A fix that is not deployed is never verified.
func TestVerify_NoDeployNoVerified(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", CheckKind: "scan", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed, MergeRequest: "mr-1"})
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	if evs := VerificationSystem(w); len(evs) != 0 {
		t.Fatalf("a fix with no deploy changed status: %v", evs)
	}
}

func TestVerify_IsQuiescent(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	verify(w)
	if evs := VerificationSystem(w); len(evs) != 0 {
		t.Fatalf("second pass emitted %v", evs)
	}
}

// A revert opens the Finding again and forgets the fix, even from verified.
func TestFixReverted_ReopensTheFinding(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: false, EvidenceAt: at(4)})
	verify(w)
	Reduce(w, FixReverted{MergeRequest: "mr-1", At: at(5)})
	f := findingByID(t, w, "f1")
	if f.Status != FindingStatusOpen || f.MergeRequest != "" {
		t.Fatalf("finding = %+v, want open with no merge request", f)
	}
}

// The events round trip through the Timeline codec, so a replay sees them.
func TestFixLoopEvents_RoundTripThroughTheCodec(t *testing.T) {
	events := []Event{
		DeployObserved{MergeRequest: "mr", DeploymentKey: "d", ApplicationKey: "a", At: at(1)},
		HealthObserved{MergeRequest: "mr", Held: true, At: at(2)},
		FixReverted{MergeRequest: "mr", At: at(3)},
		CheckRerun{ID: "f", CheckKind: "scan", Found: true, EvidenceAt: at(4)},
		MergeRequestQueued{MergeRequest: "mr", Application: "a", At: at(5)},
		MergeGranted{MergeRequest: "mr", Application: "a", At: at(6)},
	}
	for _, ev := range events {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode %T: %v", ev, err)
		}
		got, err := DecodeEvent(data)
		if err != nil {
			t.Fatalf("decode %T: %v", ev, err)
		}
		if got.Kind() != ev.Kind() {
			t.Fatalf("kind %q != %q", got.Kind(), ev.Kind())
		}
	}
}

// A snapshot round trip keeps the fields that FindingRaised does not carry.
func TestSnapshot_KeepsTheFixLoopFacts(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, FindingPrioritized{ID: "f1", Priority: "P2", Rule: "kev"})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "app", At: at(1)})
	restored, err := RestoreWorld(SnapshotWorld(w, "1-0"), "t1")
	if err != nil {
		t.Fatal(err)
	}
	got, want := findingByID(t, restored, "f1"), findingByID(t, w, "f1")
	if got.Status != want.Status || got.MergeRequest != want.MergeRequest || got.Priority != want.Priority ||
		got.PriorityRule != want.PriorityRule || got.CheckKind != want.CheckKind ||
		!got.DeployedAt.Equal(want.DeployedAt) || got.DeploymentKey != want.DeploymentKey || got.Priority != "P2" {
		t.Fatalf("restored finding = %+v, want %+v", got, want)
	}
	if len(restored.MergeSlots()) != 1 {
		t.Fatalf("merge slots = %v", restored.MergeSlots())
	}
}

// The deploy event holds the hold time of the fix mission, so the health read
// never needs the mission record. A new deploy replaces it, and the event keeps it
// across the Timeline codec.
func TestDeployObserved_HoldsTheHoldTimeOfTheFixMission(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, DeployObserved{MergeRequest: "mr-1", DeploymentKey: "dep-2", At: at(3), HoldSeconds: 2700})
	if got := findingByID(t, w, "f1").HealthHold; got != 45*time.Minute {
		t.Errorf("HealthHold = %v, want 45m", got)
	}
	Reduce(w, DeployObserved{MergeRequest: "mr-1", DeploymentKey: "dep-3", At: at(4)})
	if got := findingByID(t, w, "f1").HealthHold; got != 0 {
		t.Errorf("HealthHold = %v, want zero for a deploy that states none", got)
	}

	raw, err := EncodeEvent(DeployObserved{MergeRequest: "mr-1", At: at(3), HoldSeconds: 60, HoldUnreadable: true})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ev.(*DeployObserved)
	if !ok {
		got2, ok2 := ev.(DeployObserved)
		if !ok2 {
			t.Fatalf("decoded %T", ev)
		}
		got = &got2
	}
	if got.HoldSeconds != 60 || !got.HoldUnreadable {
		t.Errorf("decoded %+v", got)
	}
}

// A fix whose health signal failed waits for its revert. A rescan that finds the flaw
// again must not reopen the finding: the reopen would clear the merge request and
// free the merge slot, and the next fix of the Application would merge onto the
// broken service before the revert merges. The slot stays held until the revert
// merges, and then it frees.
func TestRevertPending_ARescanDoesNotFreeTheSlot(t *testing.T) {
	w := NewWorld("t1")
	w.clock = func() time.Time { return at(10) }
	Reduce(w, FindingRaised{ID: "f1", CheckKind: "scan", CheckRef: "ref", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", MissionID: "m1", At: at(1)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "m1"})
	Reduce(w, FindingRaised{ID: "f2", CheckKind: "scan", CheckRef: "ref2", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f2", Status: FindingStatusFixing, MergeRequest: "mr-2", MissionID: "m2", At: at(1)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(1), MissionID: "m2"})
	applyAll(w, MergeGateSystem(w)) // mr-1 holds the slot, mr-2 waits
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixed, At: at(2)})
	Reduce(w, DeployObserved{MergeRequest: "mr-1", DeploymentKey: "dep-1", At: at(2)})
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: false, At: at(3)})
	Reduce(w, RevertRequested{MergeRequest: "mr-1", RevertMergeRequest: "mr-1-revert", At: at(4)})

	holds := func(mr string) bool { return w.MayMerge(mr) }
	if !holds("mr-1") || holds("mr-2") {
		t.Fatalf("before the rescan: slots = %+v, want mr-1 granted and mr-2 waiting", w.MergeSlots())
	}

	// A rescan finds the flaw again, after the deploy.
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: true, EvidenceAt: at(5)})
	applyAll(w, VerificationSystem(w))
	// Another producer also asks to reopen the finding.
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusOpen, At: at(6)})
	applyAll(w, MergeSlotExpirySystem(w))
	applyAll(w, MergeGateSystem(w))

	f := findingByID(t, w, "f1")
	if f.Status != FindingStatusFixed || f.MergeRequest != "mr-1" {
		t.Fatalf("finding = %q with merge request %q, want fixed and mr-1: the revert is pending", f.Status, f.MergeRequest)
	}
	if !holds("mr-1") || holds("mr-2") || len(w.MergeSlots()) != 2 {
		t.Fatalf("after the rescan: slots = %+v, want mr-1 still granted and mr-2 waiting", w.MergeSlots())
	}

	// The revert merges. The finding opens and the slot frees, and mr-2 gets its turn.
	Reduce(w, FixReverted{MergeRequest: "mr-1", At: at(7)})
	applyAll(w, MergeGateSystem(w))
	if f := findingByID(t, w, "f1"); f.Status != FindingStatusOpen {
		t.Errorf("status = %q, want open after the revert merged", f.Status)
	}
	if holds("mr-1") || !holds("mr-2") {
		t.Fatalf("after the revert: slots = %+v, want mr-1 gone and mr-2 granted", w.MergeSlots())
	}
}

// A fixed finding whose health held still reopens on a rescan that finds the flaw.
func TestRescanFound_StillReopensAFixedFindingWhoseHealthHeld(t *testing.T) {
	w := fixedFinding(t, "scan")
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(3)})
	Reduce(w, CheckRerun{ID: "f1", CheckKind: "scan", Found: true, EvidenceAt: at(5)})
	applyAll(w, VerificationSystem(w))
	if got := status(t, w); got != FindingStatusOpen {
		t.Errorf("status = %q, want open", got)
	}
}
