// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "testing"

func fixingWorld(t *testing.T, mr string) *World {
	t.Helper()
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1"})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: mr})
	return w
}

func TestMergeRequest_MergedSetsFixed(t *testing.T) {
	w := fixingWorld(t, "mr-1")
	Reduce(w, MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged})
	applyAll(w, MergeRequestReconciliationSystem(w))
	if got := findingByID(t, w, "f1").Status; got != FindingStatusFixed {
		t.Fatalf("status = %q, want fixed", got)
	}
	if evs := MergeRequestReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("System is not quiescent: %v", evs)
	}
}

func TestMergeRequest_ClosedSetsOpen(t *testing.T) {
	w := fixingWorld(t, "mr-1")
	Reduce(w, MergeRequestObserved{Key: "mr-1", State: MergeRequestClosed})
	applyAll(w, MergeRequestReconciliationSystem(w))
	if got := findingByID(t, w, "f1").Status; got != FindingStatusOpen {
		t.Fatalf("status = %q, want open", got)
	}
}

func TestMergeRequest_OtherKeyOrNoReportChangesNothing(t *testing.T) {
	w := fixingWorld(t, "mr-1")
	if evs := MergeRequestReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("no report must not move the Finding: %v", evs)
	}
	Reduce(w, MergeRequestObserved{Key: "mr-2", State: MergeRequestMerged})
	if evs := MergeRequestReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("a report for another merge request must not move the Finding: %v", evs)
	}
}

func TestMergeRequest_NewFixForgetsOldState(t *testing.T) {
	w := fixingWorld(t, "mr-1")
	Reduce(w, MergeRequestObserved{Key: "mr-1", State: MergeRequestClosed})
	applyAll(w, MergeRequestReconciliationSystem(w))
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-2"})
	if evs := MergeRequestReconciliationSystem(w); len(evs) != 0 {
		t.Fatalf("the state of mr-1 must not carry to mr-2: %v", evs)
	}
}

func TestMergeRequest_ReplayGivesSameStatuses(t *testing.T) {
	events := []Event{
		FindingRaised{ID: "f1"},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1"},
		MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixed},
	}
	w := NewWorld("t1")
	for _, ev := range events {
		Reduce(w, ev)
	}
	if got := findingByID(t, w, "f1").Status; got != FindingStatusFixed {
		t.Fatalf("replayed status = %q, want fixed", got)
	}
}
