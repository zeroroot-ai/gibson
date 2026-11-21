// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"
)

func grants(w *World) []MergeGranted {
	evs := MergeGateSystem(w)
	out := make([]MergeGranted, 0, len(evs))
	for _, ev := range evs {
		out = append(out, ev.(MergeGranted))
	}
	return out
}

// Two fixes for one Application merge one after the other, each after the
// health result of the one before.
func TestMergeGate_OneFixAtATimeForOneApplication(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(1)})

	first := grants(w)
	if len(first) != 1 || first[0].MergeRequest != "mr-1" {
		t.Fatalf("grants = %+v, want only mr-1", first)
	}
	Reduce(w, first[0])
	if len(grants(w)) != 0 {
		t.Fatal("mr-2 was granted while mr-1 has no health result")
	}
	if w.MayMerge("mr-2", "m1") || !w.MayMerge("mr-1", "m1") {
		t.Fatal("MayMerge must say yes for mr-1 and no for mr-2")
	}

	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(2)})
	second := grants(w)
	if len(second) != 1 || second[0].MergeRequest != "mr-2" {
		t.Fatalf("grants = %+v, want mr-2 after the health result of mr-1", second)
	}
}

// Two fixes for two Applications merge in parallel.
func TestMergeGate_DifferentApplicationsRunInParallel(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "bank", At: at(0)})
	if got := grants(w); len(got) != 2 {
		t.Fatalf("grants = %+v, want both", got)
	}
}

// A revert and a closed merge request each free the slot.
func TestMergeGate_RevertAndCloseFreeTheSlot(t *testing.T) {
	for _, free := range []Event{
		FixReverted{MergeRequest: "mr-1", At: at(2)},
		MergeRequestObserved{Key: "mr-1", State: MergeRequestClosed, At: at(2)},
	} {
		w := NewWorld("t1")
		Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
		Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(1)})
		Reduce(w, grants(w)[0])
		Reduce(w, free)
		if got := grants(w); len(got) != 1 || got[0].MergeRequest != "mr-2" {
			t.Fatalf("after %T grants = %+v, want mr-2", free, got)
		}
	}
}

func TestMergeGate_IsQuiescentAndIgnoresADuplicateRequest(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1)})
	if n := len(w.MergeSlots()); n != 1 {
		t.Fatalf("slots = %d, want 1", n)
	}
	Reduce(w, grants(w)[0])
	if len(grants(w)) != 0 {
		t.Fatal("not quiescent")
	}
}

// A failed health signal keeps the slot until the revert merges, so the next
// fix of the Application does not ship on a broken service (review M2). A
// service with no health signal frees the slot (review M1).
func TestMergeGate_AFailedSignalKeepsTheSlotUntilTheRevert(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(1)})
	Reduce(w, grants(w)[0])
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: false, At: at(2)})
	if got := grants(w); len(got) != 0 {
		t.Fatalf("grants after a failed signal = %+v, want none before the revert", got)
	}
	Reduce(w, FixReverted{MergeRequest: "mr-1", At: at(3)})
	if got := grants(w); len(got) != 1 || got[0].MergeRequest != "mr-2" {
		t.Fatalf("grants after the revert = %+v, want mr-2", got)
	}

	w = NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(1)})
	Reduce(w, grants(w)[0])
	Reduce(w, HealthUnavailable{MergeRequest: "mr-1", At: at(2)})
	if got := grants(w); len(got) != 1 || got[0].MergeRequest != "mr-2" {
		t.Fatalf("grants after no health signal = %+v, want mr-2", got)
	}
}

// A released slot leaves the queue, so the list does not grow (review m10).
func TestMergeGate_AReleasedSlotLeavesTheQueue(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0)})
	Reduce(w, grants(w)[0])
	Reduce(w, HealthObserved{MergeRequest: "mr-1", Held: true, At: at(1)})
	if n := len(w.MergeSlots()); n != 0 {
		t.Fatalf("slots = %d, want 0", n)
	}
}

// The expiry frees a slot that no Finding carries (a rerun opened the Finding
// again), and a granted slot with no deploy after MergeSlotHold. A deployed
// merge request keeps its slot (review M1).
func TestMergeSlotExpirySystem(t *testing.T) {
	w := NewWorld("t1")
	now := at(0).Add(MergeSlotHold + time.Hour)
	w.clock = func() time.Time { return now }
	for _, id := range []string{"f-1", "f-2", "f-3"} {
		Reduce(w, FindingRaised{ID: id, At: at(0)})
		Reduce(w, FindingStatusChanged{ID: id, Status: FindingStatusFixing, MergeRequest: "mr-" + id, At: at(0)})
	}
	for i, app := range []string{"a1", "a2", "a3"} {
		mr := "mr-f-" + string(rune('1'+i))
		Reduce(w, MergeRequestQueued{MergeRequest: mr, Application: app, At: at(0)})
		Reduce(w, MergeGranted{MergeRequest: mr, Application: app, At: at(0)})
	}
	Reduce(w, FindingStatusChanged{ID: "f-1", Status: FindingStatusOpen, At: at(1)}) // a rerun found it again
	Reduce(w, DeployObserved{MergeRequest: "mr-f-3", At: at(1)})

	got := map[string]bool{}
	for _, ev := range MergeSlotExpirySystem(w) {
		e := ev.(MergeSlotExpired)
		got[e.MergeRequest] = true
		Reduce(w, e)
	}
	if !got["mr-f-1"] || !got["mr-f-2"] || got["mr-f-3"] {
		t.Fatalf("expired = %v, want mr-f-1 and mr-f-2", got)
	}
	if len(MergeSlotExpirySystem(w)) != 0 {
		t.Fatal("not quiescent")
	}
	if !w.MayMerge("mr-f-3", "m1") || w.MayMerge("mr-f-2", "m1") {
		t.Fatal("the deployed slot must stay and the expired one must go")
	}
	w.clock = func() time.Time { return at(0).Add(time.Hour) }
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-f-2", Application: "a2", At: at(0)})
	Reduce(w, MergeGranted{MergeRequest: "mr-f-2", Application: "a2", At: at(0)})
	if len(MergeSlotExpirySystem(w)) != 0 {
		t.Fatal("a young slot expired")
	}
}

// A slot that names its mission lets only a call of that mission merge, and a
// call with no mission never merges (review m16).
func TestMergeGate_TheSlotIsBoundToItsMission(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0), MissionID: "fix-1"})
	Reduce(w, grants(w)[0])
	if !w.MayMerge("mr-1", "fix-1") {
		t.Fatal("the mission of the fix must merge")
	}
	if w.MayMerge("mr-1", "other-mission") || w.MayMerge("mr-1", "") {
		t.Fatal("another mission or no mission merged with the slot")
	}
	// The mission that originated the fix mission merges too.
	Reduce(w, MissionOriginated{MissionID: "fix-1", ParentMissionID: "fix-agent-run"})
	if !w.MayMerge("mr-1", "fix-agent-run") {
		t.Fatal("the originating mission must merge")
	}
}
