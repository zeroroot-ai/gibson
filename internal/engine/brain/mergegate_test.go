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
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(0), MissionID: "m1"})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(1), MissionID: "m1"})

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
		Reduce(w, MergeRequestQueued{MergeRequest: mr, Application: app, At: at(0), MissionID: "m1"})
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
	// A slot that names no mission lets no call merge (review r2).
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "bank", At: at(0)})
	Reduce(w, MergeGranted{MergeRequest: "mr-2", Application: "bank", At: at(0)})
	if w.MayMerge("mr-2", "fix-1") {
		t.Fatal("a slot with no mission let a call merge")
	}
	// The mission that originated the fix mission merges too.
	Reduce(w, MissionOriginated{MissionID: "fix-1", ParentMissionID: "fix-agent-run"})
	if !w.MayMerge("mr-1", "fix-agent-run") {
		t.Fatal("the originating mission must merge")
	}
}

// A merged merge request keeps its slot, whatever the time since the grant,
// until its health signal answers (review R4). Only a merge request that did
// not merge loses the slot after MergeSlotHold.
func TestMergeSlotExpirySystem_KeepsTheSlotOfAMergedFix(t *testing.T) {
	w := NewWorld("t1")
	w.clock = func() time.Time { return at(0).Add(10 * MergeSlotHold) }
	Reduce(w, FindingRaised{ID: "f1", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "a", At: at(0)})
	Reduce(w, MergeGranted{MergeRequest: "mr-1", Application: "a", At: at(0)})
	Reduce(w, MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged, At: at(30)})
	if evs := MergeSlotExpirySystem(w); len(evs) != 0 {
		t.Fatalf("a merged fix with no health result lost its slot: %+v", evs)
	}
}

// asked records that a run of the agent mission asked for the merge.
func asked(w *World, mr, mission, run string) {
	Reduce(w, MergeAsked{MergeRequest: mr, MissionID: mission, RunID: run, At: at(2)})
}

func slotOf(w *World, mr string) MergeSlot {
	for _, s := range w.MergeSlots() {
		if s.MergeRequest == mr {
			return s
		}
	}
	return MergeSlot{}
}

// The waiter of a slot is a run. It has ended when its mission is terminal in
// that run, or a later run replaced it. A slot with no waiter, and a mission that
// the World does not know, have not ended (gibson#1609).
func TestMergeSlots_WaiterEndedIsKeyedByTheRun(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionStarted{ID: "agent-1", RunID: "run-1"})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	if slotOf(w, "mr-1").WaiterEnded {
		t.Fatal("a slot with no waiter ended")
	}

	asked(w, "mr-1", "agent-1", "run-1")
	if s := slotOf(w, "mr-1"); s.WaiterMission != "agent-1" || s.WaiterRun != "run-1" || s.WaiterEnded {
		t.Fatalf("slot = %+v, want the waiter run-1 and not ended", s)
	}

	// The mission ends in the run that waits.
	Reduce(w, MissionDone{ID: "agent-1", RunID: "run-1", Outcome: MissionCompleted})
	if !slotOf(w, "mr-1").WaiterEnded {
		t.Fatal("the run ended and the slot says it did not")
	}

	// A mission has many runs. A waiter in a run that a later run replaced has
	// ended, and a waiter in the current run has not.
	w2 := NewWorld("t1")
	Reduce(w2, MissionStarted{ID: "agent-1", RunID: "run-2"})
	Reduce(w2, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	asked(w2, "mr-1", "agent-1", "run-1")
	if !slotOf(w2, "mr-1").WaiterEnded {
		t.Fatal("a waiter in an older run did not end")
	}
	asked(w2, "mr-1", "agent-1", "run-2")
	if slotOf(w2, "mr-1").WaiterEnded {
		t.Fatal("the latest ask names the current run, and it has not ended")
	}

	// A waiter that the World does not know has not ended: no fallback to the
	// fix mission or to any other mission.
	w3 := NewWorld("t1")
	Reduce(w3, MissionStarted{ID: "fix-1"})
	Reduce(w3, MissionDone{ID: "fix-1", Outcome: MissionCompleted})
	Reduce(w3, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	asked(w3, "mr-1", "ghost", "run-1")
	if slotOf(w3, "mr-1").WaiterEnded {
		t.Fatal("an unknown waiter ended")
	}
}

// MergeAsked changes nothing for a merge request with no slot, and it ignores an
// ask with no run or no mission.
func TestMergeAsked_NeedsASlotAndAnIdentity(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeAsked{MergeRequest: "mr-9", MissionID: "m", RunID: "r"})
	if len(w.MergeSlots()) != 0 {
		t.Fatal("an ask made a slot")
	}
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	Reduce(w, MergeAsked{MergeRequest: "mr-1", MissionID: "m"})
	Reduce(w, MergeAsked{MergeRequest: "mr-1", RunID: "r"})
	if s := slotOf(w, "mr-1"); s.WaiterRun != "" || s.WaiterMission != "" {
		t.Fatalf("slot = %+v, want no waiter", s)
	}
}

// The World alone never frees a slot because its waiter ended. The run may have
// merged, and only the host says so. The watcher frees the slot.
func TestMergeSlotExpirySystem_DoesNotFreeASlotWhoseWaiterEnded(t *testing.T) {
	w := NewWorld("t1")
	w.clock = func() time.Time { return at(3) }
	Reduce(w, MissionStarted{ID: "agent-1", RunID: "run-1"})
	Reduce(w, FindingRaised{ID: "f1", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", MissionID: "fix-1", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	Reduce(w, MergeGranted{MergeRequest: "mr-1", Application: "shop", At: at(1)})
	asked(w, "mr-1", "agent-1", "run-1")
	Reduce(w, MissionDone{ID: "agent-1", RunID: "run-1", Outcome: MissionCompleted})
	if evs := MergeSlotExpirySystem(w); len(evs) != 0 {
		t.Fatalf("the World freed a slot that the host may show as merged: %+v", evs)
	}
}

// The other fix of the Application gets its slot only after the first slot is
// gone.
func TestMergeGate_TheNextFixWaitsUntilTheFirstSlotIsGone(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(2), MissionID: "fix-2"})
	Reduce(w, grants(w)[0])
	if len(grants(w)) != 0 {
		t.Fatal("mr-2 was granted while mr-1 holds the slot")
	}
	Reduce(w, MergeSlotExpired{MergeRequest: "mr-1", Application: "shop", Reason: "the run ended", At: at(3)})
	next := grants(w)
	if len(next) != 1 || next[0].MergeRequest != "mr-2" {
		t.Fatalf("grants = %+v, want mr-2 after the slot of mr-1 is gone", next)
	}
}
