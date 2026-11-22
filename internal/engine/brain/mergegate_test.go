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
// again). It frees no granted slot on a clock: only the watcher, which reads the
// host, frees a slot that no merge used (gibson#1609). A deployed merge request
// keeps its slot (review M1).
func TestMergeSlotExpirySystem(t *testing.T) {
	w := NewWorld("t1")
	now := at(0).Add(1000 * time.Hour)
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
	if !got["mr-f-1"] || got["mr-f-2"] || got["mr-f-3"] {
		t.Fatalf("expired = %v, want only mr-f-1, whatever the time since the grant", got)
	}
	if len(MergeSlotExpirySystem(w)) != 0 {
		t.Fatal("not quiescent")
	}
	if !w.MayMerge("mr-f-3", "m1") || w.MayMerge("mr-f-1", "m1") {
		t.Fatal("the deployed slot must stay and the freed one must go")
	}
	if !w.MayMerge("mr-f-2", "m1") {
		t.Fatal("a granted slot that a Finding carries must stay, whatever the time since the grant")
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
// until its health signal answers (review R4).
func TestMergeSlotExpirySystem_KeepsTheSlotOfAMergedFix(t *testing.T) {
	w := NewWorld("t1")
	w.clock = func() time.Time { return at(0).Add(240 * time.Hour) }
	Reduce(w, FindingRaised{ID: "f1", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "a", At: at(0)})
	Reduce(w, MergeGranted{MergeRequest: "mr-1", Application: "a", At: at(0)})
	Reduce(w, MergeRequestObserved{Key: "mr-1", State: MergeRequestMerged, At: at(30)})
	if evs := MergeSlotExpirySystem(w); len(evs) != 0 {
		t.Fatalf("a merged fix with no health result lost its slot: %+v", evs)
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

// A later pass of the fix agent can be a new mission. It merges a granted merge
// request that an earlier mission opened when it works on the same Application. A
// mission of another Application, a mission with no target and a call with no
// mission are refused (gibson#1609).
func TestMayMerge_AnyMissionOfTheSameApplicationMergesAGrantedSlot(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionStarted{ID: "later-pass", TargetID: "shop"})
	Reduce(w, MissionStarted{ID: "other-app-pass", TargetID: "bank"})
	Reduce(w, MissionStarted{ID: "no-target-pass"})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})

	if w.MayMerge("mr-1", "later-pass") {
		t.Fatal("a slot that is not granted let a call merge")
	}
	Reduce(w, grants(w)[0])
	if !w.MayMerge("mr-1", "later-pass") {
		t.Fatal("a new mission of the same Application must merge a granted merge request that an earlier mission opened")
	}
	for name, mission := range map[string]string{
		"a mission of another Application": "other-app-pass",
		"a mission with no target":         "no-target-pass",
		"a mission that the World lacks":   "ghost",
		"no mission":                       "",
	} {
		if w.MayMerge("mr-1", mission) {
			t.Errorf("%s merged with the slot of another Application", name)
		}
	}
	// A slot that names no mission lets no call merge, also of the same Application.
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-2", Application: "shop", At: at(2)})
	Reduce(w, MergeGranted{MergeRequest: "mr-2", Application: "shop", At: at(2)})
	if w.MayMerge("mr-2", "later-pass") {
		t.Fatal("a slot with no mission let a call merge")
	}
}

// The World of one tenant knows no mission of another tenant, so a mission of
// another tenant never merges with a slot of this tenant.
func TestMayMerge_AMissionOfAnotherTenantIsRefused(t *testing.T) {
	a, b := NewWorld("tenant-a"), NewWorld("tenant-b")
	Reduce(a, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	Reduce(a, grants(a)[0])
	Reduce(b, MissionStarted{ID: "pass-of-b", TargetID: "shop"})
	if a.MayMerge("mr-1", "pass-of-b") {
		t.Fatal("a mission of tenant B merged with a slot of tenant A")
	}
}

// The System frees no granted slot on a clock, whatever the time since the grant.
// The watcher frees it after it reads the host.
func TestMergeSlotExpirySystem_FreesNoGrantedSlotOnAClock(t *testing.T) {
	w := NewWorld("t1")
	w.clock = func() time.Time { return at(0).Add(1000 * time.Hour) }
	Reduce(w, FindingRaised{ID: "f1", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", MissionID: "fix-1", At: at(0)})
	Reduce(w, MergeRequestQueued{MergeRequest: "mr-1", Application: "shop", At: at(1), MissionID: "fix-1"})
	Reduce(w, grants(w)[0])
	if evs := MergeSlotExpirySystem(w); len(evs) != 0 {
		t.Fatalf("the World freed a granted slot on a clock: %+v", evs)
	}
}
