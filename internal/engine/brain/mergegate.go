// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "time"

// mergegate.go lets one fix at a time go out for each Application (gibson#1466).
//
// An agent that holds a merge request asks for a slot with MergeRequestQueued.
// MergeGateSystem grants the slot to the oldest request of an Application when no
// other merge request of that Application holds a slot. The agent merges only
// after MergeGranted. The slot is free again when the health signal holds,
// when the merge is reverted after a failed signal, when the service has no
// health signal, or when the merge request closes. MergeSlotExpirySystem
// frees a slot that no Finding carries any more (review M1). The fix loop
// watcher frees a granted slot that no merge used within the grant window, after
// it reads the merge request on the host (gibson#1609). A released slot leaves
// the queue (review m10). Fixes for different Applications never wait
// on each other.
//
// The time that a merge request waits in this queue is agent time. It is not an
// explicit wait, so the exposure window counts it as agent time.

// MergeRequestQueued records that an agent holds a merge request for the
// Application and waits for its slot.
type MergeRequestQueued struct {
	MergeRequest string
	Application  string
	At           time.Time
	MissionID    string
}

// Kind identifies the merge_request.queued brain event.
func (MergeRequestQueued) Kind() string { return "merge_request.queued" }

// MergeGranted records that the merge request may merge now.
type MergeGranted struct {
	MergeRequest string
	Application  string
	At           time.Time
	MissionID    string
}

// Kind identifies the merge_request.granted brain event.
func (MergeGranted) Kind() string { return "merge_request.granted" }

// MergeSlot is the place of one merge request in the queue of its Application.
type MergeSlot struct {
	MergeRequest string
	Application  string
	QueuedAt     time.Time
	Granted      bool
	// GrantedAt is the time of the grant. It is zero until the grant.
	GrantedAt time.Time
	// MissionID is the mission of the fix that holds the slot. Only a call
	// of that mission may merge with it (review m16).
	MissionID string
}

// MergeSlotExpired records that the daemon freed a slot that nothing else
// frees (review M1). Reason says why.
type MergeSlotExpired struct {
	MergeRequest string
	Application  string
	Reason       string
	At           time.Time
	MissionID    string
}

// Kind identifies the merge_request.slot_expired brain event.
func (MergeSlotExpired) Kind() string { return "merge_request.slot_expired" }

func applyMergeSlotExpired(w *World, e MergeSlotExpired) { releaseMergeSlot(w, e.MergeRequest) }

func findMergeSlot(w *World, mr string) *MergeSlot {
	for i := range w.mergeSlots {
		if w.mergeSlots[i].MergeRequest == mr {
			return &w.mergeSlots[i]
		}
	}
	return nil
}

func applyMergeRequestQueued(w *World, e MergeRequestQueued) {
	if e.MergeRequest == "" || e.Application == "" || findMergeSlot(w, e.MergeRequest) != nil {
		return
	}
	w.mergeSlots = append(w.mergeSlots, MergeSlot{
		MergeRequest: e.MergeRequest, Application: e.Application, QueuedAt: e.At, MissionID: e.MissionID,
	})
}

func applyMergeGranted(w *World, e MergeGranted) {
	if s := findMergeSlot(w, e.MergeRequest); s != nil && !s.Granted {
		s.Granted, s.GrantedAt = true, e.At
	}
}

// releaseMergeSlot frees the slot of the merge request and drops it from the
// queue. An unknown merge request changes nothing.
func releaseMergeSlot(w *World, mr string) {
	for i := range w.mergeSlots {
		if w.mergeSlots[i].MergeRequest == mr {
			w.mergeSlots = append(w.mergeSlots[:i:i], w.mergeSlots[i+1:]...)
			return
		}
	}
}

// MergeSlots returns the queue in the order of the Timeline.
func (w *World) MergeSlots() []MergeSlot { return append([]MergeSlot(nil), w.mergeSlots...) }

// MayMerge reports whether the merge request holds a granted slot for a call
// of the mission. A call with no mission never merges. The slot lets three
// missions merge: the mission that it names, the mission that originated that
// one (the fix agent originates the fix mission and merges from its own mission,
// review m16), and any mission that works on the same Application. The last rule
// is for a later pass of the fix agent, which can be a new dispatch with a new
// mission and merges a merge request that an earlier mission opened (gibson#1609).
// A mission works on an Application when the World holds the Application as its
// target. A mission of another Application, and a mission with no target, do not
// merge. The tenant is the World itself, so a mission of another tenant is never
// here. One slot for each Application stays the rule of the gate.
func (w *World) MayMerge(mr, missionID string) bool {
	s := findMergeSlot(w, mr)
	if s == nil || !s.Granted || missionID == "" {
		return false
	}
	if s.MissionID == "" {
		return false // a slot that names no mission lets no call merge (review r2)
	}
	if s.MissionID == missionID {
		return true
	}
	if l, ok := w.MissionLineage(s.MissionID); ok && l.ParentMissionID == missionID {
		return true
	}
	return s.Application != "" && w.missionTarget(missionID) == s.Application
}

// missionTarget returns the target of the mission, or "" when the World does not
// know the mission.
func (w *World) missionTarget(missionID string) string {
	ent, ok := findMission(w, missionID)
	if !ok {
		return ""
	}
	return w.missions.Get(ent).TargetID
}

// MergeGateSystem grants the slot of an Application to its oldest queued merge
// request when no other merge request of the Application holds a slot.
func MergeGateSystem(w *World) []Event {
	busy := map[string]bool{}
	for _, s := range w.mergeSlots {
		if s.Granted {
			busy[s.Application] = true
		}
	}
	var out []Event
	for _, s := range w.mergeSlots { // the slice is in Timeline order
		if s.Granted || busy[s.Application] {
			continue
		}
		busy[s.Application] = true
		out = append(out, MergeGranted{MergeRequest: s.MergeRequest, Application: s.Application, At: w.Now()})
	}
	return out
}

// MergeSlotExpirySystem frees the slots that no other event frees (review M1):
//
//	no Finding carries the merge request          → free (a rerun opened the
//	                                                 Finding again, or it moved on)
//
// This System frees no slot on a clock. A slot that no merge used is freed by the
// fix loop watcher, because only the watcher can read the merge request on the
// host: a merged merge request keeps its slot until its health signal answers,
// and no second fix of the Application ships before that (gibson#1609).
//
// The System is quiescent: a freed slot leaves the queue.
func MergeSlotExpirySystem(w *World) []Event {
	if len(w.mergeSlots) == 0 {
		return nil
	}
	carried := map[string]bool{}
	mission := map[string]string{}
	for _, f := range w.FindingSnapshot() {
		if f.MergeRequest == "" {
			continue
		}
		carried[f.MergeRequest] = true
		if f.FixMissionID != "" {
			mission[f.MergeRequest] = f.FixMissionID
		}
	}
	var out []Event
	for _, s := range w.mergeSlots {
		if carried[s.MergeRequest] {
			continue
		}
		out = append(out, MergeSlotExpired{
			MergeRequest: s.MergeRequest, Application: s.Application, At: w.Now(),
			Reason:    "no finding carries the merge request",
			MissionID: mission[s.MergeRequest],
		})
	}
	return out
}
