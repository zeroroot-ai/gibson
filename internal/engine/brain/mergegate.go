// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "time"

// mergegate.go lets one fix at a time go out for each Application (gibson#1466).
//
// An agent that holds a merge request asks for a slot with MergeRequestQueued.
// MergeGateSystem grants the slot to the oldest request of an Application when no
// other merge request of that Application holds a slot. The agent merges only
// after MergeGranted. The slot is free again when the health signal answers,
// when the merge is reverted, or when the merge request closes. Fixes for
// different Applications never wait on each other.
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
	Released     bool
}

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
		MergeRequest: e.MergeRequest, Application: e.Application, QueuedAt: e.At,
	})
}

func applyMergeGranted(w *World, e MergeGranted) {
	if s := findMergeSlot(w, e.MergeRequest); s != nil {
		s.Granted = true
	}
}

// releaseMergeSlot frees the slot of the merge request. An unknown merge request
// changes nothing.
func releaseMergeSlot(w *World, mr string) {
	if s := findMergeSlot(w, mr); s != nil {
		s.Released = true
	}
}

// MergeSlots returns the queue in the order of the Timeline.
func (w *World) MergeSlots() []MergeSlot { return append([]MergeSlot(nil), w.mergeSlots...) }

// MayMerge reports whether the merge request holds a slot that is not free yet.
func (w *World) MayMerge(mr string) bool {
	s := findMergeSlot(w, mr)
	return s != nil && s.Granted && !s.Released
}

// MergeGateSystem grants the slot of an Application to its oldest queued merge
// request when no other merge request of the Application holds a slot.
func MergeGateSystem(w *World) []Event {
	busy := map[string]bool{}
	for _, s := range w.mergeSlots {
		if s.Granted && !s.Released {
			busy[s.Application] = true
		}
	}
	var out []Event
	for _, s := range w.mergeSlots { // the slice is in Timeline order
		if s.Granted || s.Released || busy[s.Application] {
			continue
		}
		busy[s.Application] = true
		out = append(out, MergeGranted{MergeRequest: s.MergeRequest, Application: s.Application, At: w.Now()})
	}
	return out
}
