// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"time"

	"github.com/mlange-42/ark/ecs"
)

// mergerequest.go moves a Finding from `fixing` to `fixed` or back to `open`
// (gibson#1505).
//
// The fix job opens a merge request and the daemon sets the Finding to `fixing`
// (internal/server/daemon/job_graph_link.go). The Git host then decides the
// outcome. The daemon records what the host reports as a MergeRequestObserved
// event. This System turns that report into a status change, so each change is
// its own Timeline event and a replay gives the same statuses.
//
// A merge sets `fixed` and never `verified`. Only the check that raised the
// Finding verifies it.

// Merge request states that the Git host reports.
const (
	MergeRequestMerged = "merged"
	MergeRequestClosed = "closed"
	// MergeRequestRefused is a merge that the Git host refused, for example
	// because of a branch protection rule. The merge request stays open and the
	// fix waits on a person. It moves no Finding. The exposure window counts the
	// time until the next report as wait time.
	MergeRequestRefused = "refused"
)

// MergeRequestObserved records the state of one merge request as the Git host
// reports it. Key is the same key that the FIXED_BY link uses: the URL of the
// merge request, or its ref when it has no URL.
type MergeRequestObserved struct {
	Key       string
	State     string
	MissionID string
	// Reason is what the host said when it refused the merge. It is empty for
	// any other state (gibson#1609).
	Reason string
	// At is the time of the report. The exposure window and the revert rate
	// read it.
	At time.Time
}

// Kind identifies the merge_request.observed brain event.
func (MergeRequestObserved) Kind() string { return "merge_request.observed" }

// applyMergeRequestObserved stores the state on each Finding that the merge
// request carries. An unknown key or a state other than merged or closed
// changes nothing.
func applyMergeRequestObserved(w *World, e MergeRequestObserved) {
	if e.Key == "" || (e.State != MergeRequestMerged && e.State != MergeRequestClosed) {
		return // a refusal has no state to store. The Timeline holds it.
	}
	if e.State == MergeRequestClosed {
		releaseMergeSlot(w, e.Key)
	}
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		f := q.Get()
		if f.MergeRequest == e.Key {
			f.MergeRequestState = e.State
		}
	}
}

// MergeRequestReconciliationSystem emits one FindingStatusChanged for each
// `fixing` Finding whose merge request the Git host has settled:
//
//	merged → fixed
//	closed → open   (the fix did not ship)
//
// A Finding in any other status does not move. The System is quiescent: after
// the status change the Finding is no longer `fixing`.
func MergeRequestReconciliationSystem(w *World) []Event {
	now := w.Now()
	var out []Event
	for _, f := range w.FindingSnapshot() {
		if f.Status != FindingStatusFixing {
			continue
		}
		switch f.MergeRequestState {
		case MergeRequestMerged:
			out = append(out, FindingStatusChanged{ID: f.ID, Status: FindingStatusFixed, MissionID: f.FixMissionID, At: now})
		case MergeRequestClosed:
			out = append(out, FindingStatusChanged{ID: f.ID, Status: FindingStatusOpen, MissionID: f.FixMissionID, At: now})
		}
	}
	return out
}
