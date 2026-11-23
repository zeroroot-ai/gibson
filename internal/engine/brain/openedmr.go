// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "time"

// openedMergeRequestLimit bounds the opened merge requests that one World keeps.
// The oldest one goes first. The World belongs to one tenant, so the tenant that
// opens the most merge requests can evict only its own.
const openedMergeRequestLimit = 4096

// MergeRequestOpened records that the tool open_merge_request succeeded for a
// merge request. The daemon takes the values from the result of the tool call at
// the tool gate, so they are not the claim of an agent. The link of a closed fix
// job compares the head with the head that the Git host reports, so a commit that
// the job did not make never becomes the head of the fix.
type MergeRequestOpened struct {
	// MergeRequest is the reference of the merge request, and URL is its URL. The
	// deliverable of a job names either.
	MergeRequest string
	URL          string
	// JobID is the job whose branch the tool opened. It is empty when the branch
	// is no job branch.
	JobID        string
	SourceBranch string
	HeadSHA      string
	// RunID and MissionID name the run and the mission of the call, so a call of
	// another agent cannot replace the head of the merge request of a job.
	// MissionRunID is the mission run of the call. It is empty for a call of an
	// agent that runs outside a mission run, such as a member of a bank.
	RunID        string
	MissionID    string
	MissionRunID string
	At           time.Time
}

// Kind identifies the merge_request.opened brain event.
func (MergeRequestOpened) Kind() string { return "merge_request.opened" }

// OpenedMergeRequest is the state that MergeRequestOpened leaves in the World.
type OpenedMergeRequest struct {
	MergeRequest string    `json:"merge_request"`
	URL          string    `json:"url,omitempty"`
	JobID        string    `json:"job_id,omitempty"`
	SourceBranch string    `json:"source_branch"`
	HeadSHA      string    `json:"head_sha"`
	RunID        string    `json:"run_id,omitempty"`
	MissionID    string    `json:"mission_id,omitempty"`
	MissionRunID string    `json:"mission_run_id,omitempty"`
	At           time.Time `json:"at"`
}

// applyMergeRequestOpened keeps the record under the reference and the URL. A
// record of one run is never replaced by an event of another run or mission.
func applyMergeRequestOpened(w *World, e MergeRequestOpened) {
	if e.HeadSHA == "" || e.SourceBranch == "" {
		return
	}
	rec := OpenedMergeRequest{
		MergeRequest: e.MergeRequest, URL: e.URL, JobID: e.JobID, SourceBranch: e.SourceBranch,
		HeadSHA: e.HeadSHA, RunID: e.RunID, MissionID: e.MissionID, MissionRunID: e.MissionRunID, At: e.At,
	}
	for _, key := range []string{e.MergeRequest, e.URL} {
		if key == "" {
			continue
		}
		if old, ok := w.openedMRs[key]; ok && (old.RunID != e.RunID || old.MissionID != e.MissionID) {
			continue
		}
		if w.openedMRs == nil {
			w.openedMRs = map[string]OpenedMergeRequest{}
		}
		if _, ok := w.openedMRs[key]; !ok {
			w.openedMROrder = append(w.openedMROrder, key)
		}
		w.openedMRs[key] = rec
	}
	for len(w.openedMROrder) > openedMergeRequestLimit {
		delete(w.openedMRs, w.openedMROrder[0])
		w.openedMROrder = w.openedMROrder[1:]
	}
}

// OpenedMergeRequest returns the record of the merge request that the key names, as
// a reference or as a URL.
func (w *World) OpenedMergeRequest(key string) (OpenedMergeRequest, bool) {
	r, ok := w.openedMRs[key]
	return r, ok
}

// OpenedMergeRequests returns the records in the order of the Timeline, once each.
func (w *World) OpenedMergeRequests() []OpenedMergeRequest {
	out := make([]OpenedMergeRequest, 0, len(w.openedMRs))
	seen := map[OpenedMergeRequest]bool{}
	for _, k := range w.openedMROrder {
		r, ok := w.openedMRs[k]
		if !ok || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

// FixHeadMissing records that the link of a closed fix job could not record a head
// for the fix, and why. The finding waits on a person while it has no head,
// because the fix agent makes no merge call without one.
type FixHeadMissing struct {
	ID           string
	MergeRequest string
	Reason       string
	MissionID    string
	At           time.Time
}

// Kind identifies the finding.fix_head_missing brain event.
func (FixHeadMissing) Kind() string { return "finding.fix_head_missing" }

// applyFixHeadMissing records the reason on the Finding whose current merge
// request is the one that the event names. A Finding that has a head keeps it.
func applyFixHeadMissing(w *World, e FixHeadMissing) {
	forFinding(w, e.ID, func(f *Finding) {
		if f.MergeRequest == e.MergeRequest && f.FixHeadSHA == "" {
			f.FixHeadMissingReason, f.FixHeadMissingAt = e.Reason, e.At
		}
	})
}
