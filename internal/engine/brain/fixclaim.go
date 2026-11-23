// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"time"

	"github.com/mlange-42/ark/ecs"
)

// fixclaim.go lets one fix job at a time work on one Finding.
//
// A Finding stays `open` until a fix job closes with a merge request. Two
// dispatches for one Application could therefore start two fix jobs for one
// Finding. The daemon claims each Finding for its job before the job opens. A
// second job for a claimed Finding is refused. The claim ends when the job
// ends with no merge request. A job that delivers a merge request moves the
// Finding to `fixing`, and the claim then ends with the fix: a revert or a
// failed proof opens the Finding again with no claim. The four statuses of
// ADR-0178 stay as they are: a claim is no status.

// FixClaimed records that a fix job claims a Finding.
type FixClaimed struct {
	ID string
	// Claim names the fix job: the mission run and the node of the job.
	Claim     string
	MissionID string
	At        time.Time
}

// Kind identifies the finding.fix_claimed brain event.
func (FixClaimed) Kind() string { return "finding.fix_claimed" }

// FixClaimReleased records that the fix job of a claim ended with no merge
// request.
type FixClaimReleased struct {
	ID        string
	Claim     string
	MissionID string
	At        time.Time
}

// Kind identifies the finding.fix_claim_released brain event.
func (FixClaimReleased) Kind() string { return "finding.fix_claim_released" }

// applyFixClaimed sets the claim of an open Finding with no claim. A claim of a
// claimed Finding, or of a Finding in another status, changes nothing, so the
// first claim wins and a replay gives the same holder.
func applyFixClaimed(w *World, e FixClaimed) {
	if e.ID == "" || e.Claim == "" {
		return
	}
	forFinding(w, e.ID, func(f *Finding) {
		if f.Status == FindingStatusOpen && f.FixClaim == "" {
			f.FixClaim, f.FixClaimedAt = e.Claim, e.At
		}
	})
}

// applyFixClaimReleased ends the claim when the holder releases it.
func applyFixClaimReleased(w *World, e FixClaimReleased) {
	forFinding(w, e.ID, func(f *Finding) {
		if f.FixClaim == e.Claim {
			f.FixClaim, f.FixClaimedAt = "", time.Time{}
			f.FixLinkWait = FixLinkWait{}
		}
	})
}

// FixLinkRefused records that the daemon refused to link a merge request to a
// Finding (review B1). The fix job named the merge request, and the daemon
// read it on the Git host. The merge request was not open, was older than the
// claim of the job, or came from a branch that is not the job branch. The
// Finding keeps its status, and the claim of the job ends. The event changes
// nothing else. It is the record of the refusal in the Timeline.
type FixLinkRefused struct {
	ID           string
	MergeRequest string
	JobID        string
	Reason       string
	MissionID    string
	At           time.Time
}

// Kind identifies the finding.fix_link_refused brain event.
func (FixLinkRefused) Kind() string { return "finding.fix_link_refused" }

// FixLinkPending records that the daemon could not read the merge request of a
// closed fix job on the Git host, so it could not check the merge request yet
// (gibson#1581). The Finding keeps its claim, and the daemon reads the merge
// request again. A later read ends in a link or in a FixLinkRefused. The event
// changes nothing else. It is the record of the wait in the Timeline.
//
// The event holds what the daemon needs to read the merge request again after
// a restart: the node and the mission run of the job, the url and the ref of
// the merge request and the countermeasure of the fix.
type FixLinkPending struct {
	ID             string
	MergeRequest   string
	JobID          string
	Reason         string
	MissionID      string
	NodeID         string
	URL            string
	Ref            string
	Countermeasure string
	At             time.Time
}

// FixHeadRecorded records the head commit of a merge request and the files that
// it changes, as the daemon read them on the Git host when it linked the merge
// request to the Finding. The values come from the host and never from an agent.
// Files is the JSON list of the changed files.
type FixHeadRecorded struct {
	ID           string
	MergeRequest string
	HeadSHA      string
	Files        string
	MissionID    string
	At           time.Time
}

// Kind identifies the finding.fix_head_recorded brain event.
func (FixHeadRecorded) Kind() string { return "finding.fix_head_recorded" }

// applyFixHeadRecorded keeps the head on the Finding whose current merge
// request is the one that the event names.
func applyFixHeadRecorded(w *World, e FixHeadRecorded) {
	forFinding(w, e.ID, func(f *Finding) {
		if f.MergeRequest == e.MergeRequest {
			f.FixHeadSHA, f.FixFiles = e.HeadSHA, e.Files
			f.FixHeadMissingReason, f.FixHeadMissingAt = "", time.Time{}
		}
	})
}

// FixLinkWait is the state that FixLinkPending leaves on a Finding.
type FixLinkWait struct {
	JobID          string
	MissionRunID   string
	NodeID         string
	MergeRequest   string
	URL            string
	Ref            string
	Countermeasure string
	Since          time.Time
}

// applyFixLinkPending records the wait on an open Finding that a job claims.
func applyFixLinkPending(w *World, e FixLinkPending) {
	if e.ID == "" || e.JobID == "" {
		return
	}
	forFinding(w, e.ID, func(f *Finding) {
		if f.Status == FindingStatusOpen && f.FixClaim != "" {
			f.FixLinkWait = FixLinkWait{
				JobID: e.JobID, MissionRunID: e.MissionID, NodeID: e.NodeID, MergeRequest: e.MergeRequest,
				URL: e.URL, Ref: e.Ref, Countermeasure: e.Countermeasure, Since: e.At,
			}
		}
	})
}

// applyFixLinkRefused ends the wait of a link that the daemon refused.
func applyFixLinkRefused(w *World, e FixLinkRefused) {
	forFinding(w, e.ID, func(f *Finding) {
		if f.FixLinkWait.JobID == e.JobID {
			f.FixLinkWait = FixLinkWait{}
		}
	})
}

// Kind identifies the finding.fix_link_pending brain event.
func (FixLinkPending) Kind() string { return "finding.fix_link_pending" }

// FixClaimOf returns the claim that holds the Finding, or "".
func (w *World) FixClaimOf(id string) string {
	var out string
	forFinding(w, id, func(f *Finding) { out = f.FixClaim })
	return out
}

// forFinding runs fn on the Finding with the id, if the World holds it.
func forFinding(w *World, id string, fn func(*Finding)) {
	q := ecs.NewFilter1[Finding](w.ecs).Query()
	for q.Next() {
		if f := q.Get(); f.ID == id {
			fn(f)
			q.Close()
			return
		}
	}
}

// FixClaimExpired records that the daemon ended a claim whose job is known to
// be gone (review M3, r11): the daemon restarted, and the job node of the
// claim ended with it. A job node has no time limit, so a claim never ends
// for its age. The reducer ends the claim only for its holder.
type FixClaimExpired struct {
	ID        string
	Claim     string
	Reason    string
	MissionID string
	At        time.Time
}

// Kind identifies the finding.fix_claim_expired brain event.
func (FixClaimExpired) Kind() string { return "finding.fix_claim_expired" }

func applyFixClaimExpired(w *World, e FixClaimExpired) {
	applyFixClaimReleased(w, FixClaimReleased{ID: e.ID, Claim: e.Claim})
}

// ResumeReleaseFixClaims ends each claim of an open Finding when the daemon
// starts. A claim is held by a job node that runs in the daemon, so a claim in
// a World that the daemon just read from its store has no live job. Call once
// on resume, after rebuilding the World, like ResumeFailInFlight.
func ResumeReleaseFixClaims(w *World) []Event {
	now := w.Now()
	var out []Event
	for _, f := range w.FindingSnapshot() {
		// A claim with a link that waits for the Git host stays. The daemon
		// reads the merge request again (gibson#1581).
		if f.FixClaim != "" && f.Status == FindingStatusOpen && f.FixLinkWait.JobID == "" {
			out = append(out, FixClaimExpired{
				ID: f.ID, Claim: f.FixClaim, Reason: "the daemon restarted, and the job of the claim ended with it", At: now,
			})
		}
	}
	return out
}
