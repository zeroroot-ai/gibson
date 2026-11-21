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

// FixClaimHold is how long a claim can hold a Finding that is still open. A
// fix job that runs longer has lost its node: the node ended without a
// release, or the job closed elsewhere (review M3).
const FixClaimHold = 24 * time.Hour

// FixClaimExpired records that the daemon ended a claim whose job is gone
// (review M3): the claim is older than FixClaimHold, or the daemon restarted
// and the job ended with it. The reducer ends the claim only for its holder.
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

// FixClaimExpirySystem ends each claim of an open Finding that is older than
// FixClaimHold. It is quiescent: an ended claim is gone.
func FixClaimExpirySystem(w *World) []Event {
	now := w.Now()
	var out []Event
	for _, f := range w.FindingSnapshot() {
		if f.FixClaim == "" || f.Status != FindingStatusOpen || f.FixClaimedAt.IsZero() {
			continue
		}
		if now.Sub(f.FixClaimedAt) > FixClaimHold {
			out = append(out, FixClaimExpired{
				ID: f.ID, Claim: f.FixClaim, Reason: "the claim is older than " + FixClaimHold.String(), At: now,
			})
		}
	}
	return out
}

// ResumeReleaseFixClaims ends each claim of an open Finding when the daemon
// starts. A claim is held by a job node that runs in the daemon, so a claim in
// a World that the daemon just read from its store has no live job. Call once
// on resume, after rebuilding the World, like ResumeFailInFlight.
func ResumeReleaseFixClaims(w *World) []Event {
	now := w.Now()
	var out []Event
	for _, f := range w.FindingSnapshot() {
		if f.FixClaim != "" && f.Status == FindingStatusOpen {
			out = append(out, FixClaimExpired{
				ID: f.ID, Claim: f.FixClaim, Reason: "the daemon restarted, and the job of the claim ended with it", At: now,
			})
		}
	}
	return out
}
