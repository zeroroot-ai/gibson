// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"slices"
	"time"
)

// fixattempt.go records the fix jobs that fail on a Finding (gibson#1674).
//
// A failed job releases its claim, and the Finding stays open. A Finding whose
// fix fails each time would then look like normal work. The World keeps each
// failed attempt on the Finding. After MaxFixAttempts failures in a row, the
// Finding shows a wait on a person and takes no new fix job. A linked fix ends
// the count. Only the daemon records an attempt. No agent claim moves it.

// MaxFixAttempts is the number of failed fix jobs in a row that block a Finding.
const MaxFixAttempts = 3

// maxKeptFixAttempts bounds the list of attempts that a Finding holds. The
// Timeline holds each attempt.
const maxKeptFixAttempts = 10

// FixAttempt is one failed fix job on a Finding.
type FixAttempt struct {
	JobID   string
	Verdict string
	Reason  string
	At      time.Time
}

// FixAttemptFailed records that a fix job closed as failed while it held the
// Finding.
type FixAttemptFailed struct {
	ID        string
	JobID     string
	Verdict   string
	Reason    string
	MissionID string
	At        time.Time
}

// Kind identifies the finding.fix_attempt_failed brain event.
func (FixAttemptFailed) Kind() string { return "finding.fix_attempt_failed" }

// applyFixAttemptFailed adds the attempt to an open Finding. A second event of
// the same job changes nothing, so a replay gives the same count.
func applyFixAttemptFailed(w *World, e FixAttemptFailed) {
	if e.ID == "" || e.JobID == "" {
		return
	}
	forFinding(w, e.ID, func(f *Finding) {
		if f.Status != FindingStatusOpen {
			return
		}
		for _, a := range f.FixAttempts {
			if a.JobID == e.JobID {
				return
			}
		}
		f.FixAttempts = append(f.FixAttempts, FixAttempt{JobID: e.JobID, Verdict: e.Verdict, Reason: e.Reason, At: e.At})
		if len(f.FixAttempts) > maxKeptFixAttempts {
			f.FixAttempts = append([]FixAttempt(nil), f.FixAttempts[len(f.FixAttempts)-maxKeptFixAttempts:]...)
		}
		if f.FixBlockedAt.IsZero() && len(f.FixAttempts) >= MaxFixAttempts {
			f.FixBlockedAt = e.At
		}
	})
}

// FixAttemptsResolved records that a person acted on a wait of a Finding
// (gibson#1674). The action retry clears the failed attempts, so the next fix job
// can claim the Finding. The action merge_request_closed ends each wait of a
// merge request that the daemon could not close, after the person closed it.
// UserID is the person that the daemon read from the identity of the call.
type FixAttemptsResolved struct {
	ID     string
	Action string
	UserID string
	// CloseWaits are the waits that the person closed and the daemon confirmed, for
	// the action merge_request_closed. The reducer ends these and no other, so a
	// wait that lands during the confirmation stays.
	CloseWaits []FixCloseWaitKey
	MissionID  string
	At         time.Time
}

// Kind identifies the finding.fix_attempts_resolved brain event.
func (FixAttemptsResolved) Kind() string { return "finding.fix_attempts_resolved" }

// FixCloseWaitKey names one close wait: the failed job and the merge request.
type FixCloseWaitKey struct {
	JobID        string
	MergeRequest string
}

// The actions of a person on the waits of a failed fix job.
const (
	// FixActionRetry clears the failed attempts of a Finding.
	FixActionRetry = "retry"
	// FixActionMergeRequestClosed ends the waits of the merge requests that the
	// daemon could not close.
	FixActionMergeRequestClosed = "merge_request_closed"
)

func applyFixAttemptsResolved(w *World, e FixAttemptsResolved) {
	forFinding(w, e.ID, func(f *Finding) {
		switch e.Action {
		case FixActionRetry:
			f.FixAttempts, f.FixBlockedAt = nil, time.Time{}
		case FixActionMergeRequestClosed:
			kept := make([]FixCloseWait, 0, len(f.FixCloseWaits))
			for _, c := range f.FixCloseWaits {
				if !slices.Contains(e.CloseWaits, FixCloseWaitKey{JobID: c.JobID, MergeRequest: c.MergeRequest}) {
					kept = append(kept, c)
				}
			}
			f.FixCloseWaits = kept
		}
	})
}

// FixAttemptsBlocked reports whether the Finding has MaxFixAttempts failed fix
// jobs in a row. No new fix job takes it, until a person acts.
func (f FixFacts) FixAttemptsBlocked() bool { return !f.FixBlockedAt.IsZero() }

// FixCloseWait is a merge request of a failed job that the daemon could not
// close. A finding holds one for each job and merge request, so a second failed
// job never replaces the wait of the first.
//
// Comment is the text that the first attempt posted or tried to post. Each
// retry posts the same text, so the duplicate check of the connector finds it
// after a restart too. Attempts counts the tries. GaveUp is true when the
// daemon stopped the retries. The wait then stays until a person acts.
type FixCloseWait struct {
	JobID        string
	MissionRunID string
	MergeRequest string
	Reason       string
	Comment      string
	Attempts     int
	GaveUp       bool
	Since        time.Time
}

// FixCloseWaiting records that the daemon could not close a merge request of a
// failed fix job, or ends that wait when Waiting is false.
type FixCloseWaiting struct {
	ID           string
	JobID        string
	MergeRequest string
	Waiting      bool
	Reason       string
	Comment      string
	Attempts     int
	GaveUp       bool
	MissionID    string
	At           time.Time
}

// Kind identifies the finding.fix_close_waiting brain event.
func (FixCloseWaiting) Kind() string { return "finding.fix_close_waiting" }

func applyFixCloseWaiting(w *World, e FixCloseWaiting) {
	if e.ID == "" || e.JobID == "" || e.MergeRequest == "" {
		return
	}
	forFinding(w, e.ID, func(f *Finding) {
		idx := -1
		for i, c := range f.FixCloseWaits {
			if c.JobID == e.JobID && c.MergeRequest == e.MergeRequest {
				idx = i
			}
		}
		if !e.Waiting {
			if idx >= 0 {
				f.FixCloseWaits = append(f.FixCloseWaits[:idx:idx], f.FixCloseWaits[idx+1:]...)
			}
			return
		}
		c := FixCloseWait{
			JobID: e.JobID, MissionRunID: e.MissionID, MergeRequest: e.MergeRequest, Reason: e.Reason,
			Comment: e.Comment, Attempts: e.Attempts, GaveUp: e.GaveUp, Since: e.At,
		}
		if idx < 0 {
			f.FixCloseWaits = append(f.FixCloseWaits, c)
			return
		}
		old := f.FixCloseWaits[idx]
		// The wait starts at the first failed close, and the comment is the first one.
		c.Since = old.Since
		if old.Comment != "" {
			c.Comment = old.Comment
		}
		f.FixCloseWaits = append([]FixCloseWait(nil), f.FixCloseWaits...)
		f.FixCloseWaits[idx] = c
	})
}

// copyFacts copies the slices of the facts, so a snapshot shares no memory with
// the World.
func (f FixFacts) copyFacts() FixFacts {
	f.FixAttempts = append([]FixAttempt(nil), f.FixAttempts...)
	f.FixCloseWaits = append([]FixCloseWait(nil), f.FixCloseWaits...)
	return f
}
