// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import "time"

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

// FixAttemptsBlocked reports whether the Finding has MaxFixAttempts failed fix
// jobs in a row. No new fix job takes it, until a person acts.
func (f FixFacts) FixAttemptsBlocked() bool { return !f.FixBlockedAt.IsZero() }

// FixCloseWait is the failed job whose merge request the daemon could not
// close. ClaimedAt is the time of the claim of the job. The daemon needs it to
// check the age of the merge request when it tries the close again.
type FixCloseWait struct {
	JobID        string
	MissionRunID string
	MergeRequest string
	Reason       string
	ClaimedAt    time.Time
	Since        time.Time
}

// FixCloseWaiting records that the daemon could not close the merge request of
// a failed fix job, or ends that wait when Waiting is false.
type FixCloseWaiting struct {
	ID           string
	JobID        string
	MergeRequest string
	Waiting      bool
	Reason       string
	ClaimedAt    time.Time
	MissionID    string
	At           time.Time
}

// Kind identifies the finding.fix_close_waiting brain event.
func (FixCloseWaiting) Kind() string { return "finding.fix_close_waiting" }

func applyFixCloseWaiting(w *World, e FixCloseWaiting) {
	if e.ID == "" || e.JobID == "" {
		return
	}
	forFinding(w, e.ID, func(f *Finding) {
		if !e.Waiting {
			if f.FixCloseWait.JobID == e.JobID {
				f.FixCloseWait = FixCloseWait{}
			}
			return
		}
		since := e.At
		if f.FixCloseWait.JobID == e.JobID && !f.FixCloseWait.Since.IsZero() {
			since = f.FixCloseWait.Since // the wait starts at the first failed close
		}
		f.FixCloseWait = FixCloseWait{
			JobID: e.JobID, MissionRunID: e.MissionID, MergeRequest: e.MergeRequest, Reason: e.Reason,
			ClaimedAt: e.ClaimedAt, Since: since,
		}
	})
}

// clone copies the slices of the facts, so a snapshot shares no memory with
// the World.
func (ff FixFacts) clone() FixFacts {
	ff.FixAttempts = append([]FixAttempt(nil), ff.FixAttempts...)
	return ff
}
