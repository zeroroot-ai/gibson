// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"
)

func attemptAt(h int) time.Time {
	return time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC).Add(time.Duration(h) * time.Hour)
}

func failAttempt(w *World, job string, h int) {
	Reduce(w, FixAttemptFailed{ID: "f1", JobID: job, Verdict: "failed", Reason: "r-" + job, At: attemptAt(h)})
}

func snapshotOf(w *World, id string) FindingSnapshot {
	for _, f := range w.FindingSnapshot() {
		if f.ID == id {
			return f
		}
	}
	return FindingSnapshot{}
}

// The third failed attempt in a row blocks the finding, at the time of that
// attempt. Two failures do not block. A repeated event of one job counts once.
func TestFixAttempts_TheThirdFailureInARowBlocks(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	failAttempt(w, "j1", 1)
	failAttempt(w, "j1", 1)
	failAttempt(w, "j2", 2)
	if s := snapshotOf(w, "f1"); s.FixAttemptsBlocked() || len(s.FixAttempts) != 2 {
		t.Fatalf("after two failures: blocked=%v attempts=%+v", s.FixAttemptsBlocked(), s.FixAttempts)
	}
	failAttempt(w, "j3", 3)
	s := snapshotOf(w, "f1")
	if !s.FixAttemptsBlocked() || !s.FixBlockedAt.Equal(attemptAt(3)) || len(s.FixAttempts) != 3 {
		t.Fatalf("after three failures: blocked=%v at=%v attempts=%+v", s.FixAttemptsBlocked(), s.FixBlockedAt, s.FixAttempts)
	}
	if a := s.FixAttempts[2]; a.JobID != "j3" || a.Verdict != "failed" || a.Reason != "r-j3" {
		t.Errorf("last attempt = %+v", a)
	}
}

// A blocked finding takes no claim, so no new fix job starts on it.
func TestFixAttempts_ABlockedFindingTakesNoClaim(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	for i, j := range []string{"j1", "j2", "j3"} {
		failAttempt(w, j, i+1)
	}
	Reduce(w, FixClaimed{ID: "f1", Claim: "run-9/fix", At: attemptAt(5)})
	if got := w.FixClaimOf("f1"); got != "" {
		t.Fatalf("a blocked finding took the claim %q", got)
	}
}

// A linked fix is a success. It ends the count, and the finding takes jobs again.
func TestFixAttempts_ASuccessResetsTheCount(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	failAttempt(w, "j1", 1)
	failAttempt(w, "j2", 2)
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: attemptAt(3)})
	if s := snapshotOf(w, "f1"); len(s.FixAttempts) != 0 || s.FixAttemptsBlocked() {
		t.Fatalf("a linked fix left attempts: %+v", s.FixAttempts)
	}
	// The next failures count from zero. Two more do not block.
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusOpen, At: attemptAt(4)})
	failAttempt(w, "j3", 5)
	failAttempt(w, "j4", 6)
	if s := snapshotOf(w, "f1"); s.FixAttemptsBlocked() || len(s.FixAttempts) != 2 {
		t.Fatalf("blocked=%v attempts=%+v", s.FixAttemptsBlocked(), s.FixAttempts)
	}
}

// An attempt on a finding that is not open changes nothing.
func TestFixAttempts_OnlyAnOpenFindingTakesAnAttempt(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	Reduce(w, FixClaimed{ID: "f1", Claim: "c", At: attemptAt(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: attemptAt(1)})
	failAttempt(w, "j1", 2)
	if s := snapshotOf(w, "f1"); len(s.FixAttempts) != 0 {
		t.Fatalf("a fixing finding took an attempt: %+v", s.FixAttempts)
	}
}

// A finding holds one close wait for each job and merge request. A second failed
// job never replaces the wait of the first, and each wait ends on its own. The
// wait starts at the first failed close and keeps the first comment.
func TestFixCloseWait_OneForEachJobAndMergeRequest(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	wait := func(job, mr, reason, comment string, h int) FixCloseWaiting {
		return FixCloseWaiting{
			ID: "f1", JobID: job, MergeRequest: mr, Waiting: true, Reason: reason, Comment: comment, At: attemptAt(h),
		}
	}
	Reduce(w, wait("j1", "g/p!7", "down", "first comment", 1))
	Reduce(w, wait("j2", "g/p!8", "refused", "second comment", 2))
	Reduce(w, wait("j1", "g/p!7", "still down", "changed text", 3))
	waits := snapshotOf(w, "f1").FixCloseWaits
	if len(waits) != 2 {
		t.Fatalf("waits = %+v, want two", waits)
	}
	c := waits[0]
	if c.JobID != "j1" || c.Reason != "still down" || c.Comment != "first comment" || !c.Since.Equal(attemptAt(1)) {
		t.Fatalf("first wait = %+v", c)
	}
	if c := waits[1]; c.JobID != "j2" || c.MergeRequest != "g/p!8" || c.Comment != "second comment" {
		t.Fatalf("second wait = %+v", c)
	}
	// The end of an unknown pair changes nothing. Each wait ends on its own.
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "other", At: attemptAt(4)})
	if len(snapshotOf(w, "f1").FixCloseWaits) != 2 {
		t.Fatal("the end of another pair ended a wait")
	}
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "g/p!7", At: attemptAt(5)})
	if got := snapshotOf(w, "f1").FixCloseWaits; len(got) != 1 || got[0].JobID != "j2" {
		t.Fatalf("after the end of the first: %+v", got)
	}
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "j2", MergeRequest: "g/p!8", At: attemptAt(6)})
	if len(snapshotOf(w, "f1").FixCloseWaits) != 0 {
		t.Fatal("the second wait did not end")
	}
}

// The action merge_request_closed of a person ends every close wait and leaves
// the failed attempts. The action retry leaves the close waits.
func TestFixCloseWait_APersonEndsTheWaits(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	failAttempt(w, "j1", 1)
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "a", Waiting: true, At: attemptAt(1)})
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "j2", MergeRequest: "b", Waiting: true, At: attemptAt(1)})
	Reduce(w, FixAttemptsResolved{ID: "f1", Action: FixActionRetry, UserID: "u", At: attemptAt(2)})
	if s := snapshotOf(w, "f1"); len(s.FixCloseWaits) != 2 || len(s.FixAttempts) != 0 {
		t.Fatalf("after retry: %+v", s.FixFacts)
	}
	Reduce(w, FixAttemptsResolved{
		ID: "f1", Action: FixActionMergeRequestClosed, UserID: "u", At: attemptAt(3),
		CloseWaits: []FixCloseWaitKey{{JobID: "j1", MergeRequest: "a"}},
	})
	if got := snapshotOf(w, "f1").FixCloseWaits; len(got) != 1 || got[0].JobID != "j2" {
		t.Fatalf("waits = %+v, want only the wait that the event does not name", got)
	}
}

// The events survive the codec.
func TestFixAttemptEvents_SurviveTheCodec(t *testing.T) {
	for _, ev := range []Event{
		FixAttemptFailed{ID: "f1", JobID: "j1", Verdict: "failed", Reason: "r", MissionID: "m1", At: attemptAt(1)},
		FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "g/p!7", Waiting: true, MissionID: "m1", At: attemptAt(1)},
		FixAttemptsResolved{ID: "f1", Action: FixActionRetry, UserID: "u1", MissionID: "m1", At: attemptAt(1)},
	} {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode %s: %v", ev.Kind(), err)
		}
		got, err := DecodeEvent(data)
		if err != nil || got.Kind() != ev.Kind() {
			t.Fatalf("decode %s: %v, %v", ev.Kind(), got, err)
		}
		if f, _ := EventSubject(got); f != "f1" {
			t.Errorf("%s: finding = %q", ev.Kind(), f)
		}
		if !EventTime(got).Equal(attemptAt(1)) {
			t.Errorf("%s: time = %v", ev.Kind(), EventTime(got))
		}
	}
}

// A retry clears the failed attempts and the block, so the finding takes a claim
// again. Another action changes nothing.
func TestFixAttempts_ARetryClearsTheBlock(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	for i, j := range []string{"j1", "j2", "j3"} {
		failAttempt(w, j, i+1)
	}
	Reduce(w, FixAttemptsResolved{ID: "f1", Action: "dismiss", UserID: "u1", At: attemptAt(4)})
	if !snapshotOf(w, "f1").FixAttemptsBlocked() {
		t.Fatal("an unknown action ended the block")
	}
	Reduce(w, FixAttemptsResolved{ID: "f1", Action: FixActionRetry, UserID: "u1", At: attemptAt(5)})
	if s := snapshotOf(w, "f1"); s.FixAttemptsBlocked() || len(s.FixAttempts) != 0 {
		t.Fatalf("after the retry: %+v", s.FixFacts)
	}
	Reduce(w, FixClaimed{ID: "f1", Claim: "run-9/fix", At: attemptAt(6)})
	if got := w.FixClaimOf("f1"); got != "run-9/fix" {
		t.Fatalf("claim after the retry = %q", got)
	}
}
