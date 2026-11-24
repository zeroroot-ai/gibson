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

// The close wait starts at the first failed close, names the merge request and
// ends only for the job that set it.
func TestFixCloseWait_SetsAndEnds(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", At: attemptAt(0)})
	wait := func(reason string, h int) FixCloseWaiting {
		return FixCloseWaiting{ID: "f1", JobID: "j1", MergeRequest: "g/p!7", Waiting: true, Reason: reason, At: attemptAt(h)}
	}
	Reduce(w, wait("down", 1))
	Reduce(w, wait("still down", 2))
	cw := snapshotOf(w, "f1").FixCloseWait
	if cw.JobID != "j1" || cw.MergeRequest != "g/p!7" || cw.Reason != "still down" || !cw.Since.Equal(attemptAt(1)) {
		t.Fatalf("wait = %+v", cw)
	}
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "other", At: attemptAt(3)})
	if snapshotOf(w, "f1").FixCloseWait.JobID != "j1" {
		t.Fatal("the end of another job ended the wait")
	}
	Reduce(w, FixCloseWaiting{ID: "f1", JobID: "j1", At: attemptAt(4)})
	if snapshotOf(w, "f1").FixCloseWait.JobID != "" {
		t.Fatal("the wait did not end")
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
