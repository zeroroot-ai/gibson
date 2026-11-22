// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"
)

// The first claim of an open Finding wins. A second claim, a release by
// another job and a claim of a Finding in another status change nothing. The
// holder's release ends the claim, and a reopened Finding has no claim.
func TestFixClaim_TheFirstClaimWins(t *testing.T) {
	w := NewWorld("t1")
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	Reduce(w, FindingRaised{ID: "f1", At: at})
	Reduce(w, FixClaimed{ID: "f1", Claim: "run-1/fix", At: at})
	Reduce(w, FixClaimed{ID: "f1", Claim: "run-2/fix", At: at})
	if got := w.FixClaimOf("f1"); got != "run-1/fix" {
		t.Fatalf("holder = %q, want run-1/fix", got)
	}
	Reduce(w, FixClaimReleased{ID: "f1", Claim: "run-2/fix", At: at})
	if got := w.FixClaimOf("f1"); got != "run-1/fix" {
		t.Fatalf("a release by another job moved the claim to %q", got)
	}
	Reduce(w, FixClaimReleased{ID: "f1", Claim: "run-1/fix", At: at})
	if got := w.FixClaimOf("f1"); got != "" {
		t.Fatalf("holder after the release = %q, want none", got)
	}
	Reduce(w, FixClaimed{ID: "", Claim: "x", At: at})
	Reduce(w, FixClaimed{ID: "f1", Claim: "", At: at})
	if got := w.FixClaimOf("f1"); got != "" {
		t.Fatalf("an empty claim set %q", got)
	}

	Reduce(w, FixClaimed{ID: "f1", Claim: "run-3/fix", At: at})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at})
	Reduce(w, FixClaimed{ID: "f1", Claim: "run-4/fix", At: at})
	if got := w.FixClaimOf("f1"); got != "run-3/fix" {
		t.Fatalf("holder of a fixing finding = %q, want run-3/fix", got)
	}
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusOpen, At: at})
	if got := w.FixClaimOf("f1"); got != "" {
		t.Fatalf("a reopened finding keeps the claim %q", got)
	}
	if got := w.FixClaimOf("no-such-finding"); got != "" {
		t.Fatalf("an unknown finding has the claim %q", got)
	}
}

// The new events of the fix loop survive the codec and keep their kind, and a
// mission slice holds them only with their mission.
func TestFixLoopEvents_SurviveTheCodecAndTheMissionSlice(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	for _, ev := range []Event{
		FixClaimed{ID: "f1", Claim: "c", MissionID: "m1", At: at},
		FixClaimReleased{ID: "f1", Claim: "c", MissionID: "m1", At: at},
		FixLinkRefused{ID: "f1", MergeRequest: "mr-1", JobID: "j1", Reason: "r", MissionID: "m1", At: at},
		FixLinkPending{ID: "f1", MergeRequest: "mr-1", JobID: "j1", Reason: "r", MissionID: "m1", At: at},
		RevertRequested{MergeRequest: "mr-1", RevertMergeRequest: "mr-2", MissionID: "m1", At: at},
	} {
		data, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode %s: %v", ev.Kind(), err)
		}
		got, err := DecodeEvent(data)
		if err != nil || got.Kind() != ev.Kind() {
			t.Fatalf("decode %s: %v, %v", ev.Kind(), got, err)
		}
		if f, _ := EventSubject(got); ev.Kind() != "fix.revert_requested" && f != "f1" {
			t.Errorf("%s: finding = %q", ev.Kind(), f)
		}
		if !EventTime(got).Equal(at) {
			t.Errorf("%s: time = %v", ev.Kind(), EventTime(got))
		}
	}
}

// A revert request is recorded once on each Finding of the merge request and
// takes the revert merge request that the first request did not name.
func TestRevertRequested_RecordsTheFirstRequest(t *testing.T) {
	w := NewWorld("t1")
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	Reduce(w, FindingRaised{ID: "f1", At: at})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", MissionID: "fix-1", At: at})
	Reduce(w, RevertRequested{MergeRequest: "mr-1", At: at})
	Reduce(w, RevertRequested{MergeRequest: "mr-1", RevertMergeRequest: "mr-2", At: at.Add(time.Minute)})
	Reduce(w, RevertRequested{MergeRequest: "", At: at})
	f := w.FindingSnapshot()[0]
	if !f.RevertRequestedAt.Equal(at) || f.RevertMergeRequest != "mr-2" || f.FixMissionID != "fix-1" {
		t.Fatalf("finding = %+v", f.FixFacts)
	}
}

// Pointer events, as the codec decodes them, name their subject too.
func TestEventSubject_ReadsPointerEvents(t *testing.T) {
	cases := map[string]Event{
		"mr-a": &HealthObserved{MergeRequest: "mr-a"},
		"mr-b": &HealthUnavailable{MergeRequest: "mr-b"},
		"mr-c": &MergeRequestQueued{MergeRequest: "mr-c"},
		"mr-d": &MergeGranted{MergeRequest: "mr-d"},
		"mr-e": &FixReverted{MergeRequest: "mr-e"},
		"mr-f": &RevertRequested{MergeRequest: "mr-f"},
		"mr-g": HealthObserved{MergeRequest: "mr-g"},
		"mr-h": HealthUnavailable{MergeRequest: "mr-h"},
		"mr-i": MergeRequestQueued{MergeRequest: "mr-i"},
		"mr-j": MergeGranted{MergeRequest: "mr-j"},
	}
	for want, ev := range cases {
		if f, mr := EventSubject(ev); f != "" || mr != want {
			t.Errorf("%T: subject = %q, %q, want merge request %q", ev, f, mr, want)
		}
	}
	for _, ev := range []Event{&FindingPrioritized{ID: "f"}, FindingPrioritized{ID: "f"}, &FixClaimed{ID: "f"}, &FixClaimReleased{ID: "f"}} {
		if f, _ := EventSubject(ev); f != "f" {
			t.Errorf("%T: finding = %q", ev, f)
		}
	}
	if f, mr := EventSubject(MissionDone{ID: "m"}); f != "" || mr != "" {
		t.Errorf("a mission event names %q, %q", f, mr)
	}
	var nilEv *HealthObserved
	if !EventTime(nilEv).IsZero() {
		t.Error("a nil event has a time")
	}
}

// A revert that waits for its pipeline is wait time until the revert merges,
// and a revert that never merges runs to the end of the window.
func TestExposureWindows_ARevertThatWaitsIsWaitTime(t *testing.T) {
	at := func(h int) time.Time { return time.Date(2026, 11, 20, h, 0, 0, 0, time.UTC) }
	events := []Event{
		FindingRaised{ID: "f1", At: at(0)},
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)},
		RevertRequested{MergeRequest: "mr-1", At: at(2)},
		RevertRequested{MergeRequest: "mr-1", At: at(3)}, // the first request starts the wait
		FixReverted{MergeRequest: "mr-1", At: at(4)},
		FindingRaised{ID: "f2", At: at(0)},
		FindingStatusChanged{ID: "f2", Status: FindingStatusFixing, MergeRequest: "mr-2", At: at(1)},
		RevertRequested{MergeRequest: "mr-2", At: at(5)},
	}
	wins := ExposureWindows(events, at(6))
	if len(wins) != 2 {
		t.Fatalf("windows = %+v", wins)
	}
	if wins[0].Wait != 2*time.Hour {
		t.Errorf("f1 wait = %v, want 2h", wins[0].Wait)
	}
	if wins[1].Wait != time.Hour {
		t.Errorf("f2 wait = %v, want 1h", wins[1].Wait)
	}
}

// A replay of the mission of a fix holds each event of the fix loop that
// names the mission, and no event of another mission (gibson#1465).
func TestMissionSlice_HoldsTheFixLoopOfTheMission(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	mine := []Event{
		FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		DeployObserved{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		HealthObserved{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		HealthUnavailable{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		RevertRequested{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		FixClaimed{ID: "f1", Claim: "c", MissionID: "fix-1", At: at},
		FixClaimReleased{ID: "f1", Claim: "c", MissionID: "fix-1", At: at},
		FixReverted{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		CheckRerun{ID: "f1", MissionID: "fix-1", EvidenceAt: at},
		MergeRequestQueued{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		MergeGranted{MergeRequest: "mr-1", MissionID: "fix-1", At: at},
		FindingPrioritized{ID: "f1", MissionID: "fix-1"},
		MergeRequestObserved{Key: "mr-1", MissionID: "fix-1", At: at},
	}
	others := []Event{
		FixReverted{MergeRequest: "mr-2", MissionID: "fix-2", At: at},
		RevertRequested{MergeRequest: "mr-2", At: at},
	}
	got := MissionSlice(append(append([]Event(nil), mine...), others...), "fix-1")
	if len(got) != len(mine) {
		t.Fatalf("slice holds %d events, want %d: %+v", len(got), len(mine), got)
	}
}

// The claim keeps its time, so the graph link can check that a merge request
// is newer than the claim (review B1). A release forgets the time.
func TestFixClaim_KeepsTheTimeOfTheClaim(t *testing.T) {
	w := NewWorld("t1")
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	Reduce(w, FindingRaised{ID: "f1", At: at})
	Reduce(w, FixClaimed{ID: "f1", Claim: "run-1/fix", At: at.Add(time.Minute)})
	if got := w.FindingSnapshot()[0].FixClaimedAt; !got.Equal(at.Add(time.Minute)) {
		t.Fatalf("claimed at = %v", got)
	}
	Reduce(w, FixClaimReleased{ID: "f1", Claim: "run-1/fix", At: at})
	if got := w.FindingSnapshot()[0].FixClaimedAt; !got.IsZero() {
		t.Fatalf("claimed at after the release = %v", got)
	}
}

// A claim ends with its job, never for its age: a job node has no time limit
// (review r11). A restart ends each claim of an open Finding, because the job
// node of the claim ran in the daemon that stopped (review M3).
func TestFixClaim_OnlyARestartEndsAClaimWithNoJob(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	w := NewWorld("t1")
	w.clock = func() time.Time { return at.Add(30 * 24 * time.Hour) }
	Reduce(w, FindingRaised{ID: "old", At: at})
	Reduce(w, FixClaimed{ID: "old", Claim: "run-1/fix", At: at})
	for _, sys := range ExecutorSystems() {
		for _, ev := range sys(w) {
			if _, ok := ev.(FixClaimExpired); ok {
				t.Fatalf("a system ended a claim for its age: %+v", ev)
			}
		}
	}
	for _, ev := range ResumeReleaseFixClaims(w) {
		Reduce(w, ev)
	}
	if w.FixClaimOf("old") != "" {
		t.Fatal("a restart kept the claim of a job that is gone")
	}
}

// A link that waits for the Git host leaves a FixLinkWait on the finding. A
// restart keeps the claim of that finding, and a refusal ends the wait
// (gibson#1581).
func TestFixLinkPending_TheWaitKeepsTheClaimAcrossAResume(t *testing.T) {
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	events := []Event{
		FindingRaised{ID: "f1", Title: "t", Severity: "high", ScopeID: "s", At: at},
		FindingRaised{ID: "f2", Title: "t", Severity: "high", ScopeID: "s", At: at},
		FixClaimed{ID: "f1", Claim: "run-1/fix", MissionID: "run-1", At: at},
		FixClaimed{ID: "f2", Claim: "run-2/fix", MissionID: "run-2", At: at},
		FixLinkPending{ID: "f1", MergeRequest: "!7", JobID: "j1", Reason: "down", MissionID: "run-1", NodeID: "fix",
			URL: "https://git/mr/7", Ref: "!7", Countermeasure: "D3-X", At: at},
	}
	tl := &Timeline{}
	for _, ev := range events {
		if _, ok := ev.(FixLinkPending); ok {
			data, err := EncodeEvent(ev)
			if err != nil {
				t.Fatal(err)
			}
			ev, err = DecodeEvent(data) // a replay reads the decoded event
			if err != nil {
				t.Fatal(err)
			}
		}
		tl.Append(ev)
	}
	w := Replay("acme", tl)
	var f1 FindingSnapshot
	for _, f := range w.FindingSnapshot() {
		if f.ID == "f1" {
			f1 = f
		}
	}
	want := FixLinkWait{JobID: "j1", MissionRunID: "run-1", NodeID: "fix", MergeRequest: "!7",
		URL: "https://git/mr/7", Ref: "!7", Countermeasure: "D3-X", Since: at}
	if f1.FixLinkWait != want {
		t.Fatalf("wait = %+v, want %+v", f1.FixLinkWait, want)
	}

	// The resume ends the claim of f2 and keeps the claim of f1.
	var ended []string
	for _, ev := range ResumeReleaseFixClaims(w) {
		ended = append(ended, ev.(FixClaimExpired).ID)
	}
	if len(ended) != 1 || ended[0] != "f2" {
		t.Fatalf("the resume ended the claims of %v, want only f2", ended)
	}

	// The refusal ends the wait, and the claim release does too.
	Reduce(w, FixLinkRefused{ID: "f1", MergeRequest: "!7", JobID: "j1", Reason: "r", MissionID: "run-1", At: at})
	for _, f := range w.FindingSnapshot() {
		if f.FixLinkWait.JobID != "" {
			t.Fatalf("a refusal left the wait of %s: %+v", f.ID, f.FixLinkWait)
		}
	}
}
