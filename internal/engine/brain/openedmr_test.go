// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"fmt"
	"testing"
)

func opened(run, mission, head string) MergeRequestOpened {
	return MergeRequestOpened{
		MergeRequest: "!7", URL: "https://forge.example/mr/7", JobID: "job-1", SourceBranch: "job/job-1",
		HeadSHA: head, RunID: run, MissionID: mission, MissionRunID: "run-1", At: at(1), Verified: true,
	}
}

func TestMergeRequestOpened_FoldsUnderTheReferenceAndTheURL(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, opened("agent-1", "m-1", "aaaa"))
	for _, key := range []string{"!7", "https://forge.example/mr/7"} {
		r, ok := w.OpenedMergeRequest(key, "job-1")
		if !ok || r.HeadSHA != "aaaa" || r.SourceBranch != "job/job-1" || r.MissionRunID != "run-1" {
			t.Errorf("key %q: %+v, %v", key, r, ok)
		}
	}
	if got := w.OpenedMergeRequests(); len(got) != 1 {
		t.Errorf("records = %+v, want one", got)
	}
	Reduce(w, MergeRequestOpened{MergeRequest: "!8", SourceBranch: "b"}) // no head
	if _, ok := w.OpenedMergeRequest("!8", "job-1"); ok {
		t.Error("an event with no head was folded")
	}
}

// The key comes from the verified grant. Inside one job, the newest event replaces the
// record: a second turn of the job, in another member run, pushes another head and opens
// again, and the link must see that head.
func TestMergeRequestOpened_TheNewestEventOfTheJobReplacesTheRecord(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, opened("member-run-1", "bank-1", "aaaa"))
	Reduce(w, opened("member-run-2", "bank-1", "bbbb")) // a restart, or another member of the bank
	if r, _ := w.OpenedMergeRequest("!7", "job-1"); r.HeadSHA != "bbbb" || r.RunID != "member-run-2" {
		t.Errorf("record = %+v, want the head bbbb of the second turn", r)
	}
}

// A record with no verified job never binds. An event from before the daemon read the
// grant took its job from the name of the branch, and a snapshot from then holds such a
// record. Both are dropped.
func TestMergeRequestOpened_AnUnverifiedJobNeverBinds(t *testing.T) {
	w := NewWorld("t1")
	e := opened("agent-1", "m-1", "aaaa")
	e.Verified = false
	Reduce(w, e)
	if got := w.OpenedMergeRequests(); len(got) != 0 {
		t.Fatalf("an unverified event was kept: %+v", got)
	}

	// A snapshot of the old shape: one record with a branch-derived job and no mark.
	old := opened("agent-1", "m-1", "oldh")
	old.Verified = false
	w.openedMRs = map[string]OpenedMergeRequest{openedKey("!7", "job-1"): OpenedMergeRequest(old)}
	w.openedMROrder = []string{openedKey("!7", "job-1")}
	verified := opened("agent-2", "m-2", "newh")
	verified.MergeRequest, verified.URL = "!8", ""
	verified.Verified = true
	applyMergeRequestOpened(w, verified)

	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.OpenedMergeRequest("!7", "job-1"); ok {
		t.Error("a record with no verified job survived the restore")
	}
	if r, ok := restored.OpenedMergeRequest("!8", "job-1"); !ok || r.HeadSHA != "newh" || !r.Verified {
		t.Errorf("the verified record = %+v, %v, want it kept", r, ok)
	}
}

// One tenant that opens many merge requests evicts only the records of its own
// World, because each tenant has a World of its own.
func TestMergeRequestOpened_TheLimitIsPerWorld(t *testing.T) {
	acme, globex := NewWorld("acme"), NewWorld("globex")
	Reduce(acme, MergeRequestOpened{MergeRequest: "!acme", SourceBranch: "job/a", HeadSHA: "aaaa", RunID: "r", JobID: "job-1", At: at(1), Verified: true})
	for i := 0; i <= openedMergeRequestLimit; i++ {
		Reduce(globex, MergeRequestOpened{
			MergeRequest: fmt.Sprintf("!g%d", i), SourceBranch: "job/g", HeadSHA: "gggg", RunID: "r", JobID: "job-1", At: at(1), Verified: true,
		})
	}
	if _, ok := globex.OpenedMergeRequest("!g0", "job-1"); ok {
		t.Error("the oldest record stayed over the limit")
	}
	if _, ok := globex.OpenedMergeRequest(fmt.Sprintf("!g%d", openedMergeRequestLimit), "job-1"); !ok {
		t.Error("the newest record is gone")
	}
	if _, ok := acme.OpenedMergeRequest("!acme", "job-1"); !ok {
		t.Error("the flood of tenant globex evicted a record of tenant acme")
	}
}

func TestMergeRequestOpened_SurvivesASnapshotAndTheCodec(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, opened("agent-1", "m-1", "aaaa"))
	restored, err := RestoreWorld(SnapshotWorld(w, "seq-1"), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := restored.OpenedMergeRequest("!7", "job-1"); !ok || r.HeadSHA != "aaaa" || r.RunID != "agent-1" {
		t.Errorf("restored = %+v, %v", r, ok)
	}
	raw, err := EncodeEvent(opened("agent-1", "m-1", "aaaa"))
	if err != nil {
		t.Fatal(err)
	}
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	var got MergeRequestOpened
	switch v := ev.(type) {
	case MergeRequestOpened:
		got = v
	case *MergeRequestOpened:
		got = *v
	default:
		t.Fatalf("decoded %T", ev)
	}
	if got.HeadSHA != "aaaa" || got.MissionRunID != "run-1" {
		t.Errorf("decoded %+v", got)
	}
	if EventTime(opened("a", "m", "h")).IsZero() {
		t.Error("the event holds a time")
	}
}

func TestFixHeadMissing_FoldsAndIsClearedByAHead(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, FindingRaised{ID: "f1", CheckKind: "scan", CheckRef: "ref", At: at(0)})
	Reduce(w, FindingStatusChanged{ID: "f1", Status: FindingStatusFixing, MergeRequest: "mr-1", At: at(1)})

	Reduce(w, FixHeadMissing{ID: "f1", MergeRequest: "other", Reason: "x", At: at(2)})
	if f := findingByID(t, w, "f1"); f.FixHeadMissingReason != "" {
		t.Error("an event for another merge request was folded")
	}
	Reduce(w, FixHeadMissing{ID: "f1", MergeRequest: "mr-1", Reason: "no result of the open", At: at(2)})
	f := findingByID(t, w, "f1")
	if f.FixHeadMissingReason != "no result of the open" || !f.FixHeadMissingAt.Equal(at(2)) {
		t.Errorf("finding = %+v", f.FixFacts)
	}
	Reduce(w, FixHeadRecorded{ID: "f1", MergeRequest: "mr-1", HeadSHA: "aaaa", At: at(3)})
	if f := findingByID(t, w, "f1"); f.FixHeadMissingReason != "" || f.FixHeadSHA != "aaaa" {
		t.Errorf("a recorded head must clear the reason: %+v", f.FixFacts)
	}
	Reduce(w, FixHeadMissing{ID: "f1", MergeRequest: "mr-1", Reason: "late", At: at(4)})
	if f := findingByID(t, w, "f1"); f.FixHeadMissingReason != "" {
		t.Error("a finding that has a head keeps no missing reason")
	}
}

// The records are keyed by the merge request and the job. An open in a turn of another
// job has a record of its own: it neither replaces nor blocks the record of the job,
// even when it came first.
func TestMergeRequestOpened_AForeignOpenInAnotherJobNeitherBlocksNorReplaces(t *testing.T) {
	w := NewWorld("t1")
	foreign := opened("agent-x", "m-9", "ffff")
	foreign.JobID = "job-other"
	Reduce(w, foreign) // the foreign open comes first
	Reduce(w, opened("agent-1", "m-1", "aaaa"))

	if r, ok := w.OpenedMergeRequest("!7", "job-1"); !ok || r.HeadSHA != "aaaa" {
		t.Errorf("the record of the job = %+v, %v, want head aaaa", r, ok)
	}
	if r, ok := w.OpenedMergeRequest("!7", "job-other"); !ok || r.HeadSHA != "ffff" {
		t.Errorf("the foreign record = %+v, %v", r, ok)
	}
	if _, ok := w.OpenedMergeRequest("!7", "job-3"); ok {
		t.Error("a run that made no open has a record")
	}
}

// An event with no job is not kept, because no job can claim it.
func TestMergeRequestOpened_NoJobIsNotKept(t *testing.T) {
	w := NewWorld("t1")
	e := opened("agent-1", "m-1", "aaaa")
	e.JobID = ""
	Reduce(w, e)
	if got := w.OpenedMergeRequests(); len(got) != 0 {
		t.Errorf("records = %+v, want none", got)
	}
}
