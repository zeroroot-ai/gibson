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
		HeadSHA: head, RunID: run, MissionID: mission, MissionRunID: "run-1", At: at(1),
	}
}

func TestMergeRequestOpened_FoldsUnderTheReferenceAndTheURL(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, opened("agent-1", "m-1", "aaaa"))
	for _, key := range []string{"!7", "https://forge.example/mr/7"} {
		r, ok := w.OpenedMergeRequest(key, "run-1")
		if !ok || r.HeadSHA != "aaaa" || r.SourceBranch != "job/job-1" || r.MissionRunID != "run-1" {
			t.Errorf("key %q: %+v, %v", key, r, ok)
		}
	}
	if got := w.OpenedMergeRequests(); len(got) != 1 {
		t.Errorf("records = %+v, want one", got)
	}
	Reduce(w, MergeRequestOpened{MergeRequest: "!8", SourceBranch: "b"}) // no head
	if _, ok := w.OpenedMergeRequest("!8", "run-1"); ok {
		t.Error("an event with no head was folded")
	}
}

// Inside one mission run, a call of another agent run, or of another mission, cannot
// replace the head. The agent run of the first call can update it.
func TestMergeRequestOpened_AnotherRunCannotReplaceTheHead(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, opened("agent-1", "m-1", "aaaa"))
	Reduce(w, opened("agent-2", "m-1", "bbbb"))
	Reduce(w, opened("agent-1", "m-2", "cccc"))
	if r, _ := w.OpenedMergeRequest("!7", "run-1"); r.HeadSHA != "aaaa" {
		t.Errorf("head = %q, want aaaa: another run replaced it", r.HeadSHA)
	}
	Reduce(w, opened("agent-1", "m-1", "dddd"))
	if r, _ := w.OpenedMergeRequest("!7", "run-1"); r.HeadSHA != "dddd" {
		t.Errorf("head = %q, want dddd: the same run may update it", r.HeadSHA)
	}
}

// One tenant that opens many merge requests evicts only the records of its own
// World, because each tenant has a World of its own.
func TestMergeRequestOpened_TheLimitIsPerWorld(t *testing.T) {
	acme, globex := NewWorld("acme"), NewWorld("globex")
	Reduce(acme, MergeRequestOpened{MergeRequest: "!acme", SourceBranch: "job/a", HeadSHA: "aaaa", RunID: "r", MissionRunID: "run-1", At: at(1)})
	for i := 0; i <= openedMergeRequestLimit; i++ {
		Reduce(globex, MergeRequestOpened{
			MergeRequest: fmt.Sprintf("!g%d", i), SourceBranch: "job/g", HeadSHA: "gggg", RunID: "r", MissionRunID: "run-1", At: at(1),
		})
	}
	if _, ok := globex.OpenedMergeRequest("!g0", "run-1"); ok {
		t.Error("the oldest record stayed over the limit")
	}
	if _, ok := globex.OpenedMergeRequest(fmt.Sprintf("!g%d", openedMergeRequestLimit), "run-1"); !ok {
		t.Error("the newest record is gone")
	}
	if _, ok := acme.OpenedMergeRequest("!acme", "run-1"); !ok {
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
	if r, ok := restored.OpenedMergeRequest("!7", "run-1"); !ok || r.HeadSHA != "aaaa" || r.RunID != "agent-1" {
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

// The records are keyed by the merge request and the mission run. An open in another
// mission run has a record of its own: it neither replaces nor blocks the record of
// the job, even when it came first.
func TestMergeRequestOpened_AForeignOpenInAnotherRunNeitherBlocksNorReplaces(t *testing.T) {
	w := NewWorld("t1")
	foreign := opened("agent-x", "m-9", "ffff")
	foreign.MissionRunID = "run-other"
	Reduce(w, foreign) // the foreign open comes first
	Reduce(w, opened("agent-1", "m-1", "aaaa"))

	if r, ok := w.OpenedMergeRequest("!7", "run-1"); !ok || r.HeadSHA != "aaaa" {
		t.Errorf("the record of the job = %+v, %v, want head aaaa", r, ok)
	}
	if r, ok := w.OpenedMergeRequest("!7", "run-other"); !ok || r.HeadSHA != "ffff" {
		t.Errorf("the foreign record = %+v, %v", r, ok)
	}
	if _, ok := w.OpenedMergeRequest("!7", "run-3"); ok {
		t.Error("a run that made no open has a record")
	}
}

// An event with no mission run is not kept, because no job can claim it.
func TestMergeRequestOpened_NoMissionRunIsNotKept(t *testing.T) {
	w := NewWorld("t1")
	e := opened("agent-1", "m-1", "aaaa")
	e.MissionRunID = ""
	Reduce(w, e)
	if got := w.OpenedMergeRequests(); len(got) != 0 {
		t.Errorf("records = %+v, want none", got)
	}
}
