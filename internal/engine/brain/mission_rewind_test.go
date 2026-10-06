// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"encoding/json"
	"testing"
)

// A replay of the Timeline gives the same parent. The parent is a Timeline
// event, so the World rebuilds it from the events alone.
func TestMissionRewound_AReplayRebuildsTheParent(t *testing.T) {
	tl := &Timeline{}
	tl.Append(MissionProjected{ID: "run-1", Nodes: []WorkNode{{ID: "scan"}}})
	tl.Append(MissionRewound{MissionID: "run-2", ParentMissionID: "run-1", ParentCheckpointID: "scan"})

	w := Replay("t", tl)
	got, ok := w.MissionRewind("run-2")
	if !ok {
		t.Fatal("the replayed World has no parent for run-2")
	}
	want := MissionRewind{MissionID: "run-2", ParentMissionID: "run-1", ParentCheckpointID: "scan"}
	if got != want {
		t.Fatalf("parent = %+v, want %+v", got, want)
	}
	if _, ok := w.MissionRewind("run-1"); ok {
		t.Fatal("run-1 was not rewound, but it has a parent")
	}
}

// The parent is a fact about the start of the mission. The first event wins.
func TestMissionRewound_TheFirstEventWins(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionRewound{MissionID: "run-2", ParentMissionID: "run-1", ParentCheckpointID: "a"})
	Reduce(w, MissionRewound{MissionID: "run-2", ParentMissionID: "run-9", ParentCheckpointID: "b"})
	Reduce(w, MissionRewound{ParentMissionID: "run-1"})

	got, _ := w.MissionRewind("run-2")
	if got.ParentMissionID != "run-1" || got.ParentCheckpointID != "a" {
		t.Fatalf("parent = %+v, want the first event", got)
	}
	if n := len(w.MissionRewindSnapshot()); n != 1 {
		t.Fatalf("snapshot holds %d parents, want 1", n)
	}
}

// The parent stays after a snapshot and a restore, so a trim of the Timeline
// does not lose it.
func TestMissionRewound_SurvivesASnapshot(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, MissionRewound{MissionID: "run-2", ParentMissionID: "run-1", ParentCheckpointID: "scan"})

	restored, err := RestoreWorld(SnapshotWorld(w, "7-0"), "t")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, ok := restored.MissionRewind("run-2")
	if !ok || got.ParentMissionID != "run-1" || got.ParentCheckpointID != "scan" {
		t.Fatalf("restored parent = %+v (ok=%v)", got, ok)
	}
}

// The event goes through the durable codec without loss.
func TestMissionRewound_CodecRoundTrip(t *testing.T) {
	in := MissionRewound{MissionID: "run-2", ParentMissionID: "run-1", ParentCheckpointID: "scan"}
	b, err := EncodeEvent(in)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !json.Valid(b) {
		t.Fatalf("encoded event is not JSON: %s", b)
	}
	out, err := DecodeEvent(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out != in {
		t.Fatalf("round trip = %#v, want %#v", out, in)
	}
}

// The event belongs to the slice of the new mission, so the Scroller of that
// mission shows where it came from.
func TestMissionRewound_IsInTheSliceOfTheNewMission(t *testing.T) {
	evs := []Event{
		MissionProjected{ID: "run-1", Nodes: []WorkNode{{ID: "scan"}}},
		MissionRewound{MissionID: "run-2", ParentMissionID: "run-1", ParentCheckpointID: "scan"},
	}
	if got := MissionSlice(evs, "run-2"); len(got) != 1 {
		t.Fatalf("slice of run-2 has %d events, want 1", len(got))
	}
	if got := MissionSlice(evs, "run-1"); len(got) != 1 {
		t.Fatalf("slice of run-1 has %d events, want only its projection", len(got))
	}
}
