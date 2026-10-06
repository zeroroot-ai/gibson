// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// The snapshot of a node end is on the work item after WorkCompleted, and it
// survives a snapshot restore of the World (ADR-0170).
func TestWorkCompleted_KeepsTheCheckpointSnapshot(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "agent", Target: "recon", Checkpoint: true}}})
	Reduce(w, WorkDispatched{ID: WorkID("m1", "a"), MissionID: "m1", ItemKind: "agent", Target: "recon", Checkpoint: true})
	Reduce(w, WorkCompleted{ID: WorkID("m1", "a"), Result: "ok", Snapshot: "snap-1"})

	work := w.WorkSnapshot()
	if len(work) != 1 || work[0].Snapshot != "snap-1" || !work[0].Checkpoint {
		t.Fatalf("work = %+v", work)
	}
	restored, err := RestoreWorld(SnapshotWorld(w, "1"), "t1")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := restored.WorkSnapshot(); len(got) != 1 || got[0].Snapshot != "snap-1" {
		t.Fatalf("restored work = %+v", got)
	}
}

// The start node of a rewound mission starts from the snapshot of its
// checkpoint, and no other node does.
func TestMissionRewound_TheStartNodeGetsTheSnapshot(t *testing.T) {
	rec := &recordingDispatcher{}
	h := NewDispatchHandler(rec)
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.Subscribe(h.Tap)
	e.Submit(MissionRewound{MissionID: "m2", ParentMissionID: "m1", ParentCheckpointID: "exploit", StartSnapshot: "snap-1"})
	e.Submit(MissionProjected{ID: "m2", Nodes: []WorkNode{
		{ID: "exploit", Kind: "agent", Target: "zerocool"},
		{ID: "report", Kind: "agent", Target: "zerocool", DependsOn: []string{"exploit"}},
	}})
	e.Tick()
	h.Drain()

	if len(rec.reqs) != 1 || rec.reqs[0].WorkID != WorkID("m2", "exploit") || rec.reqs[0].FromSnapshot != "snap-1" {
		t.Fatalf("dispatches = %+v", rec.reqs)
	}
	for _, wi := range e.Work() {
		if wi.ID == WorkID("m2", "report") && wi.FromSnapshot != "" {
			t.Fatal("only the start node starts from the snapshot")
		}
	}
}

// The Timeline stores the events as JSON. The checkpoint fields survive the
// codec.
func TestCheckpointEvents_SurviveTheCodec(t *testing.T) {
	for _, ev := range []Event{
		WorkCompleted{ID: "m1/a", Result: "ok", Snapshot: "snap-1"},
		MissionRewound{MissionID: "m2", ParentMissionID: "m1", ParentCheckpointID: "a", StartSnapshot: "snap-1"},
		WorkDispatched{ID: "m1/a", MissionID: "m1", ItemKind: "agent", Checkpoint: true, FromSnapshot: "snap-0"},
	} {
		b, err := EncodeEvent(ev)
		if err != nil {
			t.Fatalf("encode %T: %v", ev, err)
		}
		back, err := DecodeEvent(b)
		if err != nil {
			t.Fatalf("decode %T: %v", ev, err)
		}
		if !reflect.DeepEqual(back, ev) {
			t.Fatalf("decoded = %+v, want %+v", back, ev)
		}
	}
}
