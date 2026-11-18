// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
)

func TestWorkStateFromTask_MapsEveryTaskState(t *testing.T) {
	cases := []struct {
		in   a2a.TaskState
		want WorkState
	}{
		{a2a.TaskStateSubmitted, WorkPending},
		{a2a.TaskStateWorking, WorkRunning},
		{a2a.TaskStateCompleted, WorkDone},
		{a2a.TaskStateCanceled, WorkCanceled},
		{a2a.TaskStateInputRequired, WorkInputRequired},
		{a2a.TaskStateAuthRequired, WorkInputRequired},
		{a2a.TaskStateFailed, WorkFailed},
		{a2a.TaskStateRejected, WorkFailed},
		{a2a.TaskStateUnspecified, WorkFailed},
	}
	for _, tc := range cases {
		if got := WorkStateFromTask(tc.in); got != tc.want {
			t.Errorf("WorkStateFromTask(%s) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestTaskStateFromWork_RoundTripsTheNewStates(t *testing.T) {
	if got := TaskStateFromWork(WorkCanceled); got != a2a.TaskStateCanceled {
		t.Errorf("canceled maps to %s", got)
	}
	if got := TaskStateFromWork(WorkInputRequired); got != a2a.TaskStateInputRequired {
		t.Errorf("input_required maps to %s", got)
	}
	for _, s := range []WorkState{WorkCanceled, WorkInputRequired} {
		if got := WorkStateFromTask(TaskStateFromWork(s)); got != s {
			t.Errorf("state %s did not round trip, got %s", s, got)
		}
	}
}

func TestWorkCompleted_CanceledIsTerminal(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, WorkDispatched{ID: "w1", ItemKind: "agent", Target: "a"})
	Reduce(w, WorkCompleted{ID: "w1", State: WorkCanceled, Err: "stopped by the caller"})
	got := w.WorkSnapshot()[0]
	if got.State != WorkCanceled || got.Err != "stopped by the caller" || got.CompletedSeq != 1 {
		t.Fatalf("got %+v", got)
	}
	// A late result must not change a canceled item.
	Reduce(w, WorkCompleted{ID: "w1", Result: "late"})
	if got := w.WorkSnapshot()[0]; got.State != WorkCanceled || got.Result != "" {
		t.Fatalf("late completion changed a canceled item: %+v", got)
	}
}

func TestWorkCompleted_InputRequiredIsNotTerminal(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, WorkDispatched{ID: "w1", ItemKind: "agent", Target: "a"})
	Reduce(w, WorkCompleted{ID: "w1", State: WorkInputRequired, Err: "which host?"})
	got := w.WorkSnapshot()[0]
	if got.State != WorkInputRequired || got.Err != "which host?" || got.CompletedSeq != 0 {
		t.Fatalf("got %+v", got)
	}
	Reduce(w, WorkCompleted{ID: "w1", Result: "answer"})
	if got := w.WorkSnapshot()[0]; got.State != WorkDone || got.Result != "answer" {
		t.Fatalf("want done after the input arrived, got %+v", got)
	}
}

func TestMissionCompletion_WaitsForInputAndFailsOnCancel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		state   WorkState
		wantEnd bool
		outcome MissionStatus
	}{
		{"input_required keeps the mission open", WorkInputRequired, false, ""},
		{"canceled ends the mission as failed", WorkCanceled, true, MissionFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := liveMission(t, time.Hour)
			for _, ev := range SchedulerSystem(w) {
				Reduce(w, ev)
			}
			Reduce(w, WorkCompleted{ID: WorkID("m1", "watch"), State: tc.state, Err: "x"})
			events := MissionCompletionSystem(w)
			if !tc.wantEnd {
				if len(events) != 0 {
					t.Fatalf("want no event, got %+v", events)
				}
				return
			}
			if len(events) != 1 {
				t.Fatalf("want one event, got %+v", events)
			}
			if done, ok := events[0].(MissionDone); !ok || done.Outcome != tc.outcome {
				t.Fatalf("got %+v", events[0])
			}
		})
	}
}

func TestWorkStates_SurviveSnapshotAndCodec(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, WorkDispatched{ID: "c", ItemKind: "agent", Target: "a"})
	Reduce(w, WorkDispatched{ID: "i", ItemKind: "agent", Target: "a"})
	Reduce(w, WorkCompleted{ID: "c", State: WorkCanceled, Err: "stop"})
	Reduce(w, WorkCompleted{ID: "i", State: WorkInputRequired, Err: "ask"})

	restored, err := RestoreWorld(SnapshotWorld(w, "0"), "t")
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]WorkSnapshot{}
	for _, wi := range restored.WorkSnapshot() {
		states[wi.ID] = wi
	}
	if states["c"].State != WorkCanceled || states["c"].Err != "stop" {
		t.Errorf("canceled item restored as %+v", states["c"])
	}
	if states["i"].State != WorkInputRequired || states["i"].Err != "ask" {
		t.Errorf("input_required item restored as %+v", states["i"])
	}

	raw, err := EncodeEvent(WorkCompleted{ID: "c", State: WorkCanceled, Err: "stop"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := DecodeEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if wc, ok := ev.(WorkCompleted); !ok || wc.State != WorkCanceled || wc.Err != "stop" {
		t.Fatalf("decoded %+v", ev)
	}
}

func TestWorkParentID_SurvivesSnapshotAndReplay(t *testing.T) {
	w := NewWorld("t")
	Reduce(w, WorkDispatched{ID: "parent", ItemKind: "agent", Target: "a"})
	Reduce(w, WorkDispatched{ID: "child", ItemKind: "agent", Target: "b", ParentID: "parent"})
	got := map[string]string{}
	for _, wi := range w.WorkSnapshot() {
		got[wi.ID] = wi.ParentID
	}
	if got["child"] != "parent" || got["parent"] != "" {
		t.Fatalf("parents = %v", got)
	}
	restored, err := RestoreWorld(SnapshotWorld(w, "0"), "t")
	if err != nil {
		t.Fatal(err)
	}
	for _, wi := range restored.WorkSnapshot() {
		if wi.ID == "child" && wi.ParentID != "parent" {
			t.Fatalf("restored parent = %q", wi.ParentID)
		}
	}
}
