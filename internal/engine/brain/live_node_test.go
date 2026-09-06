// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
	"time"
)

// A live agent node runs for hours, so the mission that owns it must stay
// RUNNING for those hours and complete when — and only when — the node reports
// its result (gibson#1602). These tests pin that, and pin the node's declared
// timeout surviving every hop the brain owns.

func liveMission(t *testing.T, nodeTimeout time.Duration) *World {
	t.Helper()
	w := NewWorld("t1")
	Reduce(w, MissionProjected{
		ID: "m1",
		Nodes: []WorkNode{
			{ID: "watch", Kind: "agent", Target: "zerocool", Input: "watch the portal", Timeout: nodeTimeout},
		},
	})
	return w
}

func TestSchedulerCarriesTheNodeTimeoutToDispatch(t *testing.T) {
	// The dispatch effect-handler must not have to read the World back inside
	// the locked tick, so the bound rides on the event — the same reason
	// MissionID and Input do.
	w := liveMission(t, 8*time.Hour)

	events := SchedulerSystem(w)
	if len(events) != 1 {
		t.Fatalf("want one dispatch, got %d", len(events))
	}
	d, ok := events[0].(WorkDispatched)
	if !ok {
		t.Fatalf("want WorkDispatched, got %T", events[0])
	}
	if d.Timeout != 8*time.Hour {
		t.Fatalf("dispatched timeout = %s, want 8h", d.Timeout)
	}
}

func TestDispatchHandlerCarriesTheNodeTimeout(t *testing.T) {
	rec := &recordingDispatcher{}
	h := NewDispatchHandler(rec)
	h.Tap(WorkDispatched{ID: "m1/watch", MissionID: "m1", ItemKind: "agent", Target: "zerocool", Timeout: 8 * time.Hour})
	h.Drain()

	if len(rec.reqs) != 1 {
		t.Fatalf("want one request, got %d", len(rec.reqs))
	}
	if rec.reqs[0].Timeout != 8*time.Hour {
		t.Fatalf("request timeout = %s, want 8h", rec.reqs[0].Timeout)
	}
}

func TestALiveAgentNodeKeepsItsMissionRunning(t *testing.T) {
	// The always-on case: one agent node, dispatched, still working. Nothing may
	// complete the mission while its node is running.
	w := liveMission(t, 8*time.Hour)
	for _, ev := range SchedulerSystem(w) {
		Reduce(w, ev)
	}

	work := w.WorkSnapshot()
	if len(work) != 1 || work[0].State != WorkRunning {
		t.Fatalf("want the node running, got %+v", work)
	}
	if got := work[0].Timeout; got != 8*time.Hour {
		t.Fatalf("running node's timeout = %s, want 8h preserved on the item", got)
	}

	if events := MissionCompletionSystem(w); len(events) != 0 {
		t.Fatalf("a mission whose only node is still running must not complete, got %+v", events)
	}
	if m := w.MissionSnapshot(); len(m) != 1 || m[0].Status != MissionRunning {
		t.Fatalf("mission status = %+v, want running", m)
	}
}

func TestTheMissionCompletesWhenTheLiveNodeReportsItsResult(t *testing.T) {
	w := liveMission(t, 8*time.Hour)
	for _, ev := range SchedulerSystem(w) {
		Reduce(w, ev)
	}

	// SubmitResult lands as WorkCompleted for the node.
	Reduce(w, WorkCompleted{ID: WorkID("m1", "watch"), Result: `{"status":"success"}`})

	events := MissionCompletionSystem(w)
	if len(events) != 1 {
		t.Fatalf("want the mission to complete, got %+v", events)
	}
	done, ok := events[0].(MissionDone)
	if !ok || done.Outcome != MissionCompleted {
		t.Fatalf("want MissionDone/completed, got %+v", events[0])
	}
}

func TestARestoredWorldKeepsTheNodeTimeout(t *testing.T) {
	// A snapshot restore re-creates work items through WorkDispatched. Dropping
	// the bound there would silently re-cap a live session at the default after
	// a daemon restart.
	w := liveMission(t, 8*time.Hour)
	for _, ev := range SchedulerSystem(w) {
		Reduce(w, ev)
	}

	restored := NewWorld("t1")
	for _, wi := range w.WorkSnapshot() {
		Reduce(restored, WorkDispatched{
			ID:        wi.ID,
			MissionID: wi.MissionID,
			ItemKind:  wi.Kind,
			Target:    wi.Target,
			Input:     wi.Input,
			Timeout:   wi.Timeout,
		})
	}
	got := restored.WorkSnapshot()
	if len(got) != 1 || got[0].Timeout != 8*time.Hour {
		t.Fatalf("restored timeout = %+v, want 8h", got)
	}
}
