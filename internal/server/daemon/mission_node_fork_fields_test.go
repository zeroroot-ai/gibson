// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	missionpb "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
)

// The fork fields of a mission node (ADR-0169, gibson#802) must reach the
// agent.Task that the harness launches: StartsFrom names the earlier node
// whose parked sandbox the node forks, and Forkable marks a node that a later
// node names. These tests follow the fields from the projection to the
// dispatch request, through a snapshot restore, and into the agent task.

// forkDef is a mission of three agent nodes. "build" runs first. "probe"
// starts from "build", so "build" is forkable. "report" names no node and no
// node names it.
func forkDef() *missionpb.MissionDefinition {
	probe := agentNode("prober", "build")
	probe.StartsFrom = "build"
	return &missionpb.MissionDefinition{
		Id: "m1",
		Nodes: map[string]*missionpb.MissionNode{
			"build":  agentNode("builder"),
			"probe":  probe,
			"report": agentNode("reporter"),
		},
	}
}

// forkFields is the pair of fork fields that one stage carries.
type forkFields struct {
	StartsFrom string
	Forkable   bool
}

var wantForkFields = map[string]forkFields{
	"build":  {Forkable: true},
	"probe":  {StartsFrom: "build"},
	"report": {},
}

// checkForkFields compares the fork fields of each node with wantForkFields.
// The "report" entry proves that a node with no starts_from and no later
// reference gets the zero values.
func checkForkFields(t *testing.T, stage string, got map[string]forkFields) {
	t.Helper()
	for id, want := range wantForkFields {
		g, ok := got[id]
		if !ok {
			t.Errorf("%s: node %q is missing", stage, id)
			continue
		}
		if g != want {
			t.Errorf("%s: node %q fork fields = %+v, want %+v", stage, id, g, want)
		}
	}
}

func projectForkDef(t *testing.T) brain.MissionProjected {
	t.Helper()
	proj, _, err := missionDefinitionToProjected(forkDef(), "", nil)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	return proj
}

// recordingForkDispatcher records each dispatch request.
type recordingForkDispatcher struct{ reqs []brain.DispatchRequest }

func (r *recordingForkDispatcher) Dispatch(req brain.DispatchRequest) { r.reqs = append(r.reqs, req) }

func TestForkFields_ReachTheDispatchRequest(t *testing.T) {
	proj := projectForkDef(t)

	rec := &recordingForkDispatcher{}
	h := brain.NewDispatchHandler(rec)
	eng := brain.NewEngine("tenant-a")
	eng.AddSystem(brain.SchedulerSystem)
	eng.Subscribe(h.Tap)
	eng.Submit(proj)

	// "probe" depends on "build", so it dispatches only after "build" is done.
	eng.Tick()
	h.Drain()
	eng.Submit(brain.WorkCompleted{ID: brain.WorkID("m1", "build"), Result: "ok"})
	eng.Tick()
	h.Drain()

	got := map[string]forkFields{}
	for _, r := range rec.reqs {
		got[nodeIDOf(r.WorkID, r.MissionID)] = forkFields{StartsFrom: r.StartsFrom, Forkable: r.Forkable}
	}
	checkForkFields(t, "dispatch request", got)
}

func TestForkFields_SurviveASnapshotRestore(t *testing.T) {
	w := brain.NewWorld("tenant-a")
	brain.Reduce(w, projectForkDef(t))

	restored, err := brain.RestoreWorld(brain.SnapshotWorld(w, "1"), "tenant-a")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	got := map[string]forkFields{}
	for _, wi := range restored.WorkSnapshot() {
		got[nodeIDOf(wi.ID, wi.MissionID)] = forkFields{StartsFrom: wi.StartsFrom, Forkable: wi.Forkable}
	}
	checkForkFields(t, "restored world", got)
}

func TestForkFields_ReachTheAgentTask(t *testing.T) {
	cases := map[string]brain.DispatchRequest{
		"build":  {WorkID: "m1/build", Kind: "agent", Target: "builder", Forkable: true},
		"probe":  {WorkID: "m1/probe", Kind: "agent", Target: "prober", StartsFrom: "build"},
		"report": {WorkID: "m1/report", Kind: "agent", Target: "reporter"},
	}
	got := map[string]forkFields{}
	for id, req := range cases {
		h := &taskHarness{}
		if wc := dispatchOutcome(t, h, req); wc.Err != "" {
			t.Fatalf("%s: dispatch failed: %s", id, wc.Err)
		}
		if len(h.tasks) != 1 {
			t.Fatalf("%s: tasks = %+v, want one", id, h.tasks)
		}
		task := h.tasks[0]
		if task.NodeID != id {
			t.Errorf("%s: task NodeID = %q, want %q", id, task.NodeID, id)
		}
		got[id] = forkFields{StartsFrom: task.StartsFrom, Forkable: task.Forkable}
	}
	checkForkFields(t, "agent task", got)
}
