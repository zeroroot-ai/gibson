// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"reflect"
	"testing"
)

// TestProjection_TwoMissionsMayShareNodeNames is the regression: node ids are
// unique within one mission definition, but the World is per-tenant and
// long-lived, so a second mission naming a node "fetch" used to be skipped as
// already-projected. It then had zero work items, and MissionCompletionSystem
// read "nothing running, nothing ready" as "all work complete" — reporting
// SUCCESS for a mission that did nothing at all.
func TestProjection_TwoMissionsMayShareNodeNames(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "fetch", Kind: "tool", Target: "http", Input: `{"url":"https://a.example"}`},
	}})
	Reduce(w, MissionProjected{ID: "m2", Nodes: []WorkNode{
		{ID: "fetch", Kind: "tool", Target: "http", Input: `{"url":"https://b.example"}`},
	}})

	byMission := map[string][]WorkSnapshot{}
	for _, wi := range w.WorkSnapshot() {
		byMission[wi.MissionID] = append(byMission[wi.MissionID], wi)
	}
	if len(byMission["m1"]) != 1 || len(byMission["m2"]) != 1 {
		t.Fatalf("work per mission = m1:%d m2:%d, want one each",
			len(byMission["m1"]), len(byMission["m2"]))
	}
	// Each mission must carry its OWN input; sharing one work item would have
	// silently run the first mission's parameters for the second.
	if byMission["m2"][0].Input != `{"url":"https://b.example"}` {
		t.Errorf("m2 input = %q, want its own", byMission["m2"][0].Input)
	}
}

func TestProjection_ScopesDependenciesToTheSameMission(t *testing.T) {
	// A dependency names a node; unscoped, it would resolve against another
	// mission's identically-named node and gate on the wrong work.
	w := NewWorld("acme")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "scan", Kind: "tool", Target: "nmap"},
		{ID: "report", Kind: "tool", Target: "md", DependsOn: []string{"scan"}},
	}})

	for _, wi := range w.WorkSnapshot() {
		if nodeName(wi.ID) != "report" {
			continue
		}
		if len(wi.DependsOn) != 1 || wi.DependsOn[0] != WorkID("m1", "scan") {
			t.Fatalf("report depends on %v, want the mission-scoped scan id", wi.DependsOn)
		}
	}
}

func TestProjection_RemainsIdempotentWithinAMission(t *testing.T) {
	// Replay folds the same event again; it must not duplicate work.
	w := NewWorld("acme")
	ev := MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "fetch", Kind: "tool", Target: "http"}}}
	Reduce(w, ev)
	Reduce(w, ev)
	if got := len(w.WorkSnapshot()); got != 1 {
		t.Fatalf("work items = %d, want 1 after re-applying the same projection", got)
	}
}

func TestWorkID_RoundTripsThroughNodeName(t *testing.T) {
	if got := WorkID("m1", "fetch"); got != "m1/fetch" {
		t.Errorf("WorkID = %q", got)
	}
	if got := nodeName(WorkID("m1", "fetch")); got != "fetch" {
		t.Errorf("nodeName = %q, want the node back", got)
	}
	// A bare id (pre-scoping events replayed from an older Timeline) still reads
	// as its own node name rather than being mangled.
	if got := nodeName("fetch"); got != "fetch" {
		t.Errorf("nodeName of an unscoped id = %q", got)
	}
}

// runProjection is a mission of two nodes that is projected as the given run.
func runProjection(runID string) MissionProjected {
	return MissionProjected{ID: "m1", RunID: runID, Nodes: []WorkNode{
		{ID: "scan", Kind: "tool", Target: "nmap"},
		{ID: "report", Kind: "tool", Target: "md", DependsOn: []string{"scan"}},
	}}
}

func tickN(e *Engine, n int) {
	for range n {
		e.Tick()
	}
}

// worldView is what a replay must give back: the mission, work, decision and
// VoI state of a World.
func worldView(w *World) []any {
	return []any{w.MissionSnapshot(), w.WorkSnapshot(), w.DecisionSnapshot(), w.VoIPlanSnapshot()}
}

func countEvents[T Event](e *Engine) int {
	n := 0
	for _, ev := range e.Timeline.Events() {
		if _, ok := ev.(T); ok {
			n++
		}
	}
	return n
}

// TestProjection_SecondRunOfAFinishedMissionRunsItsWork is the regression for
// gibson#1217. The mission ID is the stable record ID, so run 2 of a mission
// projects the same ID as run 1. It used to find run 1 terminal, add no work,
// and end at once with nothing dispatched.
func TestProjection_SecondRunOfAFinishedMissionRunsItsWork(t *testing.T) {
	e := engineWithScheduler(nil)

	for _, runID := range []string{"run-1", "run-2"} {
		e.Submit(runProjection(runID))
		e.Submit(MissionStarted{ID: "m1", RunID: runID})
		tickN(e, 10)

		ms := e.Missions()
		if len(ms) != 1 || ms[0].RunID != runID || ms[0].Status != MissionCompleted {
			t.Fatalf("%s: missions = %+v, want one completed mission of this run", runID, ms)
		}
		for _, wi := range e.Work() {
			if wi.RunID != runID || wi.State != WorkDone {
				t.Fatalf("%s: work %s run = %s state = %s, want this run and done", runID, wi.ID, wi.RunID, wi.State)
			}
		}
	}

	// Two runs of two nodes dispatch four times, and each run ends once.
	if got := countEvents[WorkDispatched](e); got != 4 {
		t.Errorf("WorkDispatched events = %d, want 4", got)
	}
	if got := countEvents[MissionDone](e); got != 2 {
		t.Errorf("MissionDone events = %d, want 2", got)
	}

	// The Timeline gives back the World the engine holds.
	if got, want := worldView(Replay("t1", e.Timeline)), worldView(e.World); !reflect.DeepEqual(got, want) {
		t.Errorf("replay differs from the live World\nreplay: %+v\nlive:   %+v", got, want)
	}
}

// TestProjection_LateEventOfRun1DoesNotChangeRun2 covers a worker of run 1 that
// reports after run 2 has started. Work and mission have the same IDs in both
// runs, so without the run ID the late result marks the work of run 2 done.
func TestProjection_LateEventOfRun1DoesNotChangeRun2(t *testing.T) {
	e := NewEngine("t1", &memTimelineStore{})
	e.AddSystem(SchedulerSystem)

	e.Submit(runProjection("run-1"))
	tickN(e, 3) // run 1 dispatches scan, which stays running

	e.Submit(runProjection("run-2"))
	tickN(e, 3)

	// The late events of run 1.
	e.Submit(WorkCompleted{ID: "m1/scan", RunID: "run-1", Result: "late result of run 1"})
	e.Submit(MissionDone{ID: "m1", RunID: "run-1", Outcome: MissionCompleted, Reason: "late end of run 1"})
	tickN(e, 3)

	ms := e.Missions()
	if len(ms) != 1 || ms[0].RunID != "run-2" || ms[0].Status != MissionRunning {
		t.Fatalf("missions = %+v, want run-2 still running", ms)
	}
	for _, wi := range e.Work() {
		if wi.Result == "late result of run 1" {
			t.Errorf("work %s of run 2 took the result of run 1", wi.ID)
		}
		if wi.ID == "m1/scan" && wi.State != WorkRunning {
			t.Errorf("work m1/scan state = %s, want running (dispatched by run 2)", wi.State)
		}
	}
	if got, want := worldView(Replay("t1", e.Timeline)), worldView(e.World); !reflect.DeepEqual(got, want) {
		t.Errorf("replay differs from the live World\nreplay: %+v\nlive:   %+v", got, want)
	}
}

// TestProjection_StopWithRunningWorkThenRerun covers a user who stops a run
// while a node runs and then runs the mission again.
func TestProjection_StopWithRunningWorkThenRerun(t *testing.T) {
	// Run 1 dispatches scan. No dispatcher system runs before the stop, so the
	// node is still running when the run stops.
	e := NewEngine("t1", &memTimelineStore{})
	e.AddSystem(SchedulerSystem)
	e.Submit(runProjection("run-1"))
	tickN(e, 3)
	e.Submit(MissionDone{ID: "m1", RunID: "run-1", Outcome: MissionFailed, Reason: "stopped by user"})
	tickN(e, 2)
	if ms := e.Missions(); len(ms) != 1 || ms[0].Status != MissionFailed {
		t.Fatalf("run 1 after the stop: %+v, want failed", ms)
	}

	// Run 2 on the same engine runs both nodes to the end.
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(MissionCompletionSystem)
	e.Submit(runProjection("run-2"))
	tickN(e, 10)

	ms := e.Missions()
	if len(ms) != 1 || ms[0].RunID != "run-2" || ms[0].Status != MissionCompleted {
		t.Fatalf("run 2: %+v, want completed", ms)
	}
	for _, wi := range e.Work() {
		if wi.State != WorkDone || wi.RunID != "run-2" {
			t.Errorf("work %s = %s of %s, want done of run-2", wi.ID, wi.State, wi.RunID)
		}
	}
}

// TestProjection_StaleEventIsNotShownToSubscribers keeps the lifecycle
// projector from telling a client that run 1 ended while run 2 runs.
func TestProjection_StaleEventIsNotShownToSubscribers(t *testing.T) {
	e := NewEngine("t1", &memTimelineStore{})
	var seen []Event
	e.Subscribe(func(ev Event) { seen = append(seen, ev) })

	e.Submit(runProjection("run-1"))
	e.Submit(runProjection("run-2"))
	e.Submit(MissionDone{ID: "m1", RunID: "run-1", Outcome: MissionCompleted})
	tickN(e, 2)

	for _, ev := range seen {
		if d, ok := ev.(MissionDone); ok {
			t.Fatalf("a subscriber saw %+v of run 1 while run 2 runs", d)
		}
	}
}

// TestProjection_PendingMissionGetsItsWork covers a mission that CreateMission
// recorded and that runs later. The pending entity is not terminal, and its
// projection used to add no work.
func TestProjection_PendingMissionGetsItsWork(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, MissionCreated{ID: "m1", Name: "recon"})
	Reduce(w, runProjection("run-1"))
	Reduce(w, MissionStarted{ID: "m1", RunID: "run-1"})

	ms := w.MissionSnapshot()
	if len(ms) != 1 || ms[0].Status != MissionRunning || ms[0].RunID != "run-1" || ms[0].Name != "recon" {
		t.Fatalf("missions = %+v, want one running mission of run-1 that keeps its name", ms)
	}
	if got := len(w.WorkSnapshot()); got != 2 {
		t.Fatalf("work items = %d, want 2", got)
	}
}

// TestProjection_NewRunRetiresDecisionAndPlanOfTheLastRun keeps a decision
// that was open when run 1 stopped from becoming the decision of run 2.
func TestProjection_NewRunRetiresDecisionAndPlanOfTheLastRun(t *testing.T) {
	w := NewWorld("acme")
	proj := runProjection("run-1")
	proj.Goal = "find a way in"
	Reduce(w, proj)
	Reduce(w, DecisionRequested{MissionID: "m1", RunID: "run-1", Cursor: 0})
	Reduce(w, VoIPlanRequested{MissionID: "m1", RunID: "run-1", Cursor: 0})
	Reduce(w, MissionDone{ID: "m1", RunID: "run-1", Outcome: MissionFailed, Reason: "stopped by user"})

	proj.RunID = "run-2"
	Reduce(w, proj)

	if got := w.DecisionSnapshot(); len(got) != 0 {
		t.Errorf("decisions = %+v, want none of run 1", got)
	}
	if got := w.VoIPlanSnapshot(); len(got) != 0 {
		t.Errorf("VoI plans = %+v, want none of run 1", got)
	}
	// A late answer of run 1 changes nothing.
	Reduce(w, DecisionCompleted{MissionID: "m1", RunID: "run-1"})
	Reduce(w, VoIPlanned{MissionID: "m1", RunID: "run-1"})
	if got := len(w.VoIPlanSnapshot()); got != 0 {
		t.Errorf("a late VoIPlanned of run 1 made %d VoI plans", got)
	}
}

// TestProjection_LateEvidenceOfRun1IsDropped covers the evidence that a worker
// of run 1 reports after run 2 has started. Each kind carries the run of the
// mission that produced it.
func TestProjection_LateEvidenceOfRun1IsDropped(t *testing.T) {
	w := NewWorld("acme")
	Reduce(w, runProjection("run-1"))
	Reduce(w, MissionDone{ID: "m1", RunID: "run-1", Outcome: MissionFailed, Reason: "stopped by user"})
	Reduce(w, runProjection("run-2"))

	Reduce(w, FindingRaised{ID: "f1", MissionID: "m1", MissionRunID: "run-1"})
	Reduce(w, HostObserved{MissionID: "m1", MissionRunID: "run-1", ScopeID: "s", Address: "10.0.0.5"})
	Reduce(w, EntityObserved{Label: "Application", Key: "app", MissionID: "m1", MissionRunID: "run-1"})
	Reduce(w, ObservationRecorded{EventID: "e1", MissionID: "m1", MissionRunID: "run-1", Shape: "x"})
	Reduce(w, HypothesisObserved{MissionID: "m1", MissionRunID: "run-1", Claim: "c"})
	Reduce(w, LlmCallObserved{CallID: "c1", MissionID: "m1", MissionRunID: "run-1"})
	Reduce(w, AgentToolCallObserved{ToolCallID: "t1", MissionID: "m1", MissionRunID: "run-1"})

	if n := len(w.FindingSnapshot()); n != 0 {
		t.Errorf("findings = %d, want 0", n)
	}
	if n := len(w.Snapshot()); n != 0 {
		t.Errorf("hosts = %d, want 0", n)
	}
	if n := len(w.EntitySnapshot()); n != 0 {
		t.Errorf("entities = %d, want 0", n)
	}
	if n := len(w.ObservationSnapshot()); n != 0 {
		t.Errorf("observations = %d, want 0", n)
	}
	if n := len(w.HypothesisSnapshot()); n != 0 {
		t.Errorf("hypotheses = %d, want 0", n)
	}
	if n := len(w.LlmCallSnapshot()); n != 0 {
		t.Errorf("LLM calls = %d, want 0", n)
	}
	if n := len(w.AgentToolCallSnapshot()); n != 0 {
		t.Errorf("tool calls = %d, want 0", n)
	}

	// The same evidence of the current run lands.
	Reduce(w, FindingRaised{ID: "f1", MissionID: "m1", MissionRunID: "run-2"})
	if n := len(w.FindingSnapshot()); n != 1 {
		t.Errorf("findings of run 2 = %d, want 1", n)
	}
}
