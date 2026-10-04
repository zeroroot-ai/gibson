// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"testing"
)

// fanOutMission is a two-instance fan-out converging on a report node. The
// instances carry DependentsRunOnFailure, as the daemon's projection sets it for
// a for_each instance; `report` stands for whatever the author put after the
// join, since a join is collapsed into DependsOn and is never work itself.
func fanOutMission(id string) MissionProjected {
	return MissionProjected{
		ID: id,
		Nodes: []WorkNode{
			{ID: "scan#a", Kind: "tool", Target: "nmap", DependentsRunOnFailure: true},
			{ID: "scan#b", Kind: "tool", Target: "nmap", DependentsRunOnFailure: true},
			{ID: "report", Kind: "agent", Target: "writer", DependsOn: []string{"scan#a", "scan#b"}},
		},
	}
}

// The whole point of the slice: one unreachable target must not throw away the
// findings from the targets that answered. Before this, `report` waited on a
// dependency that would never reach `done`, the mission settled failed, and the
// nine targets' worth of work was never reported (gibson#527).
func TestScheduler_JoinRunsAfterAPartiallyFailedFanOut(t *testing.T) {
	e := engineWithScheduler(map[string]bool{"scan#b": true})
	e.Submit(fanOutMission("m1"))
	e.Tick()

	order := dispatchOrder(e)
	if indexOf(order, "report") < 0 {
		t.Fatalf("report never dispatched after a partially failed fan-out: %v", order)
	}
	if indexOf(order, "report") < indexOf(order, "scan#a") {
		t.Errorf("report must dispatch after the fan-out, not before it: %v", order)
	}

	state := map[string]WorkState{}
	for _, wi := range e.Work() {
		state[nodeOf(wi.ID)] = wi.State
	}
	if state["scan#b"] != WorkFailed {
		t.Errorf("scan#b: want failed, got %s", state["scan#b"])
	}
	if state["report"] != WorkDone {
		t.Errorf("report: want done, got %s", state["report"])
	}

	// The mission still reports the failure. Running the join is not the same as
	// calling the run a success — the fan-out decision is that the fan-out fails
	// if any instance failed (gibson#524).
	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionFailed {
		t.Fatalf("mission want failed (an instance failed), got %+v", ms)
	}
}

// holdingDispatcher completes nothing on its own: work stays running until the
// test completes it, so the ceiling is observable as a count of running items
// rather than as an order that a synchronous fake would collapse.
func holdingDispatcher(*World) []Event { return nil }

// engineWithHeldDispatch wires the scheduler, a dispatcher that never completes,
// and the completion System.
func engineWithHeldDispatch() *Engine {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(holdingDispatcher)
	e.AddSystem(MissionCompletionSystem)
	return e
}

// boundedFanOut is five instances of one group with the given ceiling, plus a
// report node after them. No instance depends on another: the ceiling is the
// only thing that holds them back.
func boundedFanOut(id string, limit int) MissionProjected {
	keys := []string{"a", "b", "c", "d", "e"}
	nodes := make([]WorkNode, 0, len(keys)+1)
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		nodes = append(nodes, WorkNode{ID: "scan#" + k, Kind: "tool", Target: "nmap", DependentsRunOnFailure: true, Group: "each", Limit: limit})
		ids = append(ids, "scan#"+k)
	}
	nodes = append(nodes, WorkNode{ID: "report", Kind: "agent", Target: "writer", DependsOn: ids})
	return MissionProjected{ID: id, Nodes: nodes}
}

// runningByGroup counts the running members of each group.
func runningByGroup(e *Engine) map[string]int {
	out := map[string]int{}
	for _, wi := range e.Work() {
		if wi.State == WorkRunning {
			out[wi.Group]++
		}
	}
	return out
}

// The property gibson#538 asks for: a group with max_concurrency N has at most N
// members dispatched and not completed, however many are ready. Without the
// ceiling every instance dispatches on the first tick, so this fails without the
// change.
func TestScheduler_AGroupNeverExceedsItsLimit(t *testing.T) {
	e := engineWithHeldDispatch()
	e.Submit(boundedFanOut("m1", 2))
	e.Tick()

	if got := runningByGroup(e)["each"]; got != 2 {
		t.Fatalf("running in group = %d, want exactly the limit 2: %v", got, dispatchOrder(e))
	}

	// A completion frees exactly one slot, in id order, and a failure frees it
	// the same way: the ceiling is a count, not a condition.
	e.Submit(WorkCompleted{ID: WorkID("m1", "scan#a"), Result: "ok"})
	e.Tick()
	if got := runningByGroup(e)["each"]; got != 2 {
		t.Fatalf("after one completion running = %d, want 2", got)
	}
	e.Submit(WorkCompleted{ID: WorkID("m1", "scan#b"), Err: "boom"})
	e.Tick()
	if got := runningByGroup(e)["each"]; got != 2 {
		t.Fatalf("after one failure running = %d, want 2", got)
	}
	order := dispatchOrder(e)
	if want := []string{"scan#a", "scan#b", "scan#c", "scan#d"}; !eqOrder(order, want) {
		t.Fatalf("dispatch order = %v, want %v", order, want)
	}
	if indexOf(order, "report") >= 0 {
		t.Fatalf("report dispatched while instances are still running: %v", order)
	}
}

// Every instance runs even when an earlier one failed, including instances held
// back by the ceiling, and the join runs after all of them.
func TestScheduler_EveryInstanceRunsUnderTheCeiling(t *testing.T) {
	e := engineWithScheduler(map[string]bool{"scan#a": true})
	e.Submit(boundedFanOut("m1", 1))
	e.Tick()

	order := dispatchOrder(e)
	for _, want := range []string{"scan#a", "scan#b", "scan#c", "scan#d", "scan#e", "report"} {
		if indexOf(order, want) < 0 {
			t.Errorf("%q never ran; the ceiling turned into a gate: %v", want, order)
		}
	}
	if indexOf(order, "report") < indexOf(order, "scan#e") {
		t.Errorf("report must dispatch after the last instance: %v", order)
	}
}

// Two groups do not share a ceiling, and a zero limit is unlimited.
func TestScheduler_CeilingsAreScopedToTheirGroup(t *testing.T) {
	e := engineWithHeldDispatch()
	proj := MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "x#1", Kind: "tool", Target: "nmap", Group: "gx", Limit: 1},
		{ID: "x#2", Kind: "tool", Target: "nmap", Group: "gx", Limit: 1},
		{ID: "y#1", Kind: "tool", Target: "nmap", Group: "gy", Limit: 1},
		{ID: "y#2", Kind: "tool", Target: "nmap", Group: "gy", Limit: 1},
		{ID: "free#1", Kind: "tool", Target: "nmap", Group: "unbounded"},
		{ID: "free#2", Kind: "tool", Target: "nmap", Group: "unbounded"},
	}}
	e.Submit(proj)
	e.Tick()
	got := runningByGroup(e)
	if got["gx"] != 1 || got["gy"] != 1 || got["unbounded"] != 2 {
		t.Fatalf("running by group = %v, want gx=1 gy=1 unbounded=2", got)
	}

	// The same group name in another mission is another ceiling.
	proj2 := proj
	proj2.ID = "m2"
	e.Submit(proj2)
	e.Tick()
	if got := runningByGroup(e); got["gx"] != 2 {
		t.Fatalf("a second mission's gx must have its own slot: %v", got)
	}
}

// The ceiling is replayable: the Timeline a bounded run wrote folds back into
// the same work states, and a snapshot restore keeps the ceiling on the item.
func TestScheduler_CeilingReplaysAndRestores(t *testing.T) {
	e := engineWithScheduler(map[string]bool{"scan#c": true})
	e.Submit(boundedFanOut("m1", 2))
	e.Tick()

	live := e.World.WorkSnapshot()
	replayed := Replay("t1", e.Timeline)
	if got := replayed.WorkSnapshot(); !workEqual(got, live) {
		t.Errorf("replay work mismatch:\n got %+v\nwant %+v", got, live)
	}
	for _, wi := range live {
		if nodeOf(wi.ID) != "report" && (wi.Group != "each" || wi.Limit != 2) {
			t.Errorf("%s lost its ceiling in the live World: group=%q limit=%d", wi.ID, wi.Group, wi.Limit)
		}
	}

	held := engineWithHeldDispatch()
	held.Submit(boundedFanOut("m2", 2))
	held.Tick()
	restored, err := RestoreWorld(SnapshotWorld(held.World, "1-0"), "t1")
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	for _, wi := range restored.WorkSnapshot() {
		if wi.State == WorkRunning && (wi.Group != "each" || wi.Limit != 2) {
			t.Errorf("%s lost its ceiling through the snapshot: group=%q limit=%d", wi.ID, wi.Group, wi.Limit)
		}
	}
}

func eqOrder(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// An ordinary node is unchanged: a failed dependency still stops it. This is the
// behaviour TestScheduler_FailedNodeBlocksDependentsAndFailsMission asserts, kept
// here against the fan-out mission shape so the flag cannot leak into nodes that
// did not ask for it.
func TestScheduler_AnOrdinaryFailedNodeStillBlocksItsDependents(t *testing.T) {
	proj := fanOutMission("m1")
	for i := range proj.Nodes {
		proj.Nodes[i].DependentsRunOnFailure = false
	}
	e := engineWithScheduler(map[string]bool{"scan#b": true})
	e.Submit(proj)
	e.Tick()

	if idx := indexOf(dispatchOrder(e), "report"); idx >= 0 {
		t.Errorf("report ran although its dependency failed and nothing said dependents may run")
	}
}

// A failure with a retry still owed does not release dependents. RetrySystem
// re-arms it in the same tick cycle, so releasing on the first failure would run
// the join one attempt before the fan-out was finished with that target.
func TestScheduler_AFailureWithRetriesLeftDoesNotReleaseDependents(t *testing.T) {
	proj := MissionProjected{
		ID: "m1",
		Nodes: []WorkNode{
			{ID: "scan#a", Kind: "tool", Target: "nmap", MaxRetries: 2, DependentsRunOnFailure: true},
			{ID: "report", Kind: "agent", Target: "writer", DependsOn: []string{"scan#a"}},
		},
	}
	// The scheduler and dispatcher run without RetrySystem, so the item sits in
	// `failed` with attempts (1) still inside its budget (2).
	e := engineWithScheduler(map[string]bool{"scan#a": true})
	e.Submit(proj)
	e.Tick()

	var scan WorkSnapshot
	for _, wi := range e.Work() {
		if nodeOf(wi.ID) == "scan#a" {
			scan = wi
		}
	}
	if scan.State != WorkFailed {
		t.Fatalf("scan#a: want failed, got %s", scan.State)
	}
	if scan.Attempts > scan.MaxRetries {
		t.Fatalf("test premise broken: attempts %d already past max_retries %d, so the "+
			"failure is terminal and this case proves nothing", scan.Attempts, scan.MaxRetries)
	}
	if idx := indexOf(dispatchOrder(e), "report"); idx >= 0 {
		t.Errorf("report ran while its dependency still had a retry owed to it")
	}
}

// depsSatisfied's own rules, stated once, so a change to the scheduler that
// happens to keep the end-to-end tests green still has to answer for them.
func TestDepsSatisfied(t *testing.T) {
	cases := []struct {
		name string
		dep  WorkSnapshot
		want bool
	}{
		{
			name: "done satisfies, as it always has",
			dep:  WorkSnapshot{ID: "d", State: WorkDone},
			want: true,
		},
		{
			name: "a terminal failure satisfies when the dependency says dependents may run",
			dep:  WorkSnapshot{ID: "d", State: WorkFailed, Attempts: 1, DependentsRunOnFailure: true},
			want: true,
		},
		{
			name: "a terminal failure does not satisfy an ordinary dependency",
			dep:  WorkSnapshot{ID: "d", State: WorkFailed, Attempts: 1},
			want: false,
		},
		{
			name: "a failure with a retry owed does not satisfy, flag or not",
			dep:  WorkSnapshot{ID: "d", State: WorkFailed, Attempts: 1, MaxRetries: 1, DependentsRunOnFailure: true},
			want: false,
		},
		{
			name: "skipped never satisfies: a not-taken branch did not produce a result",
			dep:  WorkSnapshot{ID: "d", State: WorkSkipped, DependentsRunOnFailure: true},
			want: false,
		},
		{
			name: "running does not satisfy",
			dep:  WorkSnapshot{ID: "d", State: WorkRunning},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := map[string]WorkSnapshot{"d": tc.dep}
			if got := depsSatisfied([]string{"d"}, idx); got != tc.want {
				t.Errorf("depsSatisfied = %v, want %v", got, tc.want)
			}
		})
	}
}

// A dependency on work that does not exist blocks. Reading a missing id as
// satisfied would dispatch a node whose upstream was never projected.
func TestDepsSatisfied_UnknownDependencyBlocks(t *testing.T) {
	if depsSatisfied([]string{"nope"}, map[string]WorkSnapshot{}) {
		t.Error("an unknown dependency id satisfied a dependency; it must block")
	}
}
