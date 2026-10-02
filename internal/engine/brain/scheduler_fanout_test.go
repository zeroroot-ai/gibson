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

// Every instance runs even when an earlier one failed, including instances held
// back by the concurrency chain — chaining is a ceiling, not a condition.
func TestScheduler_EveryInstanceRunsThroughTheConcurrencyChain(t *testing.T) {
	// A limit of 1 over three instances: each waits on the previous one.
	proj := MissionProjected{
		ID: "m1",
		Nodes: []WorkNode{
			{ID: "scan#a", Kind: "tool", Target: "nmap", DependentsRunOnFailure: true},
			{ID: "scan#b", Kind: "tool", Target: "nmap", DependsOn: []string{"scan#a"}, DependentsRunOnFailure: true},
			{ID: "scan#c", Kind: "tool", Target: "nmap", DependsOn: []string{"scan#b"}, DependentsRunOnFailure: true},
		},
	}
	e := engineWithScheduler(map[string]bool{"scan#a": true})
	e.Submit(proj)
	e.Tick()

	order := dispatchOrder(e)
	for _, want := range []string{"scan#a", "scan#b", "scan#c"} {
		if indexOf(order, want) < 0 {
			t.Errorf("instance %q never ran; the chain turned a ceiling into a gate: %v", want, order)
		}
	}
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
