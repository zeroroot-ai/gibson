package brain

import (
	"encoding/json"
	"testing"
)

// engineWithCondition wires scheduler + condition + fake dispatcher + completion.
func engineWithCondition(fails map[string]bool) *Engine {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(ConditionSystem)
	e.AddSystem(fakeDispatcher(fails))
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	return e
}

// Mission: a (tool) → cond → {yes | no}. cond checks nodes['a'].
func conditionMission(expr string) MissionProjected {
	cs := func(expr string) string {
		b, _ := json.Marshal(ConditionSpec{Expression: expr, TrueBranch: []string{"yes"}, FalseBranch: []string{"no"}})
		return string(b)
	}
	return MissionProjected{
		ID: "m1", // no goal → mechanical completion
		Nodes: []WorkNode{
			{ID: "a", Kind: "tool", Target: "scan"},
			{ID: "cond", Kind: "condition", Input: cs(expr), DependsOn: []string{"a"}},
			{ID: "yes", Kind: "tool", Target: "exploit", DependsOn: []string{"cond"}},
			{ID: "no", Kind: "tool", Target: "report", DependsOn: []string{"cond"}},
		},
	}
}

func TestCondition_TrueBranchRunsFalseBranchSkipped(t *testing.T) {
	e := engineWithCondition(nil)
	// fakeDispatcher sets result "ok:a"; expression matches it → true branch.
	e.Submit(conditionMission(`nodes['a'] == 'ok:a'`))
	e.Tick()

	st := map[string]WorkState{}
	for _, wi := range e.Work() {
		st[wi.ID] = wi.State
	}
	if st["cond"] != WorkDone {
		t.Errorf("cond: want done, got %s", st["cond"])
	}
	if st["yes"] != WorkDone {
		t.Errorf("yes (taken): want done, got %s", st["yes"])
	}
	if st["no"] != WorkSkipped {
		t.Errorf("no (not taken): want skipped, got %s", st["no"])
	}
	ms := e.Missions()
	if ms[0].Status != MissionCompleted {
		t.Fatalf("mission want completed (skip is not failure), got %s", ms[0].Status)
	}
}

func TestCondition_FalseBranchRunsTrueBranchSkipped(t *testing.T) {
	e := engineWithCondition(nil)
	e.Submit(conditionMission(`nodes['a'] == 'never'`)) // false → false branch
	e.Tick()

	st := map[string]WorkState{}
	for _, wi := range e.Work() {
		st[wi.ID] = wi.State
	}
	if st["no"] != WorkDone {
		t.Errorf("no (taken): want done, got %s", st["no"])
	}
	if st["yes"] != WorkSkipped {
		t.Errorf("yes (not taken): want skipped, got %s", st["yes"])
	}
}

func TestCondition_ReplayReproduces(t *testing.T) {
	e := engineWithCondition(nil)
	e.Submit(conditionMission(`nodes['a'] == 'ok:a'`))
	e.Tick()

	replayed := Replay("t1", e.Timeline)
	if !workEqual(replayed.WorkSnapshot(), e.World.WorkSnapshot()) {
		t.Errorf("replay diverged:\n got %+v\nwant %+v", replayed.WorkSnapshot(), e.World.WorkSnapshot())
	}
}

func TestCondition_MalformedSpecFailsConditionAndMission(t *testing.T) {
	e := engineWithCondition(nil)
	m := conditionMission("")      // expr irrelevant; override Input below
	m.Nodes[1].Input = "{not json" // malformed
	e.Submit(m)
	e.Tick()

	st := map[string]WorkState{}
	for _, wi := range e.Work() {
		st[wi.ID] = wi.State
	}
	if st["cond"] != WorkFailed {
		t.Errorf("malformed condition: want cond failed, got %s", st["cond"])
	}
	// branches depend on cond (failed, never done) → dead, never run.
	if st["yes"] == WorkDone || st["no"] == WorkDone {
		t.Errorf("branches must not run when condition failed: yes=%s no=%s", st["yes"], st["no"])
	}
	if e.Missions()[0].Status != MissionFailed {
		t.Errorf("mission want failed, got %s", e.Missions()[0].Status)
	}
}
