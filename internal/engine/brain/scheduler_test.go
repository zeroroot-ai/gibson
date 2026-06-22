package brain

import (
	"testing"
)

// fakeDispatcher is a test stand-in for the real dispatch effect-handler
// (gibson#845): it completes any running WorkItem inline, succeeding unless the
// node id is in fails. It lets the scheduler/completion Systems run a whole
// scripted mission to quiescence within a single Tick.
func fakeDispatcher(fails map[string]bool) System {
	return func(w *World) []Event {
		var out []Event
		for _, wi := range w.WorkSnapshot() {
			if wi.State != WorkRunning {
				continue
			}
			if fails[wi.ID] {
				out = append(out, WorkCompleted{ID: wi.ID, Err: "boom"})
			} else {
				out = append(out, WorkCompleted{ID: wi.ID, Result: "ok:" + wi.ID})
			}
		}
		return out
	}
}

// engineWithScheduler wires the scheduler, a fake dispatcher, and the completion
// System (in that order) onto a fresh engine.
func engineWithScheduler(fails map[string]bool) *Engine {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(fakeDispatcher(fails))
	e.AddSystem(MissionCompletionSystem)
	return e
}

// dispatchOrder returns the WorkItem ids in the order they were dispatched, read
// off the Timeline.
func dispatchOrder(e *Engine) []string {
	var order []string
	for _, ev := range e.Timeline.Events() {
		if d, ok := ev.(WorkDispatched); ok {
			order = append(order, d.ID)
		}
	}
	return order
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

// diamond: a -> {b, c} -> d. b and c both depend on a; d depends on b and c.
func diamondMission(id, goal string) MissionProjected {
	return MissionProjected{
		ID:   id,
		Goal: goal,
		Nodes: []WorkNode{
			{ID: "a", Kind: "tool", Target: "recon"},
			{ID: "b", Kind: "agent", Target: "scan-b", DependsOn: []string{"a"}},
			{ID: "c", Kind: "agent", Target: "scan-c", DependsOn: []string{"a"}},
			{ID: "d", Kind: "tool", Target: "report", DependsOn: []string{"b", "c"}},
		},
	}
}

func TestScheduler_NoGoalMissionRunsInDependencyOrderAndCompletes(t *testing.T) {
	e := engineWithScheduler(nil)
	e.Submit(diamondMission("m1", "")) // no goal → mechanical completion
	e.Tick()                           // one Tick sweeps the whole graph to quiescence

	order := dispatchOrder(e)
	if len(order) != 4 {
		t.Fatalf("expected 4 dispatches, got %d (%v)", len(order), order)
	}
	// a before b and c; b and c before d.
	if indexOf(order, "a") > indexOf(order, "b") || indexOf(order, "a") > indexOf(order, "c") {
		t.Errorf("a must dispatch before b and c: %v", order)
	}
	if indexOf(order, "b") > indexOf(order, "d") || indexOf(order, "c") > indexOf(order, "d") {
		t.Errorf("d must dispatch after b and c: %v", order)
	}

	for _, wi := range e.Work() {
		if wi.State != WorkDone {
			t.Errorf("work %q: want done, got %s", wi.ID, wi.State)
		}
	}
	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionCompleted {
		t.Fatalf("mission want completed, got %+v", ms)
	}
}

func TestScheduler_FailedNodeBlocksDependentsAndFailsMission(t *testing.T) {
	e := engineWithScheduler(map[string]bool{"a": true}) // a fails
	e.Submit(diamondMission("m1", ""))
	e.Tick()

	order := dispatchOrder(e)
	// a dispatched; b/c/d never become dispatchable because a failed.
	if len(order) != 1 || order[0] != "a" {
		t.Fatalf("only a should dispatch, got %v", order)
	}
	work := map[string]WorkState{}
	for _, wi := range e.Work() {
		work[wi.ID] = wi.State
	}
	if work["a"] != WorkFailed {
		t.Errorf("a: want failed, got %s", work["a"])
	}
	for _, id := range []string{"b", "c", "d"} {
		if work[id] != WorkPending {
			t.Errorf("%s: want still pending (dead), got %s", id, work[id])
		}
	}
	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionFailed {
		t.Fatalf("mission want failed, got %+v", ms)
	}
}

func TestScheduler_GoalMissionDoesNotAutoComplete(t *testing.T) {
	e := engineWithScheduler(nil)
	e.Submit(diamondMission("m1", "find the flag")) // has a goal
	e.Tick()

	// Scripted graph still runs (the scheduler is goal-agnostic)...
	for _, wi := range e.Work() {
		if wi.State != WorkDone {
			t.Errorf("work %q: want done, got %s", wi.ID, wi.State)
		}
	}
	// ...but a goal mission is NOT completed mechanically — the Decider owns that.
	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionRunning {
		t.Fatalf("goal mission must stay running (Decider completes it), got %+v", ms)
	}
}

func TestScheduler_ReplayReproducesRun(t *testing.T) {
	e := engineWithScheduler(nil)
	e.Submit(diamondMission("m1", ""))
	e.Tick()

	live := e.World.MissionSnapshot()
	liveWork := e.World.WorkSnapshot()

	replayed := Replay("t1", e.Timeline)
	if got := replayed.MissionSnapshot(); !missionsEqual(got, live) {
		t.Errorf("replay mission mismatch:\n got %+v\nwant %+v", got, live)
	}
	if got := replayed.WorkSnapshot(); !workEqual(got, liveWork) {
		t.Errorf("replay work mismatch:\n got %+v\nwant %+v", got, liveWork)
	}
}

func missionsEqual(a, b []MissionSnapshot) bool {
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

func workEqual(a, b []WorkSnapshot) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].State != b[i].State || a[i].MissionID != b[i].MissionID || a[i].Result != b[i].Result {
			return false
		}
	}
	return true
}
