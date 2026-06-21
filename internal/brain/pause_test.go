package brain

import "testing"

// A paused mission must not dispatch further work; resuming continues it.
func TestPause_HaltsDispatchUntilResumed(t *testing.T) {
	e := engineWithScheduler(nil) // scheduler + fake dispatcher + completion
	// b depends on a, so after a completes b is dispatchable.
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "t"},
		{ID: "b", Kind: "tool", Target: "t", DependsOn: []string{"a"}},
	}})
	// Pause before any tick: nothing should dispatch.
	e.Submit(MissionPauseRequested{ID: "m1"})
	e.Tick()

	if got := len(dispatchOrder(e)); got != 0 {
		t.Fatalf("paused mission must not dispatch, got %d dispatches", got)
	}
	if ms := e.Missions(); ms[0].Status != MissionPaused {
		t.Fatalf("want paused, got %s", ms[0].Status)
	}

	// Resume → the scripted graph runs to completion.
	e.Submit(MissionResumed{ID: "m1"})
	e.Tick()

	if ms := e.Missions(); ms[0].Status != MissionCompleted {
		t.Fatalf("after resume want completed, got %s", ms[0].Status)
	}
	for _, wi := range e.Work() {
		if wi.State != WorkDone {
			t.Errorf("work %s: want done after resume, got %s", wi.ID, wi.State)
		}
	}
}

// Pausing mid-flight (after some work done) halts further dispatch; resume finishes.
func TestPause_MidFlightThenResume(t *testing.T) {
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	// dispatcher that completes work, so the chain would progress each tick.
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(MissionCompletionSystem)

	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "t"},
		{ID: "b", Kind: "tool", Target: "t", DependsOn: []string{"a"}},
		{ID: "c", Kind: "tool", Target: "t", DependsOn: []string{"b"}},
	}})

	// Pause immediately: a never dispatches.
	e.Submit(MissionPauseRequested{ID: "m1"})
	e.Tick()
	for _, wi := range e.Work() {
		if wi.State != WorkPending {
			t.Fatalf("paused: %s should be pending, got %s", wi.ID, wi.State)
		}
	}
	if e.Missions()[0].Status != MissionPaused {
		t.Fatal("mission should be paused")
	}

	e.Submit(MissionResumed{ID: "m1"})
	e.Tick()
	if e.Missions()[0].Status != MissionCompleted {
		t.Fatalf("after resume want completed, got %s", e.Missions()[0].Status)
	}
}

func TestPause_ReducerGuards(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Goal: "g"})
	// resume a running mission: no-op (stays running).
	Reduce(w, MissionResumed{ID: "m1"})
	if w.MissionSnapshot()[0].Status != MissionRunning {
		t.Fatal("resume on running should stay running")
	}
	Reduce(w, MissionPauseRequested{ID: "m1"})
	if w.MissionSnapshot()[0].Status != MissionPaused {
		t.Fatal("pause should set paused")
	}
	// pause again: stays paused.
	Reduce(w, MissionPauseRequested{ID: "m1"})
	if w.MissionSnapshot()[0].Status != MissionPaused {
		t.Fatal("double pause should stay paused")
	}
	// Stop semantics: MissionDone terminates a paused mission (paused/running → done).
	Reduce(w, MissionDone{ID: "m1", Outcome: MissionFailed, Reason: "stopped"})
	if w.MissionSnapshot()[0].Status != MissionFailed {
		t.Fatalf("MissionDone should terminate a paused mission, got %s", w.MissionSnapshot()[0].Status)
	}
}
