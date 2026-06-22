package brain

import "testing"

// recordingDispatcher records the requests it receives.
type recordingDispatcher struct{ reqs []DispatchRequest }

func (r *recordingDispatcher) Dispatch(req DispatchRequest) { r.reqs = append(r.reqs, req) }

func TestDispatchHandler_LiveWorkDispatchedActuates(t *testing.T) {
	rec := &recordingDispatcher{}
	h := NewDispatchHandler(rec)

	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.Subscribe(h.Tap)

	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "recon", Input: "cfg-a"},
	}})
	e.Tick()  // scheduler dispatches a (live) → tap buffers it
	h.Drain() // actuate off the tick

	if len(rec.reqs) != 1 {
		t.Fatalf("want 1 dispatch, got %d", len(rec.reqs))
	}
	got := rec.reqs[0]
	if got.WorkID != "a" || got.MissionID != "m1" || got.Kind != "tool" || got.Target != "recon" || got.Input != "cfg-a" {
		t.Fatalf("dispatch request wrong: %+v", got)
	}
}

func TestDispatchHandler_ReplayDoesNotActuate(t *testing.T) {
	// Build a Timeline by running live, capturing events.
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "recon"}}})
	e.Tick()

	// Now replay that Timeline into a fresh engine with a tap attached. Replay must
	// NOT fire the tap (no effects re-fire on resume — ADR-0009).
	rec := &recordingDispatcher{}
	h := NewDispatchHandler(rec)
	re := NewEngine("t1")
	re.Subscribe(h.Tap)
	for _, ev := range e.Timeline.Events() {
		Reduce(re.World, ev) // Replay path: Reduce directly, never e.apply
	}
	h.Drain()

	if len(rec.reqs) != 0 {
		t.Fatalf("replay must not actuate dispatch, got %d", len(rec.reqs))
	}
}

func TestResumeFailInFlight_FailsRunningWork(t *testing.T) {
	w := NewWorld("t1")
	Reduce(w, MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "t"},
		{ID: "b", Kind: "tool", Target: "t"},
	}})
	Reduce(w, WorkDispatched{ID: "a", ItemKind: "tool", Target: "t"}) // a is running, b still pending

	evs := ResumeFailInFlight(w)
	if len(evs) != 1 {
		t.Fatalf("want 1 fail event (only running work), got %d", len(evs))
	}
	wc, ok := evs[0].(WorkCompleted)
	if !ok || wc.ID != "a" || wc.Err == "" {
		t.Fatalf("want WorkCompleted{a, err}, got %+v", evs[0])
	}
}

func TestRetrySystem_ReDispatchesUpToMaxThenFailsMission(t *testing.T) {
	// node "a" fails every time; MaxRetries=2 → 3 total attempts, then mission fails.
	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(fakeDispatcher(map[string]bool{"a": true})) // always fails a
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)

	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "t", MaxRetries: 2},
	}})
	e.Tick()

	var a WorkSnapshot
	for _, wi := range e.Work() {
		if wi.ID == "a" {
			a = wi
		}
	}
	if a.State != WorkFailed {
		t.Fatalf("a: want failed after exhausting retries, got %s", a.State)
	}
	if a.Attempts != 3 {
		t.Errorf("a: want 3 attempts (1 + 2 retries), got %d", a.Attempts)
	}
	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionFailed {
		t.Fatalf("mission want failed, got %+v", ms)
	}
}

func TestRetrySystem_RecoversWhenRetrySucceeds(t *testing.T) {
	// "a" would fail, but we only fail it on the first attempt via a stateful dispatcher.
	failedOnce := false
	dispatcher := func(w *World) []Event {
		var out []Event
		for _, wi := range w.WorkSnapshot() {
			if wi.State != WorkRunning {
				continue
			}
			if wi.ID == "a" && !failedOnce {
				failedOnce = true
				out = append(out, WorkCompleted{ID: wi.ID, Err: "transient"})
			} else {
				out = append(out, WorkCompleted{ID: wi.ID, Result: "ok"})
			}
		}
		return out
	}

	e := NewEngine("t1")
	e.AddSystem(SchedulerSystem)
	e.AddSystem(dispatcher)
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)

	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "t", MaxRetries: 1}}})
	e.Tick()

	ms := e.Missions()
	if len(ms) != 1 || ms[0].Status != MissionCompleted {
		t.Fatalf("mission want completed after successful retry, got %+v", ms)
	}
}
