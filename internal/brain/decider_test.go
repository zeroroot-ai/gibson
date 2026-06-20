package brain

import (
	"context"
	"testing"
)

// scriptedLLM returns a programmed sequence of decisions, then empty.
type scriptedLLM struct {
	outputs []DeciderOutput
	i       int
	calls   int
}

func (s *scriptedLLM) Decide(_ context.Context, _ MissionContext) (DeciderOutput, error) {
	s.calls++
	if s.i >= len(s.outputs) {
		return DeciderOutput{}, nil
	}
	o := s.outputs[s.i]
	s.i++
	return o, nil
}

// goalEngine wires the full goal-mission loop: scheduler, gate, fake dispatcher,
// retry, and the no-goal completion System (harmless for goal missions). The
// DeciderWorker is returned for off-tick draining.
func goalEngine(llm DeciderLLM) (*Engine, *DeciderWorker) {
	e := NewEngine("t1")
	dw := NewDeciderWorker(e, llm, func() []Capability {
		return []Capability{{Kind: "agent", Name: "exploit", Description: "exploit a host"}}
	})
	e.AddSystem(SchedulerSystem)
	e.AddSystem(DeciderGateSystem)
	e.AddSystem(fakeDispatcher(nil))
	e.AddSystem(RetrySystem)
	e.AddSystem(MissionCompletionSystem)
	e.Subscribe(dw.Tap)
	return e, dw
}

func runRounds(e *Engine, dw *DeciderWorker, rounds int) {
	for i := 0; i < rounds; i++ {
		e.Tick()
		dw.Drain(context.Background())
	}
	e.Tick() // apply the final round's submitted events
}

func missionStatus(e *Engine, id string) MissionStatus {
	for _, m := range e.Missions() {
		if m.ID == id {
			return m.Status
		}
	}
	return ""
}

func TestDecider_GoalMissionDispatchesThenCompletes(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "exploit", Input: "pop the box"}}},
		{Complete: &DeciderComplete{Outcome: "success", Reason: "flag captured"}},
	}}
	e, dw := goalEngine(llm)

	// scripted recon node "a", plus a goal → Decider takes over after a runs.
	e.Submit(MissionProjected{ID: "m1", Goal: "find the flag", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "recon"},
	}})
	runRounds(e, dw, 8)

	if got := missionStatus(e, "m1"); got != MissionCompleted {
		t.Fatalf("mission status: got %s want completed", got)
	}
	// The Decider-dispatched agent ran (fake dispatcher completed it).
	var sawAgent bool
	for _, wi := range e.Work() {
		if wi.Target == "exploit" && wi.State == WorkDone {
			sawAgent = true
		}
	}
	if !sawAgent {
		t.Errorf("expected the Decider-dispatched 'exploit' agent to have run; work=%+v", e.Work())
	}
}

func TestDecider_NoGoalMissionNeverInvokesDecider(t *testing.T) {
	llm := &scriptedLLM{}
	e, dw := goalEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "recon"}}}) // no goal
	runRounds(e, dw, 4)

	if llm.calls != 0 {
		t.Errorf("Decider must not be called for a no-goal mission, got %d calls", llm.calls)
	}
	if got := missionStatus(e, "m1"); got != MissionCompleted {
		t.Errorf("no-goal mission should complete mechanically, got %s", got)
	}
}

func TestDecider_OneInFlightPerMission(t *testing.T) {
	// The LLM "stalls" (we never drain between two ticks); the gate must not queue a
	// second request while one is in flight.
	llm := &scriptedLLM{outputs: []DeciderOutput{{Complete: &DeciderComplete{Outcome: "success"}}}}
	e, dw := goalEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "g"})

	e.Tick() // gate fires DecisionRequested (in flight) — worker not drained yet
	e.Tick() // gate must NOT fire again while in flight
	e.Tick()

	requests := 0
	for _, ev := range e.Timeline.Events() {
		if _, ok := ev.(DecisionRequested); ok {
			requests++
		}
	}
	if requests != 1 {
		t.Fatalf("want exactly 1 in-flight decision request, got %d", requests)
	}

	// Now drain → worker completes the mission.
	dw.Drain(context.Background())
	e.Tick()
	if got := missionStatus(e, "m1"); got != MissionCompleted {
		t.Errorf("mission want completed after drain, got %s", got)
	}
}

func TestDecider_EmptyOnQuiescenceCompletes(t *testing.T) {
	// Pure goal mission, no scripted nodes; the Decider returns empty → quiescent → complete.
	llm := &scriptedLLM{} // always empty
	e, dw := goalEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "nothing to do"})
	runRounds(e, dw, 4)

	if got := missionStatus(e, "m1"); got != MissionCompleted {
		t.Fatalf("empty-on-quiescence should complete, got %s", got)
	}
}

func TestDecider_ContextCarriesOwnMissionAndCapabilities(t *testing.T) {
	var captured MissionContext
	llm := llmFunc(func(_ context.Context, mc MissionContext) (DeciderOutput, error) {
		captured = mc
		return DeciderOutput{Complete: &DeciderComplete{Outcome: "success"}}, nil
	})
	e, dw := goalEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "recon the net", Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "scan"}}})
	runRounds(e, dw, 6)

	if captured.MissionID != "m1" || captured.Goal != "recon the net" {
		t.Errorf("context mission/goal wrong: %+v", captured)
	}
	if len(captured.Capabilities) != 1 || captured.Capabilities[0].Name != "exploit" {
		t.Errorf("context should carry the capability catalog, got %+v", captured.Capabilities)
	}
}

func TestDecider_MissionSlotFlowsToContext(t *testing.T) {
	var captured MissionContext
	llm := llmFunc(func(_ context.Context, mc MissionContext) (DeciderOutput, error) {
		captured = mc
		return DeciderOutput{Complete: &DeciderComplete{Outcome: "success"}}, nil
	})
	e, dw := goalEngine(llm)
	e.Submit(MissionProjected{ID: "m1", Goal: "g", DeciderSlot: DeciderSlot{Provider: "anthropic", Model: "claude-opus-4-8"}})
	runRounds(e, dw, 4)

	if captured.DeciderSlot.Provider != "anthropic" || captured.DeciderSlot.Model != "claude-opus-4-8" {
		t.Fatalf("decider slot not carried into context: %+v", captured.DeciderSlot)
	}
}

// llmFunc adapts a func to DeciderLLM.
type llmFunc func(context.Context, MissionContext) (DeciderOutput, error)

func (f llmFunc) Decide(ctx context.Context, mc MissionContext) (DeciderOutput, error) { return f(ctx, mc) }
