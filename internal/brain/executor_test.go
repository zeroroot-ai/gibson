package brain

import (
	"context"
	"testing"
	"time"
)

// goroutineDispatcher actuates agent work by immediately reporting completion back
// to the engine (stands in for the real harness dispatch).
type goroutineDispatcher struct{ eng *Engine }

func (g *goroutineDispatcher) Dispatch(req DispatchRequest) {
	g.eng.Submit(WorkCompleted{ID: req.WorkID, Result: "ran:" + req.Target})
}

func TestWireExecutor_DrivesGoalMissionEndToEnd(t *testing.T) {
	llm := &scriptedLLM{outputs: []DeciderOutput{
		{Dispatches: []DeciderDispatch{{Kind: "agent", Target: "exploit", Input: "go"}}},
		{Complete: &DeciderComplete{Outcome: "success", Reason: "done"}},
	}}

	reg := NewRegistry(context.Background(), ExecutorSystems()...)
	disp := &goroutineDispatcher{}
	reg.OnEngine(func(e *Engine) {
		disp.eng = e
		WireExecutor(context.Background(), e, ExecutorDeps{
			Dispatcher:    disp,
			Decider:       llm,
			Catalog:       func() []Capability { return []Capability{{Kind: "agent", Name: "exploit"}} },
			DrainInterval: 5 * time.Millisecond,
		})
	})

	eng := reg.For("t1")          // creates engine, wires executor, starts tick + drain loops
	eng.Submit(MissionProjected{ // goal mission, one scripted recon node
		ID: "m1", Goal: "find flag",
		Nodes: []WorkNode{{ID: "a", Kind: "tool", Target: "recon"}},
	})

	// The live engine (tick loop) + drain loop drive it to completion asynchronously.
	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("mission did not complete; missions=%+v work=%+v", eng.Missions(), eng.Work())
		default:
		}
		ms := eng.Missions()
		if len(ms) == 1 && ms[0].Status == MissionCompleted {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestWireExecutor_NoGoalMissionCompletesMechanically(t *testing.T) {
	reg := NewRegistry(context.Background(), ExecutorSystems()...)
	disp := &goroutineDispatcher{}
	reg.OnEngine(func(e *Engine) {
		disp.eng = e
		WireExecutor(context.Background(), e, ExecutorDeps{
			Dispatcher:    disp,
			Decider:       &scriptedLLM{}, // never called for a no-goal mission
			Catalog:       func() []Capability { return nil },
			DrainInterval: 5 * time.Millisecond,
		})
	})

	eng := reg.For("t1")
	eng.Submit(MissionProjected{ID: "m1", Nodes: []WorkNode{
		{ID: "a", Kind: "tool", Target: "recon"},
		{ID: "b", Kind: "tool", Target: "scan", DependsOn: []string{"a"}},
	}})

	deadline := time.After(3 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatalf("no-goal mission did not complete; work=%+v", eng.Work())
		default:
		}
		ms := eng.Missions()
		if len(ms) == 1 && ms[0].Status == MissionCompleted {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
