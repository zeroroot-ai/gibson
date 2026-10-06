// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
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

	reg := NewRegistry(context.Background(), memStoreFactory(), ExecutorSystems()...)
	disp := &goroutineDispatcher{}
	beliefRegistry := liveBeliefRegistry(t)
	reg.OnEngine(func(e *Engine) {
		disp.eng = e
		// The daemon wires the VoI planner beside the executor. The Decider
		// waits for the plan that the VoI gate requested, so an engine with
		// the gate and no planner never decides.
		WireVoIPlanner(context.Background(), e, beliefRegistry, ExactVoIScorer(), DefaultVoITopK,
			5*time.Millisecond, nil, testBAMCPPlanner(beliefRegistry))
		WireExecutor(context.Background(), e, ExecutorDeps{
			Dispatcher:    disp,
			Decider:       llm,
			Catalog:       func(string) []Capability { return []Capability{{Kind: "agent", Name: "exploit"}} },
			DrainInterval: 5 * time.Millisecond,
		})
	})

	eng := reg.For("t1")         // creates engine, wires executor, starts tick + drain loops
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
	reg := NewRegistry(context.Background(), memStoreFactory(), ExecutorSystems()...)
	disp := &goroutineDispatcher{}
	reg.OnEngine(func(e *Engine) {
		disp.eng = e
		WireExecutor(context.Background(), e, ExecutorDeps{
			Dispatcher:    disp,
			Decider:       &scriptedLLM{}, // never called for a no-goal mission
			Catalog:       func(string) []Capability { return nil },
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

// A nil capability catalog is a wiring defect: the VoI gate would refuse each
// Decider dispatch (gibson#693). WireExecutor must stop the start.
func TestWireExecutor_NilCatalogPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WireExecutor accepted a nil capability catalog")
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	WireExecutor(ctx, NewEngine("t1", &memTimelineStore{}), ExecutorDeps{
		Dispatcher: &goroutineDispatcher{},
		Decider:    &scriptedLLM{},
	})
}

// The VoI planner reads the catalog that WireExecutor set on the engine, in
// each order of the two Wire calls. The daemon wires the planner first.
func TestWireExecutor_GivesThePlannerItsCatalog(t *testing.T) {
	for _, plannerFirst := range []bool{true, false} {
		registry := liveBeliefRegistry(t)
		hierarchy := dispatchTestHierarchy(t)
		hunter := Capability{Kind: "agent", Name: "injection-hunter",
			Coverage: dispatchCoverage(t, hierarchy, []taxonomy.CategoryID{"prompt_injection"}, nil)}
		deps := ExecutorDeps{
			Dispatcher:    &goroutineDispatcher{},
			Decider:       &scriptedLLM{},
			Catalog:       func(string) []Capability { return []Capability{hunter} },
			DrainInterval: time.Hour,
		}

		ctx, cancel := context.WithCancel(context.Background())
		e := NewEngine("t1", &memTimelineStore{})
		e.AddSystem(VoIGateSystem)
		var w *VoIWorker
		if plannerFirst {
			w = WireVoIPlanner(ctx, e, registry, ExactVoIScorer(), DefaultVoITopK, time.Hour, hierarchy, testBAMCPPlanner(registry))
			WireExecutor(ctx, e, deps)
		} else {
			WireExecutor(ctx, e, deps)
			w = WireVoIPlanner(ctx, e, registry, ExactVoIScorer(), DefaultVoITopK, time.Hour, hierarchy, testBAMCPPlanner(registry))
		}

		e.Submit(MissionProjected{ID: "m1", Goal: "find a path"})
		e.Submit(HypothesisObserved{ScopeID: "s", Claim: "the filter is bypassable", Proposer: "a", Technique: "indirect_prompt_injection"})
		voiSettle(e, w, 1)
		cancel()

		plans := e.VoIPlanSnapshot()
		if len(plans) != 1 || len(plans[0].Candidates) != 1 {
			t.Fatalf("plannerFirst=%v: plans = %+v, want one plan with one candidate", plannerFirst, plans)
		}
		got := plans[0].Candidates[0].CoveringCapabilities
		if len(got) != 1 || got[0].Name != "injection-hunter" {
			t.Fatalf("plannerFirst=%v: CoveringCapabilities = %+v, want injection-hunter", plannerFirst, got)
		}
	}
}
