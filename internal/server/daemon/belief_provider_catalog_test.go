// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
)

// alwaysDispatch is a Decider that asks for the same dispatch on each call.
type alwaysDispatch struct{ dispatch brain.DeciderDispatch }

func (a alwaysDispatch) Decide(context.Context, brain.MissionContext) (brain.DeciderOutput, error) {
	return brain.DeciderOutput{Dispatches: []brain.DeciderDispatch{a.dispatch}}, nil
}

// recordingDispatcher records each dispatch that passed the gate.
type recordingDispatcher struct {
	mu      sync.Mutex
	targets []string
}

func (r *recordingDispatcher) Dispatch(req brain.DispatchRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.targets = append(r.targets, req.Target)
}

func (r *recordingDispatcher) dispatched(target string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Contains(r.targets, target)
}

// TestWireBrainRegistry_ADeciderDispatchForACoveringCapabilityPassesTheGate
// proves gibson#693 at the daemon level. The registry is wired as Start wires
// it: wireBrainRegistry first, then the executor hook with the capability
// catalog. A hypothesis names a technique, an agent covers the category of that
// technique, and the Decider dispatches that agent. The dispatch must pass the
// VoI gate (ADR-0126).
//
// The test fails when the planner gets no catalog: no candidate then resolves a
// covering capability, and the gate refuses the dispatch.
func TestWireBrainRegistry_ADeciderDispatchForACoveringCapabilityPassesTheGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The global hierarchy holds no technique until a Domain Pack can declare
	// one (gibson#699), so the test adds one technique to it.
	const category = taxonomy.CategoryID("prompt_injection")
	if !taxonomy.GlobalTechniques.HasCategory(category) {
		t.Fatalf("the global hierarchy does not admit the category %q", category)
	}
	hierarchy, err := taxonomy.GlobalTechniques.WithTechnique("indirect_prompt_injection", category)
	if err != nil {
		t.Fatalf("WithTechnique: %v", err)
	}
	coverage, err := taxonomy.NewCoverage(hierarchy, []taxonomy.CategoryID{category}, nil)
	if err != nil {
		t.Fatalf("NewCoverage: %v", err)
	}
	catalog := func(string) []brain.Capability {
		return []brain.Capability{
			{Kind: "agent", Name: "injection-hunter", Coverage: coverage},
			{Kind: "agent", Name: "port-scanner"},
		}
	}

	registry := brain.NewRegistry(ctx, append(
		[]brain.System{brain.BeliefSystem},
		brain.ExecutorSystems()...,
	)...)
	beliefSchemaRegistry, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	beliefProvider, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	wireBrainRegistryWithHierarchy(ctx, registry, beliefProvider,
		resolveSliceBeliefProvider(beliefSchemaRegistry, nil), beliefSchemaRegistry, nil, hierarchy)

	// The executor hook comes second, as in Start (daemon.go).
	disp := &recordingDispatcher{}
	registry.OnEngine(func(e *brain.Engine) {
		brain.WireExecutor(ctx, e, brain.ExecutorDeps{
			Dispatcher:    disp,
			Decider:       alwaysDispatch{brain.DeciderDispatch{Kind: "agent", Target: "injection-hunter", Input: "test the filter"}},
			Catalog:       catalog,
			DrainInterval: 5 * time.Millisecond,
		})
	})

	e := registry.For("tenant-catalog-wire-test")
	e.Submit(brain.MissionProjected{ID: "m1", Goal: "find a path"})
	e.Submit(brain.HypothesisObserved{
		MissionID: "m1", ScopeID: "s", Claim: "the filter is bypassable",
		Proposer: "recon", Technique: "indirect_prompt_injection",
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if disp.dispatched("injection-hunter") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("the gate never passed a dispatch for the covering capability; plans = %+v", e.VoIPlanSnapshot())
}

// TestWireBrainRegistry_PlannerReadsTheEngineCatalog proves that the planner
// of the production entry point reads the capability catalog that the executor
// hook set on the engine. The test fails when the production wiring gives the
// planner a nil catalog, because the planner then never asks for one.
func TestWireBrainRegistry_PlannerReadsTheEngineCatalog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	registry := brain.NewRegistry(ctx, append(
		[]brain.System{brain.BeliefSystem},
		brain.ExecutorSystems()...,
	)...)
	beliefSchemaRegistry, err := newBeliefSchemaRegistry()
	if err != nil {
		t.Fatalf("newBeliefSchemaRegistry: %v", err)
	}
	beliefProvider, err := resolveBeliefProvider()
	if err != nil {
		t.Fatalf("resolveBeliefProvider: %v", err)
	}
	wireBrainRegistry(ctx, registry, beliefProvider, resolveSliceBeliefProvider(beliefSchemaRegistry, nil), beliefSchemaRegistry, nil)

	var mu sync.Mutex
	asked := map[string]bool{}
	registry.OnEngine(func(e *brain.Engine) {
		brain.WireExecutor(ctx, e, brain.ExecutorDeps{
			Dispatcher: &recordingDispatcher{},
			Decider:    &noopDecider{},
			Catalog: func(missionID string) []brain.Capability {
				mu.Lock()
				defer mu.Unlock()
				asked[missionID] = true
				return nil
			},
			DrainInterval: time.Hour, // the Decider never drains, so only the planner asks
		})
	})

	e := registry.For("tenant-catalog-read-test")
	e.Submit(brain.MissionProjected{ID: "m1", Goal: "find a path"})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := asked["m1"]
		mu.Unlock()
		if ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the live planner never read the capability catalog of the mission")
}
