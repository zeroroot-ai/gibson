package brain

import (
	"context"
	"time"
)

// executor.go makes the brain a LIVE mission engine (gibson#851): it wires the
// dispatch effect-handler and the async Decider worker onto an engine and drains
// them off the tick. Until this is wired, the engine only reduces/observes; with
// it, agent observations → World, the Scheduler dispatches scripted work, and the
// Decider drives goal missions — the brain IS the orchestrator.

// ExecutorSystems returns the mission-execution Systems in the order they must
// run within a tick: budget first (abort an over-budget mission before it
// dispatches more), then scheduler/condition (advance the scripted graph), retry
// (re-arm failures before completion judges them), the Decider gate (request
// decisions on current state), and completion last (mechanical no-goal finish).
// The daemon installs these alongside the belief System on the per-tenant engines.
func ExecutorSystems() []System {
	return []System{
		BudgetSystem,
		SchedulerSystem,
		ConditionSystem,
		RetrySystem,
		DeciderGateSystem,
		MissionCompletionSystem,
	}
}

// ExecutorDeps are the live bindings the daemon supplies (concrete Dispatcher +
// DeciderLLM that route by mission, and the tenant capability catalog).
type ExecutorDeps struct {
	Dispatcher    Dispatcher
	Decider       DeciderLLM
	Catalog       func() []Capability
	DrainInterval time.Duration // how often to actuate buffered dispatch/decision work
}

// WireExecutor subscribes the dispatch + decider taps to eng and starts a single
// drain goroutine (bound to ctx) that actuates buffered work off the tick. The
// taps run in-tick and only buffer; Drain does the I/O (LLM calls, agent
// dispatch) so the ~50ms tick never blocks (ADR-0004/0009).
func WireExecutor(ctx context.Context, eng *Engine, deps ExecutorDeps) {
	interval := deps.DrainInterval
	if interval <= 0 {
		interval = TickInterval
	}
	dh := NewDispatchHandler(deps.Dispatcher)
	dw := NewDeciderWorker(eng, deps.Decider, deps.Catalog)
	eng.Subscribe(dh.Tap)
	eng.Subscribe(dw.Tap)

	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				dh.Drain()
				dw.Drain(context.Background())
				return
			case <-t.C:
				dh.Drain()
				dw.Drain(ctx)
			}
		}
	}()
}
