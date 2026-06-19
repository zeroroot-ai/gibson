package brain

import (
	"context"
	"time"
)

// TickInterval is the clock-tick period (ADR-0004): ~one gRPC round-trip, the
// fastest an external result can arrive. Ticking faster polls for nothing.
const TickInterval = 50 * time.Millisecond

// intakeBuffer bounds the number of un-applied events Submit can queue between
// ticks before it blocks (back-pressure).
const intakeBuffer = 4096

// Engine drives the brain as a clock-tick game loop (ADR-0004). Each Tick drains
// the intake queue, appending events to the Timeline and folding them into the
// World. The Engine owns the single-writer reducer: only Tick/Run mutate the
// World, so concurrent producers Submit (enqueue) and read Snapshots safely.
type Engine struct {
	World    *World
	Timeline *Timeline
	intake   chan Event
}

// NewEngine creates an Engine with an empty Tenant World and Timeline.
func NewEngine(tenant string) *Engine {
	return &Engine{
		World:    NewWorld(tenant),
		Timeline: &Timeline{},
		intake:   make(chan Event, intakeBuffer),
	}
}

// Submit enqueues an event for application on the next tick. Safe to call from
// any goroutine; never mutates the World directly.
func (e *Engine) Submit(ev Event) { e.intake <- ev }

// Tick drains every event queued since the last tick and folds each into the
// World (sweep-to-quiescence: it loops until the intake is empty so an in-memory
// cascade settles within a single tick). Returns the number of events applied.
func (e *Engine) Tick() int {
	applied := 0
	for {
		select {
		case ev := <-e.intake:
			e.Timeline.Append(ev)
			Reduce(e.World, ev)
			applied++
		default:
			return applied
		}
	}
}

// Run ticks every TickInterval until ctx is cancelled. It is the single writer;
// run it in exactly one goroutine per tenant.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			e.Tick() // final drain
			return
		case <-ticker.C:
			e.Tick()
		}
	}
}
