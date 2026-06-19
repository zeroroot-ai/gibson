package brain

import (
	"context"
	"sync"
	"time"
)

// TickInterval is the clock-tick period (ADR-0004): ~one gRPC round-trip, the
// fastest an external result can arrive. Ticking faster polls for nothing.
const TickInterval = 50 * time.Millisecond

// intakeBuffer bounds the number of un-applied events Submit can queue between
// ticks before it blocks (back-pressure).
const intakeBuffer = 4096

// maxSweeps caps the drain+systems iterations within one tick, guarding against a
// non-quiescent system that emits an event every call (a programming error).
const maxSweeps = 1024

// System is a unit of behavior over the World (ADR-0001): it reads the World and
// returns domain events to apply. Systems must be **quiescent** — once their work
// is reflected in the World they return no events — so a tick settles.
type System func(*World) []Event

// Engine drives the brain as a clock-tick game loop (ADR-0004). Each Tick drains
// the intake queue and runs the systems, sweeping to quiescence so an in-memory
// cascade settles within one tick. The Engine owns the single-writer reducer:
// only Tick/Run mutate the World, so concurrent producers Submit (enqueue) and
// read Snapshots safely.
type Engine struct {
	World    *World
	Timeline *Timeline
	intake   chan Event
	systems  []System

	// mu guards World + Timeline. The tick (single writer) takes the write lock;
	// external readers (e.g. the read-path gRPC handlers) take the read lock so
	// they never race the reducer. Submit does not touch the World, so it is
	// lock-free.
	mu sync.RWMutex
}

// NewEngine creates an Engine with an empty Tenant World and Timeline.
func NewEngine(tenant string) *Engine {
	return &Engine{
		World:    NewWorld(tenant),
		Timeline: &Timeline{},
		intake:   make(chan Event, intakeBuffer),
	}
}

// AddSystem registers a system to run every tick (e.g., the Orchestrator).
func (e *Engine) AddSystem(s System) { e.systems = append(e.systems, s) }

// Submit enqueues an event for application on the next tick. Safe from any
// goroutine; never mutates the World directly.
func (e *Engine) Submit(ev Event) { e.intake <- ev }

func (e *Engine) apply(ev Event) {
	e.Timeline.Append(ev)
	Reduce(e.World, ev)
}

func (e *Engine) drainIntake() int {
	n := 0
	for {
		select {
		case ev := <-e.intake:
			e.apply(ev)
			n++
		default:
			return n
		}
	}
}

func (e *Engine) runSystems() int {
	n := 0
	for _, sys := range e.systems {
		for _, ev := range sys(e.World) {
			e.apply(ev)
			n++
		}
	}
	return n
}

// Tick applies queued events and runs systems, sweeping to quiescence (events
// beget systems beget events) until nothing new is produced. Returns the number
// of events applied.
func (e *Engine) Tick() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	applied := 0
	for i := 0; i < maxSweeps; i++ {
		n := e.drainIntake() + e.runSystems()
		applied += n
		if n == 0 {
			break
		}
	}
	return applied
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

// Read accessors — read-locked, safe to call concurrently with the tick loop
// (the read path / Scroller use these). They return value snapshots, never live
// references into the World.

// Hosts returns the current host snapshots.
func (e *Engine) Hosts() []HostSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.Snapshot()
}

// Missions returns the current mission snapshots.
func (e *Engine) Missions() []MissionSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.MissionSnapshot()
}

// Work returns the current work-item snapshots.
func (e *Engine) Work() []WorkSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.WorkSnapshot()
}

// Findings returns the current finding snapshots.
func (e *Engine) Findings() []FindingSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.FindingSnapshot()
}

// Domains returns the current domain snapshots.
func (e *Engine) Domains() []DomainSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.DomainSnapshot()
}

// Subdomains returns the current subdomain snapshots.
func (e *Engine) Subdomains() []SubdomainSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.SubdomainSnapshot()
}

// Events returns a copy of the Timeline (the Scroller scrubs this).
func (e *Engine) Events() []Event {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Event(nil), e.Timeline.Events()...)
}
