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
	World       *World
	Timeline    *Timeline
	intake      chan Event
	systems     []System
	subscribers []func(Event) // live-only event taps (ADR-0009); never fire on Replay

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

// Subscribe registers a live-only event tap, invoked (in Timeline order, inside
// the tick) for every event applied during Tick — but NEVER during Replay, since
// Replay re-folds the Timeline without effects (ADR-0009). The tap must not block
// or do I/O (it runs under the tick lock); buffer and act off the tick. Used by
// the dispatch effect-handler.
func (e *Engine) Subscribe(fn func(Event)) { e.subscribers = append(e.subscribers, fn) }

// Submit enqueues an event for application on the next tick. Safe from any
// goroutine; never mutates the World directly.
func (e *Engine) Submit(ev Event) { e.intake <- ev }

func (e *Engine) apply(ev Event) {
	e.Timeline.Append(ev)
	Reduce(e.World, ev)
	for _, fn := range e.subscribers {
		fn(ev)
	}
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

// RewindTo makes the frame after folding the first n Timeline events the new live
// state: it truncates the Timeline to n events and rebuilds the World by replay
// (ADR-0001: World == fold(Timeline)). Brain-native rewind — the durable record IS
// the Timeline, so rewinding is discarding the tail and re-folding; no checkpoint
// store. n is clamped to [0, len(Timeline)].
//
// Work that was `running` in the rewound frame is left as recorded; the caller
// should reconcile in-flight work (e.g. ResumeFailInFlight) so the engine
// re-engages it, since the original dispatch is no longer outstanding.
func (e *Engine) RewindTo(n int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	evs := e.Timeline.Events()
	if n < 0 {
		n = 0
	}
	if n > len(evs) {
		n = len(evs)
	}
	tl := &Timeline{}
	for _, ev := range evs[:n] {
		tl.Append(ev)
	}
	e.Timeline = tl
	e.World = Replay(e.World.Tenant, tl)
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

// Labels returns the tenant's pooled review labels (ADR-0006) in deterministic
// order — the HITL training signal the offline trainer consumes.
func (e *Engine) Labels() []LabelSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.LabelSnapshot()
}

// ReviewQueue returns the tenant's review queue — surfaced surprises + Findings
// with any applied label — for the async HITL labelling UI. Read-only; building
// it never gates a mission.
func (e *Engine) ReviewQueue() []ReviewItem {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.ReviewQueue()
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

// Credentials returns the current credential snapshots.
func (e *Engine) Credentials() []CredentialSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.CredentialSnapshot()
}

// Accounts returns the current account snapshots.
func (e *Engine) Accounts() []AccountSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.AccountSnapshot()
}

// AgentRuns returns the current agent-run snapshots (run-provenance).
func (e *Engine) AgentRuns() []AgentRunSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.AgentRunSnapshot()
}

// LlmCalls returns the mission's LLM-call provenance (gibson#755) in deterministic
// order — the per-call model + token data the dashboard surfaces in place of the
// retired Langfuse trace/cost views.
func (e *Engine) LlmCalls() []LlmCallSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.LlmCallSnapshot()
}

// Events returns a copy of the Timeline (the Scroller scrubs this).
func (e *Engine) Events() []Event {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Event(nil), e.Timeline.Events()...)
}

// FrameAt returns the World as of folding the first n Timeline events — a replay
// frame (ADR-0001: World == fold(Timeline)). It is a fresh, independent fold, so
// it never touches the live World and is safe to call concurrently with the tick.
// n is clamped to [0, len(Timeline)]; FrameAt(len) reproduces the live World.
func (e *Engine) FrameAt(n int) *World {
	e.mu.RLock()
	evs := e.Timeline.Events()
	if n < 0 {
		n = 0
	}
	if n > len(evs) {
		n = len(evs)
	}
	prefix := append([]Event(nil), evs[:n]...)
	tenant := e.World.Tenant
	e.mu.RUnlock()

	tl := &Timeline{}
	for _, ev := range prefix {
		tl.Append(ev)
	}
	return Replay(tenant, tl)
}
