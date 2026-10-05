// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package brain

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// TickInterval is the clock-tick period (ADR-0104): ~one gRPC round-trip, the
// fastest an external result can arrive. Ticking faster polls for nothing.
const TickInterval = 50 * time.Millisecond

// defaultSnapshotCadence is the number of persisted events between automatic
// snapshot-and-trim cycles (ADR-0163). After every N appended events the Engine
// writes a snapshot and trims the Timeline prefix it covers, bounding the replay
// cost on restart to at most N events plus the restore overhead.
const defaultSnapshotCadence = 100

// intakeBuffer bounds the number of un-applied events Submit can queue between
// ticks before it blocks (back-pressure).
const intakeBuffer = 4096

// appendAttempts is the number of times the tick tries one durable append
// before it stops the engine (ADR-0163). Each try uses the same idempotency key.
const appendAttempts = 3

// appendRetryDelay is the wait before the second try of a durable append. Each
// later try waits twice as long. The tick holds the write lock for the wait, so
// the total stays below one second.
var appendRetryDelay = 50 * time.Millisecond

// maxSweeps caps the drain+systems iterations within one tick, guarding against a
// non-quiescent system that emits an event every call (a programming error).
const maxSweeps = 1024

// System is a unit of behavior over the World (ADR-0101): it reads the World and
// returns domain events to apply. Systems must be **quiescent** — once their work
// is reflected in the World they return no events — so a tick settles.
type System func(*World) []Event

// Engine drives the brain as a clock-tick game loop (ADR-0104). Each Tick drains
// the intake queue and runs the systems, sweeping to quiescence so an in-memory
// cascade settles within one tick. The Engine owns the single-writer reducer:
// only Tick/Run mutate the World, so concurrent producers Submit (enqueue) and
// read Snapshots safely.
type Engine struct {
	World       *World
	Timeline    *Timeline
	intake      chan Event
	systems     []System
	subscribers []func(Event) // live-only event taps (ADR-0109); never fire on Replay

	// store is the durable-log seam (ADR-0163). Nil when no durable store is
	// configured (in-memory only, backward-compatible). Set via WithStore.
	store TimelineStore

	// Snapshot-cadence bookkeeping (ADR-0163). After every
	// snapshotCadence persisted events the engine writes a snapshot and trims
	// the Timeline prefix it covers.
	snapshotCadence    int    // 0 = disabled; defaultSnapshotCadence at construction
	snapshotEventCount int    // events appended since last snapshot
	lastSnapshotSeq    string // AtSeq of the last successfully written snapshot
	lastAppendedSeq    string // seq returned by the most recent successful Append

	// mu guards World + Timeline. The tick (single writer) takes the write lock;
	// external readers (e.g. the read-path gRPC handlers) take the read lock so
	// they never race the reducer. Submit does not touch the World, so it is
	// lock-free.
	mu sync.RWMutex

	// destructiveAuthzOnce/destructiveAuthz lazily construct this engine's
	// DestructiveAuthorizationQueue (ADR-0132, gibson#336) on first access via
	// DestructiveAuthorizationQueue() — see destructive_authz.go. Lazy because
	// most engines never see a destructive proof request.
	destructiveAuthzOnce sync.Once
	destructiveAuthz     *DestructiveAuthorizationQueue

	// stopped closes when the engine stops with an error (ADR-0163). stopErr
	// is written once, before the close, so a reader that sees the close also
	// sees the error. onStop tells the owner (the Registry) to drop the engine.
	stopped  chan struct{}
	stopOnce sync.Once
	stopErr  error
	onStop   func(*Engine)
}

// NewEngine creates an Engine with an empty Tenant World and Timeline.
func NewEngine(tenant string) *Engine {
	return &Engine{
		World:           NewWorld(tenant),
		Timeline:        &Timeline{},
		intake:          make(chan Event, intakeBuffer),
		snapshotCadence: defaultSnapshotCadence,
		stopped:         make(chan struct{}),
	}
}

// Err returns the error that stopped the engine, or nil while the engine runs.
// A stopped engine applies no event and its World is not the fold of the
// Timeline, so a caller must not serve from it (ADR-0163). The Registry drops a
// stopped engine, and the next For builds a new one from the durable store.
func (e *Engine) Err() error {
	select {
	case <-e.stopped:
		return e.stopErr
	default:
		return nil
	}
}

// stop puts the engine in its terminal state. It is safe to call more than once.
// The first error wins.
func (e *Engine) stop(err error) {
	e.stopOnce.Do(func() {
		e.stopErr = err
		close(e.stopped)
		slog.Error("brain/engine: the engine stopped",
			"tenant", e.World.Tenant,
			"err", err,
		)
		if e.onStop != nil {
			e.onStop(e)
		}
	})
}

// WithSnapshotCadence overrides the automatic snapshot-and-trim cadence (number
// of persisted events between snapshots). Set to 0 to disable automatic
// snapshots. Returns the receiver for chaining. Call before Run.
func (e *Engine) WithSnapshotCadence(n int) *Engine {
	e.snapshotCadence = n
	return e
}

// WithStore wires a TimelineStore for durable event persistence (ADR-0163).
// Returns the receiver for chaining. Call before the first Submit or Run.
// A nil store (the default) is safe — the engine operates in-memory only.
func (e *Engine) WithStore(s TimelineStore) *Engine {
	e.store = s
	return e
}

// AddSystem registers a system to run every tick (e.g., the Orchestrator).
func (e *Engine) AddSystem(s System) { e.systems = append(e.systems, s) }

// Subscribe registers a live-only event tap, invoked (in Timeline order, inside
// the tick) for every event applied during Tick — but NEVER during Replay, since
// Replay re-folds the Timeline without effects (ADR-0109). The tap must not block
// or do I/O (it runs under the tick lock); buffer and act off the tick. Used by
// the dispatch effect-handler.
//
// A TAP MUST NOT CALL A LOCKING ACCESSOR (Work, Missions, Findings, …). It runs
// with the write lock held and sync.RWMutex is not reentrant, so taking the read
// lock blocks the tick goroutine against itself — permanently, silently, with no
// panic and no log. A tap that needs World state reads e.World directly, exactly
// as Systems do under the same lock.
//
// This is not hypothetical: the lifecycle projector called eng.Work() to resolve
// a WorkCompleted's mission, and every tenant's engine stopped ticking the first
// time any work item finished (gibson#1206).
func (e *Engine) Subscribe(fn func(Event)) { e.subscribers = append(e.subscribers, fn) }

// Submit enqueues an event for application on the next tick. Safe from any
// goroutine; never mutates the World directly.
//
// A stopped engine drops the event and logs it: the event is in neither the
// Timeline nor the World, so the two stay equal (ADR-0163).
func (e *Engine) Submit(ev Event) {
	select {
	case <-e.stopped:
		e.logDropped(ev)
		return
	default:
	}
	select {
	case e.intake <- ev:
	case <-e.stopped:
		e.logDropped(ev)
	}
}

func (e *Engine) logDropped(ev Event) {
	slog.Warn("brain/engine: the engine is stopped, so the event is dropped",
		"tenant", e.World.Tenant,
		"kind", ev.Kind(),
		"err", e.stopErr,
	)
}

// appendDurable writes ev to the durable log. It tries up to appendAttempts
// times with one idempotency key, so a try whose reply was lost writes nothing
// the second time.
func (e *Engine) appendDurable(ev Event) (string, error) {
	key := uuid.NewString()
	delay := appendRetryDelay
	var lastErr error
	for attempt := 1; attempt <= appendAttempts; attempt++ {
		seq, err := e.store.Append(context.Background(), e.World.Tenant, key, ev)
		if err == nil {
			return seq, nil
		}
		lastErr = err
		slog.Warn("brain/engine: durable append failed",
			"tenant", e.World.Tenant,
			"kind", ev.Kind(),
			"attempt", attempt,
			"err", err,
		)
		if attempt < appendAttempts {
			time.Sleep(delay)
			delay *= 2
		}
	}
	return "", fmt.Errorf("durable append of %q failed after %d tries: %w", ev.Kind(), appendAttempts, lastErr)
}

// apply appends ev to the durable log and then folds it into the World. When
// the append fails after its retries, apply folds nothing, stops the engine and
// returns false (ADR-0163: the append comes before the fold). The caller (the
// tick goroutine) holds the write lock. The append uses context.Background()
// because the tick has no caller context.
func (e *Engine) apply(ev Event) bool {
	snapshotDue := false
	if e.store != nil {
		seq, err := e.appendDurable(ev)
		if err != nil {
			e.stop(err)
			return false
		}
		e.lastAppendedSeq = seq
		if e.snapshotCadence > 0 {
			e.snapshotEventCount++
			if e.snapshotEventCount >= e.snapshotCadence {
				e.snapshotEventCount = 0
				snapshotDue = true
			}
		}
	}
	e.Timeline.Append(ev)
	Reduce(e.World, ev)
	// Snapshot AFTER folding ev so the snapshot's World reflects ev (whose seq is
	// lastAppendedSeq / AtSeq). Snapshotting before the fold would exclude ev from
	// both the snapshot and the exclusive-after-AtSeq tail — losing it on hydrate.
	if snapshotDue {
		e.maybeSnapshot()
	}
	for _, fn := range e.subscribers {
		fn(ev)
	}
	return true
}

// maybeSnapshot writes a snapshot of the current World and trims the Timeline
// prefix it covers. Errors are logged but do not abort the engine.
// Called from apply() under the write lock, so no additional locking is needed.
func (e *Engine) maybeSnapshot() {
	snap := SnapshotWorld(e.World, e.lastAppendedSeq)
	handle, err := e.store.WriteSnapshot(context.Background(), e.World.Tenant, snap)
	if err != nil {
		slog.Error("brain/engine: snapshot write failed",
			"tenant", e.World.Tenant,
			"err", err,
		)
		return
	}
	if err := e.store.TrimTo(context.Background(), e.World.Tenant, handle); err != nil {
		slog.Error("brain/engine: stream trim failed",
			"tenant", e.World.Tenant,
			"err", err,
		)
	}
	e.lastSnapshotSeq = handle
}

func (e *Engine) drainIntake() int {
	n := 0
	for {
		select {
		case ev := <-e.intake:
			if !e.apply(ev) {
				return n
			}
			n++
		default:
			return n
		}
	}
}

func (e *Engine) runSystems() int {
	n := 0
	for _, sys := range e.systems {
		if e.Err() != nil {
			return n
		}
		for _, ev := range sys(e.World) {
			if !e.apply(ev) {
				return n
			}
			n++
		}
	}
	return n
}

// Tick applies queued events and runs systems, sweeping to quiescence (events
// beget systems beget events) until nothing new is produced. Returns the number
// of events applied. A stopped engine applies nothing.
func (e *Engine) Tick() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	applied := 0
	for i := 0; i < maxSweeps; i++ {
		if e.Err() != nil {
			break
		}
		n := e.drainIntake() + e.runSystems()
		applied += n
		if n == 0 {
			break
		}
	}
	return applied
}

// Run ticks every TickInterval until ctx is cancelled or the engine stops with
// an error. It is the single writer; run it in exactly one goroutine per tenant.
func (e *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(TickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-e.stopped:
			return
		case <-ctx.Done():
			e.Tick() // final drain
			return
		case <-ticker.C:
			e.Tick()
		}
	}
}

// Hydrate loads the persisted Timeline from the store and folds it into the
// Engine's live World (ADR-0163 crash-resume: "on resume, work still `running`
// with no completion is marked WorkFailed"). It is called once per Engine, before
// the tick loop starts, so the World is fully reconstructed before the first tick
// applies live events.
//
// Hydrate holds the write lock for the fold so concurrent reads (from gRPC
// handlers that happen to race the hydration) see a consistent World. Effects
// (subscribers) are intentionally NOT fired during the fold — they are live-only
// by ADR-0109. In-flight work left `running` in the recovered World is failed
// via ResumeFailInFlight events, which ARE submitted to the live intake queue so
// the retry system and mission-completion system run on the next tick.
//
// A nil store is a no-op (the Engine operates in-memory only).
//
// Hydrate returns an error when the snapshot or the Timeline tail does not load
// or the snapshot does not restore. The engine then keeps its empty World and
// the caller must not serve from it: after a trim, a replay without the
// snapshot gives a partial World (ADR-0163).
func (e *Engine) Hydrate(ctx context.Context) error {
	if e.store == nil {
		return nil
	}
	tenant := e.World.Tenant

	// A snapshot covers the events up to its AtSeq. The replay then reads only
	// the tail, so its cost is at most snapshotCadence events.
	snap, err := e.store.LoadSnapshot(ctx, tenant)
	if err != nil {
		return fmt.Errorf("brain/engine: hydrate tenant %q: load the snapshot: %w", tenant, err)
	}
	afterSeq := ""
	var restored *World
	if snap != nil {
		restored, err = RestoreWorld(*snap, tenant)
		if err != nil {
			return fmt.Errorf("brain/engine: hydrate tenant %q: restore the snapshot: %w", tenant, err)
		}
		afterSeq = snap.AtSeq
	}

	evs, err := e.store.LoadForReplay(ctx, tenant, afterSeq)
	if err != nil {
		return fmt.Errorf("brain/engine: hydrate tenant %q: load the Timeline: %w", tenant, err)
	}

	if afterSeq == "" && len(evs) == 0 {
		return nil // no history and no snapshot: a new tenant
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if restored != nil {
		e.World = restored
		e.lastSnapshotSeq = afterSeq
	}

	// Fold the tail events into the (possibly snapshot-restored) World.
	// Only the tail (events after the snapshot) goes into the in-memory Timeline
	// so the in-memory Timeline stays bounded.
	tl := &Timeline{}
	for _, ev := range evs {
		tl.Append(ev)
		Reduce(e.World, ev)
	}
	e.Timeline = tl

	// Fail any work that was `running` when the daemon crashed — a crash IS a
	// failure (ADR-0163). Submit them to the live intake queue so the
	// retry System / Decider re-engage on the next tick without re-firing the
	// original dispatch (effects are live-only, ADR-0109).
	for _, failEv := range ResumeFailInFlight(e.World) {
		// Non-blocking: we are not yet running (called before go e.Run(ctx)), so
		// the intake channel has no consumer. Use a direct append so these failure
		// events enter the next tick's drain without blocking.
		e.intake <- failEv
	}

	slog.Info("brain/engine: hydrated World from persisted store",
		"tenant", e.World.Tenant,
		"snapshot_seq", afterSeq,
		"tail_events", len(evs),
	)
	return nil
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

// Labels returns the tenant's pooled review labels (ADR-0106) in deterministic
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

// Observations returns the current out-of-taxonomy observation snapshots
// (ADR-0112).
func (e *Engine) Observations() []ObservationSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.ObservationSnapshot()
}

// Entities returns the typed application-lifecycle entities (gibson#1656) in
// deterministic (label, key) order.
func (e *Engine) Entities() []EntitySnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.EntitySnapshot()
}

// AgentRuns returns the current agent-run snapshots (run-provenance).
func (e *Engine) AgentRuns() []AgentRunSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.AgentRunSnapshot()
}

// Hypotheses returns the current hypothesis snapshots (ADR-0121, gibson#265)
// in deterministic (scope, claim) order — the Hypothesis provenance class,
// distinct from both Evidence and Belief.
func (e *Engine) Hypotheses() []HypothesisSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.HypothesisSnapshot()
}

// VoIPlanSnapshot returns every mission's current value-of-information
// planning state (ADR-0126, gibson#283) in deterministic (MissionID) order —
// the read accessor a caller (a test, or a future admin surface) uses to
// observe VoIGateSystem/VoIWorker's live output without reaching into World
// directly.
func (e *Engine) VoIPlanSnapshot() []VoIPlanSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.VoIPlanSnapshot()
}

// LlmCalls returns the mission's LLM-call provenance (gibson#755) in deterministic
// order — the per-call model + token data the dashboard surfaces in place of the
// retired Langfuse trace/cost views.
func (e *Engine) LlmCalls() []LlmCallSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.LlmCallSnapshot()
}

// AgentToolCalls returns the mission's captured tool I/O (ADR-0120, gibson#271)
// in deterministic order — the flight recorder's tool-call counterpart to
// LlmCalls.
func (e *Engine) AgentToolCalls() []AgentToolCallSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.AgentToolCallSnapshot()
}

// FlightRecorderPolicy returns the tenant's current retention/redaction policy
// (ADR-0120, gibson#271).
func (e *Engine) FlightRecorderPolicy() FlightRecorderPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.FlightRecorderPolicy()
}

// DomainPacks returns the tenant's currently enabled Domain Packs (ADR-0133,
// gibson#381).
func (e *Engine) DomainPacks() []DomainPackSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.World.DomainPackSnapshot()
}

// Events returns a copy of the Timeline (the Scroller scrubs this).
func (e *Engine) Events() []Event {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]Event(nil), e.Timeline.Events()...)
}

// FrameAt returns the World as of folding the first n Timeline events — a replay
// frame (ADR-0101: World == fold(Timeline)). It is a fresh, independent fold, so
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

// MissionEvents returns the mission's slice of the tenant Timeline (gibson#1060) —
// the sub-sequence of events attributable to missionID, in Timeline order and
// re-indexed from 0 by their position in the slice. An empty missionID returns the
// whole Timeline (the tenant-wide view, unchanged). Read-locked; safe to call
// concurrently with the tick.
func (e *Engine) MissionEvents(missionID string) []Event {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return MissionSlice(e.Timeline.Events(), missionID)
}

// MissionFrameAt returns the World as of folding the first n events of the
// mission's slice (gibson#1060) — a mission-scoped replay frame. It is the same
// pure events→world fold as FrameAt, but over the mission's slice of the Timeline
// rather than the whole tenant Timeline, so another mission's events never bleed
// in. It never touches the live World and is safe to call concurrently with the
// tick. n is clamped to [0, len(slice)]; an empty missionID folds the whole
// Timeline (equivalent to FrameAt).
func (e *Engine) MissionFrameAt(missionID string, n int) *World {
	e.mu.RLock()
	slice := MissionSlice(e.Timeline.Events(), missionID)
	tenant := e.World.Tenant
	e.mu.RUnlock()

	if n < 0 {
		n = 0
	}
	if n > len(slice) {
		n = len(slice)
	}
	tl := &Timeline{}
	for _, ev := range slice[:n] {
		tl.Append(ev)
	}
	return Replay(tenant, tl)
}
