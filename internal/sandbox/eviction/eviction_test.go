package eviction_test

// Unit tests for the spot-eviction drain handler.
//
// Design: setec-sandbox-prod-default §C7 Task 49 / NFR-R1
//
// All tests use:
//  - A fake clock (no real timers) so tests complete immediately.
//  - A fake NodeCordonner that records whether CordonNode was called.
//  - A fake fileExists function that the Watch test controls.
//
// The fake clock works by replacing time.After with a channel the test
// triggers manually, making timing assertions deterministic.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/sandbox/eviction"
)

// --- Fake helpers -----------------------------------------------------------

// fakeCordonner records whether CordonNode was called and with which node.
type fakeCordonner struct {
	mu       sync.Mutex
	called   bool
	lastName string
	err      error // if non-nil, CordonNode returns this error
}

func (f *fakeCordonner) CordonNode(_ context.Context, nodeName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = true
	f.lastName = nodeName
	return f.err
}

func (f *fakeCordonner) WasCalled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.called
}

func (f *fakeCordonner) LastNode() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastName
}

// fakeClock controls After() and NewTicker() calls so tests can advance
// time deterministically. Each call to After returns the same internal
// channel; the test fires it by calling Advance(). NewTicker returns a
// separate channel (tickCh) the test can fire independently via Tick().
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	afterCh chan time.Time
	tickCh  chan time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{
		now:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		afterCh: make(chan time.Time, 1),
		tickCh:  make(chan time.Time, 1),
	}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After returns the shared afterCh. Production callers pass different
// durations but the fake ignores the duration; tests call Advance() to fire
// the timer.
func (f *fakeClock) After(_ time.Duration) <-chan time.Time {
	return f.afterCh
}

// NewTicker returns the shared tickCh and a no-op stop function.
func (f *fakeClock) NewTicker(_ time.Duration) (<-chan time.Time, func()) {
	return f.tickCh, func() {}
}

// Advance sends the current fake time on the After channel, simulating
// grace timer expiry in BeginDrain.
func (f *fakeClock) Advance() {
	f.mu.Lock()
	t := f.now
	f.mu.Unlock()
	select {
	case f.afterCh <- t:
	default:
	}
}

// Tick sends a tick on the tickCh, simulating a NewTicker firing in Watch.
func (f *fakeClock) Tick() {
	f.mu.Lock()
	t := f.now
	f.mu.Unlock()
	select {
	case f.tickCh <- t:
	default:
	}
}

// --- Tests ------------------------------------------------------------------

// TestDrain_ZeroInFlight verifies that a drain with no registered
// detonations completes without cancellations, marks health degraded, and
// cordons the node.
func TestDrain_ZeroInFlight(t *testing.T) {
	t.Parallel()

	fc := newFakeClock()
	cordonner := &fakeCordonner{}
	healthCh := make(chan eviction.HealthState, 1)

	h, err := eviction.NewForTest(eviction.TestConfig{
		NodeName:  "sandbox-node-1",
		Cordonner: cordonner,
		Clock:     fc,
		OnHealthChange: func(s eviction.HealthState) {
			select {
			case healthCh <- s:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Advance the fake clock immediately so the grace timer fires.
	go fc.Advance()

	ctx := context.Background()
	if err := h.BeginDrain(ctx, 1*time.Millisecond); err != nil {
		t.Fatalf("BeginDrain: %v", err)
	}

	if !cordonner.WasCalled() {
		t.Error("expected CordonNode to be called; was not")
	}
	if cordonner.LastNode() != "sandbox-node-1" {
		t.Errorf("expected node %q, got %q", "sandbox-node-1", cordonner.LastNode())
	}
	if h.Health() != eviction.HealthDegraded {
		t.Errorf("expected health=degraded, got %s", h.Health())
	}

	select {
	case state := <-healthCh:
		if state != eviction.HealthDegraded {
			t.Errorf("onHealthChange got %s, want degraded", state)
		}
	case <-time.After(time.Second):
		t.Error("onHealthChange never called")
	}
}

// TestDrain_OneInFlightFinishesInTime verifies that a detonation that
// completes (deregisters) within the grace window does NOT get hard-killed.
func TestDrain_OneInFlightFinishesInTime(t *testing.T) {
	t.Parallel()

	fc := newFakeClock()
	cordonner := &fakeCordonner{}

	h, err := eviction.NewForTest(eviction.TestConfig{
		NodeName:  "sandbox-node-2",
		Cordonner: cordonner,
		Clock:     fc,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Register a detonation with a cancel function.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancelCalled := &atomic.Bool{}
	wrappedCancel := func() {
		cancelCalled.Store(true)
		cancel()
	}
	deregister := h.Register("det-001", wrappedCancel)

	// Simulate the detonation completing quickly: it deregisters itself
	// just after BeginDrain starts (in a concurrent goroutine).
	drainStarted := make(chan struct{})
	go func() {
		<-drainStarted
		// Small sleep so BeginDrain can broadcast the cancel before we
		// deregister (otherwise we race with the snapshot loop).
		time.Sleep(5 * time.Millisecond)
		deregister()
		// Advance clock so grace timer fires.
		fc.Advance()
	}()

	// Signal that BeginDrain is about to start.
	close(drainStarted)

	if err := h.BeginDrain(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("BeginDrain: %v", err)
	}

	if !cancelCalled.Load() {
		t.Error("expected cancel to be called on in-flight detonation")
	}
	if ctx.Err() == nil {
		t.Error("expected detonation context to be cancelled")
	}

	// Hard-kill channel should never have been used because deregister was
	// called. There is no public API to assert that, but we can assert the
	// detonation is no longer tracked.
	if ch := h.HardKillChan("det-001"); ch != nil {
		t.Error("expected HardKillChan to return nil for deregistered detonation")
	}
}

// TestDrain_OneInFlightExceedsGrace verifies that a detonation that does
// NOT deregister within the grace window receives a hard-kill signal.
func TestDrain_OneInFlightExceedsGrace(t *testing.T) {
	t.Parallel()

	fc := newFakeClock()
	cordonner := &fakeCordonner{}

	h, err := eviction.NewForTest(eviction.TestConfig{
		NodeName:  "sandbox-node-3",
		Cordonner: cordonner,
		Clock:     fc,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cancelCalled := &atomic.Bool{}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	wrappedCancel := func() {
		cancelCalled.Store(true)
		cancel()
	}
	// Register but intentionally do NOT call deregister — simulating a
	// stuck detonation that will not clean up on its own.
	_ = h.Register("det-stuck", wrappedCancel)

	// Retrieve the hard-kill channel before drain starts.
	// After drain begins the channel will be closed.
	hkCh := make(chan struct{})
	go func() {
		// Poll until the channel is available (registration must happen
		// before BeginDrain is called, so it's available immediately).
		ch := h.HardKillChan("det-stuck")
		if ch != nil {
			<-ch // blocks until hard-kill fires
		}
		close(hkCh)
	}()

	// Advance the clock in a goroutine so the grace timer fires while
	// BeginDrain is waiting.
	go func() {
		time.Sleep(5 * time.Millisecond)
		fc.Advance()
	}()

	if err := h.BeginDrain(context.Background(), 50*time.Millisecond); err != nil {
		t.Fatalf("BeginDrain: %v", err)
	}

	if !cancelCalled.Load() {
		t.Error("expected cancel to be called on stuck detonation")
	}
	if h.Health() != eviction.HealthDegraded {
		t.Errorf("expected health=degraded after drain, got %s", h.Health())
	}

	// hkCh should be closed because the hard-kill channel was fired.
	select {
	case <-hkCh:
		// pass — hard-kill channel was closed as expected
	case <-time.After(2 * time.Second):
		t.Error("hard-kill channel was not closed within timeout")
	}
}

// TestDrain_Idempotent verifies that a second BeginDrain call returns
// ErrDrainAlreadyStarted and does not double-cancel detonations.
func TestDrain_Idempotent(t *testing.T) {
	t.Parallel()

	fc := newFakeClock()

	h, err := eviction.NewForTest(eviction.TestConfig{
		Cordonner: &fakeCordonner{},
		Clock:     fc,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cancelCount := &atomic.Int32{}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped := func() {
		cancelCount.Add(1)
		cancel()
	}
	_ = h.Register("det-idem", wrapped)

	go fc.Advance()

	ctx := context.Background()
	if err := h.BeginDrain(ctx, 1*time.Millisecond); err != nil {
		t.Fatalf("first BeginDrain: %v", err)
	}

	// Second call must return the sentinel error.
	if err := h.BeginDrain(ctx, 1*time.Millisecond); !isAlreadyStarted(err) {
		t.Errorf("second BeginDrain returned %v, want ErrDrainAlreadyStarted", err)
	}

	// Cancel should have been called exactly once.
	if n := cancelCount.Load(); n != 1 {
		t.Errorf("cancel called %d times, want 1", n)
	}
}

// TestWatch_FileAppearanceTriggersDrain verifies that Watch detects the
// notice file and calls BeginDrain.
func TestWatch_FileAppearanceTriggersDrain(t *testing.T) {
	t.Parallel()

	fc := newFakeClock()
	cordonner := &fakeCordonner{}
	healthCh := make(chan eviction.HealthState, 2)

	filePresent := &atomic.Bool{}
	fakeFileExists := func(_ string) bool {
		return filePresent.Load()
	}

	h, err := eviction.NewForTest(eviction.TestConfig{
		NodeName:  "watch-node",
		Cordonner: cordonner,
		Clock:     fc,
		FileExists: fakeFileExists,
		OnHealthChange: func(s eviction.HealthState) {
			select {
			case healthCh <- s:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancelCtx := context.WithCancel(context.Background())
	defer cancelCtx()

	// Start the watcher (production path).
	h.Watch(ctx)

	// File not yet present — health should remain Up.
	if h.Health() != eviction.HealthUp {
		t.Errorf("expected health=up before notice, got %s", h.Health())
	}

	// Simulate file appearance then trigger a poll tick.
	filePresent.Store(true)
	fc.Tick() // fires Watch's NewTicker channel → Watch sees the file

	// Advance the fake clock so the grace timer in BeginDrain fires. We do
	// this in a loop with a tiny real sleep to avoid a race where the
	// Watch goroutine hasn't called BeginDrain yet when we fire Advance.
	go func() {
		time.Sleep(10 * time.Millisecond)
		fc.Advance()
	}()

	// Wait for health to transition to degraded.
	select {
	case state := <-healthCh:
		if state != eviction.HealthDegraded {
			t.Errorf("expected degraded after notice, got %s", state)
		}
	case <-time.After(5 * time.Second):
		t.Error("health never transitioned to degraded after notice file appeared")
	}

	if !cordonner.WasCalled() {
		t.Error("expected CordonNode to be called after notice")
	}
}

// TestRegister_AfterDrainStarted verifies that registering a new detonation
// after drain has started immediately cancels the provided context function
// so the caller fails fast.
func TestRegister_AfterDrainStarted(t *testing.T) {
	t.Parallel()

	fc := newFakeClock()

	h, err := eviction.NewForTest(eviction.TestConfig{
		Cordonner: &fakeCordonner{},
		Clock:     fc,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	go fc.Advance()

	// Start drain in background.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		_ = h.BeginDrain(context.Background(), 1*time.Millisecond)
	}()
	<-drainDone

	// Now try to register after drain has completed.
	cancelCalled := &atomic.Bool{}
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	wrapped := func() {
		cancelCalled.Store(true)
		cancel()
	}
	deregister := h.Register("det-late", wrapped)
	defer deregister()

	if !cancelCalled.Load() {
		t.Error("expected late registration to cancel immediately; cancel was not called")
	}
}

// isAlreadyStarted is a helper so the test does not import the eviction
// package's sentinel error directly (avoids import-cycle in case the
// test package is external).
func isAlreadyStarted(err error) bool {
	return err != nil && err.Error() == "eviction: drain already started"
}
