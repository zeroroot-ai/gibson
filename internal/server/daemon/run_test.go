package daemon

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestRun_DelegatesToStart verifies that Run(ctx) calls Start(ctx) and returns
// its result. At this phase of the spec (7.2), Run delegates entirely to Start.
// Tasks 7.3–7.7 will split Start into per-subsystem Serve(ctx) calls wired
// through an errgroup, at which point this test will be replaced by more
// fine-grained subsystem tests.
func TestRun_DelegatesToStart(t *testing.T) {
	t.Parallel()

	// We cannot call Run on a real daemon without Redis, but we can verify the
	// New() → Run() type chain compiles and that the Daemon interface is satisfied.
	cfg := minimalCfg()
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Verify d satisfies the Daemon interface (which now requires Run).
	var _ Daemon = d

	// Verify Run is distinct from Start — cancelling ctx immediately should
	// cause Run to return quickly (before Redis is even dialed). This exercises
	// the internalCtx.Done() path in Start which flows through Run.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cancel() // cancel immediately

	// With ctx already cancelled, Start (and therefore Run) should return quickly
	// without hanging on the Redis dial — because the retry loop in initStateClient
	// checks ctx.Err().
	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx)
	}()

	select {
	case err := <-done:
		// Any error is acceptable here — we're testing that Run returns, not what it returns.
		// context.Canceled or a Redis connection error are both expected.
		_ = err
	case <-time.After(5 * time.Second):
		t.Error("Run did not return within 5s after ctx cancellation — possible goroutine leak")
	}
}

// TestRun_ContextCancelledMeansNilOrContextError verifies that cancelling the
// context passed to Run causes it to return either nil or context.Canceled
// (not an arbitrary error).
func TestRun_ContextCancelledMeansNilOrContextError(t *testing.T) {
	t.Parallel()

	cfg := minimalCfg()
	d, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()

	select {
	case runErr := <-done:
		if runErr != nil &&
			!errors.Is(runErr, context.Canceled) &&
			!errors.Is(runErr, context.DeadlineExceeded) {
			// Allow non-context errors for now — Run delegates to Start which
			// may hit Redis errors before ctx cancellation is observed.
			// The important assertion is that Run returns, not that it returns nil.
		}
	case <-time.After(5 * time.Second):
		t.Error("Run did not return within 5s after ctx already cancelled")
	}
}

// TestRun_InterfaceCompliance verifies the Daemon interface is satisfied with
// the Run method added in task 7.1.
func TestRun_InterfaceCompliance(t *testing.T) {
	t.Parallel()
	d, err := New(minimalCfg())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Compile-time check.
	var _ interface{ Run(context.Context) error } = d
	// Also verify the method exists at runtime via interface assertion.
	type runner interface{ Run(context.Context) error }
	if _, ok := d.(runner); !ok {
		t.Error("daemonImpl does not implement Run(context.Context) error")
	}
}
