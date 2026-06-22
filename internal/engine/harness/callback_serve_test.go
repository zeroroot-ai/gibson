package harness

import (
	"context"
	"log/slog"
	"testing"
	"time"
)

// TestCallbackManager_ServeReturnsOnCancel verifies that Serve blocks while
// the context is live and returns nil when the context is cancelled.
func TestCallbackManager_ServeReturnsOnCancel(t *testing.T) {
	t.Parallel()

	cfg := CallbackConfig{
		// Use an ephemeral port so the test does not collide with a live daemon.
		ListenAddress: "127.0.0.1:0",
		Enabled:       true,
	}
	mgr := NewCallbackManager(cfg, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- mgr.Serve(ctx) }()

	// Give the server a moment to start.
	time.Sleep(20 * time.Millisecond)

	// Verify the manager is running before we cancel.
	if !mgr.IsRunning() {
		t.Error("manager should be running after Serve started")
	}

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned non-nil error on clean cancel: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return within 5s after ctx cancellation")
	}
}

// TestCallbackManager_ServeDisabled verifies that Serve returns quickly when
// the callback server is not enabled (Start is a no-op then we block until cancel).
func TestCallbackManager_ServeNotStartedUntilCalled(t *testing.T) {
	t.Parallel()

	cfg := CallbackConfig{
		ListenAddress: "127.0.0.1:0",
		Enabled:       false,
	}
	mgr := NewCallbackManager(cfg, slog.Default())

	// Manager should not be running before Serve is called.
	if mgr.IsRunning() {
		t.Error("manager should not be running before Serve is called")
	}

	// Serve with an immediately-cancelled context to test the fast-cancel path.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- mgr.Serve(ctx) }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve returned non-nil error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("Serve did not return within 3s for disabled config with pre-cancelled ctx")
	}
}

// TestCallbackManager_ServeIdempotentStop verifies that calling Stop multiple times
// (via Serve's internal Stop + explicit Stop) does not panic or block.
func TestCallbackManager_ServeIdempotentStop(t *testing.T) {
	t.Parallel()

	cfg := CallbackConfig{
		ListenAddress: "127.0.0.1:0",
		Enabled:       true,
	}
	mgr := NewCallbackManager(cfg, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() { done <- mgr.Serve(ctx) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("Serve did not return")
	}

	// Calling Stop() again after Serve has already stopped it must be a no-op.
	stopped := make(chan struct{})
	go func() {
		mgr.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Error("second Stop() call blocked — not idempotent")
	}
}
