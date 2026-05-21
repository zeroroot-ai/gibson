// Tests for the sandbox-eviction-handler sidecar binary. The handler's
// contract is small: poll the notice path on every tick, cordon the node
// on appearance, idle until shutdown. Each test drives run() with an
// injectable tick channel and a fake cordonner so the assertions stay
// deterministic.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeCordonner counts cordon invocations and lets the test choose
// whether each call succeeds. Once succeeded==true is set, the call
// returns nil; otherwise it returns failErr (also configurable).
type fakeCordonner struct {
	mu      sync.Mutex
	calls   atomic.Int32
	succeed bool
	failErr error
}

func (f *fakeCordonner) cordon(_ context.Context, _ string) error {
	f.calls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.succeed {
		return nil
	}
	return f.failErr
}

// existsAfter returns a fileExistsFunc that flips from "absent" to
// "present" after the n-th call. Used to simulate aws-node-termination-
// handler creating the notice file partway through the run loop.
func existsAfter(n int32) (fn fileExistsFunc, calls *atomic.Int32) {
	c := &atomic.Int32{}
	return func(_ string) bool {
		v := c.Add(1)
		return v > n
	}, c
}

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRun_CordonsOnNoticeAppearance is the happy path: notice file
// appears on the third poll, cordon succeeds, and the handler stays in
// its idle loop until ctx cancellation.
func TestRun_CordonsOnNoticeAppearance(t *testing.T) {
	t.Parallel()

	cord := &fakeCordonner{succeed: true}
	exists, _ := existsAfter(2)

	tick := make(chan time.Time, 8)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, runConfig{
			nodeName:   "test-node",
			noticeFile: "/dev/null/notice",
			cordonner:  cord,
			exists:     exists,
			tick:       tick,
			logger:     silentLogger(),
		})
	}()

	for i := 0; i < 5; i++ {
		tick <- time.Now()
	}

	// Allow the goroutine to process ticks then cancel.
	time.Sleep(20 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("run returned err=%v, want nil", err)
	}
	if got := cord.calls.Load(); got != 1 {
		t.Errorf("cordon called %d times, want exactly 1 (idempotent after success)", got)
	}
}

// TestRun_RetriesOnCordonFailure verifies that a failed cordon call does
// NOT mark the handler "cordoned" — the next tick should retry.
func TestRun_RetriesOnCordonFailure(t *testing.T) {
	t.Parallel()

	cord := &fakeCordonner{succeed: false, failErr: errors.New("transient API outage")}
	exists := func(_ string) bool { return true }
	tick := make(chan time.Time, 4)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, runConfig{
			nodeName:   "test-node",
			noticeFile: "/notice",
			cordonner:  cord,
			exists:     exists,
			tick:       tick,
			logger:     silentLogger(),
		})
	}()

	tick <- time.Now()
	tick <- time.Now()
	tick <- time.Now()

	time.Sleep(20 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("run returned err=%v, want nil", err)
	}
	if got := cord.calls.Load(); got < 2 {
		t.Errorf("cordon called %d times after failures, want at least 2 retries", got)
	}
}

// TestRun_NoNoticeNoCordon: when the notice file never appears, the
// handler must never invoke the cordon API.
func TestRun_NoNoticeNoCordon(t *testing.T) {
	t.Parallel()

	cord := &fakeCordonner{succeed: true}
	tick := make(chan time.Time, 4)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- run(ctx, runConfig{
			nodeName:   "test-node",
			noticeFile: "/notice",
			cordonner:  cord,
			exists:     func(_ string) bool { return false },
			tick:       tick,
			logger:     silentLogger(),
		})
	}()

	for i := 0; i < 4; i++ {
		tick <- time.Now()
	}
	time.Sleep(20 * time.Millisecond)
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("run returned err=%v, want nil", err)
	}
	if got := cord.calls.Load(); got != 0 {
		t.Errorf("cordon called %d times when notice was absent, want 0", got)
	}
}

// TestRun_ContextCancelExits: a cancelled context must drain the run
// loop cleanly with nil error so the DaemonSet's restart policy can
// observe a graceful shutdown.
func TestRun_ContextCancelExits(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	err := run(ctx, runConfig{
		nodeName:   "test-node",
		noticeFile: "/notice",
		cordonner:  &fakeCordonner{succeed: true},
		exists:     func(_ string) bool { return false },
		tick:       make(chan time.Time),
		logger:     silentLogger(),
	})
	if err != nil {
		t.Errorf("run on cancelled ctx returned err=%v, want nil", err)
	}
}
