// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSessionClient counts launches and records kills so the tests can assert
// on the properties that actually matter: how MANY sandboxes got created, and
// whether they were torn down.
type fakeSessionClient struct {
	SandboxClient // embedded, nil — the per-call surface is unused here

	mu        sync.Mutex
	launches  int32
	killed    []string
	launchErr error
	// block, when non-nil, holds every LaunchSession until closed. Lets a test
	// create a real race rather than hoping for one.
	block chan struct{}
}

func (f *fakeSessionClient) LaunchSession(ctx context.Context, _ SessionLaunchRequest) (LaunchResponse, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return LaunchResponse{}, fmt.Errorf("blocked launch cancelled: %w", ctx.Err())
		}
	}
	if f.launchErr != nil {
		return LaunchResponse{}, f.launchErr
	}
	n := atomic.AddInt32(&f.launches, 1)
	return LaunchResponse{SandboxID: fmt.Sprintf("ns/sb-%d/uid", n)}, nil
}

func (f *fakeSessionClient) Exec(_ context.Context, sandboxID string, argv []string) (ExecStream, error) {
	return &fakeExecStream{sandboxID: sandboxID, argv: argv}, nil
}

func (f *fakeSessionClient) Kill(_ context.Context, sandboxID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killed = append(f.killed, sandboxID)
	return nil
}

func (f *fakeSessionClient) launchCount() int { return int(atomic.LoadInt32(&f.launches)) }

type fakeExecStream struct {
	sandboxID string
	argv      []string
}

func (s *fakeExecStream) Send([]byte) error { return nil }
func (s *fakeExecStream) CloseSend() error  { return nil }
func (s *fakeExecStream) Close() error      { return nil }
func (s *fakeExecStream) Recv() (ExecEvent, error) {
	return ExecEvent{Exit: &ExecExit{Status: ExecExited}}, nil
}

func newTestRegistry(c SessionClient) *SessionRegistry {
	return NewSessionRegistry(c, SessionSpec{Image: "busybox:1.36", VCPU: 1, Memory: "512Mi"})
}

// The whole point of a session: the second command must reach the SAME
// sandbox, or the workspace the first command wrote is invisible.
func TestSessionRegistry_ReusesOneSandboxPerSession(t *testing.T) {
	c := &fakeSessionClient{}
	r := newTestRegistry(c)
	ctx := context.Background()

	first, err := r.Resolve(ctx, "tenant-a", "sess-1")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	second, err := r.Resolve(ctx, "tenant-a", "sess-1")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if first != second {
		t.Fatalf("session not pinned: %q then %q", first, second)
	}
	if got := c.launchCount(); got != 1 {
		t.Fatalf("expected exactly 1 launch, got %d", got)
	}
}

// Two tenants using the same session id must not share a sandbox. The tenant
// half is server-derived, so a collision here would be cross-tenant execution.
func TestSessionRegistry_TenantIsolatesIdenticalSessionIDs(t *testing.T) {
	c := &fakeSessionClient{}
	r := newTestRegistry(c)
	ctx := context.Background()

	a, err := r.Resolve(ctx, "tenant-a", "same-id")
	if err != nil {
		t.Fatalf("tenant-a: %v", err)
	}
	b, err := r.Resolve(ctx, "tenant-b", "same-id")
	if err != nil {
		t.Fatalf("tenant-b: %v", err)
	}
	if a == b {
		t.Fatalf("cross-tenant session collision: both resolved to %q", a)
	}
	if got := c.launchCount(); got != 2 {
		t.Fatalf("expected 2 launches, got %d", got)
	}
}

// A NUL in a session id must not let one tenant forge another's key.
func TestSessionRegistry_KeyCannotBeForgedAcrossTenants(t *testing.T) {
	// Every one of these pairs collides under a single-separator scheme, and
	// session_id is agent-chosen, so it is attacker-controlled input.
	cases := [][2][2]string{
		{{"a", "\x00x"}, {"a\x00", "x"}},
		{{"a", ":b"}, {"a:", "b"}},
		{{"ab", "c"}, {"a", "bc"}},
		{{"t", "1:x"}, {"t1", ":x"}},
	}
	for _, c := range cases {
		l, r := sessionKey(c[0][0], c[0][1]), sessionKey(c[1][0], c[1][1])
		if l == r {
			t.Fatalf("session keys collide: (%q,%q) and (%q,%q) both -> %q",
				c[0][0], c[0][1], c[1][0], c[1][1], l)
		}
	}
}

// Concurrent first-use of one session must launch ONE sandbox, not N. Without
// per-key once-semantics every racing caller launches its own and all but one
// leak (a pinned PVC and a metal node each).
func TestSessionRegistry_ConcurrentFirstUseLaunchesOnce(t *testing.T) {
	c := &fakeSessionClient{block: make(chan struct{})}
	r := newTestRegistry(c)

	const n = 25
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = r.Resolve(context.Background(), "tenant-a", "hot")
		}(i)
	}
	// Let every goroutine pile up on the same key before the launch returns.
	time.Sleep(50 * time.Millisecond)
	close(c.block)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
		if ids[i] != ids[0] {
			t.Fatalf("resolve %d got %q, want %q", i, ids[i], ids[0])
		}
	}
	if got := c.launchCount(); got != 1 {
		t.Fatalf("expected exactly 1 launch under %d concurrent callers, got %d", n, got)
	}
}

// A caller that gives up must not be pinned to someone else's slow launch.
func TestSessionRegistry_WaiterHonoursContextCancellation(t *testing.T) {
	c := &fakeSessionClient{block: make(chan struct{})}
	defer close(c.block)
	r := newTestRegistry(c)

	go func() { _, _ = r.Resolve(context.Background(), "t", "slow") }()
	time.Sleep(30 * time.Millisecond) // let the owner claim the key

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := r.Resolve(ctx, "t", "slow"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("waiter blocked for %s — it is not honouring cancellation", elapsed)
	}
}

// A failed launch must not poison the session forever; the next command gets a
// fresh attempt.
func TestSessionRegistry_FailedLaunchIsNotCached(t *testing.T) {
	c := &fakeSessionClient{launchErr: errors.New("no capacity")}
	r := newTestRegistry(c)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "t", "s"); err == nil {
		t.Fatal("expected first resolve to fail")
	}
	c.launchErr = nil
	id, err := r.Resolve(ctx, "t", "s")
	if err != nil {
		t.Fatalf("retry after failure should succeed, got %v", err)
	}
	if id == "" {
		t.Fatal("retry returned an empty sandbox id")
	}
}

func TestSessionRegistry_ReleaseKillsAndForgets(t *testing.T) {
	c := &fakeSessionClient{}
	r := newTestRegistry(c)
	ctx := context.Background()

	id, err := r.Resolve(ctx, "t", "s")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := r.Release(ctx, "t", "s"); err != nil {
		t.Fatalf("release: %v", err)
	}
	c.mu.Lock()
	killed := append([]string(nil), c.killed...)
	c.mu.Unlock()
	if len(killed) != 1 || killed[0] != id {
		t.Fatalf("expected kill of %q, got %v", id, killed)
	}
	// Forgotten: the next resolve launches a NEW sandbox rather than handing
	// back the killed one.
	again, err := r.Resolve(ctx, "t", "s")
	if err != nil {
		t.Fatalf("resolve after release: %v", err)
	}
	if again == id {
		t.Fatalf("release did not forget the mapping: got the killed id %q back", id)
	}
}

// Releasing an unknown session is success, so a component can call it
// unconditionally on shutdown.
func TestSessionRegistry_ReleaseUnknownIsNoError(t *testing.T) {
	r := newTestRegistry(&fakeSessionClient{})
	if err := r.Release(context.Background(), "t", "never-used"); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

// With no client wired the failure must be explicit and per-call, not a panic
// and not a silent success.
func TestSessionRegistry_UnavailableWithoutClient(t *testing.T) {
	r := NewSessionRegistry(nil, SessionSpec{})
	if _, err := r.Resolve(context.Background(), "t", "s"); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("want ErrSessionUnavailable, got %v", err)
	}
	if _, err := r.Exec(context.Background(), "t", "s", []string{"true"}); !errors.Is(err, ErrSessionUnavailable) {
		t.Fatalf("Exec want ErrSessionUnavailable, got %v", err)
	}
}

func TestSessionRegistry_ExecRequiresArgv(t *testing.T) {
	r := newTestRegistry(&fakeSessionClient{})
	if _, err := r.Exec(context.Background(), "t", "s", nil); err == nil {
		t.Fatal("empty argv must be rejected")
	}
}

// Exec must reach the session's sandbox, not a fresh one.
func TestSessionRegistry_ExecTargetsTheSessionSandbox(t *testing.T) {
	c := &fakeSessionClient{}
	r := newTestRegistry(c)
	ctx := context.Background()

	id, err := r.Resolve(ctx, "t", "s")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	st, err := r.Exec(ctx, "t", "s", []string{"go", "build"})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	defer func() { _ = st.Close() }()
	fs, ok := st.(*fakeExecStream)
	if !ok {
		t.Fatalf("unexpected stream type %T", st)
	}
	if fs.sandboxID != id {
		t.Fatalf("exec went to %q, want the session sandbox %q", fs.sandboxID, id)
	}
	if got := c.launchCount(); got != 1 {
		t.Fatalf("exec launched a second sandbox: %d launches", got)
	}
}

// A registry with a client but empty identifiers must refuse rather than
// resolve into some default session.
func TestSessionRegistry_RejectsEmptyIdentifiers(t *testing.T) {
	r := newTestRegistry(&fakeSessionClient{})
	if _, err := r.Resolve(context.Background(), "", "s"); err == nil {
		t.Fatal("empty tenant must be rejected")
	}
	if _, err := r.Resolve(context.Background(), "t", ""); err == nil {
		t.Fatal("empty session id must be rejected")
	}
}

// Release must not kill a session whose launch failed — there is no sandbox,
// and reporting an error would break the absent-is-success contract.
func TestSessionRegistry_ReleaseAfterFailedLaunchIsSilent(t *testing.T) {
	c := &fakeSessionClient{launchErr: errors.New("no capacity")}
	r := newTestRegistry(c)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, "t", "s"); err == nil {
		t.Fatal("expected the launch to fail")
	}
	// The failed entry is forgotten, so Release sees nothing at all.
	if err := r.Release(ctx, "t", "s"); err != nil {
		t.Fatalf("release after a failed launch must be silent, got %v", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.killed) != 0 {
		t.Fatalf("nothing should have been killed, got %v", c.killed)
	}
}

// A Kill that fails must be reported — a leaked session pins a PVC and a
// metal node, so silently swallowing it hides real cost.
func TestSessionRegistry_ReleaseSurfacesKillFailure(t *testing.T) {
	c := &killFailClient{}
	r := newTestRegistry(c)
	ctx := context.Background()
	if _, err := r.Resolve(ctx, "t", "s"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := r.Release(ctx, "t", "s"); err == nil {
		t.Fatal("a failed kill must be reported, not swallowed")
	}
}

type killFailClient struct{ fakeSessionClient }

func (c *killFailClient) Kill(context.Context, string) error {
	return errors.New("sandbox already gone")
}

// A cancelled Release must not block on an in-flight launch forever.
func TestSessionRegistry_ReleaseHonoursCancellation(t *testing.T) {
	c := &fakeSessionClient{block: make(chan struct{})}
	defer close(c.block)
	r := newTestRegistry(c)

	go func() { _, _ = r.Resolve(context.Background(), "t", "slow") }()
	time.Sleep(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	if err := r.Release(ctx, "t", "slow"); err == nil {
		t.Fatal("release should have honoured the deadline")
	}
}
