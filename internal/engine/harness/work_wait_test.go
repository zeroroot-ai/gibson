// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"go.opentelemetry.io/otel/trace/noop"
)

// waitQueueFake answers WaitForResult from a script: one entry per call. It
// records the bound each call was given, which is how the node-timeout tests
// assert what the wait was actually bounded by.
type waitQueueFake struct {
	mu     sync.Mutex
	bounds []time.Duration

	// script is consumed one entry per call; the last entry repeats.
	script []waitStep
	calls  int
}

type waitStep struct {
	result *component.WorkResult
	err    error
}

func (q *waitQueueFake) WaitForResult(_ context.Context, workID string, timeout time.Duration) (*component.WorkResult, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.bounds = append(q.bounds, timeout)
	step := q.script[len(q.script)-1]
	if q.calls < len(q.script) {
		step = q.script[q.calls]
	}
	q.calls++
	if step.err != nil {
		return nil, step.err
	}
	if step.result != nil {
		return step.result, nil
	}
	return &component.WorkResult{WorkID: workID}, nil
}

func (q *waitQueueFake) boundsSeen() []time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]time.Duration(nil), q.bounds...)
}

func (q *waitQueueFake) Enqueue(context.Context, string, string, string, component.WorkItem) (string, error) {
	return "1-0", nil
}

func (q *waitQueueFake) Claim(context.Context, string, string, string, string, time.Duration) (*component.WorkItem, error) {
	return nil, nil
}
func (q *waitQueueFake) DeliverResult(context.Context, string, component.WorkResult) error {
	return nil
}
func (q *waitQueueFake) Acknowledge(context.Context, string, string, string, string) error {
	return nil
}
func (q *waitQueueFake) ReclaimAbandoned(context.Context, string, string, string, time.Duration) error {
	return nil
}

// livenessRegistry answers Discover from a script of presence values, so a test
// can make a worker vanish, come back, or fail to answer.
type livenessRegistry struct {
	mu       sync.Mutex
	present  []bool // one entry per call; the last repeats
	calls    int
	err      error
	instance string
}

func (r *livenessRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	here := r.present[len(r.present)-1]
	if r.calls < len(r.present) {
		here = r.present[r.calls]
	}
	r.calls++
	if !here {
		return nil, nil
	}
	id := r.instance
	if id == "" {
		id = "i1"
	}
	return []component.ComponentInfo{{Kind: "agent", Name: "zerocool", InstanceID: id}}, nil
}

func (r *livenessRegistry) probes() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *livenessRegistry) DiscoverSystemOnly(context.Context, string, string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func (r *livenessRegistry) Register(context.Context, string, string, string, component.ComponentInfo) (string, error) {
	return "", nil
}
func (r *livenessRegistry) Deregister(context.Context, string, string, string, string) error {
	return nil
}
func (r *livenessRegistry) RefreshTTL(context.Context, string, string, string, string) error {
	return nil
}
func (r *livenessRegistry) DiscoverAll(context.Context, string, string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *livenessRegistry) ListTenantComponents(context.Context, string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *livenessRegistry) DiscoverTenantOnly(context.Context, string, string, string) ([]component.ComponentInfo, error) {
	return nil, nil
}

func newWaitHarness(t *testing.T, q component.WorkQueue, reg component.ComponentRegistry) *DefaultAgentHarness {
	t.Helper()
	return &DefaultAgentHarness{
		logger:            slog.New(slog.NewTextHandler(noopWriter{}, nil)),
		tracer:            noop.NewTracerProvider().Tracer("test"),
		metrics:           &NoOpMetricsRecorder{},
		workQueue:         q,
		componentRegistry: reg,
		// Probe in microseconds so a liveness test is a unit test, not a wall clock.
		livenessProbeEvery: time.Microsecond,
	}
}

func liveAgentPolicy() waitPolicy {
	return waitPolicy{
		livenessBounded: true,
		tenant:          "acme",
		kind:            "agent",
		name:            "zerocool",
		instanceID:      "i1",
	}
}

// deadlineErr is what WaitForResult returns when its slice expires: the redis
// implementation wraps the timeout context's error, so the wait loop keys on
// errors.Is(err, context.DeadlineExceeded) and this fake matches that shape.
func deadlineErr() error {
	return fmt.Errorf("work queue wait for result: timeout waiting for work w1: %w", context.DeadlineExceeded)
}

func TestWaitForWorkResult_ANodeTimeoutBoundsTheWait(t *testing.T) {
	// The defect: MissionNode.timeout never reached the wait, so every dispatch
	// got the one harness-wide value (gibson#1602).
	q := &waitQueueFake{script: []waitStep{{result: &component.WorkResult{WorkID: "w1"}}}}
	h := newWaitHarness(t, q, &livenessRegistry{present: []bool{true}})
	h.workQueueTimeout = 5 * time.Minute

	p := liveAgentPolicy()
	p.bound = 8 * time.Hour

	if _, err := h.waitForWorkResult(context.Background(), "w1", p); err != nil {
		t.Fatalf("wait: %v", err)
	}
	bounds := q.boundsSeen()
	if len(bounds) != 1 {
		t.Fatalf("want one wait call, got %d", len(bounds))
	}
	// The bound is the node's, minus the microseconds spent getting here.
	if bounds[0] <= 7*time.Hour {
		t.Fatalf("wait was bounded by %s, want the node's 8h timeout", bounds[0])
	}
}

func TestWaitForWorkResult_ANodeWithoutATimeoutKeepsTheDefaultWhenItIsNotLive(t *testing.T) {
	// Tool and plugin dispatch must be unchanged: their five-minute default is
	// the behaviour they have always had.
	q := &waitQueueFake{script: []waitStep{{result: &component.WorkResult{WorkID: "w1"}}}}
	h := newWaitHarness(t, q, &livenessRegistry{present: []bool{true}})
	h.workQueueTimeout = 5 * time.Minute

	if _, err := h.waitForWorkResult(context.Background(), "w1", waitPolicy{kind: "tool", name: "nmap"}); err != nil {
		t.Fatalf("wait: %v", err)
	}
	bounds := q.boundsSeen()
	if len(bounds) != 1 {
		t.Fatalf("want one wait call, got %d", len(bounds))
	}
	if bounds[0] > 5*time.Minute || bounds[0] < 4*time.Minute {
		t.Fatalf("tool wait bounded by %s, want the 5m default", bounds[0])
	}
}

func TestWaitForWorkResult_ALiveAgentOutlivesTheDefaultWhileItsWorkerHeartbeats(t *testing.T) {
	// This is the always-on case: the node declares no timeout, the agent keeps
	// working, and the wait must not end just because a clock says five minutes.
	const slices = 40 // far more slices than the default bound would allow
	script := make([]waitStep, 0, slices+1)
	for range slices {
		script = append(script, waitStep{err: deadlineErr()})
	}
	script = append(script, waitStep{result: &component.WorkResult{WorkID: "w1", Result: []byte(`{"status":"success"}`)}})

	q := &waitQueueFake{script: script}
	reg := &livenessRegistry{present: []bool{true}}
	h := newWaitHarness(t, q, reg)
	h.workQueueTimeout = 5 * time.Minute

	res, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy())
	if err != nil {
		t.Fatalf("a live agent whose worker is heartbeating must keep waiting, got: %v", err)
	}
	if string(res.Result) != `{"status":"success"}` {
		t.Fatalf("result = %s", res.Result)
	}
	if q.calls <= slices {
		t.Fatalf("wait gave up after %d slices, want it to keep waiting past %d", q.calls, slices)
	}
	if reg.probes() == 0 {
		t.Fatal("an unbounded wait must probe worker liveness; it never did")
	}
}

func TestWaitForWorkResult_FailsOnceTheWorkerStopsHeartbeating(t *testing.T) {
	// The other half of unbounded: a crashed worker must fail the node, not hang
	// it forever.
	q := &waitQueueFake{script: []waitStep{{err: deadlineErr()}}}
	reg := &livenessRegistry{present: []bool{false}}
	h := newWaitHarness(t, q, reg)

	_, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy())
	if err == nil {
		t.Fatal("want a failure when the worker is gone, got nil")
	}
	if !errors.Is(err, errWorkerGone) {
		t.Fatalf("want errWorkerGone, got %v", err)
	}
	if reg.probes() < livenessGraceProbes {
		t.Fatalf("gave up after %d probes, want at least the %d-probe grace", reg.probes(), livenessGraceProbes)
	}
}

func TestWaitForWorkResult_OneAbsentProbeIsNotEvidence(t *testing.T) {
	// A single missed probe is a blip, not a departure: the worker comes back and
	// the wait must carry on to its result.
	q := &waitQueueFake{script: []waitStep{
		{err: deadlineErr()}, {err: deadlineErr()}, {err: deadlineErr()},
		{result: &component.WorkResult{WorkID: "w1"}},
	}}
	// absent, absent, present → the counter resets before the grace is spent.
	reg := &livenessRegistry{present: []bool{false, false, true}}
	h := newWaitHarness(t, q, reg)

	if _, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy()); err != nil {
		t.Fatalf("a worker that reappears within the grace must not fail the node: %v", err)
	}
}

func TestWaitForWorkResult_ADifferentInstanceIsNotTheWorker(t *testing.T) {
	// Another instance of the same component is a different process and is not
	// holding this work item, so it must not count as the worker being alive.
	q := &waitQueueFake{script: []waitStep{{err: deadlineErr()}}}
	reg := &livenessRegistry{present: []bool{true}, instance: "someone-else"}
	h := newWaitHarness(t, q, reg)

	_, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy())
	if !errors.Is(err, errWorkerGone) {
		t.Fatalf("want errWorkerGone when only a different instance is registered, got %v", err)
	}
}

func TestWaitForWorkResult_AFailingProbeDoesNotEndTheWait(t *testing.T) {
	// A registry that cannot answer is not evidence the worker left. Treating it
	// as a departure would fail live agents on every Redis blip.
	q := &waitQueueFake{script: []waitStep{
		{err: deadlineErr()}, {err: deadlineErr()}, {err: deadlineErr()}, {err: deadlineErr()},
		{result: &component.WorkResult{WorkID: "w1"}},
	}}
	reg := &livenessRegistry{present: []bool{true}, err: errors.New("redis unavailable")}
	h := newWaitHarness(t, q, reg)

	if _, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy()); err != nil {
		t.Fatalf("a probe error must not fail the node: %v", err)
	}
}

func TestWaitForWorkResult_ARealErrorReturnsAtOnce(t *testing.T) {
	// Only a slice expiry loops. A queue error would fail the same way forever.
	boom := errors.New("work queue wait for result: work w1: no owner binding")
	q := &waitQueueFake{script: []waitStep{{err: boom}}}
	h := newWaitHarness(t, q, &livenessRegistry{present: []bool{true}})

	_, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy())
	if !errors.Is(err, boom) {
		t.Fatalf("want the queue error returned verbatim, got %v", err)
	}
	if q.calls != 1 {
		t.Fatalf("want one call, got %d — a non-timeout error must not be retried", q.calls)
	}
}

func TestWaitForWorkResult_WithoutARegistryTheWaitStaysBounded(t *testing.T) {
	// Fail-safe: with no way to observe the worker leaving, waiting forever is
	// worse than the bound this replaces, so an unbounded policy falls back.
	q := &waitQueueFake{script: []waitStep{{result: &component.WorkResult{WorkID: "w1"}}}}
	h := newWaitHarness(t, q, nil)
	h.componentRegistry = nil
	h.workQueueTimeout = 5 * time.Minute

	if _, err := h.waitForWorkResult(context.Background(), "w1", liveAgentPolicy()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	bounds := q.boundsSeen()
	if len(bounds) != 1 || bounds[0] > 5*time.Minute {
		t.Fatalf("want a single bounded wait at the default, got %v", bounds)
	}
}

func TestWaitForWorkResult_CancellingTheMissionEndsTheWait(t *testing.T) {
	// An unbounded wait must still answer to its mission's context.
	q := &waitQueueFake{script: []waitStep{{err: deadlineErr()}}}
	h := newWaitHarness(t, q, &livenessRegistry{present: []bool{true}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.waitForWorkResult(ctx, "w1", liveAgentPolicy())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestWaitPolicyDeadline(t *testing.T) {
	now := time.Now()
	def := 5 * time.Minute

	t.Run("a declared bound wins", func(t *testing.T) {
		d, ok := waitPolicy{bound: time.Hour, livenessBounded: true}.deadline(def, now)
		if !ok || !d.Equal(now.Add(time.Hour)) {
			t.Fatalf("deadline = %v, %v", d, ok)
		}
	})
	t.Run("live and undeclared is unbounded", func(t *testing.T) {
		if _, ok := (waitPolicy{livenessBounded: true}).deadline(def, now); ok {
			t.Fatal("a live node with no declared timeout must have no clock bound")
		}
	})
	t.Run("not live and undeclared keeps the default", func(t *testing.T) {
		d, ok := waitPolicy{}.deadline(def, now)
		if !ok || !d.Equal(now.Add(def)) {
			t.Fatalf("deadline = %v, %v", d, ok)
		}
	})
}

func TestWaitForWorkResult_ANodeTimeoutAlreadyElapsedNeverReachesTheQueue(t *testing.T) {
	// A node whose own timeout runs out before the dispatch reaches the queue has
	// no wait left to spend. Handing the queue a zero or negative bound would
	// either block forever or read as "unbounded", so the wait refuses instead —
	// and it says the node timed out rather than blaming the worker.
	//
	// A one-nanosecond bound is that case: the deadline is already behind us by
	// the time the wait computes what is left of it.
	q := &waitQueueFake{script: []waitStep{{result: &component.WorkResult{WorkID: "w1"}}}}
	h := newWaitHarness(t, q, &livenessRegistry{present: []bool{true}})

	p := waitPolicy{kind: "tool", name: "nmap", bound: time.Nanosecond}

	_, err := h.waitForWorkResult(context.Background(), "w1", p)
	if err == nil {
		t.Fatal("an already-elapsed node timeout must fail the wait")
	}
	if !strings.Contains(err.Error(), "already elapsed") {
		t.Fatalf("error must name the elapsed node timeout, got %v", err)
	}
	if got := len(q.boundsSeen()); got != 0 {
		t.Fatalf("the queue must never be waited on, got %d call(s)", got)
	}
}

func TestProbeInterval_ProductionUsesTheConstantNotTheTestSeam(t *testing.T) {
	// livenessProbeEvery exists so a liveness test runs in microseconds. Production
	// leaves it zero, and must then get the real interval — a zero probe interval
	// would spin the wait loop against the registry as fast as the CPU allows.
	h := &DefaultAgentHarness{}
	if got := h.probeInterval(); got != livenessProbeInterval {
		t.Fatalf("unset seam must yield %s, got %s", livenessProbeInterval, got)
	}

	h.livenessProbeEvery = 3 * time.Millisecond
	if got := h.probeInterval(); got != 3*time.Millisecond {
		t.Fatalf("a set seam must win, got %s", got)
	}
}

func TestWorkerAlive_WithoutAnInstanceIDAnyLiveInstanceCounts(t *testing.T) {
	// A queue-dispatched worker has no instance id of its own, so liveness is
	// "does this component have any live instance". Requiring a match would
	// report every such worker as gone the moment it started.
	h := newWaitHarness(t, &waitQueueFake{}, &livenessRegistry{present: []bool{true}})
	p := liveAgentPolicy()
	p.instanceID = ""

	alive, err := h.workerAlive(context.Background(), p)
	if err != nil {
		t.Fatalf("workerAlive: %v", err)
	}
	if !alive {
		t.Fatal("a component with a live instance must count as alive")
	}

	none := newWaitHarness(t, &waitQueueFake{}, &livenessRegistry{present: []bool{false}})
	alive, err = none.workerAlive(context.Background(), p)
	if err != nil {
		t.Fatalf("workerAlive: %v", err)
	}
	if alive {
		t.Fatal("no instances at all must not count as alive")
	}
}
