// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// capturingPublisher is a test EventPublisher that records the registration and
// every published chunk, and reports whether finish ran.
type capturingPublisher struct {
	mu           sync.Mutex
	tenant       string
	runID        string
	agentName    string
	sandboxID    string
	sandboxClass string
	missionID    string
	missionRunID string
	registered   bool
	finished     bool
	chunks       [][]byte
}

func (p *capturingPublisher) RegisterInstance(tenant string, inst LiveInstance) (publish func([]byte), finish func()) {
	p.mu.Lock()
	p.registered = true
	p.tenant = tenant
	p.runID = inst.RunID
	p.agentName = inst.AgentName
	p.sandboxID = inst.SandboxID
	p.sandboxClass = inst.SandboxClass
	p.missionID = inst.MissionID
	p.missionRunID = inst.MissionRunID
	p.mu.Unlock()
	publish = func(chunk []byte) {
		p.mu.Lock()
		cp := make([]byte, len(chunk))
		copy(cp, chunk)
		p.chunks = append(p.chunks, cp)
		p.mu.Unlock()
	}
	finish = func() {
		p.mu.Lock()
		p.finished = true
		p.mu.Unlock()
	}
	return publish, finish
}

func newAgentLauncherWithEvents(t *testing.T, c SandboxClient, pub EventPublisher) *AgentLauncher {
	t.Helper()
	l, err := NewAgentLauncher(AgentLauncherConfig{
		Client:       c,
		Tenant:       "gibson-infra-tenant",
		SandboxClass: "agent",
		RunTimeout:   5 * time.Second,
		Events:       pub,
	})
	if err != nil {
		t.Fatalf("NewAgentLauncher: %v", err)
	}
	return l
}

// TestLaunchAgent_TeesEventsToPublisher asserts the launcher registers the run
// under the CUSTOMER tenant (from the dispatch, not the launcher's infra
// tenant), tees each streamed chunk to the publisher, and finishes at the
// terminal state.
func TestLaunchAgent_TeesEventsToPublisher(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-agent-9"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{
				[]byte(`{"event":"start"}`),
				[]byte(`{"event":"tool"}`),
			}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
	pub := &capturingPublisher{}
	l := newAgentLauncherWithEvents(t, c, pub)

	dispatch := AgentDispatch{
		MissionRunID: "run-1",
		AgentRunID:   "ar-42",
		Tenant:       "customer-tenant",
		AgentName:    "zerocool",
	}
	if _, err := l.LaunchAgent(context.Background(), agentSpec, dispatch); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if !pub.registered {
		t.Fatal("publisher was never asked to register the instance")
	}
	if pub.tenant != "customer-tenant" {
		t.Errorf("registered tenant = %q; want the customer tenant, not the infra tenant", pub.tenant)
	}
	// The run id is the sandbox id, which is unique per launch. Mission and
	// agent-run ids are shared by every agent node in one mission run, and a
	// duplicate evicts the older entry from the registry.
	if pub.runID != "sbx-agent-9" {
		t.Errorf("registered run id = %q; want the sandbox id sbx-agent-9", pub.runID)
	}
	if pub.agentName != "zerocool" {
		t.Errorf("registered agent name = %q; want zerocool", pub.agentName)
	}
	if pub.sandboxID != "sbx-agent-9" {
		t.Errorf("registered sandbox id = %q; want sbx-agent-9", pub.sandboxID)
	}
	if len(pub.chunks) != 2 {
		t.Fatalf("published %d chunks; want 2", len(pub.chunks))
	}
	if string(pub.chunks[0]) != `{"event":"start"}` {
		t.Errorf("first chunk = %q; want the start event", pub.chunks[0])
	}
	if !pub.finished {
		t.Error("finish was not called at the terminal state")
	}
}

// TestLaunchAgent_RunIDFallsBackToSandboxID asserts a dispatch with no run ids
// still registers a subscribable instance, keyed by the sandbox id.
func TestLaunchAgent_RunIDFallsBackToSandboxID(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-fallback"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("x")}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
	pub := &capturingPublisher{}
	l := newAgentLauncherWithEvents(t, c, pub)
	if _, err := l.LaunchAgent(context.Background(), agentSpec, AgentDispatch{Tenant: "customer-tenant"}); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if pub.runID != "sbx-fallback" {
		t.Errorf("run id = %q; want the sandbox id fallback", pub.runID)
	}
}

// TestLaunchAgent_RunIDNeverUsesTheMissionRunID: the run id must never be the
// mission-run id. Every agent node in one mission run carries the same one, so
// using it made the second dispatch evict the first from the registry and close
// its feed — the console showed one tile for two running agents, streaming
// nothing.
func TestLaunchAgent_RunIDNeverUsesTheMissionRunID(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-mr"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			return &fixedLogs{}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
	pub := &capturingPublisher{}
	l := newAgentLauncherWithEvents(t, c, pub)
	dispatch := AgentDispatch{Tenant: "customer-tenant", MissionRunID: "mr-7"}
	if _, err := l.LaunchAgent(context.Background(), agentSpec, dispatch); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if pub.runID == "mr-7" {
		t.Error("run id is the mission-run id; a second agent in this mission would evict this one")
	}
	if pub.runID != "sbx-mr" {
		t.Errorf("run id = %q; want the sandbox id sbx-mr", pub.runID)
	}
}

// TestLaunchAgent_NilPublisherIsSafe asserts a launcher with no event publisher
// still runs the whole path (live console disabled).
func TestLaunchAgent_NilPublisherIsSafe(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-none"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("x")}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
	l := newAgentLauncher(t, c) // no Events wired
	if _, err := l.LaunchAgent(context.Background(), agentSpec, AgentDispatch{Tenant: "customer-tenant"}); err != nil {
		t.Fatalf("LaunchAgent with nil publisher: %v", err)
	}
}

// TestLaunchAgent_LogTeeReattachesUntilFirstChunk: a sandbox queued behind
// other runs is not loggable at dispatch, so the first attach fails. The tee
// retries and the console still receives the run's events (dashboard#1148).
func TestLaunchAgent_LogTeeReattachesUntilFirstChunk(t *testing.T) {
	var attempts atomic.Int32
	logsSeen := make(chan struct{})
	pub := &capturingPublisher{}
	c := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			n := attempts.Add(1)
			if n == 1 {
				return nil, errors.New("rpc error: code = FailedPrecondition desc = timed out waiting for Pod to reach a loggable phase")
			}
			if n == 2 {
				return erroringLogs{}, nil
			}
			return &fixedLogs{chunks: [][]byte{[]byte(`{"type":"assistant"}` + "\n")}}, nil
		},
		wait: func(ctx context.Context, _ string) (WaitResponse, error) {
			select {
			case <-logsSeen:
			case <-ctx.Done():
				return WaitResponse{}, ctx.Err()
			}
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	l := newAgentLauncherWithEvents(t, c, pub)
	go func() {
		for {
			pub.mu.Lock()
			n := len(pub.chunks)
			pub.mu.Unlock()
			if n > 0 {
				close(logsSeen)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:abc"}, AgentDispatch{Tenant: "t", AgentName: "a"}); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if got := attempts.Load(); got < 3 {
		t.Fatalf("attach attempts = %d; want at least 3 (two failures, then chunks)", got)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if len(pub.chunks) != 1 || string(pub.chunks[0]) != `{"type":"assistant"}`+"\n" {
		t.Fatalf("published chunks = %q; want the one event", pub.chunks)
	}
}

// TestLaunchAgent_LogTeeStopsRetryingWhenRunEnds: when the run reaches its
// terminal phase before the tee ever attached, the tee gives up at once
// instead of retrying for the whole run timeout.
func TestLaunchAgent_LogTeeStopsRetryingWhenRunEnds(t *testing.T) {
	var attempts atomic.Int32
	c := agentStreamClient(func(context.Context, string) (LogStream, error) {
		attempts.Add(1)
		return nil, errors.New("not loggable")
	})
	l := newAgentLauncher(t, c)
	start := time.Now()
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:abc"}, AgentDispatch{}); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatalf("run took %s; the tee must stop retrying once the run ended", time.Since(start))
	}
	if attempts.Load() < 1 {
		t.Fatal("expected at least one attach attempt")
	}
}

// TestLaunchAgent_LogTeeStopsOnContextEnd: a tee that never attached stops
// when the run context ends (the run timeout), without the terminal signal.
func TestLaunchAgent_LogTeeStopsOnContextEnd(t *testing.T) {
	var attempts atomic.Int32
	c := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			attempts.Add(1)
			return nil, errors.New("not loggable")
		},
		wait: func(ctx context.Context, _ string) (WaitResponse, error) {
			<-ctx.Done()
			return WaitResponse{}, ctx.Err()
		},
		kill: func(context.Context, string) error { return nil },
	}
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: c, RunTimeout: 1200 * time.Millisecond, Tenant: "t", SandboxClass: "agent"})
	if err != nil {
		t.Fatalf("NewAgentLauncher: %v", err)
	}
	start := time.Now()
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:abc"}, AgentDispatch{}); err == nil {
		t.Fatal("want the run timeout error")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("run took %s; the tee must stop when the context ends", time.Since(start))
	}
	if attempts.Load() < 2 {
		t.Fatalf("attach attempts = %d; want retries before the context ended", attempts.Load())
	}
}

// TestLaunchAgent_RegistersResolvedSandboxClass: the instance records the
// class the run was actually launched under, so the console can show the
// isolation posture (dashboard#1160). A spec class wins over the launcher's
// deployment default.
func TestLaunchAgent_RegistersResolvedSandboxClass(t *testing.T) {
	for _, tc := range []struct{ name, specClass, want string }{
		{"spec class wins", "gvisor-strict", "gvisor-strict"},
		{"empty spec falls back to the launcher default", "", "agent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := &capturingPublisher{}
			c := okLaunchClient(func(context.Context, string) (WaitResponse, error) {
				return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
			}, nil)
			l := newAgentLauncherWithEvents(t, c, pub)
			spec := AgentLaunchSpec{Image: "img@sha256:abc", SandboxClass: tc.specClass}
			if _, err := l.LaunchAgent(context.Background(), spec, AgentDispatch{Tenant: "t", AgentName: "a"}); err != nil {
				t.Fatalf("LaunchAgent: %v", err)
			}
			pub.mu.Lock()
			defer pub.mu.Unlock()
			if pub.sandboxClass != tc.want {
				t.Fatalf("sandbox class = %q; want %q", pub.sandboxClass, tc.want)
			}
		})
	}
}

// TestLaunchAgent_RunIDsAreUniquePerDispatch: two agent nodes in ONE mission
// run share MissionRunID. Keying the console by it made the second dispatch
// replace the first in the registry, which closes the older feed — one tile
// appeared where two agents were running, streaming nothing. The run id must
// therefore be unique per launch.
func TestLaunchAgent_RunIDsAreUniquePerDispatch(t *testing.T) {
	var n atomic.Int32
	seen := make(chan string, 2)
	c := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: fmt.Sprintf("sbx-%d", n.Add(1))}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("x\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	pub := &runIDCapture{out: seen}
	l := newAgentLauncherWithEvents(t, c, pub)

	// Same mission, same mission run — exactly what two agent nodes get.
	d := AgentDispatch{Tenant: "t", AgentName: "claude", MissionID: "m-1", MissionRunID: "mr-1"}
	for range 2 {
		if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:abc"}, d); err != nil {
			t.Fatalf("LaunchAgent: %v", err)
		}
	}
	a, b := <-seen, <-seen
	if a == b {
		t.Fatalf("both dispatches registered run id %q; the second would evict the first", a)
	}
	if a == "mr-1" || b == "mr-1" {
		t.Fatalf("run id must not be the shared mission run id: %q %q", a, b)
	}
}

// runIDCapture reports the run id of every registration.
type runIDCapture struct{ out chan string }

func (p *runIDCapture) RegisterInstance(_ string, inst LiveInstance) (publish func([]byte), finish func()) {
	p.out <- inst.RunID
	return func([]byte) {}, func() {}
}

// TestRunIDIsASinglePathSegment: the console addresses a stream at
// /api/agents/<run-id>/events. setec reports a sandbox id as
// "<namespace>/<name>/<uid>", so using it whole produced a URL that could not
// route and every tile streamed nothing while the daemon streamed fine.
func TestRunIDIsASinglePathSegment(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"setec-sandboxes/sbx-rwtp6/e3664788-fb57-4bcf-aeaa-e4f644718412", "e3664788-fb57-4bcf-aeaa-e4f644718412"},
		{"sbx-plain", "sbx-plain"},
		{"ns/name/", "ns/name/"},
	} {
		if got := runIDFromSandboxID(tc.in); got != tc.want {
			t.Errorf("runIDFromSandboxID(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
	got := dispatchRunID(AgentDispatch{MissionRunID: "mr-1"}, "setec-sandboxes/sbx-a/uid-1")
	if strings.Contains(got, "/") {
		t.Errorf("dispatch run id %q carries a slash; the events URL cannot route", got)
	}
}
