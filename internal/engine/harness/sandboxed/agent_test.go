// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// newAgentLauncher builds an AgentLauncher over a mock client for tests.
func newAgentLauncher(t *testing.T, c SandboxClient) *AgentLauncher {
	t.Helper()
	l, err := NewAgentLauncher(AgentLauncherConfig{
		Client:       c,
		Tenant:       "gibson-dev",
		SandboxClass: "agent",
		RunTimeout:   5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewAgentLauncher: %v", err)
	}
	return l
}

var agentSpec = AgentLaunchSpec{
	Image:  "ghcr.io/zeroroot-ai/zerocool:dev",
	VCPU:   2,
	Memory: "512Mi",
	Egress: []EgressRule{{Host: "api.example.com", Port: 443}},
	Model:  "claude-test",
}

// TestNewAgentLauncher_RequiresClassTenantClient asserts the fail-closed
// constructor guards: a launcher may never be built without a client, tenant,
// or an explicit sandbox class (ADR-0052).
func TestNewAgentLauncher_RequiresClassTenantClient(t *testing.T) {
	if _, err := NewAgentLauncher(AgentLauncherConfig{Tenant: "t", SandboxClass: "agent"}); err == nil {
		t.Error("want error when Client is nil")
	}
	if _, err := NewAgentLauncher(AgentLauncherConfig{Client: &mockClient{}, SandboxClass: "agent"}); err == nil {
		t.Error("want error when Tenant is empty")
	}
	if _, err := NewAgentLauncher(AgentLauncherConfig{Client: &mockClient{}, Tenant: "t"}); err == nil {
		t.Error("want error when SandboxClass is empty")
	}
}

// TestLaunchAgent_LaunchesStreamsAndWaits is the happy path: the launcher
// Launches the sandbox with the injected per-dispatch scope, streams its logs,
// waits for the terminal exit, and returns the terminal outcome.
func TestLaunchAgent_LaunchesStreamsAndWaits(t *testing.T) {
	var (
		launched  bool
		streamed  bool
		waited    bool
		gotReq    LaunchRequest
		sandboxID = "sbx-agent-1"
	)
	c := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			launched = true
			gotReq = req
			return LaunchResponse{SandboxID: sandboxID}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			streamed = true
			return &fixedLogs{chunks: [][]byte{[]byte("agent starting\n"), []byte("done\n")}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			waited = true
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
	l := newAgentLauncher(t, c)

	dispatch := AgentDispatch{
		Grant:            "cg-jwt-token",
		CallbackEndpoint: "gibson:50001",
		MissionID:        "m1",
		MissionRunID:     "run-1",
		AgentRunID:       "ar-1",
		TaskB64:          "dGFzaw==",
	}
	out, err := l.LaunchAgent(context.Background(), agentSpec, dispatch)
	if err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if !launched || !streamed || !waited {
		t.Fatalf("expected launch+stream+wait; got launch=%v stream=%v wait=%v", launched, streamed, waited)
	}
	if out.SandboxID != sandboxID || out.ExitCode != 0 {
		t.Fatalf("outcome = %+v; want sandbox %q exit 0", out, sandboxID)
	}

	// The per-dispatch scope reaches the sandbox as env, and nothing standing.
	if gotReq.Env[envAgentGrant] != "cg-jwt-token" {
		t.Errorf("grant env = %q; want the per-dispatch CG-JWT", gotReq.Env[envAgentGrant])
	}
	if gotReq.Env[envAgentMissionRunID] != "run-1" {
		t.Errorf("mission-run env = %q; want run-1", gotReq.Env[envAgentMissionRunID])
	}
	if gotReq.Env[envAgentModel] != "claude-test" {
		t.Errorf("model env = %q; want claude-test", gotReq.Env[envAgentModel])
	}
	if gotReq.Env[envAgentTaskB64] != "dGFzaw==" {
		t.Errorf("task env = %q; want the base64 task", gotReq.Env[envAgentTaskB64])
	}
	// A process that has to guess which shape it is would guess wrong exactly
	// once, so the mode is always set, including for the default.
	if gotReq.Env[envInstanceMode] != "oneshot" {
		t.Errorf("instance mode env = %q; want oneshot by default", gotReq.Env[envInstanceMode])
	}
	// The tenant egress envelope is applied to the launch.
	if len(gotReq.Egress) != 1 || gotReq.Egress[0].Host != "api.example.com" {
		t.Errorf("egress = %+v; want the tenant envelope", gotReq.Egress)
	}
	if gotReq.SandboxClass != "agent" {
		t.Errorf("sandbox class = %q; want agent", gotReq.SandboxClass)
	}
}

// TestLaunchAgent_SpecClassOverridesDefault asserts the manifest spec's sandbox
// class (the S5 seam) wins over the launcher's deployment default.
func TestLaunchAgent_SpecClassOverridesDefault(t *testing.T) {
	var gotClass string
	c := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			gotClass = req.SandboxClass
			return LaunchResponse{SandboxID: "s"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) { return &fixedLogs{}, nil },
		wait:      func(_ context.Context, _ string) (WaitResponse, error) { return WaitResponse{}, nil },
		kill:      func(_ context.Context, _ string) error { return nil },
	}
	l := newAgentLauncher(t, c)

	spec := agentSpec
	spec.SandboxClass = "agent-high-assurance"
	if _, err := l.LaunchAgent(context.Background(), spec, AgentDispatch{}); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if gotClass != "agent-high-assurance" {
		t.Fatalf("class = %q; want the manifest override", gotClass)
	}
}

// TestLaunchAgent_EmptyImageRejected asserts a spec with no image is refused
// before any launch — the S5 resolver must supply an image.
func TestLaunchAgent_EmptyImageRejected(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			t.Fatal("launch must not be called for an empty-image spec")
			return LaunchResponse{}, nil
		},
	}
	l := newAgentLauncher(t, c)
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{}, AgentDispatch{}); err == nil {
		t.Fatal("want error for empty image")
	}
}

// TestLaunchAgent_NonZeroExitSurfaced asserts a non-zero terminal exit is
// returned as the outcome (the caller decides how to fail the node).
func TestLaunchAgent_NonZeroExitSurfaced(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s"}, nil
		},
		streamLog: func(_ context.Context, _ string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("boom\n")}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 7, Reason: "Error"}, nil
		},
		kill: func(_ context.Context, _ string) error { return nil },
	}
	l := newAgentLauncher(t, c)
	out, err := l.LaunchAgent(context.Background(), agentSpec, AgentDispatch{})
	if err != nil {
		t.Fatalf("LaunchAgent should return the terminal outcome, not an error: %v", err)
	}
	if out.ExitCode != 7 {
		t.Fatalf("exit = %d; want 7", out.ExitCode)
	}
}

// TestLaunchAgent_LaunchFailurePropagates asserts a Launch RPC failure is
// wrapped and returned (no sandbox to stream or wait on).
func TestLaunchAgent_LaunchFailurePropagates(t *testing.T) {
	c := &mockClient{
		launch: func(_ context.Context, _ LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{}, errors.New("setec unreachable")
		},
	}
	l := newAgentLauncher(t, c)
	if _, err := l.LaunchAgent(context.Background(), agentSpec, AgentDispatch{}); err == nil {
		t.Fatal("want error when Launch fails")
	}
}

// erroringLogs is a LogStream whose Recv fails with a non-EOF error, exercising
// the log goroutine's recv-error branch.
type erroringLogs struct{}

func (erroringLogs) Recv() ([]byte, error) { return nil, errStreamRecv }
func (erroringLogs) Close() error          { return nil }

var errStreamRecv = errorsNew("recv failed")

// errorsNew keeps this test file free of an extra import block edit.
func errorsNew(s string) error { return &stringErr{s} }

type stringErr struct{ s string }

func (e *stringErr) Error() string { return e.s }

func agentStreamClient(streamLog func(context.Context, string) (LogStream, error)) *mockClient {
	return &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s1"}, nil
		},
		streamLog: streamLog,
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
}

// TestLaunchAgent_StreamLogsError: a failure to open the log stream is logged,
// not fatal — the run still completes and returns its terminal result.
func TestLaunchAgent_StreamLogsError(t *testing.T) {
	c := agentStreamClient(func(context.Context, string) (LogStream, error) { return nil, errStreamRecv })
	l := newAgentLauncher(t, c)
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:abc"}, AgentDispatch{}); err != nil {
		t.Fatalf("StreamLogs error must not fail the run: %v", err)
	}
}

// TestLaunchAgent_LogRecvError: a non-EOF recv error mid-stream is logged and
// ends the tee, without failing the run.
func TestLaunchAgent_LogRecvError(t *testing.T) {
	c := agentStreamClient(func(context.Context, string) (LogStream, error) { return erroringLogs{}, nil })
	l := newAgentLauncher(t, c)
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:abc"}, AgentDispatch{}); err != nil {
		t.Fatalf("recv error must not fail the run: %v", err)
	}
}

func okLaunchClient(wait func(context.Context, string) (WaitResponse, error), launch func(context.Context, LaunchRequest) (LaunchResponse, error)) *mockClient {
	l := launch
	if l == nil {
		l = func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s1"}, nil
		}
	}
	return &mockClient{
		launch: l,
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("x\n")}}, nil
		},
		wait: wait,
		kill: func(context.Context, string) error { return nil },
	}
}

// TestLaunchAgent_VerifyIsolationFail: a sandbox whose bound class does not
// match what was requested is refused and killed (ADR-0016 decision 4).
func TestLaunchAgent_VerifyIsolationFail(t *testing.T) {
	killed := false
	c := okLaunchClient(
		func(context.Context, string) (WaitResponse, error) { return WaitResponse{ExitCode: 0}, nil },
		func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "s1", SandboxClass: "not-agent"}, nil
		},
	)
	c.kill = func(context.Context, string) error { killed = true; return nil }
	l := newAgentLauncher(t, c)
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:x"}, AgentDispatch{}); err == nil {
		t.Fatal("an isolation mismatch must be refused")
	}
	if !killed {
		t.Error("a refused sandbox must be killed")
	}
}

// TestLaunchAgent_WaitTimeout: a run that overshoots its budget is killed and
// surfaced as a timeout. Also exercises the TaskB64 + trace-context env path.
func TestLaunchAgent_WaitTimeout(t *testing.T) {
	c := okLaunchClient(func(context.Context, string) (WaitResponse, error) {
		return WaitResponse{}, context.DeadlineExceeded
	}, nil)
	l := newAgentLauncher(t, c)
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
	}))
	if _, err := l.LaunchAgent(ctx, AgentLaunchSpec{Image: "img@sha256:x"}, AgentDispatch{TaskB64: "dGFzaw=="}); err == nil {
		t.Fatal("a wait timeout must error")
	}
}

// TestLaunchAgent_WaitError: a non-timeout wait failure surfaces as an error.
func TestLaunchAgent_WaitError(t *testing.T) {
	c := okLaunchClient(func(context.Context, string) (WaitResponse, error) {
		return WaitResponse{}, errStreamRecv
	}, nil)
	l := newAgentLauncher(t, c)
	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{Image: "img@sha256:x"}, AgentDispatch{}); err == nil {
		t.Fatal("a wait error must surface")
	}
}

// TestLaunchAgent_MemberModeReachesTheSandbox: a member launch runs the member
// command and tells the process it is a member. One image, two shapes
// (ADR-0019).
func TestLaunchAgent_MemberModeReachesTheSandbox(t *testing.T) {
	var gotReq LaunchRequest
	client := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			gotReq = req
			return LaunchResponse{SandboxID: "sbx-member", Runtime: "gvisor"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) { return &fixedLogs{}, nil },
		wait:      func(context.Context, string) (WaitResponse, error) { return WaitResponse{ExitCode: 0}, nil },
		kill:      func(context.Context, string) error { return nil },
	}
	l, err := NewAgentLauncher(AgentLauncherConfig{Client: client, Tenant: "acme", SandboxClass: "agent"})
	if err != nil {
		t.Fatalf("NewAgentLauncher: %v", err)
	}

	if _, err := l.LaunchAgent(context.Background(), AgentLaunchSpec{
		Image:   "ghcr.io/x/claude@sha256:abc",
		Command: []string{"node", "/app/dist/member-main.js"},
		Mode:    "member",
		VCPU:    2, Memory: "4Gi",
	}, AgentDispatch{Tenant: "acme", AgentName: "claude"}); err != nil {
		t.Fatalf("LaunchAgent: %v", err)
	}
	if gotReq.Env[envInstanceMode] != "member" {
		t.Errorf("instance mode env = %q; want member", gotReq.Env[envInstanceMode])
	}
	if len(gotReq.Command) != 2 || gotReq.Command[1] != "/app/dist/member-main.js" {
		t.Errorf("command = %v; want the member entry point", gotReq.Command)
	}
}
