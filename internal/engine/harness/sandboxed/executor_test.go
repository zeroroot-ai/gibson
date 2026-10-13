// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	testpb "github.com/zeroroot-ai/sdk/api/gen/gibson/test/v1"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockClient is a configurable SandboxClient stub for unit tests.
type mockClient struct {
	launch    func(context.Context, LaunchRequest) (LaunchResponse, error)
	streamLog func(context.Context, string) (LogStream, error)
	wait      func(context.Context, string) (WaitResponse, error)
	kill      func(context.Context, string) error
	fork      func(context.Context, ForkRequest) (ForkResponse, error)
	recovery  func(context.Context, string) (SessionRecovery, bool, error)
	snapshot  func(context.Context, string, time.Duration) (string, error)
	isolation func(context.Context, string) (LaunchResponse, error)
}

// mockBoundClass is the class of the launcher of newAgentLauncher. With no
// isolation stub, setec reports that each fork and restore is bound to it on
// the launcher backend.
const mockBoundClass = "agent"

func (m *mockClient) Isolation(ctx context.Context, _, id string) (LaunchResponse, error) {
	if m.isolation == nil {
		return LaunchResponse{SandboxID: id, SandboxClass: mockBoundClass, Runtime: IsolatedRuntime}, nil
	}
	return m.isolation(ctx, id)
}

func (m *mockClient) Snapshot(ctx context.Context, _, id string, ttl time.Duration) (string, error) {
	if m.snapshot == nil {
		return "", errors.New("mockClient: no snapshot configured")
	}
	return m.snapshot(ctx, id, ttl)
}

func (m *mockClient) Recovery(ctx context.Context, _, id string) (SessionRecovery, bool, error) {
	if m.recovery == nil {
		return SessionRecovery{}, false, nil
	}
	return m.recovery(ctx, id)
}

func (m *mockClient) Launch(ctx context.Context, req LaunchRequest) (LaunchResponse, error) {
	resp, err := m.launch(ctx, req)
	if err != nil {
		return resp, err
	}
	return reportedIsolation(req, resp), nil
}

// reportedIsolation fills the class and the runtime that setec reports on a
// launch, as setec does: the class it bound (the requested one) and the
// launcher backend. A stub that sets either field keeps its own value, so a
// test can still report a mismatch or a runtime that is refused.
func reportedIsolation(req LaunchRequest, resp LaunchResponse) LaunchResponse {
	if resp.SandboxClass == "" {
		resp.SandboxClass = req.SandboxClass
	}
	if resp.Runtime == "" {
		resp.Runtime = IsolatedRuntime
	}
	return resp
}
func (m *mockClient) StreamLogs(ctx context.Context, _, id string) (LogStream, error) {
	return m.streamLog(ctx, id)
}
func (m *mockClient) Wait(ctx context.Context, _, id string) (WaitResponse, error) {
	return m.wait(ctx, id)
}
func (m *mockClient) Kill(ctx context.Context, _, id string) error { return m.kill(ctx, id) }
func (m *mockClient) Fork(ctx context.Context, req ForkRequest) (ForkResponse, error) {
	if m.fork == nil {
		return ForkResponse{}, errors.New("mockClient: no fork configured")
	}
	return m.fork(ctx, req)
}

// fixedLogs is a LogStream that emits a pre-built byte sequence once then EOF.
type fixedLogs struct {
	chunks [][]byte
	i      int
	mu     sync.Mutex
}

func (f *fixedLogs) Recv() ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.i >= len(f.chunks) {
		return nil, io.EOF
	}
	c := f.chunks[f.i]
	f.i++
	return c, nil
}
func (f *fixedLogs) Close() error { return nil }

// helloSpec is the canonical ToolSpec used across executor tests in this
// file. Callers pass it to ExecuteWithSpec; the Executor itself no longer
// carries a per-tool registry — the daemon's catalog refresher owns that
// mapping live in ComponentRegistry.
var helloSpec = ToolSpec{
	Live:    LiveScope{Tenant: "acme"},
	Image:   "ghcr.io/zeroroot-ai/gibson-tool-runner:hello-dev",
	Command: []string{"/tool-runner"},
	VCPU:    1,
	Memory:  "128Mi",
}

func newExecutor(t *testing.T, c SandboxClient) *Executor {
	t.Helper()
	e, err := New(Config{
		Client:       c,
		SandboxClass: "tool",
		CallTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

// execute is the test-only shim that calls ExecuteWithSpec with the
// canonical helloSpec so test bodies stay short. Dispatches through the
// same code path the harness uses post-spec.
func execute(t *testing.T, e *Executor, ctx context.Context, name string, req, resp proto.Message) error {
	t.Helper()
	return e.ExecuteWithSpec(ctx, name, helloSpec, req, resp)
}

func markerLine(msg string) []byte {
	enc, _ := protojson.Marshal(wrapperspb.String(msg))
	return []byte(markerOutputPrefix + base64.StdEncoding.EncodeToString(enc) + "\n")
}

func TestExecute_HappyPath(t *testing.T) {
	client := &mockClient{
		launch: func(_ context.Context, req LaunchRequest) (LaunchResponse, error) {
			if req.Env[envInputB64] == "" {
				t.Errorf("launch missing input env")
			}
			if req.Image == "" {
				t.Errorf("launch missing image")
			}
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{
				[]byte("starting tool...\n"),
				markerLine("hello, world"),
			}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e := newExecutor(t, client)
	req := wrapperspb.String("world")
	resp := &wrapperspb.StringValue{}
	if err := execute(t, e, context.Background(), "hello", req, resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.GetValue() != "hello, world" {
		t.Fatalf("response = %q; want %q", resp.GetValue(), "hello, world")
	}
}

func TestExecute_ToolNotRegistered_SoftMiss(t *testing.T) {
	e := newExecutor(t, &mockClient{})
	err := e.ExecuteWithSpec(context.Background(), "unknown", ToolSpec{}, wrapperspb.String("x"), &wrapperspb.StringValue{})
	ge := asGibsonError(t, err)
	if ge.Code != types.SANDBOX_TOOL_NOT_REGISTERED {
		t.Fatalf("code = %s; want SANDBOX_TOOL_NOT_REGISTERED", ge.Code)
	}
}

func TestExecute_LaunchFailed(t *testing.T) {
	e := newExecutor(t, &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{}, errors.New("dial refused")
		},
	})
	err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
	ge := asGibsonError(t, err)
	if ge.Code != types.SANDBOX_LAUNCH_FAILED {
		t.Fatalf("code = %s; want SANDBOX_LAUNCH_FAILED", ge.Code)
	}
}

func TestExecute_NonZeroExit_IncludesTail(t *testing.T) {
	e := newExecutor(t, &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-2"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("traceback: panic!\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 3, Reason: "Error"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	})
	err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
	ge := asGibsonError(t, err)
	if ge.Code != types.SANDBOX_NON_ZERO_EXIT {
		t.Fatalf("code = %s; want SANDBOX_NON_ZERO_EXIT", ge.Code)
	}
	if !strings.Contains(ge.Message, "traceback") {
		t.Fatalf("message missing tail: %q", ge.Message)
	}
}

func TestExecute_NoOutputMarker(t *testing.T) {
	e := newExecutor(t, &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-3"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("just some logs with no marker\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
	})
	err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
	ge := asGibsonError(t, err)
	if ge.Code != types.SANDBOX_OUTPUT_MALFORMED {
		t.Fatalf("code = %s; want SANDBOX_OUTPUT_MALFORMED", ge.Code)
	}
}

func TestExecute_MalformedMarkerBase64(t *testing.T) {
	e := newExecutor(t, &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-4"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte(markerOutputPrefix + "!!not-base64!!\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
	})
	err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
	ge := asGibsonError(t, err)
	if ge.Code != types.SANDBOX_OUTPUT_MALFORMED {
		t.Fatalf("code = %s; want SANDBOX_OUTPUT_MALFORMED", ge.Code)
	}
}

func TestExecute_InputTooLarge(t *testing.T) {
	// Force a large input by using a huge string value.
	big := make([]byte, maxInputBytes+100)
	for i := range big {
		big[i] = 'a'
	}
	e := newExecutor(t, &mockClient{})
	err := execute(t, e, context.Background(), "hello", wrapperspb.String(string(big)), &wrapperspb.StringValue{})
	ge := asGibsonError(t, err)
	if ge.Code != types.SANDBOX_INPUT_TOO_LARGE {
		t.Fatalf("code = %s; want SANDBOX_INPUT_TOO_LARGE", ge.Code)
	}
}

func TestExtractOutputMarker_LastWins(t *testing.T) {
	buf := []byte("line 1\n" +
		markerOutputPrefix + "Zmlyc3Q=\n" + // "first"
		"line 3\n" +
		markerOutputPrefix + "c2Vjb25k\n") // "second"
	got, ok := extractOutputMarker(buf)
	if !ok || got != "c2Vjb25k" {
		t.Fatalf("extractOutputMarker = (%q, %v); want (c2Vjb25k, true)", got, ok)
	}
}

func TestRing_WraparoundPreservesWriteOrder(t *testing.T) {
	r := newRing(8)
	r.write([]byte("abcd"))
	r.write([]byte("efghij"))
	// Capacity 8, wrote 10 → last 8 bytes in order should be "cdefghij".
	got := string(r.bytes())
	if got != "cdefghij" {
		t.Fatalf("bytes = %q; want %q", got, "cdefghij")
	}
}

// fakeDiscoveryProcessor records Process invocations for assertions.
type fakeDiscoveryProcessor struct {
	calls     atomic.Int32
	lastCtx   ingest.ExecContext
	lastDisc  *graphragpb.DiscoveryResult
	done      chan struct{}
	returnErr error
	mu        sync.Mutex
}

func newFakeDiscoveryProcessor() *fakeDiscoveryProcessor {
	return &fakeDiscoveryProcessor{done: make(chan struct{}, 1)}
}

func (f *fakeDiscoveryProcessor) Process(_ context.Context, execCtx ingest.ExecContext, d *graphragpb.DiscoveryResult) (interface{}, error) {
	f.mu.Lock()
	f.lastCtx = execCtx
	f.lastDisc = d
	f.mu.Unlock()
	f.calls.Add(1)
	select {
	case f.done <- struct{}{}:
	default:
	}
	if f.returnErr != nil {
		return nil, f.returnErr
	}
	return struct{}{}, nil
}

// discoveryMarkerFromFixture builds a stdout marker line whose base64 payload
// is the protojson encoding of a GenericDiscoveryResponse with field 100
// populated. The sandboxed executor should extract this and hand it to the
// DiscoveryProcessor.
func discoveryMarkerFromFixture(t *testing.T, fx *testpb.GenericDiscoveryResponse) []byte {
	t.Helper()
	enc, err := protojson.Marshal(fx)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return []byte(markerOutputPrefix + base64.StdEncoding.EncodeToString(enc) + "\n")
}

func TestExecute_DiscoveryProcessor_FieldHundredFires(t *testing.T) {
	fake := newFakeDiscoveryProcessor()

	fixture := &testpb.GenericDiscoveryResponse{
		Discovery: &graphragpb.DiscoveryResult{
			// Minimum-viable DiscoveryResult — an empty one is still non-nil
			// and should trip extraction. Parsers in the runner populate real
			// nodes; this test only verifies the plumbing.
		},
	}

	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-d3"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{discoveryMarkerFromFixture(t, fixture)}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e, err := New(Config{
		Client: client, SandboxClass: "tool",
		CallTimeout: 2 * time.Second, DiscoveryProcessor: fake,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx := contextkeys.WithMissionRunID(context.Background(), "mr-abc")
	ctx = contextkeys.WithAgentRunID(ctx, "ar-xyz")
	ctx = contextkeys.WithToolExecutionID(ctx, "te-123")
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-m1")
	ctx = context.WithValue(ctx, contextkeys.AgentName, "agent-alpha")

	resp := &testpb.GenericDiscoveryResponse{}
	if err := execute(t, e, ctx, "hello", wrapperspb.String("world"), resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Wait for the async goroutine to call into the fake processor.
	select {
	case <-fake.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("DiscoveryProcessor.Process was never called")
	}

	if fake.calls.Load() != 1 {
		t.Fatalf("DiscoveryProcessor calls = %d; want 1", fake.calls.Load())
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.lastCtx.MissionRunID != "mr-abc" {
		t.Errorf("MissionRunID = %q; want mr-abc", fake.lastCtx.MissionRunID)
	}
	if fake.lastCtx.AgentRunID != "ar-xyz" {
		t.Errorf("AgentRunID = %q; want ar-xyz", fake.lastCtx.AgentRunID)
	}
	if fake.lastCtx.ToolExecutionID != "te-123" {
		t.Errorf("ToolExecutionID = %q; want te-123", fake.lastCtx.ToolExecutionID)
	}
	if fake.lastCtx.MissionID != "mission-m1" {
		t.Errorf("MissionID = %q; want mission-m1", fake.lastCtx.MissionID)
	}
	if fake.lastCtx.AgentName != "agent-alpha" {
		t.Errorf("AgentName = %q; want agent-alpha", fake.lastCtx.AgentName)
	}
	if fake.lastDisc == nil {
		t.Error("lastDisc is nil; DiscoveryResult was not forwarded")
	}
}

func TestExecute_DiscoveryProcessor_ErrorLoggedNotReturned(t *testing.T) {
	fake := newFakeDiscoveryProcessor()
	fake.returnErr = errors.New("neo4j down")

	fixture := &testpb.GenericDiscoveryResponse{
		Discovery: &graphragpb.DiscoveryResult{},
	}

	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-d4"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{discoveryMarkerFromFixture(t, fixture)}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e, err := New(Config{
		Client: client, SandboxClass: "tool",
		CallTimeout: 2 * time.Second, DiscoveryProcessor: fake,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Tool execution must succeed even though DiscoveryProcessor.Process
	// returns an error: graph persistence failures are logged, not propagated.
	resp := &testpb.GenericDiscoveryResponse{}
	if err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), resp); err != nil {
		t.Fatalf("Execute returned error despite processor-only failure: %v", err)
	}

	select {
	case <-fake.done:
	case <-time.After(2 * time.Second):
		t.Fatalf("DiscoveryProcessor.Process was never called")
	}
}

func TestExecute_DiscoveryProcessor_NilSkips(t *testing.T) {
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-d1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{markerLine("ok")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	// No DiscoveryProcessor on Config — executor must skip extraction silently.
	e := newExecutor(t, client)
	if err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestExecute_DiscoveryProcessor_NoFieldHundredSkips(t *testing.T) {
	// wrapperspb.StringValue has no field 100; ExtractDiscovery returns nil.
	// The fake processor must never be called.
	fake := newFakeDiscoveryProcessor()
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-d2"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{markerLine("ok")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e, err := New(Config{
		Client: client, SandboxClass: "tool",
		CallTimeout: 2 * time.Second, DiscoveryProcessor: fake,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Seed contextkeys so extraction context would be propagated if triggered.
	ctx := contextkeys.WithMissionRunID(context.Background(), "mr-1")
	ctx = contextkeys.WithAgentRunID(ctx, "ar-1")
	if err := execute(t, e, ctx, "hello", wrapperspb.String("x"), &wrapperspb.StringValue{}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Give any (erroneous) goroutine a moment to fire — it shouldn't, because
	// ExtractDiscovery returns nil for wrapperspb.StringValue.
	select {
	case <-fake.done:
		t.Fatalf("DiscoveryProcessor was called on a response with no field 100")
	case <-time.After(100 * time.Millisecond):
	}
	if fake.calls.Load() != 0 {
		t.Fatalf("DiscoveryProcessor calls = %d; want 0", fake.calls.Load())
	}
}

func asGibsonError(t *testing.T, err error) *types.GibsonError {
	t.Helper()
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	var ge *types.GibsonError
	if !errors.As(err, &ge) {
		t.Fatalf("err is not *GibsonError: %v", err)
	}
	return ge
}

// --- live console (dashboard#1160 follow-up) ------------------------------

// liveCapture records what the executor registered and published.
type liveCapture struct {
	mu       sync.Mutex
	tenant   string
	inst     LiveInstance
	chunks   [][]byte
	finished bool
	calls    int
}

func (c *liveCapture) RegisterInstance(tenant string, inst LiveInstance) (publish func([]byte), finish func()) {
	c.mu.Lock()
	c.calls++
	c.tenant, c.inst = tenant, inst
	c.mu.Unlock()
	return func(b []byte) {
			c.mu.Lock()
			cp := make([]byte, len(b))
			copy(cp, b)
			c.chunks = append(c.chunks, cp)
			c.mu.Unlock()
		}, func() {
			c.mu.Lock()
			c.finished = true
			c.mu.Unlock()
		}
}

func liveExecutor(t *testing.T, pub EventPublisher) (*Executor, *mockClient) {
	t.Helper()
	c := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-tool-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{[]byte("Starting Nmap\n")}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e, err := New(Config{Client: c, SandboxClass: "tool", Events: pub})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e, c
}

// TestExecute_RegistersToolRunOnTheLiveConsole: a tool runs in a sandbox just
// like an agent, so it is enumerable and streamable on the same surface.
func TestExecute_RegistersToolRunOnTheLiveConsole(t *testing.T) {
	pub := &liveCapture{}
	e, _ := liveExecutor(t, pub)
	spec := ToolSpec{
		Image: "img@sha256:abc",
		Live:  LiveScope{Tenant: "tenant-a", MissionID: "m-1", MissionRunID: "mr-1"},
	}
	_ = e.ExecuteWithSpec(context.Background(), "nmap", spec, wrapperspb.String("x"), &wrapperspb.StringValue{})

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if pub.tenant != "tenant-a" {
		t.Fatalf("registered tenant = %q; want the CUSTOMER tenant, never the setec infra tenant", pub.tenant)
	}
	if pub.inst.ComponentKind != ComponentKindTool {
		t.Errorf("component kind = %q, want %q", pub.inst.ComponentKind, ComponentKindTool)
	}
	if pub.inst.AgentName != "nmap" || pub.inst.RunID != "sbx-tool-1" || pub.inst.SandboxID != "sbx-tool-1" {
		t.Errorf("instance = %+v; want the tool name and the sandbox id as the run id", pub.inst)
	}
	if pub.inst.MissionID != "m-1" || pub.inst.MissionRunID != "mr-1" {
		t.Errorf("mission scope = %q/%q; want m-1/mr-1", pub.inst.MissionID, pub.inst.MissionRunID)
	}
	if len(pub.chunks) != 1 || string(pub.chunks[0]) != "Starting Nmap\n" {
		t.Errorf("published chunks = %q; want the sandbox log teed to the console", pub.chunks)
	}
	if !pub.finished {
		t.Error("finish must run so the console stream closes at the terminal state")
	}
}

// TestExecute_NoLiveScopeRegistersNothing: a call whose customer tenant is
// unknown must never appear on anyone's console. Fail closed.
func TestExecute_NoLiveScopeRegistersNothing(t *testing.T) {
	pub := &liveCapture{}
	e, _ := liveExecutor(t, pub)
	_ = e.ExecuteWithSpec(context.Background(), "nmap",
		ToolSpec{Image: "img@sha256:abc"}, wrapperspb.String("x"), &wrapperspb.StringValue{})

	pub.mu.Lock()
	defer pub.mu.Unlock()
	if pub.calls != 0 {
		t.Fatalf("RegisterInstance calls = %d; want 0 when no customer tenant is known", pub.calls)
	}
}

// TestExecute_NilPublisherIsSafe: the live console is optional wiring, so a
// run must reach exactly the same outcome with and without it. Asserting the
// outcomes match catches a publisher that swallows or alters the result,
// which a "did not panic" check would not.
func TestExecute_NilPublisherIsSafe(t *testing.T) {
	spec := ToolSpec{Image: "img@sha256:abc", Live: LiveScope{Tenant: "tenant-a"}}

	withPub, _ := liveExecutor(t, &liveCapture{})
	wantErr := withPub.ExecuteWithSpec(context.Background(), "nmap", spec,
		wrapperspb.String("x"), &wrapperspb.StringValue{})

	noPub, _ := liveExecutor(t, nil)
	gotErr := noPub.ExecuteWithSpec(context.Background(), "nmap", spec,
		wrapperspb.String("x"), &wrapperspb.StringValue{})

	if (wantErr == nil) != (gotErr == nil) || fmt.Sprint(wantErr) != fmt.Sprint(gotErr) {
		t.Fatalf("outcome differs with the console wired: with=%v without=%v", wantErr, gotErr)
	}
}

// notLoggable is a LogStream whose first Recv fails the way setec answers an
// attach to a Pod that is not loggable yet.
type notLoggable struct{}

func (notLoggable) Recv() ([]byte, error) {
	return nil, errors.New("rpc error: code = FailedPrecondition desc = " +
		`timed out waiting for Pod "sbx-1-vm" to reach a loggable phase`)
}
func (notLoggable) Close() error { return nil }

// TestExecute_LogAttachRetriesUntilLoggable: a launcher Pod that is not
// loggable at the first attaches still yields its output. Before, one failed
// attach lost the output and the call ended SANDBOX_OUTPUT_MALFORMED with an
// empty tail (exit-test-belief-training run 38205635741).
func TestExecute_LogAttachRetriesUntilLoggable(t *testing.T) {
	var opens atomic.Int32
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			if opens.Add(1) <= 2 {
				return notLoggable{}, nil
			}
			return &fixedLogs{chunks: [][]byte{markerLine("hello, world")}}, nil
		},
		wait: func(ctx context.Context, _ string) (WaitResponse, error) {
			// The workload runs past the first two attaches.
			select {
			case <-time.After(2 * time.Second):
			case <-ctx.Done():
				return WaitResponse{}, ctx.Err()
			}
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e := newExecutor(t, client)
	resp := &wrapperspb.StringValue{}
	if err := execute(t, e, context.Background(), "hello", wrapperspb.String("world"), resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.GetValue() != "hello, world" {
		t.Fatalf("response = %q; want %q", resp.GetValue(), "hello, world")
	}
	if got := opens.Load(); got < 3 {
		t.Fatalf("StreamLogs opened %d times; want at least 3 (two refused attaches, then the stream)", got)
	}
}

// TestExecute_LogTeeReadsCapturedLogAfterWait: a tee that never attached
// while the workload ran reads the captured log once Wait returns. setec
// serves the captured log of a finished container (setec#263).
func TestExecute_LogTeeReadsCapturedLogAfterWait(t *testing.T) {
	var finished atomic.Bool
	firstOpen := make(chan struct{})
	var once sync.Once
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			once.Do(func() { close(firstOpen) })
			if !finished.Load() {
				return notLoggable{}, nil
			}
			return &fixedLogs{chunks: [][]byte{markerLine("hello, world")}}, nil
		},
		wait: func(ctx context.Context, _ string) (WaitResponse, error) {
			// The workload ends only after the first attach was refused.
			select {
			case <-firstOpen:
			case <-ctx.Done():
				return WaitResponse{}, ctx.Err()
			}
			finished.Store(true)
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e := newExecutor(t, client)
	resp := &wrapperspb.StringValue{}
	if err := execute(t, e, context.Background(), "hello", wrapperspb.String("world"), resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.GetValue() != "hello, world" {
		t.Fatalf("response = %q; want %q", resp.GetValue(), "hello, world")
	}
}

// TestExecute_LogTeeNeverAttaches: a sandbox whose log is never loggable,
// not even after Wait, ends SANDBOX_OUTPUT_MALFORMED, not a hang.
func TestExecute_LogTeeNeverAttaches(t *testing.T) {
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) { return notLoggable{}, nil },
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e := newExecutor(t, client)
	err := execute(t, e, context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
	if ge := asGibsonError(t, err); ge.Code != types.SANDBOX_OUTPUT_MALFORMED {
		t.Fatalf("code = %s; want SANDBOX_OUTPUT_MALFORMED", ge.Code)
	}
}

// TestExecute_LogOpenErrorRetries: an error from opening the stream is
// retried the same way as a refused attach.
func TestExecute_LogOpenErrorRetries(t *testing.T) {
	var opens atomic.Int32
	firstOpen := make(chan struct{})
	var once sync.Once
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			once.Do(func() { close(firstOpen) })
			if opens.Add(1) == 1 {
				return nil, errors.New("frontend unavailable")
			}
			return &fixedLogs{chunks: [][]byte{markerLine("hello, world")}}, nil
		},
		wait: func(_ context.Context, _ string) (WaitResponse, error) {
			<-firstOpen
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	resp := &wrapperspb.StringValue{}
	e := newExecutor(t, client)
	if err := execute(t, e, context.Background(), "hello", wrapperspb.String("world"), resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.GetValue() != "hello, world" {
		t.Fatalf("response = %q; want %q", resp.GetValue(), "hello, world")
	}
}

// errAfterChunk is a LogStream that sends one chunk and then fails.
type errAfterChunk struct{ sent bool }

func (s *errAfterChunk) Recv() ([]byte, error) {
	if !s.sent {
		s.sent = true
		return markerLine("hello, world"), nil
	}
	return nil, errors.New("stream reset")
}
func (s *errAfterChunk) Close() error { return nil }

// TestExecute_LogRecvErrorAfterAttachKeepsOutput: a stream that fails after
// its first chunk is not re-attached (a re-attach would replay the output),
// and what arrived is used.
func TestExecute_LogRecvErrorAfterAttachKeepsOutput(t *testing.T) {
	var opens atomic.Int32
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-1"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			opens.Add(1)
			return &errAfterChunk{}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0, Reason: "Completed"}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	resp := &wrapperspb.StringValue{}
	e := newExecutor(t, client)
	if err := execute(t, e, context.Background(), "hello", wrapperspb.String("world"), resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("StreamLogs opened %d times; want 1", got)
	}
}

func TestNextLogAttachBackoff(t *testing.T) {
	if got := nextLogAttachBackoff(logAttachBackoffStart); got != 2*logAttachBackoffStart {
		t.Fatalf("next(%s) = %s; want %s", logAttachBackoffStart, got, 2*logAttachBackoffStart)
	}
	if got := nextLogAttachBackoff(logAttachBackoffCap); got != logAttachBackoffCap {
		t.Fatalf("next(cap) = %s; want the cap %s", got, logAttachBackoffCap)
	}
}

// outputJSONMarker builds the stdout marker of gibson-runner for a mission
// tool node: protojson of the generic tool ExecuteResponse, whose output_json
// holds protojson(DiscoveryResult).
func outputJSONMarker(t *testing.T, outputJSON string) []byte {
	t.Helper()
	enc, err := protojson.Marshal(&toolpb.ExecuteResponse{OutputJson: outputJSON})
	if err != nil {
		t.Fatalf("marshal ExecuteResponse: %v", err)
	}
	return []byte(markerOutputPrefix + base64.StdEncoding.EncodeToString(enc) + "\n")
}

// runOutputJSON runs one tool call whose answer is the given output_json, with
// the given manifest output type, and reports the fake processor.
func runOutputJSON(t *testing.T, outputType, outputJSON string) *fakeDiscoveryProcessor {
	t.Helper()
	fake := newFakeDiscoveryProcessor()
	client := &mockClient{
		launch: func(context.Context, LaunchRequest) (LaunchResponse, error) {
			return LaunchResponse{SandboxID: "sbx-oj"}, nil
		},
		streamLog: func(context.Context, string) (LogStream, error) {
			return &fixedLogs{chunks: [][]byte{outputJSONMarker(t, outputJSON)}}, nil
		},
		wait: func(context.Context, string) (WaitResponse, error) {
			return WaitResponse{ExitCode: 0}, nil
		},
		kill: func(context.Context, string) error { return nil },
	}
	e, err := New(Config{Client: client, SandboxClass: "tool", CallTimeout: 2 * time.Second, DiscoveryProcessor: fake})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	spec := helloSpec
	spec.OutputProtoType = outputType
	resp := &toolpb.ExecuteResponse{}
	req := &toolpb.ExecuteRequest{InputJson: "{}"}
	if err := e.ExecuteWithSpec(context.Background(), "nmap", spec, req, resp); err != nil {
		t.Fatalf("ExecuteWithSpec: %v", err)
	}
	return fake
}

// A mission tool node reads the answer as the generic tool ExecuteResponse,
// and gibson-runner puts the DiscoveryResult in its output_json. The executor
// reads it there when the manifest names DiscoveryResult as the output type
// (gibson#1140). Before, ExtractDiscovery found no field 100 and no discovery
// of a mission tool node reached the World.
func TestExecute_DiscoveryFromOutputJSON(t *testing.T) {
	disc, err := protojson.Marshal(&graphragpb.DiscoveryResult{Hosts: []*graphragpb.Host{{Ip: "127.0.0.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	fake := runOutputJSON(t, discoveryResultType, string(disc))
	select {
	case <-fake.done:
	case <-time.After(2 * time.Second):
		t.Fatal("DiscoveryProcessor.Process was never called for a DiscoveryResult in output_json")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.lastDisc == nil || len(fake.lastDisc.GetHosts()) != 1 || fake.lastDisc.GetHosts()[0].GetIp() != "127.0.0.1" {
		t.Fatalf("forwarded discovery = %v, want one host 127.0.0.1", fake.lastDisc)
	}
}

// The output_json is read as a DiscoveryResult only when the manifest says so,
// and JSON that is not a DiscoveryResult folds nothing.
func TestExecute_OutputJSONNotADiscovery(t *testing.T) {
	disc, err := protojson.Marshal(&graphragpb.DiscoveryResult{Hosts: []*graphragpb.Host{{Ip: "127.0.0.1"}}})
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct{ outputType, outputJSON string }{
		"another output type":       {"gibson.test.v1.Other", string(disc)},
		"no output type":            {"", string(disc)},
		"json that is no discovery": {discoveryResultType, `{"not_a_field": 1}`},
		"empty output_json":         {discoveryResultType, ""},
	} {
		fake := runOutputJSON(t, c.outputType, c.outputJSON)
		select {
		case <-fake.done:
			t.Errorf("%s: DiscoveryProcessor.Process was called", name)
		case <-time.After(200 * time.Millisecond):
		}
	}
}
