package sandboxed

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	testpb "github.com/zero-day-ai/sdk/api/gen/gibson/test/v1"

	"github.com/zero-day-ai/gibson/internal/contextkeys"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockClient is a configurable SandboxClient stub for unit tests.
type mockClient struct {
	launch    func(context.Context, LaunchRequest) (LaunchResponse, error)
	streamLog func(context.Context, string) (LogStream, error)
	wait      func(context.Context, string) (WaitResponse, error)
	kill      func(context.Context, string) error
}

func (m *mockClient) Launch(ctx context.Context, req LaunchRequest) (LaunchResponse, error) {
	return m.launch(ctx, req)
}
func (m *mockClient) StreamLogs(ctx context.Context, id string) (LogStream, error) {
	return m.streamLog(ctx, id)
}
func (m *mockClient) Wait(ctx context.Context, id string) (WaitResponse, error) {
	return m.wait(ctx, id)
}
func (m *mockClient) Kill(ctx context.Context, id string) error { return m.kill(ctx, id) }

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
	Image:   "ghcr.io/zero-day-ai/gibson-tool-runner:hello-dev",
	Command: []string{"/tool-runner"},
	VCPU:    1,
	Memory:  "128Mi",
}

func newExecutor(t *testing.T, c SandboxClient) *Executor {
	t.Helper()
	e, err := New(Config{
		Client:      c,
		Tenant:      "gibson-dev",
		CallTimeout: 5 * time.Second,
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
	lastCtx   loader.ExecContext
	lastDisc  *graphragpb.DiscoveryResult
	done      chan struct{}
	returnErr error
	mu        sync.Mutex
}

func newFakeDiscoveryProcessor() *fakeDiscoveryProcessor {
	return &fakeDiscoveryProcessor{done: make(chan struct{}, 1)}
}

func (f *fakeDiscoveryProcessor) Process(ctx context.Context, execCtx loader.ExecContext, d *graphragpb.DiscoveryResult) (interface{}, error) {
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
		Client: client, Tenant: "t",
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
		Client: client, Tenant: "t",
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
		Client: client, Tenant: "t",
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
