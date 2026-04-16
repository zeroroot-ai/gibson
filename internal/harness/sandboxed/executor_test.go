package sandboxed

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/zero-day-ai/gibson/internal/config"
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

func newExecutor(t *testing.T, c SandboxClient) *Executor {
	t.Helper()
	cfg := config.SandboxConfig{
		Tools: map[string]config.SandboxToolConfig{
			"hello": {
				Image:     "ghcr.io/zero-day-ai/gibson-tool-runner:hello-dev",
				Command:   []string{"/tool-runner"},
				Resources: config.SandboxToolResources{VCPU: 1, Memory: "128Mi"},
			},
		},
	}
	reg, err := NewRegistryFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewRegistryFromConfig: %v", err)
	}
	e, err := New(Config{
		Client:      c,
		Registry:    reg,
		Tenant:      "gibson-dev",
		CallTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
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
	if err := e.Execute(context.Background(), "hello", req, resp); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if resp.GetValue() != "hello, world" {
		t.Fatalf("response = %q; want %q", resp.GetValue(), "hello, world")
	}
}

func TestExecute_ToolNotRegistered_SoftMiss(t *testing.T) {
	e := newExecutor(t, &mockClient{})
	err := e.Execute(context.Background(), "unknown", wrapperspb.String("x"), &wrapperspb.StringValue{})
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
	err := e.Execute(context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
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
	err := e.Execute(context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
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
	err := e.Execute(context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
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
	err := e.Execute(context.Background(), "hello", wrapperspb.String("x"), &wrapperspb.StringValue{})
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
	err := e.Execute(context.Background(), "hello", wrapperspb.String(string(big)), &wrapperspb.StringValue{})
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
