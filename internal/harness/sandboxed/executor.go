package sandboxed

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Environment variables injected into every sandbox launch. The tool-runner
// OCI image reads these via sdk/toolrunner.
const (
	envInputB64 = "GIBSON_TOOL_INPUT_B64"
	envTraceID  = "GIBSON_TRACE_ID"
	envSpanID   = "GIBSON_SPAN_ID"

	markerOutputPrefix = "===GIBSON_TOOL_OUTPUT==="
	markerErrorPrefix  = "===GIBSON_TOOL_ERROR==="

	maxInputBytes  = 100 * 1024 // 100 KiB pre-encoding guard
	logBufferLimit = 1 << 20    // 1 MiB ring buffer for stdout marker extraction
	killGrace      = 30 * time.Second
)

// SandboxClient is the minimal gRPC surface the executor needs from Setec.
// It is implemented by an adapter around Setec's generated gRPC client —
// the adapter lives in the daemon-startup wiring so this package does not
// import setec's proto package directly.
type SandboxClient interface {
	Launch(ctx context.Context, req LaunchRequest) (LaunchResponse, error)
	StreamLogs(ctx context.Context, sandboxID string) (LogStream, error)
	Wait(ctx context.Context, sandboxID string) (WaitResponse, error)
	Kill(ctx context.Context, sandboxID string) error
}

// LaunchRequest is the data the executor passes to Setec's Launch RPC.
// Adapters map it onto Setec's generated proto.
type LaunchRequest struct {
	Image    string
	Command  []string
	Env      map[string]string
	VCPU     int32
	Memory   string
	Tenant   string // informational; tenancy is resolved by Setec from client cert CN
	Timeout  time.Duration
}

// LaunchResponse is the executor-facing result of Launch.
type LaunchResponse struct {
	SandboxID string
}

// WaitResponse describes sandbox termination.
type WaitResponse struct {
	ExitCode int32
	Reason   string // human-readable termination reason (e.g., "Completed", "OOMKilled")
}

// LogStream is the minimal streaming interface the executor needs from
// Setec.StreamLogs. It returns the next chunk of sandbox stdout+stderr or
// io.EOF on termination.
type LogStream interface {
	Recv() ([]byte, error)
	Close() error
}

// Executor is the sandboxed-tool dispatch engine. It is safe for concurrent
// use: per-call state lives on the stack of Execute.
type Executor struct {
	client      SandboxClient
	registry    *Registry
	tracer      trace.Tracer
	logger      *slog.Logger
	tenant      string
	callTimeout time.Duration
}

// Config is the constructor input for the executor. All fields are required
// except Tracer (no-op used when nil) and Logger (slog.Default when nil).
type Config struct {
	Client      SandboxClient
	Registry    *Registry
	Tracer      trace.Tracer
	Logger      *slog.Logger
	Tenant      string
	CallTimeout time.Duration // defaults to 5m when zero
}

// New constructs an Executor. Returns a clear error on misconfiguration so
// the daemon can log a warning and continue (per Requirement 5.4).
func New(cfg Config) (*Executor, error) {
	if cfg.Client == nil {
		return nil, errors.New("sandboxed.New: Client is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("sandboxed.New: Registry is required")
	}
	if cfg.Tenant == "" {
		return nil, errors.New("sandboxed.New: Tenant is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Tracer == nil {
		cfg.Tracer = trace.NewNoopTracerProvider().Tracer("gibson.sandboxed")
	}
	if cfg.CallTimeout <= 0 {
		cfg.CallTimeout = 5 * time.Minute
	}
	return &Executor{
		client:      cfg.Client,
		registry:    cfg.Registry,
		tracer:      cfg.Tracer,
		logger:      cfg.Logger,
		tenant:      cfg.Tenant,
		callTimeout: cfg.CallTimeout,
	}, nil
}

// Registry exposes the executor's tool registry for lookups from the harness
// dispatch decision point.
func (e *Executor) Registry() *Registry {
	return e.registry
}

// Execute dispatches a single tool invocation through Setec. The request and
// response must be non-nil proto.Message values matching the tool's declared
// InputMessageType / OutputMessageType. Returns types.GibsonError with a
// SANDBOX_* code on any failure.
func (e *Executor) Execute(ctx context.Context, toolName string, request, response proto.Message) error {
	ctx, span := e.tracer.Start(ctx, "harness.sandboxed.execute")
	defer span.End()
	span.SetAttributes(
		attribute.String("gibson.tool.name", toolName),
		attribute.String("setec.tenant", e.tenant),
	)

	spec, ok := e.registry.Lookup(toolName)
	if !ok {
		// Soft miss — caller falls through to other dispatch paths.
		return types.WrapError(types.SANDBOX_TOOL_NOT_REGISTERED,
			fmt.Sprintf("tool %q not registered for sandboxed execution", toolName), nil)
	}

	// 1. Marshal + size-check + b64 encode request.
	rawIn, err := protojson.Marshal(request)
	if err != nil {
		return types.WrapError(types.SANDBOX_OUTPUT_MALFORMED,
			fmt.Sprintf("marshal request for tool %q", toolName), err)
	}
	if len(rawIn) > maxInputBytes {
		return types.WrapError(types.SANDBOX_INPUT_TOO_LARGE,
			fmt.Sprintf("tool %q request size %d exceeds %d bytes", toolName, len(rawIn), maxInputBytes), nil)
	}
	b64In := base64.StdEncoding.EncodeToString(rawIn)

	// 2. Build Launch request.
	env := make(map[string]string, len(spec.Env)+3)
	for k, v := range spec.Env {
		env[k] = v
	}
	env[envInputB64] = b64In
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		env[envTraceID] = sc.TraceID().String()
		env[envSpanID] = sc.SpanID().String()
	}

	// 3. Launch.
	launchCtx, launchSpan := e.tracer.Start(ctx, "setec.launch")
	launchResp, err := e.client.Launch(launchCtx, LaunchRequest{
		Image:   spec.Image,
		Command: spec.Command,
		Env:     env,
		VCPU:    spec.VCPU,
		Memory:  spec.Memory,
		Tenant:  e.tenant,
		Timeout: e.callTimeout + killGrace,
	})
	launchSpan.End()
	if err != nil {
		return types.WrapError(types.SANDBOX_LAUNCH_FAILED,
			fmt.Sprintf("launch sandbox for tool %q", toolName), err)
	}
	span.SetAttributes(attribute.String("setec.sandbox_id", launchResp.SandboxID))

	// 4. Set call deadline and start log stream concurrently with Wait.
	waitCtx, cancel := context.WithTimeout(ctx, e.callTimeout)
	defer cancel()

	ringBuf := newRing(logBufferLimit)
	logsDone := e.streamLogsAsync(waitCtx, launchResp.SandboxID, toolName, ringBuf)

	// 5. Wait.
	waitSpan := trace.SpanFromContext(waitCtx)
	waitCtx2, waitSpanNested := e.tracer.Start(waitCtx, "setec.wait")
	waitResp, waitErr := e.client.Wait(waitCtx2, launchResp.SandboxID)
	waitSpanNested.End()
	_ = waitSpan // keep for future attribute plumbing

	// 6. Let log stream finish draining (bounded by waitCtx).
	<-logsDone

	if waitErr != nil {
		if errors.Is(waitErr, context.DeadlineExceeded) {
			// Best-effort kill so Setec reaps the sandbox rather than letting it run.
			killCtx, killCancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = e.client.Kill(killCtx, launchResp.SandboxID)
			killCancel()
			return types.WrapError(types.SANDBOX_WAIT_TIMEOUT,
				fmt.Sprintf("tool %q sandbox %s exceeded %s call timeout",
					toolName, launchResp.SandboxID, e.callTimeout), waitErr)
		}
		return types.WrapError(types.SANDBOX_LAUNCH_FAILED,
			fmt.Sprintf("wait for sandbox %s", launchResp.SandboxID), waitErr)
	}

	// 7. Non-zero exit: surface with last N log lines for diagnostic.
	if waitResp.ExitCode != 0 {
		return types.WrapError(types.SANDBOX_NON_ZERO_EXIT,
			fmt.Sprintf("tool %q sandbox exited %d (%s): %s",
				toolName, waitResp.ExitCode, waitResp.Reason, ringBuf.tail(32)), nil)
	}

	// 8. Extract the tool-runner output marker from stdout.
	payload, found := extractOutputMarker(ringBuf.bytes())
	if !found {
		return types.WrapError(types.SANDBOX_OUTPUT_MALFORMED,
			fmt.Sprintf("tool %q sandbox produced no %s marker; last log tail: %s",
				toolName, markerOutputPrefix, ringBuf.tail(16)), nil)
	}
	rawOut, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return types.WrapError(types.SANDBOX_OUTPUT_MALFORMED,
			fmt.Sprintf("tool %q sandbox output base64 decode", toolName), err)
	}
	if err := protojson.Unmarshal(rawOut, response); err != nil {
		return types.WrapError(types.SANDBOX_OUTPUT_MALFORMED,
			fmt.Sprintf("tool %q sandbox output protojson unmarshal", toolName), err)
	}
	return nil
}

// streamLogsAsync consumes the sandbox log stream, mirrors each chunk to the
// ring buffer AND to the harness logger (so operators see sandbox output in
// Gibson's normal log pipeline), and returns a channel that closes when the
// stream drains.
func (e *Executor) streamLogsAsync(ctx context.Context, sandboxID, toolName string, rb *ring) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := e.client.StreamLogs(ctx, sandboxID)
		if err != nil {
			e.logger.Warn("sandbox stream logs failed",
				"tool", toolName, "sandbox_id", sandboxID, "error", err)
			return
		}
		defer stream.Close()
		for {
			chunk, err := stream.Recv()
			if err == io.EOF || errors.Is(err, context.Canceled) {
				return
			}
			if err != nil {
				e.logger.Warn("sandbox log recv error",
					"tool", toolName, "sandbox_id", sandboxID, "error", err)
				return
			}
			rb.write(chunk)
			// Forward to harness logger so sandbox output shows up in normal
			// daemon observability. Chunks may not be line-aligned; logger
			// consumers that care will split.
			e.logger.Debug("sandbox log",
				"tool", toolName, "sandbox_id", sandboxID, "chunk", string(chunk))
		}
	}()
	return done
}

// extractOutputMarker scans a stdout buffer for the LAST line beginning with
// the output marker and returns its base64 payload (trailing newline trimmed).
// Tools may log freely before the marker; the scanner skips every prior line.
func extractOutputMarker(buf []byte) (string, bool) {
	// Iterate lines in reverse so we land on the LAST marker.
	lines := bytes.Split(buf, []byte{'\n'})
	for i := len(lines) - 1; i >= 0; i-- {
		l := lines[i]
		if bytes.HasPrefix(l, []byte(markerOutputPrefix)) {
			return strings.TrimRight(string(l[len(markerOutputPrefix):]), "\r\n\t "), true
		}
	}
	return "", false
}

// ring is a naive fixed-size byte ring buffer used to capture sandbox stdout
// for marker extraction and error diagnostics. Writes past the capacity drop
// the oldest bytes. Not suitable for large-throughput use — 1 MiB cap is
// sized for tool-sized outputs, not streaming workloads.
type ring struct {
	mu    sync.Mutex
	data  []byte
	cap   int
	over  bool // true once we've wrapped past cap
	wpos  int
}

func newRing(capacity int) *ring {
	return &ring{data: make([]byte, 0, capacity), cap: capacity}
}

func (r *ring) write(p []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.over {
		if len(r.data)+len(p) <= r.cap {
			r.data = append(r.data, p...)
			return
		}
		// Fill remainder, then wrap.
		fill := r.cap - len(r.data)
		r.data = append(r.data, p[:fill]...)
		p = p[fill:]
		r.over = true
		r.wpos = 0
	}
	for len(p) > 0 {
		n := copy(r.data[r.wpos:], p)
		r.wpos = (r.wpos + n) % r.cap
		p = p[n:]
	}
}

// bytes returns the buffer contents in write order. If the ring hasn't
// wrapped, this is just data. If it has, re-assemble from wpos → end → start.
func (r *ring) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.over {
		out := make([]byte, len(r.data))
		copy(out, r.data)
		return out
	}
	out := make([]byte, r.cap)
	copy(out, r.data[r.wpos:])
	copy(out[r.cap-r.wpos:], r.data[:r.wpos])
	return out
}

// tail returns the last N lines of the buffer, newline-joined, for error
// diagnostic context.
func (r *ring) tail(nLines int) string {
	lines := bytes.Split(r.bytes(), []byte{'\n'})
	start := len(lines) - nLines
	if start < 0 {
		start = 0
	}
	return string(bytes.Join(lines[start:], []byte{'\n'}))
}
