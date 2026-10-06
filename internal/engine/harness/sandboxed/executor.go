// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// DiscoveryProcessor processes proto DiscoveryResult from tool responses.
// The executor invokes Process asynchronously after a successful tool call so
// discoveries produced in sandboxed microVMs land in the knowledge graph with
// the same semantics as the live-callback path (see
// core/gibson/internal/engine/harness/callback_service.go:727 for the reference
// implementation). The interface is declared locally to avoid importing the
// harness package (which would create an import cycle — harness imports
// sandboxed, not the other way around).
type DiscoveryProcessor interface {
	Process(ctx context.Context, execCtx ingest.ExecContext, discovery *graphragpb.DiscoveryResult) (interface{}, error)
}

// discoveryProcessTimeout bounds each asynchronous DiscoveryProcessor.Process
// invocation. Matches the callback path's budget so operators see identical
// behavior regardless of dispatch mode.
const discoveryProcessTimeout = 30 * time.Second

// ctxStringValue reads a string-typed context key that has no dedicated
// accessor in the contextkeys package. Returns "" if missing.
func ctxStringValue(ctx context.Context, key contextkeys.Key) string {
	if v := ctx.Value(key); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

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
// Each call names the customer tenant of the caller. setec keeps one
// namespace for each pair of client and tenant, and it does not derive the
// tenant from the caller certificate (ADR-0142, gibson#756).
// It is implemented by an adapter around Setec's generated gRPC client —
// the adapter lives in the daemon-startup wiring so this package does not
// import setec's proto package directly.
type SandboxClient interface {
	Launch(ctx context.Context, req LaunchRequest) (LaunchResponse, error)
	StreamLogs(ctx context.Context, tenant, sandboxID string) (LogStream, error)
	Wait(ctx context.Context, tenant, sandboxID string) (WaitResponse, error)
	Kill(ctx context.Context, tenant, sandboxID string) error
}

// LaunchRequest is the data the executor passes to Setec's Launch RPC.
// Adapters map it onto Setec's generated proto.
type LaunchRequest struct {
	Image   string
	Command []string
	Env     map[string]string
	VCPU    int32
	Memory  string
	Tenant  string // the customer tenant of the caller; required (ADR-0142)
	Timeout time.Duration

	// SandboxClass names the setec SandboxClass this launch must run under.
	// It is the isolation posture gibson is asking for, and it is required:
	// an empty value would defer to whatever class the cluster marks default,
	// which is exactly the "requested isolation nobody chose" hole ADR-0052
	// closes. setec's admission webhook rejects a create naming a class that
	// does not exist, so the request is server-validated.
	SandboxClass string

	// Egress, when non-empty, makes the launch send the network mode
	// egress-allow-list with exactly these targets. When it is empty the
	// launch sends no network message, and the sandbox takes the
	// defaultNetworkMode of its SandboxClass. setec has three modes:
	// external-only, egress-allow-list and none. It has no mode "full".
	Egress []EgressRule

	// NetworkMode, when set, is the setec network mode of the launch, and it
	// wins over the rule above: NetworkModeExternalOnly, NetworkModeAllowList
	// with the Egress rules, or NetworkModeNone. Empty keeps the rule above.
	NetworkMode string
}

// The setec network modes that a launch can name (zeroroot-ai/setec#200).
const (
	NetworkModeExternalOnly = "external-only"
	NetworkModeAllowList    = "egress-allow-list"
	NetworkModeNone         = "none"
)

// EgressRule is one egress-allow-list entry, mirroring setec's
// Network.allow shape. An entry names a Host or a CIDR. It names one Port,
// or a list of Ports.
type EgressRule struct {
	Host string
	Port uint32

	// CIDR is an address block, for example "10.0.0.0/24".
	CIDR string

	// Ports are port ranges with a protocol. When set, Port is zero.
	Ports []PortRange
}

// PortRange is one port, or a range of ports when EndPort is set, for one
// protocol. An empty Protocol means TCP.
type PortRange struct {
	Protocol string
	Port     uint32
	EndPort  uint32
}

// LaunchResponse is the executor-facing result of Launch.
type LaunchResponse struct {
	SandboxID string

	// SandboxClass is the class setec actually bound the sandbox to, and
	// Runtime is the isolation backend that class resolved to (one of
	// kata-fc, kata-qemu, gvisor, runc). Both are checked by VerifyIsolation
	// before the sandbox is used. An adapter leaves a field empty when its
	// transport does not report it; see isolation.go for why the setec.v1 ABI
	// currently reports neither.
	SandboxClass string
	Runtime      string
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
// use: per-call state lives on the stack of ExecuteWithSpec.
type Executor struct {
	client             SandboxClient
	tracer             trace.Tracer
	logger             *slog.Logger
	sandboxClass       string
	callTimeout        time.Duration
	discoveryProcessor DiscoveryProcessor // optional; nil disables graph persistence
	events             EventPublisher     // optional; nil disables the live console
}

// Config is the constructor input for the executor. All fields are required
// except Tracer (no-op used when nil) and Logger (slog.Default when nil).
// DiscoveryProcessor is optional — when nil, field-100 DiscoveryResult
// extraction is skipped entirely and no warning is logged per-call.
type Config struct {
	Client      SandboxClient
	Tracer      trace.Tracer
	Logger      *slog.Logger
	CallTimeout time.Duration // defaults to 5m when zero

	// SandboxClass is the setec SandboxClass every tool launch runs under.
	// Required — New refuses to build an executor without one rather than
	// letting tool code land on the cluster-default isolation posture.
	SandboxClass string

	DiscoveryProcessor DiscoveryProcessor

	// Events is the live-console sink. A tool runs in a sandbox exactly like
	// an agent does, so a tool run is enumerable and streamable on the same
	// surface. Nil disables it and the executor behaves as before.
	Events EventPublisher
}

// New constructs an Executor. Returns a clear error on misconfiguration so
// the daemon can log a warning and continue (per Requirement 5.4).
func New(cfg Config) (*Executor, error) {
	if cfg.Client == nil {
		return nil, errors.New("sandboxed.New: Client is required")
	}
	if cfg.SandboxClass == "" {
		return nil, errors.New("sandboxed.New: SandboxClass is required (ADR-0052: gibson must name the isolation posture, not inherit the cluster default)")
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
		client:             cfg.Client,
		tracer:             cfg.Tracer,
		logger:             cfg.Logger,
		sandboxClass:       cfg.SandboxClass,
		callTimeout:        cfg.CallTimeout,
		discoveryProcessor: cfg.DiscoveryProcessor,
		events:             cfg.Events,
	}, nil
}

// ExecuteWithSpec dispatches a single tool invocation using the provided
// ToolSpec. Used by the unified dispatch path in harness.CallToolProto,
// which resolves the spec from the tool's kind:tool catalog manifest
// (ADR-0117) and supplies image, command, env and resources per call.
func (e *Executor) ExecuteWithSpec(ctx context.Context, toolName string, spec ToolSpec, request, response proto.Message) error {
	ctx, span := e.tracer.Start(ctx, "harness.sandboxed.execute")
	defer span.End()
	// The customer tenant of the call names the setec namespace (ADR-0142).
	// A call with no tenant does not launch.
	tenant := spec.Live.Tenant
	span.SetAttributes(
		attribute.String("gibson.tool.name", toolName),
		attribute.String("setec.tenant", tenant),
	)
	if spec.Image == "" {
		return types.WrapError(types.SANDBOX_TOOL_NOT_REGISTERED,
			fmt.Sprintf("tool %q: empty image in ToolSpec", toolName), nil)
	}
	if tenant == "" {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q: the call names no tenant", toolName), nil)
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
		Image:        spec.Image,
		Command:      spec.Command,
		Env:          env,
		VCPU:         spec.VCPU,
		Memory:       spec.Memory,
		Tenant:       tenant,
		SandboxClass: e.sandboxClass,
		Timeout:      e.callTimeout + killGrace,
		Egress:       spec.Egress,
		NetworkMode:  spec.NetworkMode,
	})
	launchSpan.End()
	if err != nil {
		return types.WrapError(types.SANDBOX_LAUNCH_FAILED,
			fmt.Sprintf("launch sandbox for tool %q", toolName), err)
	}
	span.SetAttributes(attribute.String("setec.sandbox_id", launchResp.SandboxID))

	// Register this call as a live instance so the read-only console can
	// follow it, exactly as the agent launcher does (ADR-0116 S11). The key
	// is the CUSTOMER tenant the caller supplied. The run id is the sandbox
	// id: a tool call is one launch,
	// and an agent run id would collide across the calls it makes.
	var publish func([]byte)
	if e.events != nil {
		var finish func()
		publish, finish = e.events.RegisterInstance(spec.Live.Tenant, LiveInstance{
			RunID:         runIDFromSandboxID(launchResp.SandboxID),
			AgentName:     toolName,
			SandboxID:     launchResp.SandboxID,
			SandboxClass:  e.sandboxClass,
			ComponentKind: ComponentKindTool,
			StartedAt:     time.Now(),
			MissionID:     spec.Live.MissionID,
			MissionRunID:  spec.Live.MissionRunID,
		})
		defer finish()
	}

	// Isolation gate (ADR-0052). The sandbox exists but nothing has run in it
	// yet — this is the last point at which we can refuse it. A sandbox whose
	// isolation we could not confirm is killed, not used: the tool inside it
	// is untrusted by construction and must not execute without a boundary.
	if isoErr := VerifyIsolation(e.sandboxClass, launchResp); isoErr != nil {
		killCtx, killCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		_ = e.client.Kill(killCtx, tenant, launchResp.SandboxID)
		killCancel()
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q sandbox %s refused", toolName, launchResp.SandboxID), isoErr)
	}
	span.SetAttributes(attribute.String("setec.sandbox_class", e.sandboxClass))

	// 4. Set call deadline and start log stream concurrently with Wait.
	waitCtx, cancel := context.WithTimeout(ctx, e.callTimeout)
	defer cancel()

	ringBuf := newRing(logBufferLimit)
	logsDone := e.streamLogsAsync(waitCtx, tenant, launchResp.SandboxID, toolName, ringBuf, publish)

	// 5. Wait.
	waitSpan := trace.SpanFromContext(waitCtx)
	waitCtx2, waitSpanNested := e.tracer.Start(waitCtx, "setec.wait")
	waitResp, waitErr := e.client.Wait(waitCtx2, tenant, launchResp.SandboxID)
	waitSpanNested.End()
	_ = waitSpan // keep for future attribute plumbing

	// 6. Let log stream finish draining (bounded by waitCtx).
	<-logsDone

	if waitErr != nil {
		if errors.Is(waitErr, context.DeadlineExceeded) {
			// Best-effort kill so Setec reaps the sandbox rather than letting it run.
			killCtx, killCancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = e.client.Kill(killCtx, tenant, launchResp.SandboxID)
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

	// Async discovery persistence. Mirrors core/gibson/internal/engine/harness/
	// callback_service.go:727 so sandboxed-path discoveries land in Neo4j with
	// identical semantics to the callback-dispatched tools. Non-blocking: the
	// caller returns immediately; processing errors are logged, never
	// propagated. Skipped when no DiscoveryProcessor is wired (GraphRAG off).
	if e.discoveryProcessor != nil {
		if pbDiscovery := sdkgraphrag.ExtractDiscovery(response); pbDiscovery != nil {
			execCtx := ingest.ExecContext{
				MissionRunID:    contextkeys.GetMissionRunID(ctx),
				MissionID:       ctxStringValue(ctx, contextkeys.MissionID),
				AgentName:       ctxStringValue(ctx, contextkeys.AgentName),
				AgentRunID:      contextkeys.GetAgentRunID(ctx),
				ToolExecutionID: contextkeys.GetToolExecutionID(ctx),
			}
			go e.processDiscoveryAsync(toolName, execCtx, pbDiscovery)
		}
	}

	return nil
}

// processDiscoveryAsync runs DiscoveryProcessor.Process in a detached context
// with the same 30s timeout the callback path uses. Panics are recovered so a
// buggy parser cannot crash the daemon. Errors are logged, never returned.
func (e *Executor) processDiscoveryAsync(toolName string, execCtx ingest.ExecContext, discovery *graphragpb.DiscoveryResult) {
	defer func() {
		if r := recover(); r != nil {
			e.logger.Error("sandboxed discovery processor panicked",
				"tool", toolName,
				"mission_run_id", execCtx.MissionRunID,
				"panic", r,
				"stack", string(debug.Stack()),
				"dispatch_path", "sandboxed",
			)
		}
	}()

	processCtx, cancel := context.WithTimeout(context.Background(), discoveryProcessTimeout)
	defer cancel()

	result, err := e.discoveryProcessor.Process(processCtx, execCtx, discovery)
	if err != nil {
		e.logger.ErrorContext(processCtx, "failed to process discovery",
			"error", err,
			"tool", toolName,
			"mission_run_id", execCtx.MissionRunID,
			"dispatch_path", "sandboxed",
		)
		return
	}
	if result != nil {
		e.logger.DebugContext(processCtx, "discovery processed successfully",
			"tool", toolName,
			"mission_run_id", execCtx.MissionRunID,
			"dispatch_path", "sandboxed",
		)
	}
}

// streamLogsAsync consumes the sandbox log stream, mirrors each chunk to the
// ring buffer AND to the harness logger (so operators see sandbox output in
// Gibson's normal log pipeline), and returns a channel that closes when the
// stream drains.
func (e *Executor) streamLogsAsync(ctx context.Context, tenant, sandboxID, toolName string, rb *ring, publish func([]byte)) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream, err := e.client.StreamLogs(ctx, tenant, sandboxID)
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
			if publish != nil {
				publish(chunk)
			}
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
	mu   sync.Mutex
	data []byte
	cap  int
	over bool // true once we've wrapped past cap
	wpos int
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

// EgressRulesFromAllow converts a manifest egressAllow ceiling into setec egress
// rules. An empty list returns nil: the launch then sends no network message
// and the sandbox takes the defaultNetworkMode of its SandboxClass. Each entry
// is "host[:port]"; a missing port defaults to 443. The catalog loader refuses
// the value "*" (gibson#865), so it never reaches this function.
func EgressRulesFromAllow(allow []string) []EgressRule {
	if len(allow) == 0 {
		return nil
	}
	rules := make([]EgressRule, 0, len(allow))
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		host, port := a, uint32(443)
		if i := strings.LastIndex(a, ":"); i >= 0 {
			if p, err := strconv.ParseUint(a[i+1:], 10, 32); err == nil {
				host, port = a[:i], uint32(p)
			}
		}
		if host == "" {
			continue
		}
		rules = append(rules, EgressRule{Host: host, Port: port})
	}
	if len(rules) == 0 {
		return nil
	}
	return rules
}
