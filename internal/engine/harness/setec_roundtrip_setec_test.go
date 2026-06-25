//go:build setec_integration

// E10 / gibson#999 — E3 setec execution round-trip.
//
// This is the hardware-gated proof that an UNTRUSTED tool completes ONLY via a
// real setec microVM round-trip and is DENIED (typed error, no in-process
// fallback) when no sandboxed dispatch is available under setec-only.
//
// It is excluded from the default build by the `setec_integration` tag and
// further self-skips unless SETEC_ROUNDTRIP_ADDR (+ mTLS cert paths) is set, so
// `go test -tags setec_integration ./...` on a host without a reachable setec
// frontend is a no-op rather than a failure. The lane that runs it green lives
// at .github/workflows/e2e-setec-roundtrip.yml on the `setec-bare-metal`
// self-hosted KVM runner.
//
// The success path exercises the full harness dispatch chain:
//
//	CallToolProto → lookupSandboxedToolSpec (DispatchMode=SANDBOXED)
//	             → dispatch-policy gate (UNTRUSTED + sandbox available ⇒ RequireSetec)
//	             → sandboxed.Executor.ExecuteWithSpec
//	             → setec SandboxService Launch/Wait/StreamLogs over mTLS
//	             → gibson-runner emits ===GIBSON_TOOL_OUTPUT===<b64 CallToolResponse>
//	             → response unmarshalled back into the caller's proto.
//
// A bare in-test SandboxClient (setecRoundtripClient) mirrors the production
// daemon adapter's gRPC mapping so this test stays in package harness (no
// daemon import cycle) while still driving a real setec frontend.
package harness

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// roundtripEnv collects the setec-frontend connection parameters from the
// environment. SETEC_ROUNDTRIP_ADDR is the skip sentinel: when it is unset the
// whole suite self-skips.
type roundtripEnv struct {
	addr       string
	certFile   string
	keyFile    string
	caFile     string
	serverName string
	image      string
	tool       string
	inputJSON  string
	// sandboxClass selects a cluster-scoped setec SandboxClass. Empty defers to
	// the cluster default — set GIBSON_ROUNDTRIP_SANDBOX_CLASS on clusters that
	// have no default class.
	sandboxClass string
	// vcpu / memory must fit within the chosen SandboxClass's maxResources, or
	// setec rejects the Launch with ConstraintViolated.
	vcpu   int32
	memory string
}

func loadRoundtripEnv(t *testing.T) roundtripEnv {
	t.Helper()
	addr := os.Getenv("SETEC_ROUNDTRIP_ADDR")
	if addr == "" {
		t.Skip("SETEC_ROUNDTRIP_ADDR unset; skipping setec round-trip (run on the setec-bare-metal KVM runner)")
	}
	e := roundtripEnv{
		addr:       addr,
		certFile:   os.Getenv("SETEC_ROUNDTRIP_CERT"),
		keyFile:    os.Getenv("SETEC_ROUNDTRIP_KEY"),
		caFile:     os.Getenv("SETEC_ROUNDTRIP_CA"),
		serverName: getenvDefault("SETEC_ROUNDTRIP_SERVER_NAME", "setec-frontend.setec-system.svc"),
		image:      getenvDefault("GIBSON_EXECUTOR_IMAGE", "ghcr.io/zeroroot-ai/gibson-executor:dev"),
		tool:       getenvDefault("GIBSON_ROUNDTRIP_TOOL", "nmap"),
		// Loopback ping-scan: offline, deterministic, exits 0, and produces a
		// DiscoveryResult — so the assertion is on the round-trip plumbing, not
		// on any network reachability.
		inputJSON:    getenvDefault("GIBSON_ROUNDTRIP_INPUT_JSON", `{"target":"127.0.0.1","args":["-sn"]}`),
		sandboxClass: os.Getenv("GIBSON_ROUNDTRIP_SANDBOX_CLASS"),
		vcpu:         1,
		memory:       getenvDefault("GIBSON_ROUNDTRIP_MEMORY", "512Mi"),
	}
	if v := os.Getenv("GIBSON_ROUNDTRIP_VCPU"); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil {
			t.Fatalf("GIBSON_ROUNDTRIP_VCPU=%q is not an integer: %v", v, perr)
		}
		e.vcpu = int32(n)
	}
	for name, v := range map[string]string{
		"SETEC_ROUNDTRIP_CERT": e.certFile,
		"SETEC_ROUNDTRIP_KEY":  e.keyFile,
		"SETEC_ROUNDTRIP_CA":   e.caFile,
	} {
		if v == "" {
			t.Fatalf("%s must be set when SETEC_ROUNDTRIP_ADDR is set (mTLS is mandatory on the setec frontend)", name)
		}
	}
	return e
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// TestSetecRoundTrip_UntrustedToolExecutesViaSandbox is the AC-1 success path:
// an UNTRUSTED tool registered with DispatchMode=SANDBOXED completes via a real
// setec microVM round-trip and returns its CallToolResponse.
func TestSetecRoundTrip_UntrustedToolExecutesViaSandbox(t *testing.T) {
	env := loadRoundtripEnv(t)

	client := newSetecRoundtripClient(t, env)
	exec, err := sandboxed.New(sandboxed.Config{
		Client:      client,
		Logger:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Tenant:      "e2e",
		CallTimeout: 4 * time.Minute,
	})
	if err != nil {
		t.Fatalf("build sandboxed executor: %v", err)
	}

	h := newSandboxedHarness(t, exec, &sandboxedFakeRegistry{
		systemInstances: []component.ComponentInfo{{
			Kind:         "tool",
			Name:         env.tool,
			DispatchMode: componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED,
			ContentTrust: componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
			Image:        env.image,
			Command:      []string{"gibson-runner"},
			Env:          map[string]string{"GIBSON_TOOL_NAME": env.tool},
			Resources:    component.SandboxResources{VCPU: env.vcpu, Memory: env.memory},
		}},
	})

	ctx, cancel := context.WithTimeout(auth.ContextWithTenantString(context.Background(), "e2e"), 5*time.Minute)
	defer cancel()

	req := &componentpb.CallToolRequest{ToolName: env.tool, InputJson: env.inputJSON}
	var resp componentpb.CallToolResponse
	if err := h.CallToolProto(ctx, env.tool, req, &resp); err != nil {
		t.Fatalf("CallToolProto via setec round-trip failed: %v", err)
	}

	// The round-trip succeeded iff the executor parsed a CallToolResponse from
	// the sandbox's ===GIBSON_TOOL_OUTPUT=== marker. A successful tool run
	// populates output_json (a DiscoveryResult); the runner only exits 0 and
	// emits the success marker on a clean parse, so reaching here at all proves
	// the harness→setec→gibson-runner→harness chain.
	if resp.GetError() != nil {
		t.Fatalf("tool round-tripped but reported an execution error: code=%s msg=%s",
			resp.GetError().GetCode(), resp.GetError().GetMessage())
	}
	if resp.GetOutputJson() == "" {
		t.Fatalf("round-trip returned an empty CallToolResponse; expected output_json from %s", env.tool)
	}
	t.Logf("setec round-trip OK: tool=%s output_json=%d bytes", env.tool, len(resp.GetOutputJson()))
}

// TestSetecRoundTrip_UntrustedDeniedWhenNotSandboxed is the AC-2 deny path
// against the live wiring: the same UNTRUSTED tool, registered WITHOUT a
// SANDBOXED entry (DispatchMode ≠ SANDBOXED) under setec-only, is denied with
// the typed SANDBOX_POLICY_DENIED code and never dispatched — even though a
// real sandboxed executor is wired and the frontend is reachable.
func TestSetecRoundTrip_UntrustedDeniedWhenNotSandboxed(t *testing.T) {
	env := loadRoundtripEnv(t)

	client := newSetecRoundtripClient(t, env)
	exec, err := sandboxed.New(sandboxed.Config{
		Client: client, Logger: slog.Default(), Tenant: "e2e", CallTimeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("build sandboxed executor: %v", err)
	}

	// No system SANDBOXED entry; the tool only appears as a tenant instance with
	// a direct gRPC endpoint (the in-process bypass the gate must forbid).
	h := newSandboxedHarness(t, exec, &sandboxedFakeRegistry{
		tenantInstances: []component.ComponentInfo{{
			Kind:         "tool",
			Name:         env.tool,
			ContentTrust: componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED,
			Metadata:     map[string]string{"grpc_endpoint": "localhost:1"},
		}},
	})

	ctx := auth.ContextWithTenantString(context.Background(), "e2e")
	req := &componentpb.CallToolRequest{ToolName: env.tool, InputJson: env.inputJSON}
	var resp componentpb.CallToolResponse
	err = h.CallToolProto(ctx, env.tool, req, &resp)
	if code := gibsonCode(t, err); code != types.SANDBOX_POLICY_DENIED {
		t.Fatalf("code = %q; want SANDBOX_POLICY_DENIED (untrusted tool with no sandboxed dispatch must be denied)", code)
	}
}

// newSandboxedHarness builds a white-box harness on the sandboxed-dispatch path
// with deploymentShape pinned to setec-only.
func newSandboxedHarness(t *testing.T, exec *sandboxed.Executor, reg component.ComponentRegistry) *DefaultAgentHarness {
	t.Helper()
	return &DefaultAgentHarness{
		logger:            slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
		tracer:            noop.NewTracerProvider().Tracer("test"),
		componentRegistry: reg,
		sandboxedExecutor: exec,
		deploymentShape:   dispatchpolicy.ShapeSetecOnly,
	}
}

// sandboxedFakeRegistry is a component.ComponentRegistry that serves a fixed set
// of system (sandboxed) and tenant instances. DiscoverSystemOnly drives the
// SANDBOXED lookup; Discover drives the tenant/in-process path.
type sandboxedFakeRegistry struct {
	systemInstances []component.ComponentInfo
	tenantInstances []component.ComponentInfo
}

func (r *sandboxedFakeRegistry) DiscoverSystemOnly(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return r.systemInstances, nil
}
func (r *sandboxedFakeRegistry) Discover(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return r.tenantInstances, nil
}
func (r *sandboxedFakeRegistry) Register(_ context.Context, _, _, _ string, _ component.ComponentInfo) (string, error) {
	return "", nil
}
func (r *sandboxedFakeRegistry) Deregister(_ context.Context, _, _, _, _ string) error { return nil }
func (r *sandboxedFakeRegistry) RefreshTTL(_ context.Context, _, _, _, _ string) error { return nil }
func (r *sandboxedFakeRegistry) DiscoverAll(_ context.Context, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *sandboxedFakeRegistry) ListTenantComponents(_ context.Context, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}
func (r *sandboxedFakeRegistry) DiscoverTenantOnly(_ context.Context, _, _, _ string) ([]component.ComponentInfo, error) {
	return nil, nil
}

// setecRoundtripClient adapts setecv1.SandboxServiceClient to
// sandboxed.SandboxClient. It mirrors the production daemon adapter
// (internal/server/daemon/sandboxed_setec_adapter.go) minus KEK wrapping, which
// is irrelevant to the dispatch-path round-trip under test.
type setecRoundtripClient struct {
	inner        setecv1.SandboxServiceClient
	sandboxClass string
}

func newSetecRoundtripClient(t *testing.T, env roundtripEnv) *setecRoundtripClient {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(env.certFile, env.keyFile)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	caPEM, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("CA %s contained no PEM certificates", env.caFile)
	}
	conn, err := grpc.NewClient(env.addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   env.serverName,
		MinVersion:   tls.VersionTLS12,
	})))
	if err != nil {
		t.Fatalf("dial setec %s: %v", env.addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &setecRoundtripClient{inner: setecv1.NewSandboxServiceClient(conn), sandboxClass: env.sandboxClass}
}

func (c *setecRoundtripClient) Launch(ctx context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	pbReq := &setecv1.LaunchRequest{
		Image:        req.Image,
		Command:      req.Command,
		Env:          req.Env,
		SandboxClass: c.sandboxClass,
		Resources:    &setecv1.Resources{Vcpu: uint32(req.VCPU), Memory: req.Memory},
	}
	if req.Timeout > 0 {
		pbReq.Lifecycle = &setecv1.Lifecycle{Timeout: req.Timeout.String()}
	}
	resp, err := c.inner.Launch(ctx, pbReq)
	if err != nil {
		return sandboxed.LaunchResponse{}, err
	}
	return sandboxed.LaunchResponse{SandboxID: resp.GetSandboxId()}, nil
}

func (c *setecRoundtripClient) StreamLogs(ctx context.Context, sandboxID string) (sandboxed.LogStream, error) {
	stream, err := c.inner.StreamLogs(ctx, &setecv1.StreamLogsRequest{SandboxId: sandboxID, Follow: true})
	if err != nil {
		return nil, err
	}
	return &setecRoundtripLogStream{inner: stream}, nil
}

func (c *setecRoundtripClient) Wait(ctx context.Context, sandboxID string) (sandboxed.WaitResponse, error) {
	resp, err := c.inner.Wait(ctx, &setecv1.WaitRequest{SandboxId: sandboxID})
	if err != nil {
		return sandboxed.WaitResponse{}, err
	}
	return sandboxed.WaitResponse{ExitCode: resp.GetExitCode(), Reason: resp.GetReason()}, nil
}

func (c *setecRoundtripClient) Kill(ctx context.Context, sandboxID string) error {
	_, err := c.inner.Kill(ctx, &setecv1.KillRequest{SandboxId: sandboxID})
	return err
}

type setecRoundtripLogStream struct {
	inner setecv1.SandboxService_StreamLogsClient
}

func (s *setecRoundtripLogStream) Recv() ([]byte, error) {
	chunk, err := s.inner.Recv()
	if err != nil {
		return nil, err
	}
	return chunk.GetData(), nil
}

func (s *setecRoundtripLogStream) Close() error { return nil }
