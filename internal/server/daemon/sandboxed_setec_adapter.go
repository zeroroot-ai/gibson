//go:build setec_integration

// Package daemon — Setec gRPC client adapter for the sandboxed tool executor.
//
// This file wraps Setec's generated `SandboxServiceClient` to satisfy the
// internal `sandboxed.SandboxClient` interface. The sandboxed package has
// zero Setec imports — this file is the single point of contact.
//
// Build tag `setec_integration` keeps this out of the default build so
// gibson compiles even if the setec module is unavailable. Enable with:
//
//     go build -tags=setec_integration ./...
//     go test  -tags=setec_integration ./...
//
// # Wiring
//
// `NewSetecSandboxedExecutor(cfg config.SandboxConfig, tracer, logger)` dials
// the Setec frontend with mTLS using `component.TLSConfig.BuildTLSConfig()`,
// builds the client, wires a `sandboxed.Executor`, and returns it. Returns
// (nil, nil) when cfg.Enabled is false so the daemon can unconditionally
// call this during infrastructure init. On dial/TLS failure, returns
// (nil, err) — per design Requirement 5.4 the daemon LOGS the warning and
// continues startup; per-call failures surface at tool invocation time
// rather than blocking daemon start.

package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/loader"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/envelope"
	sdkauth "github.com/zeroroot-ai/sdk/auth"
)

// NewSetecSandboxClient dials Setec with mTLS and returns a bare
// sandboxed.SandboxClient — useful for callers that need the Launch
// surface without also pulling in the full sandboxed.Executor. The daemon
// catalog refresher uses this to drive `gibson-runner --list-tools`
// microVM launches on its own schedule.
func NewSetecSandboxClient(cfg config.SandboxConfig) (sandboxed.SandboxClient, error) {
	tlsCfg, err := cfg.Setec.MTLS.BuildTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("build setec mTLS config: %w", err)
	}
	conn, err := grpc.NewClient(
		cfg.Setec.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
	)
	if err != nil {
		return nil, fmt.Errorf("dial setec %s: %w", cfg.Setec.Address, err)
	}
	return &setecClient{
		inner: setecv1.NewSandboxServiceClient(conn),
		conn:  conn,
	}, nil
}

// NewSetecPinger constructs a health.Pinger from the Setec gRPC connection.
// Returns the same setecClient cast to the health.Pinger interface so the
// startup health check and periodic probe can reuse the mTLS connection.
func NewSetecPinger(cfg config.SandboxConfig) (interface{ Ping(context.Context) error }, error) {
	sc, err := NewSetecSandboxClient(cfg)
	if err != nil {
		return nil, err
	}
	return sc.(*setecClient), nil
}

// NewSetecSandboxedExecutor constructs a sandboxed.Executor backed by a real
// Setec gRPC client.
//
// `discoveryProc` is optional. When non-nil, the sandboxed executor extracts
// field-100 DiscoveryResult from successful tool responses and persists them
// to Neo4j asynchronously, matching the live-callback path's behavior at
// core/gibson/internal/engine/harness/callback_service.go:727.
func NewSetecSandboxedExecutor(cfg config.SandboxConfig, tracer trace.Tracer, logger *slog.Logger, discoveryProc ingest.DiscoveryProcessor) (*sandboxed.Executor, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	client, err := NewSetecSandboxClient(cfg)
	if err != nil {
		return nil, err
	}
	var sbxDiscovery sandboxed.DiscoveryProcessor
	if discoveryProc != nil {
		sbxDiscovery = &sandboxedDiscoveryAdapter{inner: discoveryProc}
	}
	return sandboxed.New(sandboxed.Config{
		Client:             client,
		Tracer:             tracer,
		Logger:             logger,
		Tenant:             cfg.Setec.Tenant,
		CallTimeout:        cfg.Setec.CallTimeout,
		DiscoveryProcessor: sbxDiscovery,
	})
}

// sandboxedDiscoveryAdapter widens ingest.DiscoveryProcessor's
// (*ProcessResult, error) return to the (interface{}, error) signature the
// sandboxed package's local DiscoveryProcessor interface declares. The
// sandboxed package deliberately keeps its interface narrow to avoid
// importing processor; this adapter is the single point of contact.
type sandboxedDiscoveryAdapter struct {
	inner ingest.DiscoveryProcessor
}

func (a *sandboxedDiscoveryAdapter) Process(ctx context.Context, execCtx loader.ExecContext, discovery *graphragpb.DiscoveryResult) (interface{}, error) {
	return a.inner.Process(ctx, execCtx, discovery)
}

// secretEnvPrefix is the env-var key prefix that identifies a value as
// credential/secret material. Any env var whose key starts with this prefix
// is envelope-wrapped under the tenant KEK before the Launch RPC is sent to
// Setec (R8.2). The tool-runner inside the microVM decrypts these using the
// same tenant KEK — forward-compatible once Setec ships R8.4.
//
// Currently GIBSON_SECRET_ is the sentinel; the tool-runner strips the prefix
// and decrypts the hex-encoded envelope before placing the value in the
// tool's environment.
const secretEnvPrefix = "GIBSON_SECRET_"

// setecClient adapts setecv1.SandboxServiceClient to sandboxed.SandboxClient.
// It also implements health.Pinger so the daemon's startup check and periodic
// probe can verify Setec frontend reachability without making a Launch call.
type setecClient struct {
	inner     setecv1.SandboxServiceClient
	conn      *grpc.ClientConn // kept for connectivity state checks
	masterKEK []byte           // optional; when nil, KEK wrapping is skipped
	tenantID  sdkauth.TenantID // AAD for KEK wrapping
}

// Ping verifies that the Setec frontend gRPC connection is in a usable state.
// It does NOT make an RPC call — it checks the connection's connectivity state.
// This is intentionally lightweight so the 5-second startup probe does not
// create unnecessary load on Setec during daemon startup.
//
// Implements health.Pinger (R5.2).
func (c *setecClient) Ping(_ context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("setec: no gRPC connection")
	}
	state := c.conn.GetState()
	switch state {
	case connectivity.Ready, connectivity.Idle:
		return nil
	case connectivity.Connecting:
		// Connecting is optimistic — the dial hasn't failed yet.
		return nil
	default:
		return fmt.Errorf("setec: connection state %s", state.String())
	}
}

func (c *setecClient) Launch(ctx context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	// ── KEK envelope-wrap secret env vars (R8.2) ─────────────────────────────
	// Any env var with key prefix `GIBSON_SECRET_` carries credential material.
	// When a master KEK is wired (production), we derive the tenant KEK and
	// envelope-encrypt those values before they cross the daemon→Setec boundary.
	// The ciphertext is hex-encoded so it is safe to pass as a plain env-var
	// string. The tool-runner inside the microVM decrypts them using the same
	// tenant KEK (forward-compatible with Setec R8.4).
	//
	// When masterKEK is nil (dev/kind, tests), wrapping is skipped so that
	// dev deployments without a KMS still function — intentional degraded mode.
	env := req.Env
	if c.masterKEK != nil && !c.tenantID.IsZero() {
		wrapped, err := wrapSecretEnvVars(c.masterKEK, c.tenantID, req.Env)
		if err != nil {
			// Wrapping failure is fatal: never send plaintext credentials to Setec
			// when we were supposed to wrap them (cross-tenant leakage risk).
			return sandboxed.LaunchResponse{},
				fmt.Errorf("setec: KEK envelope-wrap failed: %w", err)
		}
		env = wrapped
	}

	pbReq := &setecv1.LaunchRequest{
		Image:   req.Image,
		Command: req.Command,
		Env:     env,
		Resources: &setecv1.Resources{
			Vcpu:   uint32(req.VCPU),
			Memory: req.Memory,
		},
	}
	if req.Timeout > 0 {
		pbReq.Lifecycle = &setecv1.Lifecycle{Timeout: req.Timeout.String()}
	}
	// Egress allow-list: connector launches (gibson#684) confine the sandbox
	// to the targets declared in the connector manifest plus the platform
	// endpoints. Empty Egress keeps setec's default network mode.
	if len(req.Egress) > 0 {
		allow := make([]*setecv1.NetworkAllow, 0, len(req.Egress))
		for _, e := range req.Egress {
			allow = append(allow, &setecv1.NetworkAllow{Host: e.Host, Port: e.Port})
		}
		pbReq.Network = &setecv1.Network{Mode: "egress-allow-list", Allow: allow}
	}
	resp, err := c.inner.Launch(ctx, pbReq)
	if err != nil {
		return sandboxed.LaunchResponse{}, err
	}
	return sandboxed.LaunchResponse{SandboxID: resp.GetSandboxId()}, nil
}

// wrapSecretEnvVars envelope-wraps values whose key starts with secretEnvPrefix.
// The AAD is bound to the tenant_id so cross-tenant decryption fails with an
// authentication error (R8.2 "impossible by construction").
//
// Returns a new map; the original is not modified.
func wrapSecretEnvVars(masterKEK []byte, tenantID sdkauth.TenantID, env map[string]string) (map[string]string, error) {
	if len(env) == 0 {
		return env, nil
	}

	tenantKEK, err := datapool.DeriveTenantKEK(masterKEK, tenantID)
	if err != nil {
		return nil, fmt.Errorf("derive tenant KEK: %w", err)
	}
	defer func() {
		// Zero the derived KEK immediately after use to limit the window of
		// exposure in process memory.
		for i := range tenantKEK {
			tenantKEK[i] = 0
		}
	}()

	aad := []byte("sandbox:env:" + tenantID.String())

	out := make(map[string]string, len(env))
	for k, v := range env {
		if !strings.HasPrefix(k, secretEnvPrefix) {
			out[k] = v
			continue
		}
		ciphertext, encErr := envelope.Encrypt(tenantKEK, []byte(v), aad)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt env var %q: %w", k, encErr)
		}
		out[k] = hex.EncodeToString(ciphertext)
	}
	return out, nil
}

func (c *setecClient) StreamLogs(ctx context.Context, sandboxID string) (sandboxed.LogStream, error) {
	stream, err := c.inner.StreamLogs(ctx, &setecv1.StreamLogsRequest{SandboxId: sandboxID, Follow: true})
	if err != nil {
		return nil, err
	}
	return &setecLogStream{inner: stream}, nil
}

func (c *setecClient) Wait(ctx context.Context, sandboxID string) (sandboxed.WaitResponse, error) {
	resp, err := c.inner.Wait(ctx, &setecv1.WaitRequest{SandboxId: sandboxID})
	if err != nil {
		return sandboxed.WaitResponse{}, err
	}
	return sandboxed.WaitResponse{
		ExitCode: resp.GetExitCode(),
		Reason:   resp.GetReason(),
	}, nil
}

func (c *setecClient) Kill(ctx context.Context, sandboxID string) error {
	_, err := c.inner.Kill(ctx, &setecv1.KillRequest{SandboxId: sandboxID})
	return err
}

type setecLogStream struct {
	inner setecv1.SandboxService_StreamLogsClient
}

func (s *setecLogStream) Recv() ([]byte, error) {
	chunk, err := s.inner.Recv()
	if err != nil {
		return nil, err
	}
	return chunk.GetData(), nil
}

func (s *setecLogStream) Close() error {
	// Server-streaming RPC — client cancels via context. No explicit close
	// on the stream handle; the executor cancels the parent context when
	// the call completes, which closes the underlying HTTP/2 stream.
	return nil
}
