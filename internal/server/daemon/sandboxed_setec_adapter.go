// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
// `NewSetecSandboxedExecutor(cfg config.SandboxConfig, src, tracer, logger)`
// dials the Setec frontend with the SVID of the daemon (SPIFFE mTLS),
// builds the client, wires a `sandboxed.Executor`, and returns it. The
// sandbox fleet is required (ADR-0142), so a TLS build failure stops the
// daemon start. The dial itself is lazy: an unreachable frontend surfaces at
// tool invocation time (design Requirement 5.4).

package daemon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	setecv1 "github.com/zeroroot-ai/setec/api/grpc/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool"
	"github.com/zeroroot-ai/gibson/internal/infra/datapool/envelope"
	sdkauth "github.com/zeroroot-ai/sdk/auth"
)

// maxSetecRecvMsgBytes caps a single gRPC message received from the setec
// frontend. Log chunks on this channel are produced by untrusted code inside
// the sandbox, so the per-message cost to the daemon is bounded explicitly
// instead of inheriting grpc-go's default.
const maxSetecRecvMsgBytes = 4 * 1024 * 1024 // 4 MiB

// NewSetecSandboxClient dials Setec with mTLS and returns a bare
// sandboxed.SandboxClient — useful for callers that need the Launch
// surface without also pulling in the full sandboxed.Executor. Its callers
// are the sandboxed tool executor, the agent launcher (gibson#1596) and the
// interactive session client. The catalog refresher that once used it to
// launch `gibson-runner --list-tools` on a schedule is gone: tools are
// manifest-seeded now (ADR-0117).
func NewSetecSandboxClient(cfg config.SandboxConfig, src setecSVIDSource) (sandboxed.SandboxClient, error) {
	// The daemon presents its SVID and accepts only the SPIFFE ID of the
	// fleet (ADR-0142). No certificate file is read.
	fleet, err := spiffeid.FromString(cfg.Setec.SpiffeID)
	if err != nil {
		return nil, fmt.Errorf("sandbox.setec.spiffe_id: %w", err)
	}
	tlsCfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeID(fleet))
	conn, err := grpc.NewClient(
		cfg.Setec.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		// Everything on this channel — log chunks especially — originates
		// inside a sandbox running untrusted code. Cap what a single message
		// may cost the daemon rather than taking grpc-go's default on trust.
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxSetecRecvMsgBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("dial setec %s: %w", cfg.Setec.Address, err)
	}
	return &setecClient{
		inner: setecv1.NewSandboxServiceClient(conn),
		conn:  conn,
	}, nil
}

// NewSetecSandboxedExecutor constructs a sandboxed.Executor backed by a real
// Setec gRPC client.
//
// `discoveryProc` is optional. When non-nil, the sandboxed executor extracts
// field-100 DiscoveryResult from successful tool responses and folds them into
// the tenant's World asynchronously, matching what the live-callback path does
// with the same payload.
func NewSetecSandboxedExecutor(cfg config.SandboxConfig, src setecSVIDSource, tracer trace.Tracer, logger *slog.Logger, discoveryProc ingest.DiscoveryProcessor, events sandboxed.EventPublisher) (*sandboxed.Executor, error) {
	client, err := NewSetecSandboxClient(cfg, src)
	if err != nil {
		return nil, err
	}
	var sbxDiscovery sandboxed.DiscoveryProcessor
	if discoveryProc != nil {
		sbxDiscovery = &discoveryProcessorAdapter{inner: discoveryProc}
	}
	return sandboxed.New(sandboxed.Config{
		Client:             client,
		Tracer:             tracer,
		Logger:             logger,
		SandboxClass:       cfg.Setec.SandboxClass,
		CallTimeout:        cfg.Setec.CallTimeout,
		DiscoveryProcessor: sbxDiscovery,
		Events:             events,
	})
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
}

// errNoTenant refuses a setec call that names no tenant. setec selects the
// namespace of a sandbox from the pair of the caller cluster and the tenant
// of the request (ADR-0142), so a call with no tenant has no sandbox.
var errNoTenant = errors.New("setec: refusing a call that names no tenant")

// tenantForKEK parses the tenant of a request for the KEK envelope.
func tenantForKEK(tenant string) (sdkauth.TenantID, error) {
	id, err := sdkauth.NewTenantID(tenant)
	if err != nil {
		return sdkauth.TenantID{}, fmt.Errorf("setec: tenant %q: %w", tenant, err)
	}
	return id, nil
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
	if req.Tenant == "" {
		return sandboxed.LaunchResponse{}, errNoTenant
	}
	if req.FromSnapshot != "" {
		return c.launchFromSnapshot(ctx, req)
	}
	env, err := c.wrapEnv(req.Tenant, req.Env)
	if err != nil {
		return sandboxed.LaunchResponse{}, err
	}

	// Isolation posture (ADR-0052). gibson names the SandboxClass on every
	// launch instead of deferring to whatever class the cluster marks default.
	// setec's Sandbox admission webhook rejects a create naming a class that
	// does not resolve, so an install missing the class fails the launch
	// rather than quietly downgrading the isolation the tool runs under.
	if req.SandboxClass == "" {
		return sandboxed.LaunchResponse{},
			fmt.Errorf("setec: refusing to launch without a sandbox class")
	}

	pbReq := &setecv1.LaunchRequest{
		Tenant:       req.Tenant,
		SandboxClass: req.SandboxClass,
		Image:        req.Image,
		Command:      req.Command,
		Env:          env,
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
	pbReq.Network = setecNetwork(req.NetworkMode, req.Egress)
	resp, err := c.inner.Launch(ctx, pbReq)
	if err != nil {
		return sandboxed.LaunchResponse{}, err
	}
	// setec reports the class it bound and the runtime backend of that class.
	// sandboxed.VerifyIsolation refuses the sandbox when either one is empty,
	// differs from the request, or is not the launcher backend (ADR-0052).
	return sandboxed.LaunchResponse{
		SandboxID:    resp.GetSandboxId(),
		SandboxClass: resp.GetSandboxClass(),
		Runtime:      resp.GetRuntime(),
	}, nil
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

// wrapEnv envelope-wraps the secret env vars of a launch under the KEK of the
// tenant of the request. Wrapping failure is fatal: never send plaintext
// credentials to Setec when we were supposed to wrap them (cross-tenant
// leakage risk). With no master KEK (dev/kind, tests), the env is sent as is.
func (c *setecClient) wrapEnv(tenant string, env map[string]string) (map[string]string, error) {
	if c.masterKEK == nil {
		return env, nil
	}
	id, err := tenantForKEK(tenant)
	if err != nil {
		return nil, err
	}
	wrapped, err := wrapSecretEnvVars(c.masterKEK, id, env)
	if err != nil {
		return nil, fmt.Errorf("setec: KEK envelope-wrap failed: %w", err)
	}
	return wrapped, nil
}

// StreamLogs, Wait and Kill name the tenant of the caller on the wire
// (ADR-0142, gibson#756).
func (c *setecClient) StreamLogs(ctx context.Context, tenant, sandboxID string) (sandboxed.LogStream, error) {
	if tenant == "" {
		return nil, errNoTenant
	}
	stream, err := c.inner.StreamLogs(ctx, &setecv1.StreamLogsRequest{Tenant: tenant, SandboxId: sandboxID, Follow: true})
	if err != nil {
		return nil, err
	}
	return &setecLogStream{inner: stream}, nil
}

func (c *setecClient) Wait(ctx context.Context, tenant, sandboxID string) (sandboxed.WaitResponse, error) {
	if tenant == "" {
		return sandboxed.WaitResponse{}, errNoTenant
	}
	resp, err := c.inner.Wait(ctx, &setecv1.WaitRequest{Tenant: tenant, SandboxId: sandboxID})
	if err != nil {
		return sandboxed.WaitResponse{}, err
	}
	return sandboxed.WaitResponse{
		ExitCode: resp.GetExitCode(),
		Reason:   resp.GetReason(),
	}, nil
}

func (c *setecClient) Kill(ctx context.Context, tenant, sandboxID string) error {
	if tenant == "" {
		return errNoTenant
	}
	_, err := c.inner.Kill(ctx, &setecv1.KillRequest{Tenant: tenant, SandboxId: sandboxID})
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

// setecNetwork maps the network of a launch or a fork onto the wire. A set
// mode wins, with the egress rules for the allow-list mode. With no mode,
// egress rules select the allow-list mode, and no rules keep the default of
// the class (nil). Each rule keeps its CIDR and its port ranges
// (zeroroot-ai/setec#200), so the network scope of a mission node reaches
// setec as the node states it (gibson#865).
func setecNetwork(mode string, egress []sandboxed.EgressRule) *setecv1.Network {
	if mode == "" {
		if len(egress) == 0 {
			return nil
		}
		mode = sandboxed.NetworkModeAllowList
	}
	n := &setecv1.Network{Mode: mode}
	if mode != sandboxed.NetworkModeAllowList {
		return n
	}
	n.Allow = make([]*setecv1.NetworkAllow, 0, len(egress))
	for _, e := range egress {
		allow := &setecv1.NetworkAllow{Host: e.Host, Port: e.Port, Cidr: e.CIDR}
		for _, p := range e.Ports {
			allow.Ports = append(allow.Ports, &setecv1.NetworkAllowPort{
				Protocol: p.Protocol, Port: p.Port, EndPort: p.EndPort,
			})
		}
		n.Allow = append(n.Allow, allow)
	}
	return n
}

// Fork forks a running sandbox of the tenant (setec#195). The forks get
// the network of the request, never the network of the source.
func (c *setecClient) Fork(ctx context.Context, req sandboxed.ForkRequest) (sandboxed.ForkResponse, error) {
	if req.Tenant == "" {
		return sandboxed.ForkResponse{}, errNoTenant
	}
	if req.Count < 1 || req.Count > sandboxed.MaxForks {
		return sandboxed.ForkResponse{}, fmt.Errorf("setec: fork count %d, want 1 to %d", req.Count, sandboxed.MaxForks)
	}
	resp, err := c.inner.Fork(ctx, &setecv1.ForkRequest{
		SandboxId:          req.SandboxID,
		Tenant:             req.Tenant,
		Count:              uint32(req.Count), //nolint:gosec // G115: bounded to 1..MaxForks above
		Network:            setecNetwork(req.NetworkMode, req.Egress),
		SnapshotTtlSeconds: int64(req.SnapshotTTL / time.Second),
	})
	if err != nil {
		return sandboxed.ForkResponse{}, fmt.Errorf("setec: fork %s: %w", req.SandboxID, err)
	}
	return sandboxed.ForkResponse{Snapshot: resp.GetSnapshot(), SandboxIDs: resp.GetSandboxIds()}, nil
}

// Suspend asks setec to checkpoint a session sandbox and release its microVM
// (setec#193). The daemon suspends an idle bank member (ADR-0119, gibson#809).
func (c *setecClient) Suspend(ctx context.Context, tenant, sandboxID string) error {
	if tenant == "" {
		return errNoTenant
	}
	if _, err := c.inner.Suspend(ctx, &setecv1.SuspendRequest{Tenant: tenant, SandboxId: sandboxID}); err != nil {
		return fmt.Errorf("setec suspend %s: %w", sandboxID, err)
	}
	return nil
}

// Resume asks setec to bring a suspended session sandbox back.
func (c *setecClient) Resume(ctx context.Context, tenant, sandboxID string) error {
	if tenant == "" {
		return errNoTenant
	}
	if _, err := c.inner.Resume(ctx, &setecv1.ResumeRequest{Tenant: tenant, SandboxId: sandboxID}); err != nil {
		return fmt.Errorf("setec resume %s: %w", sandboxID, err)
	}
	return nil
}

// newSetecSuspender builds the setec client that suspends and resumes bank
// members (gibson#809).
func newSetecSuspender(cfg config.SandboxConfig, src setecSVIDSource) (sandboxSuspender, error) {
	c, err := NewSetecSandboxClient(cfg, src)
	if err != nil {
		return nil, err
	}
	return c.(*setecClient), nil
}

// Recovery reads the last recovery of a sandbox of the tenant through Attach
// (setec#237). recovered is false when the sandbox never recovered.
func (c *setecClient) Recovery(ctx context.Context, tenant, sandboxID string) (sandboxed.SessionRecovery, bool, error) {
	if tenant == "" {
		return sandboxed.SessionRecovery{}, false, errNoTenant
	}
	resp, err := c.inner.Attach(ctx, &setecv1.AttachRequest{Tenant: tenant, SandboxId: sandboxID})
	if err != nil {
		return sandboxed.SessionRecovery{}, false, fmt.Errorf("setec: attach %s: %w", sandboxID, err)
	}
	r := resp.GetLastRecovery()
	if r.GetCount() == 0 {
		return sandboxed.SessionRecovery{}, false, nil
	}
	out := sandboxed.SessionRecovery{
		Kind:      r.GetKind(),
		Recovered: time.Unix(0, r.GetRecoveredUnixNano()).UTC(),
		Count:     r.GetCount(),
	}
	if ns := r.GetStateTakenUnixNano(); ns != 0 {
		out.StateTaken = time.Unix(0, ns).UTC()
	}
	return out, true, nil
}

// Isolation reads the class and the runtime that setec bound for a sandbox
// of the tenant through Attach. A fork and a restore get no Launch response,
// so this is the report that their isolation check reads.
func (c *setecClient) Isolation(ctx context.Context, tenant, sandboxID string) (sandboxed.LaunchResponse, error) {
	if tenant == "" {
		return sandboxed.LaunchResponse{}, errNoTenant
	}
	resp, err := c.inner.Attach(ctx, &setecv1.AttachRequest{Tenant: tenant, SandboxId: sandboxID})
	if err != nil {
		return sandboxed.LaunchResponse{}, fmt.Errorf("setec: attach %s: %w", sandboxID, err)
	}
	return sandboxed.LaunchResponse{
		SandboxID:    sandboxID,
		SandboxClass: resp.GetSandboxClass(),
		Runtime:      resp.GetRuntime(),
	}, nil
}

// launchFromSnapshot starts a sandbox from a snapshot of the tenant
// (setec#242). The class, the image and the size come from the snapshot, so
// the request sends none of them. The sandbox gets the network of the
// request, never the network of the source. A snapshot that setec no longer
// has is sandboxed.ErrSnapshotGone.
func (c *setecClient) launchFromSnapshot(ctx context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	pbReq := &setecv1.LaunchRequest{
		Tenant:       req.Tenant,
		FromSnapshot: req.FromSnapshot,
		Network:      setecNetwork(req.NetworkMode, req.Egress),
	}
	if req.Timeout > 0 {
		pbReq.Lifecycle = &setecv1.Lifecycle{Timeout: req.Timeout.String()}
	}
	resp, err := c.inner.Launch(ctx, pbReq)
	if status.Code(err) == codes.NotFound {
		return sandboxed.LaunchResponse{}, fmt.Errorf("setec: launch from %s: %w", req.FromSnapshot, sandboxed.ErrSnapshotGone)
	}
	if err != nil {
		return sandboxed.LaunchResponse{}, fmt.Errorf("setec: launch from %s: %w", req.FromSnapshot, err)
	}
	return sandboxed.LaunchResponse{SandboxID: resp.GetSandboxId()}, nil
}

// Snapshot takes a snapshot of a running sandbox of the tenant that lives
// for ttl (setec#242). Zero takes the setec default of 7 days.
func (c *setecClient) Snapshot(ctx context.Context, tenant, sandboxID string, ttl time.Duration) (string, error) {
	if tenant == "" {
		return "", errNoTenant
	}
	resp, err := c.inner.Snapshot(ctx, &setecv1.SnapshotRequest{
		Tenant: tenant, SandboxId: sandboxID, TtlSeconds: int64(ttl / time.Second),
	})
	if err != nil {
		return "", fmt.Errorf("setec: snapshot %s: %w", sandboxID, err)
	}
	return resp.GetSnapshot(), nil
}
