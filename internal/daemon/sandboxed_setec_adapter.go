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
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	setecv1 "github.com/zero-day-ai/setec/api/grpc/v1alpha1"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/graphrag/ingest"
	"github.com/zero-day-ai/gibson/internal/graphrag/loader"
	"github.com/zero-day-ai/gibson/internal/harness/sandboxed"
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
	return &setecClient{inner: setecv1.NewSandboxServiceClient(conn)}, nil
}

// NewSetecSandboxedExecutor constructs a sandboxed.Executor backed by a real
// Setec gRPC client.
//
// `discoveryProc` is optional. When non-nil, the sandboxed executor extracts
// field-100 DiscoveryResult from successful tool responses and persists them
// to Neo4j asynchronously, matching the live-callback path's behavior at
// core/gibson/internal/harness/callback_service.go:727.
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

// setecClient adapts setecv1.SandboxServiceClient to sandboxed.SandboxClient.
type setecClient struct{ inner setecv1.SandboxServiceClient }

func (c *setecClient) Launch(ctx context.Context, req sandboxed.LaunchRequest) (sandboxed.LaunchResponse, error) {
	pbReq := &setecv1.LaunchRequest{
		Image:   req.Image,
		Command: req.Command,
		Env:     req.Env,
		Resources: &setecv1.Resources{
			Vcpu:   uint32(req.VCPU),
			Memory: req.Memory,
		},
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
