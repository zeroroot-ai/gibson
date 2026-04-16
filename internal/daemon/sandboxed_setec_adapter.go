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

	setecv1 "github.com/zero-day-ai/setec/api/grpc/v1alpha1"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/harness/sandboxed"
)

// NewSetecSandboxedExecutor constructs a sandboxed.Executor backed by a real
// Setec gRPC client.
func NewSetecSandboxedExecutor(cfg config.SandboxConfig, tracer trace.Tracer, logger *slog.Logger) (*sandboxed.Executor, error) {
	if !cfg.Enabled {
		return nil, nil
	}
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
	reg, err := sandboxed.NewRegistryFromConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build sandbox tool registry: %w", err)
	}
	client := &setecClient{inner: setecv1.NewSandboxServiceClient(conn)}
	return sandboxed.New(sandboxed.Config{
		Client:      client,
		Registry:    reg,
		Tracer:      tracer,
		Logger:      logger,
		Tenant:      cfg.Setec.Tenant,
		CallTimeout: cfg.Setec.CallTimeout,
	})
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
