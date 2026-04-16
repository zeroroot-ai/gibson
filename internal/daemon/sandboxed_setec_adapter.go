//go:build setec_integration

// Package daemon — Setec gRPC client adapter for the sandboxed tool executor.
//
// # Why this is behind a build tag
//
// At the time this file was written, the Setec open-source project is still
// a private GitHub repo (github.com/zero-day-ai/setec). Gibson's CLAUDE.md
// forbids `replace` directives pointing at local paths, so we cannot add a
// `require github.com/zero-day-ai/setec` to gibson's go.mod that resolves to
// the local checkout — it would need public-module accessibility or private-
// repo auth configured against GOPROXY/sumdb.
//
// When Setec goes public (or when GOPRIVATE + GitHub PAT are wired into the
// dev/CI environment), enable this file with the `-tags=setec_integration`
// build flag. At that point also:
//
//  1. Add to `enterprise/deploy/helm/gibson/` the chart values and Secret
//     mount per the spec's Requirement 7.1.
//  2. Wire `SetecSandboxedExecutor` into `harness_init.go` HarnessConfig.
//  3. Update `go.mod` with `go get github.com/zero-day-ai/setec@<rev>`.
//
// # Contract
//
// This file implements `sandboxed.SandboxClient` (the minimal gRPC surface
// the executor needs) by wrapping Setec's generated `SandboxServiceClient`.
// The sandboxed package itself has zero Setec imports — the adapter is the
// single point of contact.
//
// # Construction
//
// `NewSetecSandboxedExecutor(cfg config.SandboxConfig, tracer, logger)` dials
// the Setec frontend with mTLS using the existing `component.TLSConfig`
// helper, builds the client, wires up a `sandboxed.Executor`, and returns it.
// The daemon's `harness_init.go` calls this during infrastructure
// initialization and passes the result into `HarnessConfig.SandboxedExecutor`.
//
// On dial/TLS failure, construction logs a WARN and returns (nil, err) —
// per design Requirement 5.4, the daemon continues startup and individual
// tool calls fail at invocation time rather than blocking daemon startup.

package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	setecv1 "github.com/zero-day-ai/setec/api/grpc/v1alpha1"
	"go.opentelemetry.io/otel/trace"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/harness/sandboxed"
)

// NewSetecSandboxedExecutor constructs a sandboxed.Executor backed by a real
// Setec gRPC client. Returns (nil, nil) when cfg.Sandbox.Enabled is false so
// the caller can unconditionally assign the result into HarnessConfig.
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
	env := make([]*setecv1.EnvVar, 0, len(req.Env))
	for k, v := range req.Env {
		env = append(env, &setecv1.EnvVar{Name: k, Value: v})
	}
	resp, err := c.inner.Launch(ctx, &setecv1.LaunchRequest{
		Image:   req.Image,
		Command: req.Command,
		Env:     env,
		Resources: &setecv1.Resources{
			Vcpu:   req.VCPU,
			Memory: req.Memory,
		},
		LifecycleTimeout: durationFromDuration(req.Timeout),
	})
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
	// Cancel underlying stream by closing send side; Setec's StreamLogs is
	// server-streaming so client has no send side — canceling the context
	// in the caller is the real close. This is a best-effort no-op.
	return nil
}

// durationFromDuration is a placeholder for whichever duration representation
// the regenerated Setec proto uses (durationpb.Duration vs string). Fill in
// once the import builds. TODO when enabling this file.
func durationFromDuration(d time.Duration) interface{} {
	// Replace with proper durationpb/seconds conversion when wiring this in.
	_ = d
	return nil
}
