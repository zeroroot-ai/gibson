// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

// Package daemon — Setec-backed constructor for the ephemeral agent launcher.
//
// This mirrors NewSetecSandboxedExecutor for the agent-process path (ADR-0116,
// gibson#1596). It reuses the same setec gRPC client (NewSetecSandboxClient) —
// an agent launch needs exactly the Launch / StreamLogs / Wait / Kill surface a
// tool call needs — and wires a sandboxed.AgentLauncher over it.
//
// Build tag `setec_integration` keeps this out of the default build, exactly
// like sandboxed_setec_adapter.go. The no-op counterpart in
// sandboxed_setec_disabled.go returns (nil, nil) so the daemon can call this
// unconditionally.

package daemon

import (
	"log/slog"

	"go.opentelemetry.io/otel/trace"

	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

// NewSetecAgentLauncher constructs a sandboxed.AgentLauncher backed by a real
// Setec gRPC client. On a TLS build failure it returns (nil, err), and the
// caller logs the warning; the harness then denies an untrusted agent
// fail-closed under setec-only.
func NewSetecAgentLauncher(cfg config.SandboxConfig, tracer trace.Tracer, logger *slog.Logger, events sandboxed.EventPublisher, platformCA string) (*sandboxed.AgentLauncher, error) {
	client, err := NewSetecSandboxClient(cfg)
	if err != nil {
		return nil, err
	}
	return sandboxed.NewAgentLauncher(sandboxed.AgentLauncherConfig{
		Client:       client,
		Tracer:       tracer,
		Logger:       logger,
		SandboxClass: cfg.Setec.AgentSandboxClass,
		RunTimeout:   cfg.Setec.AgentRunTimeout,
		Events:       events,
		// The edge CA every launch is handed, when the edge is private
		// (gibson#13). The caller read it once: the mount does not change
		// while the daemon runs, and a launch must not depend on a file read.
		PlatformCAPEM: platformCA,
	})
}
