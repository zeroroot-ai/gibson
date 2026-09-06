// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build setec_integration

// Package daemon — Setec-backed constructor for the ephemeral agent launcher.
//
// This mirrors NewSetecSandboxedExecutor for the agent-process path (ADR-0016,
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
// Setec gRPC client. Returns (nil, nil) when sandbox dispatch is disabled so
// the daemon can call it unconditionally; on that nil the harness denies an
// untrusted agent fail-closed under setec-only. On a dial/TLS failure it
// returns (nil, err) — the caller logs the warning and continues, matching the
// tool executor's Requirement 5.4 behavior.
func NewSetecAgentLauncher(cfg config.SandboxConfig, tracer trace.Tracer, logger *slog.Logger, events sandboxed.EventPublisher) (*sandboxed.AgentLauncher, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	client, err := NewSetecSandboxClient(cfg)
	if err != nil {
		return nil, err
	}
	return sandboxed.NewAgentLauncher(sandboxed.AgentLauncherConfig{
		Client:       client,
		Tracer:       tracer,
		Logger:       logger,
		Tenant:       cfg.Setec.Tenant,
		SandboxClass: cfg.Setec.AgentSandboxClass,
		RunTimeout:   cfg.Setec.AgentRunTimeout,
		Events:       events,
	})
}
