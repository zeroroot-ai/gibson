// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

//go:build !setec_integration

// BUILT-IN VARIANT WHEN setec_integration BUILD TAG IS NOT SET.
// The default production build of the Gibson daemon DOES set
// setec_integration; see core/gibson/Dockerfile (default
// BUILD_TAGS=setec_integration) and the chart Makefile (passes
// --build-arg BUILD_TAGS=setec_integration[,test_fixtures]).
// This file exists for SDK and unit-test paths that build without
// the Setec dependency. Do NOT conclude from this file's presence
// that no-sandbox is the default — it is not.
//
// Spec: setec-sandbox-prod-default §"Cleanups → R11.3".
//
// No-op counterpart of sandboxed_setec_adapter.go. When the build tag
// setec_integration is NOT set, NewSetecSandboxedExecutor returns (nil, nil)
// so the daemon's harness init can call it unconditionally without a build-
// tag branch in the caller.

package daemon

import (
	"log/slog"

	"go.opentelemetry.io/otel/trace"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/config"
)

// NewSetecSandboxedExecutor is the no-op implementation used when gibson is
// built without the setec_integration tag. Always returns (nil, nil) so the
// caller treats sandboxed dispatch as disabled.
func NewSetecSandboxedExecutor(_ config.SandboxConfig, _ trace.Tracer, _ *slog.Logger, _ ingest.DiscoveryProcessor, _ sandboxed.EventPublisher) (*sandboxed.Executor, error) {
	return nil, nil
}

// NewSetecSessionClient is the no-op counterpart for builds without the
// setec_integration tag. Returns (nil, nil) so the daemon wires a session
// registry unconditionally and DevboxExec answers Unavailable naming the
// reason, rather than the caller carrying a build-tag branch.
func NewSetecSessionClient(_ config.SandboxConfig) (sandboxed.SessionClient, error) {
	return nil, nil
}

// NewSetecAgentLauncher is the no-op counterpart of the setec_integration
// build. Returns (nil, nil) so the harness treats sandboxed agent dispatch as
// unavailable and denies an untrusted agent fail-closed under setec-only,
// rather than the caller carrying a build-tag branch. The events publisher is
// unused here — with no launcher there is nothing to tee.
func NewSetecAgentLauncher(_ config.SandboxConfig, _ trace.Tracer, _ *slog.Logger, _ sandboxed.EventPublisher) (*sandboxed.AgentLauncher, error) {
	return nil, nil
}
