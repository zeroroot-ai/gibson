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

	"github.com/zeroroot-ai/gibson/internal/config"
	"github.com/zeroroot-ai/gibson/internal/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/harness/sandboxed"
)

// NewSetecSandboxedExecutor is the no-op implementation used when gibson is
// built without the setec_integration tag. Always returns (nil, nil) so the
// caller treats sandboxed dispatch as disabled.
func NewSetecSandboxedExecutor(_ config.SandboxConfig, _ trace.Tracer, _ *slog.Logger, _ ingest.DiscoveryProcessor) (*sandboxed.Executor, error) {
	return nil, nil
}

// NewSetecSandboxClient is the no-op counterpart of the setec_integration
// build. Returns (nil, nil) so callers skip wiring the Setec client.
func NewSetecSandboxClient(_ config.SandboxConfig) (sandboxed.SandboxClient, error) {
	return nil, nil
}
