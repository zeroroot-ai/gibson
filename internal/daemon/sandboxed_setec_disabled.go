//go:build !setec_integration

// No-op counterpart of sandboxed_setec_adapter.go. When the build tag
// setec_integration is NOT set, NewSetecSandboxedExecutor returns (nil, nil)
// so the daemon's harness init can call it unconditionally without a build-
// tag branch in the caller.

package daemon

import (
	"log/slog"

	"go.opentelemetry.io/otel/trace"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/harness/sandboxed"
)

// NewSetecSandboxedExecutor is the no-op implementation used when gibson is
// built without the setec_integration tag. Always returns (nil, nil) so the
// caller treats sandboxed dispatch as disabled.
func NewSetecSandboxedExecutor(_ config.SandboxConfig, _ trace.Tracer, _ *slog.Logger) (*sandboxed.Executor, error) {
	return nil, nil
}
