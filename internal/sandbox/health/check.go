// Package health — check.go
//
// StartupCheck performs a single best-effort Setec reachability probe at
// daemon startup (Task 42, setec-sandbox-prod-default R5.2).
//
// Behaviour:
//   - Single attempt, 5-second timeout.
//   - On success: logs info, returns nil. In SaaS mode, marks sandbox as
//     initially ready (the periodic probe takes over after startup).
//   - On failure: logs warn. In dev/selfhost mode, startup continues.
//     In SaaS mode (`GIBSON_MODE=saas`), the daemon's readiness gate stays
//     false until the first successful periodic probe fires.
//
// The check does NOT block daemon startup regardless of mode; it ONLY
// controls initial readiness signal.
//
// Spec: setec-sandbox-prod-default R5.2.
package health

import (
	"context"
	"log/slog"
	"time"
)

// Pinger is the minimal interface the startup health check requires.
// Implemented by any client that can ping the Setec frontend — in
// production this is the sandboxed.SandboxClient adapter; in tests it's a
// simple stub.
type Pinger interface {
	// Ping attempts to contact the Setec frontend. Returns nil on success,
	// non-nil on any connectivity or authentication failure.
	Ping(ctx context.Context) error
}

// StartupCheckConfig configures StartupCheck behaviour.
type StartupCheckConfig struct {
	// Pinger is the transport-level probe. Required.
	Pinger Pinger

	// SaaSMode controls whether a failed startup check gates readiness.
	// Set to true when GIBSON_MODE=saas. In SaaS mode the daemon's initial
	// readiness state is false (unhealthy) when the probe fails; in
	// dev/selfhost mode, readiness starts true regardless.
	SaaSMode bool

	// ReadinessGate, when non-nil, is called with the probe result. The
	// daemon wires the existing health-state manager's sandbox gate here.
	// When nil, readiness gating is skipped (acceptable in tests).
	ReadinessGate func(sandboxReady bool)

	// Logger is the structured logger. Defaults to slog.Default() when nil.
	Logger *slog.Logger
}

// StartupCheck performs the single startup sandbox health check.
//
// It is intentionally synchronous: the caller (daemon init) blocks for at
// most the 5-second timeout before returning. This gives the operator a
// single clear log line at startup, rather than a deferred background failure.
func StartupCheck(cfg StartupCheckConfig) (sandboxReady bool) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := cfg.Pinger.Ping(ctx)
	if err == nil {
		logger.Info("sandbox health check: Setec frontend reachable at startup")
		if cfg.ReadinessGate != nil {
			cfg.ReadinessGate(true)
		}
		return true
	}

	if cfg.SaaSMode {
		logger.Warn("sandbox health check: Setec frontend unreachable at startup; readiness gate closed (saas mode)",
			slog.String("error", err.Error()))
		if cfg.ReadinessGate != nil {
			cfg.ReadinessGate(false)
		}
	} else {
		logger.Warn("sandbox health check: Setec frontend unreachable at startup; continuing (dev/selfhost mode)",
			slog.String("error", err.Error()))
		if cfg.ReadinessGate != nil {
			cfg.ReadinessGate(true) // dev mode: stay ready regardless
		}
	}
	return false
}
