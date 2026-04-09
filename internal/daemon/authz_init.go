package daemon

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/config"
)

// initAuthorizer sets up the Authorization Service phase during daemon startup.
//
// It is called from Start() AFTER the State Client phase and BEFORE the
// Component Registry phase. The method always sets d.authorizer to a non-nil
// value: either a real fgaAuthorizer or a noopAuthorizer, depending on config.
//
// Behavior:
//   - authz.enabled=false → inject noopAuthorizer, log INFO, return nil
//   - authz.enabled=true, FGA reachable → inject fgaAuthorizer, log INFO, return nil
//   - authz.enabled=true, FGA unreachable, require_ready=true → return error (fail-closed)
//   - authz.enabled=true, FGA unreachable, require_ready=false → inject noopAuthorizer, log WARN
func (d *daemonImpl) initAuthorizer(ctx context.Context) error {
	cfg := d.config.Authz

	// Fast path: authorization disabled — use no-op, preserve existing behavior.
	if !cfg.Enabled {
		d.authorizer = authz.NewNoopAuthorizer(d.logger.Slog())
		d.logger.Info(ctx, "authorization service: disabled (authz.enabled=false), using no-op authorizer")
		return nil
	}

	d.logger.Info(ctx, "authorization service: initializing",
		"provider", cfg.Provider,
		"endpoint", cfg.Fga.Endpoint,
		"require_ready", cfg.RequireReady,
	)

	// Resolve store/model IDs from config → ConfigMap → env vars.
	storeID, modelID, err := authz.ResolveStoreAndModelIDs(ctx, authz.IDConfig{
		StoreID: cfg.Fga.StoreID,
		ModelID: cfg.Fga.ModelID,
	}, nil) // nil → auto-detect in-cluster config
	if err != nil {
		return d.handleAuthzFailure(ctx, cfg, fmt.Errorf("authorization service: failed to resolve IDs: %w", err))
	}

	// Construct the real FGA authorizer.
	a, err := authz.NewFgaAuthorizer(ctx, authz.FgaConfig{
		Endpoint:   cfg.Fga.Endpoint,
		StoreID:    storeID,
		ModelID:    modelID,
		TimeoutMs:  cfg.Fga.TimeoutMs,
		TLSEnabled: cfg.Fga.TLS.Enabled,
		Logger:     d.logger.Slog(),
	})
	if err != nil {
		return d.handleAuthzFailure(ctx, cfg, fmt.Errorf("authorization service: failed to construct client: %w", err))
	}

	// Connectivity probe: call Check with the system platform_operator tuple.
	// Both true and false are valid results — we only care that the call succeeds.
	_, probeErr := a.Check(ctx, "user:_system", "platform_operator", "system_tenant:_system")
	if probeErr != nil && (authz.IsUnavailable(probeErr) || authz.IsTimeout(probeErr)) {
		_ = a.Close()
		return d.handleAuthzFailure(ctx, cfg,
			fmt.Errorf("authorization service: connectivity probe failed to %s: %w", cfg.Fga.Endpoint, probeErr),
		)
	}

	// Probe succeeded (including the case where FGA returns allowed=false for the
	// probe tuple because no platform_operator tuples exist yet — that is fine).
	d.authorizer = a
	d.logger.Info(ctx, "authorization service: ready",
		"endpoint", cfg.Fga.Endpoint,
		"store_id", storeID,
		"model_id", modelID,
	)

	return nil
}

// handleAuthzFailure handles FGA startup failures according to the require_ready flag.
//
// If require_ready=true (production), returns the error to fail daemon startup.
// If require_ready=false (dev mode), logs a WARN, injects a noopAuthorizer, returns nil.
func (d *daemonImpl) handleAuthzFailure(ctx context.Context, cfg config.AuthzConfig, err error) error {
	if cfg.RequireReady {
		// Production/enterprise mode: fail loudly so the operator sees it.
		d.authorizer = authz.NewNoopAuthorizer(d.logger.Slog())
		return err
	}

	// Dev mode: log WARN and fall back to no-op so the daemon can still serve.
	d.logger.Warn(ctx, "authorization service: FGA unreachable, falling back to no-op authorizer (dev mode)",
		"error", err,
		"note", "set authz.require_ready=true to fail startup on FGA unavailability",
	)
	d.authorizer = authz.NewNoopAuthorizer(d.logger.Slog())
	return nil
}
