package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/authz"
	pcauthz "github.com/zeroroot-ai/gibson/internal/infra/authz"
)

// initAuthorizer sets up the Authorization Service phase during daemon startup.
//
// It is called from Start() AFTER the State Client phase and BEFORE the
// Component Registry phase. FGA is a hard dependency of the daemon — there is
// no longer a fall-back path. If FGA is not reachable, daemon startup fails so
// the operator surfaces a CrashLoopBackOff rather than silently bypassing
// authorization.
//
// Behavior:
//   - FGA reachable + IDs resolvable → inject fgaAuthorizer, log INFO, return nil
//   - FGA unreachable / IDs unresolvable → return error (daemon exits)
//
// One-code-path epic, slice deploy#195: noopAuthorizer + require_ready=false
// were removed. Both were the silent-allow-all path that masked missing authz
// in dev mode. Today every environment dials a real FGA endpoint at startup;
// if that endpoint is down the daemon refuses to come up. Tests that previously
// relied on noopAuthorizer must inject a real fakeAuthorizer that records its
// decisions.
func (d *daemonImpl) initAuthorizer(ctx context.Context) error {
	cfg := d.config.Authz

	d.logger.Info(ctx, "authorization service: initializing",
		"provider", cfg.Provider,
		"endpoint", cfg.Fga.Endpoint,
	)

	// Resolve store/model IDs from config → env vars (chart projects the
	// gibson-fga-config ConfigMap via envFrom per ADR-0023). ResolveWithRetry
	// polls with exponential backoff for up to 5 minutes so the daemon does
	// not depend on the gibson-fga-init Job completing before pod start.
	// The daemon remains healthy (serving /healthz) throughout the wait.
	storeID, modelID, err := authz.ResolveWithRetry(ctx, authz.IDConfig{
		StoreID: cfg.Fga.StoreID,
		ModelID: cfg.Fga.ModelID,
	}, d.logger.Slog(), 5*time.Minute)
	if err != nil {
		return fmt.Errorf("authorization service: failed to resolve FGA IDs (FGA is required — no fallback): %w", err)
	}

	// Enforce the per-call timeout floor via platform-clients/authz.
	//
	// The timeout MUST be strictly below the Envoy ext_authz budget
	// (pcauthz.EnvoyExtAuthzBudgetDefault = 5s). A value at or above the
	// budget means an OpenFGA stall surfaces as an opaque Envoy upstream-timeout
	// error rather than a structured FGA timeout metric — exactly the class of
	// invisible stall the audit finding P1 documented.
	//
	// We resolve the timeout once and log it; the actual enforcement is inside
	// the fgaAuthorizer's callContext helper (which uses the same value).
	fgaTimeoutMs := cfg.Fga.TimeoutMs
	if fgaTimeoutMs <= 0 {
		fgaTimeoutMs = 500 // default from authz.defaultTimeoutMs
	}
	fgaTimeout := time.Duration(fgaTimeoutMs) * time.Millisecond
	if fgaTimeout >= pcauthz.EnvoyExtAuthzBudgetDefault {
		return fmt.Errorf(
			"authorization service: FGA per-call timeout (%s) must be strictly less than the Envoy ext_authz budget (%s) — "+
				"a timeout at or above the budget defeats the per-call floor (platform-clients/authz.EnvoyExtAuthzBudgetDefault=%s); "+
				"set authz.fga.timeoutMs to a value strictly below %d ms",
			fgaTimeout, pcauthz.EnvoyExtAuthzBudgetDefault, pcauthz.EnvoyExtAuthzBudgetDefault,
			pcauthz.EnvoyExtAuthzBudgetDefault.Milliseconds(),
		)
	}
	d.logger.Info(ctx, "authorization service: per-call timeout validated against Envoy ext_authz budget",
		"timeout", fgaTimeout,
		"envoy_budget", pcauthz.EnvoyExtAuthzBudgetDefault,
	)

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
		return fmt.Errorf("authorization service: failed to construct FGA client (FGA is required — no fallback): %w", err)
	}

	// Connectivity probe: call Check with the system platform_operator tuple.
	// Both true and false are valid results — we only care that the call succeeds.
	_, probeErr := a.Check(ctx, "user:_system", "platform_operator", "system_tenant:_system")
	if probeErr != nil && (authz.IsUnavailable(probeErr) || authz.IsTimeout(probeErr)) {
		_ = a.Close()
		return fmt.Errorf(
			"authorization service: connectivity probe to %s failed (FGA is required — no fallback): %w",
			cfg.Fga.Endpoint, probeErr,
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
