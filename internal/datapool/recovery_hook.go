package datapool

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/sdk/auth"
)

// RecoveryHook runs once per tenant per process lifetime, on the first
// successful Pool.For dial for that tenant. The hook's job is to surface
// missions that were in `running` state when the daemon last died and
// transition them to `paused` so an operator can resume them safely.
//
// This replaces the previous eager-startup-enumeration model in
// internal/daemon/recover_missions.go, which iterated every Tenant CRD at
// daemon boot. That shape made one stuck tenant CRD a daemon-wide crash
// (testa123 incident 2026-05-19). The lazy-per-tenant shape isolates each
// tenant's failure to its own request path — a broken tenant can't take
// down sign-in for everyone else.
//
// Spec: ADR-0023 (gibson daemon does not consume the Kubernetes API).
//
// Failure semantics: any error returned by Run() is logged by the caller
// but does NOT propagate as a Pool.For error. The conn is still returned
// to the caller — the recovery sweep is a best-effort cleanup, not a
// gate on dispatch. A tenant whose mission table is unhappy gets one WARN
// per process lifetime; subsequent requests succeed.
type RecoveryHook interface {
	Run(ctx context.Context, tenant auth.TenantID, conn *Conn) error
}

// noopRecoveryHook is the default. It runs zero recovery and returns nil.
// Used when the daemon has not wired a production hook (tests, dev
// environments that don't have a redis-backed mission store).
type noopRecoveryHook struct{}

// NewNoopRecoveryHook returns a RecoveryHook that does nothing.
func NewNoopRecoveryHook() RecoveryHook { return noopRecoveryHook{} }

func (noopRecoveryHook) Run(_ context.Context, _ auth.TenantID, _ *Conn) error {
	return nil
}

// runRecoveryHook is the production implementation. It lists running
// missions for the tenant via the existing Conn.Missions().ListRunning
// API and JSON.SETs each one's status to "paused" in the per-tenant
// Redis mission_run keyspace.
//
// The transition logic mirrors what the deleted
// internal/daemon/recover_missions.go used to do at startup, except now
// it runs on first per-tenant dial inside Pool.For. No K8s API call, no
// enumeration of tenants.
type runRecoveryHook struct {
	logger *slog.Logger
}

// NewRunRecoveryHook returns the production RecoveryHook. logger may be
// nil, in which case slog.Default() is used.
func NewRunRecoveryHook(logger *slog.Logger) RecoveryHook {
	if logger == nil {
		logger = slog.Default()
	}
	return &runRecoveryHook{logger: logger}
}

func (h *runRecoveryHook) Run(ctx context.Context, tenant auth.TenantID, conn *Conn) error {
	if conn == nil {
		return fmt.Errorf("recovery_hook: nil conn")
	}
	if conn.Redis == nil {
		// Redis not configured for this conn; cannot recover mission runs.
		// Silent — this is a deliberate runtime configuration choice, not
		// a failure.
		return nil
	}

	running, err := conn.Missions().ListRunning(ctx)
	if err != nil {
		return fmt.Errorf("recovery_hook: list running missions for %s: %w", tenant, err)
	}
	if len(running) == 0 {
		return nil
	}

	for _, rm := range running {
		h.logger.WarnContext(ctx, "recovery_hook: pausing mission run after daemon restart",
			"tenant", tenant.String(),
			"mission_id", rm.MissionID,
			"mission_name", rm.MissionName,
			"run_id", rm.RunID,
		)
		key := fmt.Sprintf("gibson:mission_run:%s", rm.RunID)
		if err := conn.Redis.Do(ctx, "JSON.SET", key, "$.status", `"paused"`).Err(); err != nil {
			// Per-mission errors are logged and skipped, not aggregated
			// into a tenant-level failure. One unrecoverable mission must
			// not block the rest.
			h.logger.ErrorContext(ctx, "recovery_hook: failed to pause mission run",
				"tenant", tenant.String(),
				"run_id", rm.RunID,
				"error", err,
			)
		}
	}
	return nil
}
