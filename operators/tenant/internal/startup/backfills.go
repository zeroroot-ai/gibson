// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package startup wires operator-startup runnables that replace what
// were previously standalone Helm pre/post-install Jobs.
//
// Spec: .spec-workflow/specs/deploy-architecture-refactor (Phase 5).
package startup

import (
	"context"
	"log/slog"
	"os"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	credsbackfill "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/credentials"
	rbacbackfill "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/rbac"
	tiermigrate "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/tiermigrate"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
)

// BackfillsRunnable is a manager.Runnable that runs every absorbed
// Helm-Job-style backfill once on operator startup. It blocks until all
// backfills complete (or the context is cancelled).
//
// Implements controller-runtime's `manager.Runnable` interface.
type BackfillsRunnable struct {
	Client client.Client
	// DataPlaneProvisioner is the operator's already-built provisioner.
	// Injected by cmd/main.go so credentials-backfill can use the same
	// wiring as the TenantReconciler. May be nil — credentials-backfill
	// is skipped when nil.
	DataPlaneProvisioner dataplane.Provisioner
	// SkipBackfills, if true, makes Start a no-op. Set via the
	// SKIP_BACKFILLS env var; intended for emergency operator restarts
	// where the backfills themselves are suspect.
	SkipBackfills bool
}

// NeedLeaderElection ensures the backfills run only on the lead manager
// replica, preventing concurrent backfill races in HA deployments.
func (r *BackfillsRunnable) NeedLeaderElection() bool { return true }

// Start runs each absorbed backfill. Called by the manager after leader
// election; returns when all complete.
func (r *BackfillsRunnable) Start(ctx context.Context) error {
	if r.SkipBackfills || os.Getenv("SKIP_BACKFILLS") == "true" {
		slog.Info("startup: SKIP_BACKFILLS set; skipping all backfills")
		return nil
	}

	slog.Info("startup: running rbac backfill")
	if err := rbacbackfill.Run(ctx, r.Client, rbacbackfill.Options{
		Workers: 8,
	}); err != nil {
		slog.Error("startup: rbac backfill failed; continuing operator startup", "err", err)
		// Don't fail the manager — backfill failures should be visible
		// via metrics/logs but should not block normal reconciliation.
	}

	slog.Info("startup: running tier migration")
	if err := tiermigrate.Run(ctx, r.Client, tiermigrate.Options{
		Workers: 8,
	}); err != nil {
		slog.Error("startup: tier migration failed; continuing operator startup", "err", err)
	}

	if r.DataPlaneProvisioner != nil {
		slog.Info("startup: running credentials backfill")
		if err := credsbackfill.Run(ctx, r.Client, r.DataPlaneProvisioner, credsbackfill.Options{}); err != nil {
			slog.Error("startup: credentials backfill failed; continuing operator startup", "err", err)
		}
	} else {
		slog.Info("startup: credentials backfill skipped — operator booted without a DataPlaneProvisioner (degraded mode)")
	}

	return nil
}

// Register adds the startup runnable to the manager with the operator's
// existing dataplane.Provisioner. Pass nil for pl when the operator is
// booting in degraded mode (no dataplane wiring) — credentials-backfill
// is then skipped.
func Register(mgr manager.Manager, pl dataplane.Provisioner) error {
	return mgr.Add(&BackfillsRunnable{
		Client:               mgr.GetClient(),
		DataPlaneProvisioner: pl,
	})
}
