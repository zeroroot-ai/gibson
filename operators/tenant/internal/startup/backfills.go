// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package startup wires operator-startup runnables that replace what
// were previously standalone Helm pre/post-install Jobs.
//
// Spec: .spec-workflow/specs/deploy-architecture-refactor (Phase 5).
package startup

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	rbacbackfill "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/rbac"
	tiermigrate "github.com/zeroroot-ai/gibson/operators/tenant/internal/backfill/tiermigrate"
)

// BackfillsRunnable is a manager.Runnable that runs every absorbed
// Helm-Job-style backfill once on operator startup. It blocks until all
// backfills complete (or the context is cancelled).
//
// Implements controller-runtime's `manager.Runnable` interface.
type BackfillsRunnable struct {
	Client client.Client
	// Audit writes the record of each backfill change before the change
	// (gibson#583). Required. A backfill that finds nothing to change writes
	// no record.
	Audit *audit.SagaEmitter
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
//
// The data-plane credentials backfill was deleted (gibson#583): the
// TenantDataPlane controller runs the same Provision for every tenant on its
// resync, so the backfill was a second path to the same change.
func (r *BackfillsRunnable) Start(ctx context.Context) error {
	if r.SkipBackfills || os.Getenv("SKIP_BACKFILLS") == "true" {
		slog.Info("startup: SKIP_BACKFILLS set; skipping all backfills")
		return nil
	}

	slog.Info("startup: running rbac backfill")
	if err := rbacbackfill.Run(ctx, r.Client, rbacbackfill.Options{
		Workers: 8,
		Audit:   r.Audit,
	}); err != nil {
		slog.Error("startup: rbac backfill failed; continuing operator startup", "err", err)
		// Don't fail the manager — backfill failures should be visible
		// via metrics/logs but should not block normal reconciliation.
	}

	slog.Info("startup: running tier migration")
	if err := tiermigrate.Run(ctx, r.Client, tiermigrate.Options{
		Workers: 8,
		Audit:   r.Audit,
	}); err != nil {
		slog.Error("startup: tier migration failed; continuing operator startup", "err", err)
	}
	return nil
}

// Register adds the startup runnable to the manager. The audit emitter is
// required.
func Register(mgr manager.Manager, auditEmitter *audit.SagaEmitter) error {
	if auditEmitter == nil {
		return fmt.Errorf("startup backfills: %w", audit.ErrNoSink)
	}
	return mgr.Add(&BackfillsRunnable{
		Client: mgr.GetClient(),
		Audit:  auditEmitter,
	})
}
