/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package credentials implements the per-tenant credentials backfill
// that previously ran as a standalone CLI (cmd/backfill-credentials/)
// under a Helm pre-upgrade hook. It is now callable both as a startup
// Runnable inside the operator (internal/startup/backfills.go, with
// the operator's existing dataplane.Provisioner injected) and as the
// same standalone CLI (which builds its own Provisioner from env vars).
//
// Spec: .spec-workflow/specs/deploy-architecture-refactor (Phase 5.2).
package credentials

import (
	"context"
	"fmt"
	"log/slog"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
)

// Options control the backfill execution.
type Options struct {
	DryRun bool
}

// Run walks every Ready Tenant and re-runs the data-plane provisioner's
// Provision() method against it. Idempotent: provisioner steps are
// upsert-style. Skips Tenants whose status.phase is not Ready (those
// will be (re-)provisioned by their normal reconcile).
//
// The pipeline argument is the operator's already-built
// dataplane.Provisioner — usually obtained from buildDataPlaneProvisioner
// in cmd/main.go. The standalone CLI builds its own.
func Run(ctx context.Context, cl client.Client, pl dataplane.Provisioner, opts Options) error {
	var tenants gibsonv1alpha1.TenantList
	if err := cl.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	slog.Info("credentials-backfill: tenants discovered", "count", len(tenants.Items))

	if opts.DryRun {
		for _, t := range tenants.Items {
			slog.Info("credentials-backfill: would backfill", "tenant", t.Name, "phase", t.Status.Phase)
		}
		return nil
	}

	if pl == nil {
		return fmt.Errorf("credentials-backfill: nil Provisioner — operator's dataPlaneProvisioner was not wired")
	}

	var backfilled, skipped, failed int
	for _, t := range tenants.Items {
		if t.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
			slog.Info("credentials-backfill: skipping non-ready tenant",
				"tenant", t.Name, "phase", t.Status.Phase)
			skipped++
			continue
		}
		if err := pl.Provision(ctx, t.Name); err != nil {
			slog.Error("credentials-backfill: tenant failed", "tenant", t.Name, "err", err)
			failed++
			continue
		}
		slog.Info("credentials-backfill: backfilled", "tenant", t.Name)
		backfilled++
	}
	slog.Info("credentials-backfill: summary",
		"backfilled", backfilled, "skipped", skipped, "failed", failed)
	if failed > 0 {
		return fmt.Errorf("%d tenant(s) failed backfill", failed)
	}
	return nil
}
