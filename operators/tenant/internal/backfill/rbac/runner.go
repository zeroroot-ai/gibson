/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package rbac implements the per-tenant RBAC backfill that previously
// ran as a standalone CLI (cmd/backfill-rbac/) under a Helm pre-upgrade
// hook. It is now callable both as a startup Runnable inside the operator
// (internal/startup/backfills.go) and as the same standalone CLI.
//
// Spec: .spec-workflow/specs/deploy-architecture-refactor (Phase 5.1).
package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
)

// Options control the backfill execution.
type Options struct {
	// DryRun lists tenants without modifying RBAC.
	DryRun bool
	// Workers is the concurrency level. Default 8 if <= 0.
	Workers int
	// OperatorNamespace is read from OPERATOR_SERVICE_ACCOUNT_NAMESPACE
	// env when empty.
	OperatorNamespace string
}

// Run walks every Tenant CR and ensures the per-tenant Role +
// RoleBinding exist. Idempotent: re-running is a no-op.
//
// Uses the passed client.Client (so the operator can pass its own
// cached client; the standalone CLI builds a direct REST client).
func Run(ctx context.Context, cl client.Client, opts Options) error {
	var tenants gibsonv1alpha1.TenantList
	if err := cl.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	slog.Info("rbac-backfill: tenants discovered", "count", len(tenants.Items))

	if opts.DryRun {
		for _, t := range tenants.Items {
			slog.Info("rbac-backfill: would backfill", "tenant", t.Name, "phase", t.Status.Phase)
		}
		return nil
	}

	ns := opts.OperatorNamespace
	if ns == "" {
		ns = os.Getenv("OPERATOR_SERVICE_ACCOUNT_NAMESPACE")
	}
	provisioner := controller.NewNamespaceProvisioner(cl, ns, nil)

	type result struct {
		tenant string
		err    error
	}
	workers := opts.Workers
	if workers < 1 {
		workers = 8
	}
	jobs := make(chan gibsonv1alpha1.Tenant, len(tenants.Items))
	results := make(chan result, len(tenants.Items))

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Go(func() {
			for t := range jobs {
				err := provisioner.EnsureTenantNamespaceRBACPublic(ctx, controller.TenantNamespaceForBackfill(&t))
				results <- result{tenant: t.Name, err: err}
			}
		})
	}
	for _, t := range tenants.Items {
		jobs <- t
	}
	close(jobs)
	wg.Wait()
	close(results)

	var ok, fail int
	for r := range results {
		if r.err != nil {
			slog.Error("rbac-backfill: tenant failed", "tenant", r.tenant, "err", r.err)
			fail++
			continue
		}
		ok++
		slog.Info("rbac-backfill: backfilled", "tenant", r.tenant)
	}
	slog.Info("rbac-backfill: summary", "ok", ok, "fail", fail)
	if fail > 0 {
		return fmt.Errorf("%d tenant(s) failed", fail)
	}
	return nil
}
