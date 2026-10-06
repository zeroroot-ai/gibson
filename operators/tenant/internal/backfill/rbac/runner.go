// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package rbac implements the per-tenant RBAC backfill. It runs as a startup
// Runnable inside the operator (internal/startup/backfills.go).
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

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
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
	// Audit writes the record of each RoleBinding change before the change
	// (gibson#583). Required. A namespace whose RoleBindings are current
	// is not changed and gets no record.
	Audit *audit.SagaEmitter
}

// Run walks every Tenant CR and ensures the per-tenant Role +
// RoleBinding exist. Idempotent: re-running is a no-op.
//
// Uses the operator's client.Client.
func Run(ctx context.Context, cl client.Client, opts Options) error {
	var tenants gibsonv1alpha1.TenantList
	if err := cl.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	slog.Info("rbac-backfill: tenants discovered", "count", len(tenants.Items))

	if opts.Audit == nil && !opts.DryRun {
		return fmt.Errorf("rbac-backfill: %w", audit.ErrNoSink)
	}
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
				results <- result{tenant: t.Name, err: backfillOne(ctx, provisioner, opts.Audit, &t)}
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

// backfillOne changes the RoleBindings of one tenant namespace when they are
// not current, after it writes the record of the change.
func backfillOne(ctx context.Context, p *controller.NamespaceProvisioner, em *audit.SagaEmitter, t *gibsonv1alpha1.Tenant) error {
	ns := controller.TenantNamespaceForBackfill(t)
	current, err := p.TenantNamespaceRBACCurrent(ctx, ns)
	if err != nil || current {
		return err
	}
	ev := audit.Event{
		Action:     audit.ActionBackfill,
		TenantID:   t.Name,
		TargetType: "namespace",
		TargetID:   ns,
		Fields:     map[string]string{"backfill": "rbac"},
	}
	return em.Change(ctx, ev, func() error { return p.EnsureTenantNamespaceRBACPublic(ctx, ns) })
}
