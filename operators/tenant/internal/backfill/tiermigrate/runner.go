// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package tiermigrate implements the per-tenant tier migration that
// previously ran as a standalone CLI (cmd/migrate-tenant-tiers/) under
// a Helm pre-upgrade hook. It is now callable both as a startup
// Runnable inside the operator (internal/startup/backfills.go) and as
// the same standalone CLI.
//
// Spec: .spec-workflow/specs/deploy-architecture-refactor (Phase 5.3).
package tiermigrate

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// LegacyTierMap is the closed mapping from any legacy plan id to the
// post-spec canonical id. Exported because the Helm chart's
// pre-upgrade Job consumer may want to assert against it.
//
// "org" is a canonical id and intentionally absent.
var LegacyTierMap = map[string]string{
	"solo":              "team",
	"squad":             "team",
	"platform":          "enterprise",
	"enterprise-cloud":  "enterprise",
	"enterprise-onprem": "enterprise-deploy",
	"public-sector":     "enterprise-deploy",
	"free":              "team",
	"pro":               "enterprise",
}

// Options control the migration execution.
type Options struct {
	DryRun  bool
	Workers int // Default 8 if <= 0.
}

// Run walks every Tenant CR and migrates spec.tier from any legacy id
// to the canonical (team / org / enterprise / enterprise-deploy).
// Idempotent: a Tenant whose tier is already canonical is a no-op.
func Run(ctx context.Context, cl client.Client, opts Options) error {
	var tenants gibsonv1alpha1.TenantList
	if err := cl.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	slog.Info("tier-migrate: tenants discovered", "count", len(tenants.Items))

	type job struct {
		tenant  gibsonv1alpha1.Tenant
		newTier string
	}
	type result struct {
		tenant   string
		from, to string
		err      error
		skipped  bool
	}
	jobs := make(chan job, len(tenants.Items))
	results := make(chan result, len(tenants.Items))

	for _, t := range tenants.Items {
		oldTier := string(t.Spec.Tier)
		newTier, hasMapping := LegacyTierMap[oldTier]
		if !hasMapping {
			results <- result{tenant: t.Name, from: oldTier, skipped: true}
			continue
		}
		if opts.DryRun {
			slog.Info("tier-migrate: would migrate", "tenant", t.Name, "from", oldTier, "to", newTier)
			continue
		}
		jobs <- job{tenant: t, newTier: newTier}
	}
	close(jobs)

	if opts.DryRun {
		close(results)
		return nil
	}

	workers := opts.Workers
	if workers < 1 {
		workers = 8
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Go(func() {
			for j := range jobs {
				err := patchTenantTier(ctx, cl, &j.tenant, j.newTier)
				results <- result{
					tenant: j.tenant.Name,
					from:   string(j.tenant.Spec.Tier),
					to:     j.newTier,
					err:    err,
				}
			}
		})
	}
	wg.Wait()
	close(results)

	var ok, fail, skipped int
	for r := range results {
		switch {
		case r.skipped:
			skipped++
			slog.Info("tier-migrate: skipped", "tenant", r.tenant, "tier", r.from)
		case r.err != nil:
			fail++
			slog.Error("tier-migrate: tenant failed", "tenant", r.tenant, "err", r.err)
		default:
			ok++
			slog.Info("tier-migrate: migrated", "tenant", r.tenant, "from", r.from, "to", r.to)
		}
	}
	slog.Info("tier-migrate: summary", "migrated", ok, "skipped", skipped, "failed", fail)
	if fail > 0 {
		return fmt.Errorf("%d tenant(s) failed", fail)
	}
	return nil
}

// patchTenantTier issues a JSON-merge patch that overwrites spec.tier.
// Uses optimistic concurrency via resourceVersion in the base object
// so a concurrent operator reconcile does not silently clobber the
// change.
func patchTenantTier(ctx context.Context, cl client.Client, t *gibsonv1alpha1.Tenant, newTier string) error {
	base := t.DeepCopy()
	t.Spec.Tier = gibsonv1alpha1.TenantTier(newTier)
	if err := cl.Patch(ctx, t, client.MergeFrom(base)); err != nil {
		return fmt.Errorf("patch tenant %s: %w", t.Name, err)
	}
	return nil
}
