/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/plans"
)

// recordingProvisioner is a fake EntitlementsProvisioner that records the
// quotas passed to UpsertTenantQuota and no-ops everything else.
type recordingProvisioner struct {
	upserts []plans.Quotas
}

func (p *recordingProvisioner) UpsertTenantQuota(_ context.Context, _ string, q plans.Quotas) error {
	p.upserts = append(p.upserts, q)
	return nil
}
func (p *recordingProvisioner) ListFeatureTuples(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (p *recordingProvisioner) WriteAccessTuples(_ context.Context, _, _ []string, _ string) error {
	return nil
}
func (p *recordingProvisioner) SeedCatalogTenantEnabled(_ context.Context, _ string) error {
	return nil
}
func (p *recordingProvisioner) SetTenantZitadelOrg(_ context.Context, _, _ string) error {
	return nil
}
func (p *recordingProvisioner) EmitReconcileSummary(_ context.Context, _ ReconcileSummary) error {
	return nil
}

func loadCanonicalPlans(t *testing.T) *plans.Registry {
	t.Helper()
	reg, err := plans.Load(filepath.Join("..", "..", "plans", "plans.yaml"))
	if err != nil {
		t.Fatalf("load canonical plans: %v", err)
	}
	return reg
}

func revocationTenant(
	tier gibsonv1alpha1.TenantTier,
	billing gibsonv1alpha1.BillingSubscriptionStatus,
) *gibsonv1alpha1.Tenant {
	return &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Spec:       gibsonv1alpha1.TenantSpec{Tier: tier, Owner: "o@e.com", DisplayName: "Acme"},
		Status:     gibsonv1alpha1.TenantStatus{Billing: billing},
	}
}

func newRevocationReconciler(t *testing.T, p EntitlementsProvisioner) *EntitlementsReconciler {
	return &EntitlementsReconciler{
		Plans:       loadCanonicalPlans(t),
		Provisioner: p,
		Logger:      slog.Default(),
	}
}

// TestEntitlements_RevokedFloorsQuotaNotZero is the core tenant-operator#358
// contract: a cancelled tenant has its quota FLOORED to a minimal positive
// value — never 0, which the daemon reads as unlimited (that would grant a
// non-payer more capacity than a payer).
func TestEntitlements_RevokedFloorsQuotaNotZero(t *testing.T) {
	p := &recordingProvisioner{}
	r := newRevocationReconciler(t, p)
	tenant := revocationTenant(gibsonv1alpha1.TenantTier("enterprise"),
		gibsonv1alpha1.BillingSubscriptionStatus{Status: "cancelled"})

	if err := r.Reconcile(context.Background(), tenant); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(p.upserts) != 1 {
		t.Fatalf("expected exactly one quota upsert, got %d", len(p.upserts))
	}
	q := p.upserts[0]
	for name, v := range map[string]int{
		"ConcurrentMissions":   q.ConcurrentMissions,
		"ConcurrentAgents":     q.ConcurrentAgents,
		"ConcurrentConnectors": q.ConcurrentConnectors,
	} {
		if v == 0 {
			t.Errorf("%s floored to 0 — the daemon treats 0 as UNLIMITED; revoked tenants must get a positive floor", name)
		}
		if v != 1 {
			t.Errorf("%s = %d, want the revoked floor of 1", name, v)
		}
	}
	if q.PlanID != "enterprise" {
		t.Errorf("revoked quota PlanID = %q, want the tier the tenant was revoked from (enterprise)", q.PlanID)
	}
}

// TestEntitlements_PastDueWithinGraceKeepsPlanQuota: a past-due tenant still
// inside the 7-day grace window is NOT revoked — it keeps its real plan quota.
func TestEntitlements_PastDueWithinGraceKeepsPlanQuota(t *testing.T) {
	p := &recordingProvisioner{}
	r := newRevocationReconciler(t, p)
	recent := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	tenant := revocationTenant(gibsonv1alpha1.TenantTier("team"),
		gibsonv1alpha1.BillingSubscriptionStatus{Status: "past_due", PastDueSince: recent})

	if err := r.Reconcile(context.Background(), tenant); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(p.upserts) != 1 {
		t.Fatalf("expected one quota upsert, got %d", len(p.upserts))
	}
	team := r.Plans.MustLookup(plans.PlanTeam)
	if p.upserts[0].ConcurrentMissions != team.Quotas.ConcurrentMissions {
		t.Errorf("within grace: got floored quota %d, want full plan quota %d",
			p.upserts[0].ConcurrentMissions, team.Quotas.ConcurrentMissions)
	}
}

// TestEntitlements_PastDueBeyondGraceFloors: past the 7-day window, past-due
// revokes (floors) just like cancelled.
func TestEntitlements_PastDueBeyondGraceFloors(t *testing.T) {
	p := &recordingProvisioner{}
	r := newRevocationReconciler(t, p)
	old := time.Now().Add(-8 * 24 * time.Hour).Format(time.RFC3339)
	tenant := revocationTenant(gibsonv1alpha1.TenantTier("team"),
		gibsonv1alpha1.BillingSubscriptionStatus{Status: "past_due", PastDueSince: old})

	if err := r.Reconcile(context.Background(), tenant); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := p.upserts[0].ConcurrentMissions; got != 1 {
		t.Errorf("beyond grace: ConcurrentMissions = %d, want floor 1", got)
	}
}

// TestEntitlements_RecoveryRestoresPlanQuota: once billing returns to active,
// the normal path re-upserts the real plan quota — no manual intervention.
func TestEntitlements_RecoveryRestoresPlanQuota(t *testing.T) {
	p := &recordingProvisioner{}
	r := newRevocationReconciler(t, p)

	// Revoked reconcile floors.
	cancelled := revocationTenant(gibsonv1alpha1.TenantTier("team"),
		gibsonv1alpha1.BillingSubscriptionStatus{Status: "cancelled"})
	if err := r.Reconcile(context.Background(), cancelled); err != nil {
		t.Fatalf("revoked reconcile: %v", err)
	}
	// Billing recovers.
	active := revocationTenant(gibsonv1alpha1.TenantTier("team"),
		gibsonv1alpha1.BillingSubscriptionStatus{Status: "active"})
	if err := r.Reconcile(context.Background(), active); err != nil {
		t.Fatalf("recovered reconcile: %v", err)
	}
	if len(p.upserts) != 2 {
		t.Fatalf("expected two upserts (floor then restore), got %d", len(p.upserts))
	}
	team := r.Plans.MustLookup(plans.PlanTeam)
	if p.upserts[0].ConcurrentMissions != 1 {
		t.Errorf("first upsert should be floored, got %d", p.upserts[0].ConcurrentMissions)
	}
	if p.upserts[1].ConcurrentMissions != team.Quotas.ConcurrentMissions {
		t.Errorf("recovery should restore plan quota %d, got %d",
			team.Quotas.ConcurrentMissions, p.upserts[1].ConcurrentMissions)
	}
}

// TestEntitlements_RevocationIdempotent: the reconciler runs every loop;
// repeated revoked reconciles each floor without error or amplification.
func TestEntitlements_RevocationIdempotent(t *testing.T) {
	p := &recordingProvisioner{}
	r := newRevocationReconciler(t, p)
	tenant := revocationTenant(gibsonv1alpha1.TenantTier("org"),
		gibsonv1alpha1.BillingSubscriptionStatus{Status: "cancelled"})

	for i := range 3 {
		if err := r.Reconcile(context.Background(), tenant); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	if len(p.upserts) != 3 {
		t.Fatalf("expected 3 floor upserts across 3 reconciles, got %d", len(p.upserts))
	}
	for i, q := range p.upserts {
		if q.ConcurrentMissions != 1 {
			t.Errorf("upsert %d not floored: %d", i, q.ConcurrentMissions)
		}
	}
}
