// entitlements.go — tenant-operator reconciliation of the plan registry
// into runtime quotas, informational feature-availability FGA tuples, and
// per-tenant seed of tenant_enabled on every platform_enabled catalog item.
//
// Loaded by the controller once at startup from the Helm ConfigMap mount
// (/etc/gibson/plans/plans.yaml). The reconcile loop calls
// ReconcileEntitlements(ctx, tenant) after the existing auth/provisioning
// steps; failures are surfaced on .status.conditions but do not block
// subsequent reconciles (exponential backoff retries per standard
// controller-runtime semantics).
//
// Spec: agent-authoring-and-tenant-entitlements tasks 23–25.

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
	"github.com/zeroroot-ai/gibson/operators/tenant/plans"
)

// EntitlementsProvisioner is the narrow interface the controller uses to
// call the dashboard's SPIFFE-authenticated
// /api/admin/provisioning/entitlements/* endpoints. The concrete
// implementation lives in internal/provision/; tests pass a fake.
//
// All methods are idempotent.
type EntitlementsProvisioner interface {
	// UpsertTenantQuota writes the tenant_quotas Postgres row.
	UpsertTenantQuota(ctx context.Context, tenantID string, q plans.Quotas) error
	// ListFeatureTuples returns the has_* relation names currently set on
	// the given tenant. Empty on first reconcile.
	ListFeatureTuples(ctx context.Context, tenantID string) ([]string, error)
	// WriteAccessTuples atomically adds and/or deletes FGA tuples. `add`
	// and `delete` are fully-formed `user#relation@object` strings.
	WriteAccessTuples(ctx context.Context, add, delete []string, reason string) error
	// SeedCatalogTenantEnabled writes tenant_enabled tuples for every
	// platform_enabled catalog item.
	SeedCatalogTenantEnabled(ctx context.Context, tenantID string) error
	// SetTenantZitadelOrg seeds the daemon's tenant -> Zitadel-org mapping so
	// MembershipService can write the Zitadel half of human membership without
	// reading Kubernetes (gibson#621). Idempotent.
	SetTenantZitadelOrg(ctx context.Context, tenantID, zitadelOrgID string) error
	// EmitReconcileSummary emits one entitlements_reconcile audit event
	// carrying the plan id + delta counts + reconcile trigger.
	EmitReconcileSummary(ctx context.Context, s ReconcileSummary) error
}

// ReconcileSummary captures the per-reconcile audit payload emitted via
// EmitReconcileSummary. Trigger values: "cr_change", "background",
// "stripe_webhook".
type ReconcileSummary struct {
	TenantID   string
	Plan       string
	QuotaDelta int
	DurationMs int64
	Trigger    string
}

// EntitlementsReconciler carries the plan registry + provisioner so it can
// be instantiated once at controller startup.
type EntitlementsReconciler struct {
	Plans       *plans.Registry
	Provisioner EntitlementsProvisioner
	Logger      *slog.Logger
	// FirstSeedCondition is the Tenant.status.conditions type name set once
	// SeedCatalogTenantEnabled has run for a tenant. Defaults to
	// "CatalogSeeded" when empty.
	FirstSeedCondition string
}

// Reconcile is the single entry point for the entitlements-reconcile step.
// Runs three sub-steps in order, short-circuiting on the first failure so a
// broken Postgres connection (say) doesn't mask a subsequent FGA problem.
// isBillingRevoked returns true when the tenant's billing status requires
// paid capabilities to be revoked. Revocation occurs when:
//   - billing.status = "cancelled", or
//   - billing.status = "past_due" AND pastDueSince is older than 7 days.
//
// A tenant with no billing status (empty struct) is NOT revoked — new tenants
// on trials or without billing history keep their capabilities.
//
// Spec: stripe-billing-integration R5.2, R5.3.
func isBillingRevoked(billing gibsonv1alpha1.BillingSubscriptionStatus) bool {
	if billing.Status == "cancelled" {
		return true
	}
	if billing.Status == "past_due" && billing.PastDueSince != "" {
		pastDueSince, err := time.Parse(time.RFC3339, billing.PastDueSince)
		if err == nil && time.Since(pastDueSince) > 7*24*time.Hour {
			return true
		}
	}
	return false
}

// revokedQuotas is the floor applied to a billing-revoked tenant. Every
// dimension is 1 — the minimal positive cap. It deliberately avoids 0,
// which the daemon interprets as "unlimited" (plans.Quotas doc), so a
// non-payer cannot end up with more capacity than a paying one. The tier
// the tenant is revoked FROM is kept as PlanID so the tenant_quotas row
// stays attributable to a real plan.
func revokedQuotas(tier gibsonv1alpha1.TenantTier) plans.Quotas {
	return plans.Quotas{
		PlanID:               string(tier),
		ConcurrentMissions:   1,
		ConcurrentAgents:     1,
		ConcurrentConnectors: 1,
	}
}

func (r *EntitlementsReconciler) Reconcile(ctx context.Context, tenant *gibsonv1alpha1.Tenant) error {
	if r == nil || r.Plans == nil || r.Provisioner == nil {
		return fmt.Errorf("entitlements reconciler not configured")
	}

	tenantID := tenant.Name

	// Seed the daemon's tenant -> Zitadel-org mapping (gibson#621). The
	// operator is the lifecycle coordinator that provisions the per-tenant
	// Zitadel org; the daemon cannot read Status.ZitadelOrgID itself (ADR-0023),
	// so we hand it over here. Idempotent + runs before the billing gate so the
	// mapping persists regardless of billing state. Skipped until the org is
	// provisioned (a later reconcile seeds it once Status.ZitadelOrgID is set).
	if orgID := tenant.Status.ZitadelOrgID; orgID != "" {
		if err := r.Provisioner.SetTenantZitadelOrg(ctx, tenantID, orgID); err != nil {
			return fmt.Errorf("entitlements: seed zitadel org mapping: %w", err)
		}
	}

	// Billing status gate: revoke paid capabilities for cancelled or long-past-due tenants.
	// This check runs BEFORE the plan lookup so that a cancelled tenant with a
	// stale tier still gets its capabilities revoked.
	if isBillingRevoked(tenant.Status.Billing) {
		r.Logger.Info("entitlements: billing revocation active — flooring quotas",
			"tenant", tenantID,
			"billingStatus", tenant.Status.Billing.Status,
			"pastDueSince", tenant.Status.Billing.PastDueSince,
		)
		// Floor the tenant's runtime quotas. We CANNOT use 0 here: the
		// daemon treats a 0 quota as "unlimited" (plans.Quotas doc), so
		// zeroing would GRANT a non-payer unlimited capacity. revokedQuotas
		// is the minimal positive floor (1 on every dimension) — existing
		// in-flight work is bounded and no new paid-scale work can start.
		// Recovery is automatic: once billing returns to active/trialing
		// the gate is false and the normal path below re-upserts the plan's
		// real quotas on the next reconcile.
		//
		// Idempotent + re-entrant: UpsertTenantQuota is an upsert, so this
		// is safe under the reconciler's run-every-loop contract.
		if err := r.Provisioner.UpsertTenantQuota(ctx, tenantID, revokedQuotas(tenant.Spec.Tier)); err != nil {
			return fmt.Errorf("entitlements: floor revoked quota: %w", err)
		}
		// Feature-tuple revocation (the FGA has_* deletion half) is tracked
		// separately — it requires the daemon-side per-plan feature model so
		// revoke and restore are symmetric deltas. See the follow-up issue
		// tracked at tenant-operator#364.
		return nil
	}

	plan, err := r.lookupPlan(tenant.Spec.Tier)
	if err != nil {
		return err
	}

	start := time.Now()

	// Step 1: quota upsert.
	if err := r.Provisioner.UpsertTenantQuota(ctx, tenantID, plan.Quotas); err != nil {
		return fmt.Errorf("entitlements: quota upsert: %w", err)
	}
	r.Logger.Info("entitlements: quota upserted", "tenant", tenantID, "plan", plan.ID)

	seedCond := r.FirstSeedCondition
	if seedCond == "" {
		seedCond = "CatalogSeeded"
	}
	if !saga.IsConditionTrue(tenant.Status.Conditions, seedCond) {
		if err := r.Provisioner.SeedCatalogTenantEnabled(ctx, tenantID); err != nil {
			return fmt.Errorf("entitlements: seed catalog: %w", err)
		}
		saga.SetCondition(&tenant.Status.Conditions, metav1.Condition{
			Type:    seedCond,
			Status:  metav1.ConditionTrue,
			Reason:  "InitialSeedComplete",
			Message: "tenant_enabled tuples seeded from system catalog",
		})
		r.Logger.Info("entitlements: catalog seeded", "tenant", tenantID)
	}

	// Step 3: emit reconcile-summary audit event. Failure here does NOT
	// fail the reconcile — summary emission is best-effort.
	summary := ReconcileSummary{
		TenantID:   tenantID,
		Plan:       string(plan.ID),
		DurationMs: time.Since(start).Milliseconds(),
		Trigger:    reconcileTriggerFromContext(ctx),
	}
	if err := r.Provisioner.EmitReconcileSummary(ctx, summary); err != nil {
		r.Logger.Warn("entitlements: emit reconcile summary failed (non-fatal)",
			"tenant", tenantID, "error", err)
	}
	return nil
}

// reconcileTriggerCtxKey is the ctx key under which the controller-runtime
// caller records why this reconcile was invoked. Unset → "background".
type reconcileTriggerCtxKey struct{}

// WithReconcileTrigger attaches a trigger classification to ctx. Callers
// (controller Reconcile method) should set this before calling into the
// EntitlementsReconciler: "cr_change", "background", or "stripe_webhook".
func WithReconcileTrigger(ctx context.Context, trigger string) context.Context {
	if trigger == "" {
		return ctx
	}
	return context.WithValue(ctx, reconcileTriggerCtxKey{}, trigger)
}

func reconcileTriggerFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(reconcileTriggerCtxKey{}).(string); ok && v != "" {
		return v
	}
	return "background"
}

// lookupPlan resolves a TenantSpec.Tier to a plans.Plan. Unknown / legacy
// values produce a clear error pointing at the tier-migration runbook.
func (r *EntitlementsReconciler) lookupPlan(tier gibsonv1alpha1.TenantTier) (*plans.Plan, error) {
	p, err := r.Plans.Lookup(plans.PlanID(string(tier)))
	if err != nil {
		return nil, fmt.Errorf("entitlements: unknown plan id %q: %w (valid: team, org, enterprise, enterprise-deploy; see spec plans-and-quotas-simplification for legacy migration)", tier, err)
	}
	return p, nil
}

// AsSagaStep returns a saga.Step that runs this EntitlementsReconciler
// against the Tenant object the runner passes through. The step is
// idempotent and produces the standard Ready / Failed conditions the
// saga runner knows how to surface.
//
// Wire this step into the operator's ProvisionSteps from main.go after
// NamespaceProvisioner and whatever auth-setup steps precede it.
func (r *EntitlementsReconciler) AsSagaStep() saga.Step {
	return &entitlementsStep{
		StepBase: saga.StepBase{
			N: "Entitlements",
			C: "EntitlementsReconciled",
			// No Caps: the step delegates entirely to r.Provisioner,
			// which is either the daemon gRPC client or the HTTP-to-
			// dashboard fallback — both implement EntitlementsProvisioner
			// and are wired in cmd/main.go before AsSagaStep() is called.
			// ValidateAtStartup cannot meaningfully gate on DaemonGRPC
			// here because the step functions correctly with either
			// transport; the provision wiring is the enforcement point.
		},
		reconciler: r,
	}
}

// entitlementsStep is the saga.Step implementation that delegates to
// EntitlementsReconciler.Reconcile.
type entitlementsStep struct {
	saga.StepBase
	reconciler *EntitlementsReconciler
}

func (s *entitlementsStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	tenant, ok := obj.(*gibsonv1alpha1.Tenant)
	if !ok {
		return false, fmt.Errorf("entitlements: expected *Tenant, got %T", obj)
	}
	if err := s.reconciler.Reconcile(ctx, tenant); err != nil {
		return false, err
	}
	return true, nil
}
