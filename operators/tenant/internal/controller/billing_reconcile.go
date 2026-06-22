// billing_reconcile.go — periodic billing enforcement reconciler.
//
// BillingReconciler runs every 5 minutes and enforces the billing state machine
// by comparing Tenant CR billing status against live Stripe subscription state.
//
// Responsibilities:
//   - Trial enforcement: for tenants with status=trialing and trialEnd in the
//     past, confirm with Stripe and transition to cancelled if expired.
//   - Past-due enforcement: tenants with pastDueSince older than 7 days trigger
//     entitlements revocation.
//   - Teardown enforcement: tenants with the teardown-after annotation elapsed
//     trigger the TeardownSteps work queue.
//
// The reconciler is a safety net for missed webhooks. The webhook handlers are
// the primary signal; this loop catches cases where Stripe delivery fails.
//
// Spec: stripe-billing-integration R5.1, R5.2, R4.4.

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	stripeclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/stripe"
)

const (
	// billingReconcileInterval is how often the reconciler polls.
	billingReconcileInterval = 5 * time.Minute

	// billingPastDueGracePeriod is the dunning window after which paid
	// capabilities are revoked for past-due tenants.
	billingPastDueGracePeriod = 7 * 24 * time.Hour

	// teardownAfterAnnotation is the annotation key written on subscription
	// deletion (ISO 8601 UTC timestamp after which TeardownSteps fire).
	teardownAfterAnnotation = "gibson.zeroroot.ai/teardown-after"
)

// BillingReconciler is a periodic reconciler that enforces billing state.
type BillingReconciler struct {
	client.Client

	// StripeClient is used to verify live subscription state.
	StripeClient stripeclient.Client

	// Entitlements reconciler used to revoke capabilities for past-due tenants.
	Entitlements *EntitlementsReconciler

	// TeardownQueue is the work queue for enqueuing tenant teardown jobs.
	// Using a channel so teardown is asynchronous and doesn't block the reconcile loop.
	TeardownQueue chan string // receives tenant names
}

// Reconcile implements reconcile.Reconciler. It is registered as a non-watch
// reconciler that requeues itself on a fixed interval.
//
// For each Tenant CR:
//  1. If status=trialing and trialEnd is in the past, verify with Stripe.
//     If Stripe reports canceled/incomplete_expired, transition to cancelled.
//  2. If status=past_due and pastDueSince older than 7 days, revoke entitlements.
//  3. If teardown-after annotation is present and elapsed, enqueue teardown.
func (r *BillingReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// List all Tenant CRs. Use a label selector to avoid loading all objects in
	// large clusters (the controller-runtime cache handles this efficiently).
	var tenants gibsonv1alpha1.TenantList
	if err := r.List(ctx, &tenants); err != nil {
		slog.Error("[billing/reconciler] Failed to list tenants", "err", err)
		return ctrl.Result{RequeueAfter: billingReconcileInterval}, err
	}

	for i := range tenants.Items {
		tenant := &tenants.Items[i]
		if err := r.reconcileTenant(ctx, tenant); err != nil {
			slog.Error("[billing/reconciler] Error reconciling tenant billing",
				"tenantId", tenant.Name,
				"err", err,
			)
			// Continue to next tenant; don't fail the whole loop.
		}
	}

	return ctrl.Result{RequeueAfter: billingReconcileInterval}, nil
}

func (r *BillingReconciler) reconcileTenant(ctx context.Context, tenant *gibsonv1alpha1.Tenant) error {
	billing := tenant.Status.Billing

	// ── Abandoned-checkout teardown (card-first signup, deploy-issue #359) ──
	// When the in-page card was never completed, WaitForBillingConfirmation
	// sets BillingAbandoned=True after its window. Such a tenant must be torn
	// down (and its slug freed for re-signup), not left as a stranded
	// half-provisioned namespace + Stripe customer. Stamp teardown-after=now
	// so the enforcement block below enqueues it on this same tick. Idempotent:
	// re-stamping an already-past timestamp is a no-op once teardown is queued.
	if apimeta.IsStatusConditionTrue(tenant.Status.Conditions, gibsonv1alpha1.ConditionBillingAbandoned) {
		if _, already := tenant.Annotations[teardownAfterAnnotation]; !already {
			slog.Info("[billing/reconciler] BillingAbandoned — scheduling immediate teardown",
				"tenantId", tenant.Name,
			)
			if err := r.writeTeardownAfterNow(ctx, tenant); err != nil {
				return fmt.Errorf("stamp abandoned teardown-after: %w", err)
			}
		}
	}

	// ── Teardown enforcement ──────────────────────────────────────────────
	// Check teardown-after annotation regardless of billing status.
	if ts, ok := tenant.Annotations[teardownAfterAnnotation]; ok && ts != "" {
		teardownAt, err := time.Parse(time.RFC3339, ts)
		if err == nil && time.Now().After(teardownAt) {
			slog.Info("[billing/reconciler] Teardown-after elapsed, enqueuing teardown",
				"tenantId", tenant.Name,
				"teardownAfter", ts,
			)
			// Enqueue teardown asynchronously to avoid blocking the loop.
			select {
			case r.TeardownQueue <- tenant.Name:
			default:
				slog.Warn("[billing/reconciler] Teardown queue full, skipping teardown enqueue",
					"tenantId", tenant.Name,
				)
			}
		}
	}

	// ── Trial enforcement ──────────────────────────────────────────────────
	if billing.Status == "trialing" && billing.TrialEnd != "" {
		trialEnd, err := time.Parse(time.RFC3339, billing.TrialEnd)
		if err == nil && time.Now().After(trialEnd) && billing.SubscriptionID != "" {
			slog.Info("[billing/reconciler] Trial may have expired, verifying with Stripe",
				"tenantId", tenant.Name,
				"stripeSubscriptionId", billing.SubscriptionID,
				"trialEnd", billing.TrialEnd,
			)
			sub, err := r.StripeClient.GetSubscription(ctx, billing.SubscriptionID)
			if err != nil {
				return fmt.Errorf("GetSubscription: %w", err)
			}
			if sub.Status == "canceled" || sub.Status == "incomplete_expired" {
				slog.Info("[billing/reconciler] Stripe confirms subscription expired, transitioning to cancelled",
					"tenantId", tenant.Name,
					"stripeSubscriptionId", billing.SubscriptionID,
					"stripeStatus", sub.Status,
				)
				if err := r.patchBillingStatus(ctx, tenant, "cancelled"); err != nil {
					return fmt.Errorf("patchBillingStatus: %w", err)
				}
				if err := r.writeTeardownAfterAnnotation(ctx, tenant); err != nil {
					return fmt.Errorf("writeTeardownAfterAnnotation: %w", err)
				}
			}
		}
	}

	// ── Past-due enforcement ───────────────────────────────────────────────
	if billing.Status == "past_due" && billing.PastDueSince != "" {
		pastDueSince, err := time.Parse(time.RFC3339, billing.PastDueSince)
		if err == nil && time.Since(pastDueSince) > billingPastDueGracePeriod {
			slog.Info("[billing/reconciler] Past-due grace period elapsed, revoking entitlements",
				"tenantId", tenant.Name,
				"pastDueSince", billing.PastDueSince,
			)
			if r.Entitlements != nil {
				if err := r.Entitlements.Reconcile(ctx, tenant); err != nil {
					return fmt.Errorf("EntitlementsReconciler.Reconcile: %w", err)
				}
			}
		}
	}

	return nil
}

// patchBillingStatus patches the tenant's billing status field.
func (r *BillingReconciler) patchBillingStatus(ctx context.Context, tenant *gibsonv1alpha1.Tenant, status string) error {
	patch := client.MergeFrom(tenant.DeepCopy())
	tenant.Status.Billing.Status = status
	tenant.Status.Billing.LastUpdated = time.Now().UTC().Format(time.RFC3339)
	return r.Status().Patch(ctx, tenant, patch)
}

// writeTeardownAfterAnnotation writes the teardown-after annotation.
func (r *BillingReconciler) writeTeardownAfterAnnotation(ctx context.Context, tenant *gibsonv1alpha1.Tenant) error {
	patch := client.MergeFrom(tenant.DeepCopy())
	if tenant.Annotations == nil {
		tenant.Annotations = make(map[string]string)
	}
	tenant.Annotations[teardownAfterAnnotation] = time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	return r.Patch(ctx, tenant, patch)
}

// writeTeardownAfterNow stamps teardown-after at the current time so the
// enforcement block tears the tenant down immediately. Used for abandoned
// card-first signups, which (unlike a cancelled paying subscription) have no
// grace period — nothing was ever paid for.
func (r *BillingReconciler) writeTeardownAfterNow(ctx context.Context, tenant *gibsonv1alpha1.Tenant) error {
	patch := client.MergeFrom(tenant.DeepCopy())
	if tenant.Annotations == nil {
		tenant.Annotations = make(map[string]string)
	}
	tenant.Annotations[teardownAfterAnnotation] = time.Now().UTC().Format(time.RFC3339)
	return r.Patch(ctx, tenant, patch)
}

// SetupWithManager registers the BillingReconciler with the controller manager.
// The reconciler is triggered on a fixed interval, not by watch events.
func (r *BillingReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.Tenant{}).
		Named("billing-reconciler").
		Complete(r)
}
