// drift_reconcile.go — nightly billing state drift detection.
//
// DriftReconciler runs once per 24 hours (at approximately 02:00 UTC) and
// compares the billing state in Tenant CRs against live Stripe subscription
// data. On mismatch it logs at slog.Error and increments the
// gibson_stripe_drift_total{field} counter.
//
// NO AUTO-CORRECTION in the first 30 days (spec stripe-billing-integration
// R10.2). Drift detection is alerting-only; the on-call engineer investigates
// the root cause (missed webhook, race condition, etc.) before any data is
// corrected. Auto-correction may be enabled in a future spec revision.
//
// Spec: stripe-billing-integration R10.1, R10.2, R10.3, NFR-R2.

package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	stripeclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/stripe"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/metrics"
)

// durationUntilNextRun returns the duration until the next 02:00 UTC run.
// If it is already past 02:00 today, the next run is 02:00 tomorrow.
func durationUntilNextRun() time.Duration {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, time.UTC)
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return time.Until(next)
}

// DriftReconciler compares Tenant CR billing state against live Stripe data.
type DriftReconciler struct {
	client.Client

	// StripeClient is used to list and retrieve Stripe subscriptions.
	StripeClient stripeclient.Client
}

// Reconcile implements reconcile.Reconciler. It is triggered by the watch on
// Tenant CRs and immediately requeues itself with the time-until-next-run
// delay so the loop fires approximately at 02:00 UTC each day.
func (r *DriftReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Run drift check for all tenants.
	if err := r.runDriftCheck(ctx); err != nil {
		slog.Error("[billing/drift] Drift check failed", "err", err)
		// Requeue in 1 hour on transient failure.
		return ctrl.Result{RequeueAfter: 1 * time.Hour}, err
	}

	nextRun := durationUntilNextRun()
	slog.Info("[billing/drift] Drift check complete, next run scheduled",
		"nextRunIn", nextRun.String(),
	)
	return ctrl.Result{RequeueAfter: nextRun}, nil
}

func (r *DriftReconciler) runDriftCheck(ctx context.Context) error {
	var tenants gibsonv1alpha1.TenantList
	if err := r.List(ctx, &tenants); err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}

	for i := range tenants.Items {
		tenant := &tenants.Items[i]
		billing := tenant.Status.Billing

		// Only check tenants with an active Stripe subscription.
		if billing.SubscriptionID == "" {
			continue
		}

		sub, err := r.StripeClient.GetSubscription(ctx, billing.SubscriptionID)
		if err != nil {
			slog.Error("[billing/drift] Failed to get subscription from Stripe",
				"tenantId", tenant.Name,
				"stripeSubscriptionId", billing.SubscriptionID,
				"err", err,
			)
			// Continue to next tenant on Stripe API error.
			continue
		}

		r.checkField(tenant.Name, billing.SubscriptionID, "status", billing.Status, sub.Status)
		r.checkField(tenant.Name, billing.SubscriptionID, "priceId", billing.PriceID, sub.PriceID)

		// currentPeriodEnd: compare as Unix timestamps if billing field is present.
		if billing.CurrentPeriodEnd != "" && sub.CurrentPeriodEnd != 0 {
			localEnd, err := time.Parse(time.RFC3339, billing.CurrentPeriodEnd)
			if err == nil {
				stripeEnd := time.Unix(sub.CurrentPeriodEnd, 0).UTC()
				// Allow a 1-hour tolerance for billing cycle anchor rounding.
				if localEnd.Sub(stripeEnd).Abs() > time.Hour {
					slog.Error("[billing/drift] Field drift detected",
						"tenantId", tenant.Name,
						"stripeSubscriptionId", billing.SubscriptionID,
						"field", "currentPeriodEnd",
						"crValue", billing.CurrentPeriodEnd,
						"stripeValue", stripeEnd.Format(time.RFC3339),
					)
					metrics.StripeDriftTotal.WithLabelValues("currentPeriodEnd").Inc()
				}
			}
		}
	}
	return nil
}

// checkField compares a scalar billing field between the CR and Stripe.
// Logs and increments the drift counter on mismatch.
func (r *DriftReconciler) checkField(tenantID, subscriptionID, field, crValue, stripeValue string) {
	if crValue != "" && stripeValue != "" && crValue != stripeValue {
		slog.Error("[billing/drift] Field drift detected",
			"tenantId", tenantID,
			"stripeSubscriptionId", subscriptionID,
			"field", field,
			"crValue", crValue,
			"stripeValue", stripeValue,
		)
		metrics.StripeDriftTotal.WithLabelValues(field).Inc()
	}
}

// SetupWithManager registers the DriftReconciler with the controller manager.
func (r *DriftReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.Tenant{}).
		Named("drift-reconciler").
		Complete(r)
}
