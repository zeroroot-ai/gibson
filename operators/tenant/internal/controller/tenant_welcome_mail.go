// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/mail"
)

// welcomeRetryInterval is how soon the Tenant reconciler comes back after a
// failed welcome-email send. The tenant is already Ready at that point, so no
// watch event is guaranteed to wake the reconciler again; without this the
// retry would wait for the resync window and the owner would learn their
// workspace is live from the dashboard instead of the mail.
const welcomeRetryInterval = 60 * time.Second

// sendWelcomeEmail sends the workspace-ready welcome mail to the founding
// owner exactly once, at the Tenant's Ready transition (gibson#1447).
//
// Idempotence: the WelcomeEmailSent status condition is the record of a
// completed send. The caller invokes this BEFORE the reconcile's closing
// Status().Patch, so the condition set here rides that same patch and is
// durable — a spec write would be discarded (tenant-operator#354).
//
// Delivery is best-effort. A send failure is logged, surfaced as a Warning
// event and reported back as a retry request; it never fails the reconcile
// and never flips the tenant out of Ready. The condition stays unset so the
// next pass tries again.
//
// Returns true when the caller should requeue to retry the send. The caller
// gates on a non-nil r.Mail, matching the operator's other optional-collaborator
// call sites (r.StatusReporter, r.MigrationEmitter).
func (r *TenantReconciler) sendWelcomeEmail(ctx context.Context, tenant *gibsonv1alpha1.Tenant) bool {
	log := logf.FromContext(ctx).WithValues("tenant", tenant.Name)

	// Nobody to welcome. Mirrors ensureFoundingMember's empty-owner no-op:
	// tenants created outside the signup flow may carry no owner address.
	if tenant.Spec.Owner == "" {
		log.Info("tenant has no owner address; skipping welcome email")
		return false
	}

	if apimeta.IsStatusConditionTrue(tenant.Status.Conditions, gibsonv1alpha1.ConditionWelcomeEmailSent) {
		return false
	}

	if err := r.Mail.SendWelcome(ctx, mail.WelcomeMessage{
		To:           tenant.Spec.Owner,
		TenantName:   welcomeTenantName(tenant),
		DashboardURL: r.DashboardBaseURL,
	}); err != nil {
		log.Error(err, "welcome email send failed; retrying on the next reconcile")
		// events.EventRecorder.Eventf signature: (regarding, related,
		// eventtype, reason, action, note, args...).
		r.Recorder.Eventf(tenant, nil, corev1.EventTypeWarning,
			"WelcomeEmailFailed", "WelcomeEmailFailed", "%s", err.Error())
		return true
	}

	setWelcomeEmailSentCondition(tenant)
	r.Recorder.Eventf(tenant, nil, corev1.EventTypeNormal,
		"WelcomeEmailSent", "WelcomeEmailSent", "%s", "workspace-ready welcome email sent to the tenant owner")
	log.Info("welcome email sent")
	return false
}

// welcomeTenantName is the workspace name the welcome template renders. The
// display name is what the owner typed at signup; the CR name is the fallback
// for tenants created without one.
func welcomeTenantName(tenant *gibsonv1alpha1.Tenant) string {
	if tenant.Spec.DisplayName != "" {
		return tenant.Spec.DisplayName
	}
	return tenant.Name
}

// setWelcomeEmailSentCondition upserts the send record onto the Tenant's
// in-memory status. Persisting it is the caller's closing Status().Patch.
// Upsert shape matches the sub-CRD controllers' setter (preserve
// LastTransitionTime across an unchanged status).
func setWelcomeEmailSentCondition(tenant *gibsonv1alpha1.Tenant) {
	cond := metav1.Condition{
		Type:               gibsonv1alpha1.ConditionWelcomeEmailSent,
		Status:             metav1.ConditionTrue,
		Reason:             "WelcomeEmailSent",
		Message:            "workspace-ready welcome email sent to the tenant owner",
		ObservedGeneration: tenant.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range tenant.Status.Conditions {
		if tenant.Status.Conditions[i].Type == cond.Type {
			if tenant.Status.Conditions[i].Status == cond.Status {
				cond.LastTransitionTime = tenant.Status.Conditions[i].LastTransitionTime
			}
			tenant.Status.Conditions[i] = cond
			return
		}
	}
	tenant.Status.Conditions = append(tenant.Status.Conditions, cond)
}
