// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/identity"
)

// identityResyncInterval re-reconciles a Ready TenantIdentity periodically so
// drift in the underlying Zitadel org (a deleted organization) is corrected
// without waiting for an external event. The identity.Provisioner is idempotent
// (it verifies the known org id and re-creates on drift), so a periodic re-run
// is cheap when everything is already in place.
const identityResyncInterval = 10 * time.Minute

// TenantIdentityReconciler reconciles a TenantIdentity object. It is the
// declarative replacement for the imperative EnsureZitadelOrg / RemoveZitadelOrg
// saga steps: it composes the per-tenant Zitadel organization by delegating to
// the shared identity.Provisioner. That provisioner wraps the SAME zitadel.Client
// the Tenant saga uses today (and both call the same identity.EnsureOrg /
// identity.RemoveOrg core), so there is exactly one provisioning codepath
// (ADR-0027); this controller is a second, declarative caller of it, not a
// parallel reimplementation.
type TenantIdentityReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Provisioner is the shared identity pipeline. Always non-nil in production
	// (buildIdentityProvisioner in cmd/main.go always returns identity.New(...));
	// a nil here fails loud so a misconfigured operator crash-loops rather than
	// silently no-op'ing identity provisioning.
	Provisioner identity.Provisioner
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantidentities,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantidentities/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantidentities/finalizers,verbs=update

// Reconcile drives a TenantIdentity toward its desired state. The flow:
//
//	delete path  → run the finalizer teardown (Deprovision), then drop the
//	               finalizer once the org is gone.
//	provision    → ensure finalizer, call Provisioner.Provision (idempotent +
//	               drift-correcting), then write org id/slug + per-component +
//	               aggregate status.
//
// Status is the ONLY persisted output of this controller. Following the known
// saga hazard (steps re-run every reconcile and only Status().Patch sticks),
// the controller never mutates spec; it writes desired observed state (including
// the provisioned org id/slug — the same values the saga writes to
// Tenant.Status) to the status subresource.
func (r *TenantIdentityReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantidentity", req.NamespacedName)

	var ti gibsonv1alpha1.TenantIdentity
	if err := r.Get(ctx, req.NamespacedName, &ti); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.Provisioner == nil {
		// Fail loud: a nil provisioner means operator wiring passed nil
		// explicitly. Record the error in status and requeue with backoff.
		log.Error(clients.ErrInvalidInput, "identity provisioner unset (operator misconfigured)")
		return r.failIdentity(ctx, &ti, "identity provisioner unset (operator misconfigured)")
	}

	// Deletion path: run teardown, then drop the finalizer.
	if !ti.DeletionTimestamp.IsZero() {
		return r.reconcileIdentityDelete(ctx, &ti)
	}

	// Ensure finalizer so teardown runs before the CR is GC'd.
	if !controllerutil.ContainsFinalizer(&ti, gibsonv1alpha1.TenantIdentityFinalizer) {
		controllerutil.AddFinalizer(&ti, gibsonv1alpha1.TenantIdentityFinalizer)
		if err := r.Update(ctx, &ti); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("added finalizer")
		return ctrl.Result{Requeue: true}, nil
	}

	// Provision (idempotent + drift-correcting). On a steady-state drift-check
	// resync (already Ready for this generation) skip the Provisioning flip so
	// status stays Ready and status-patch self-triggering stops the churn.
	// First provision and spec changes (generation bump) still flip to
	// Provisioning → Ready correctly.
	alreadyReady := ti.Status.Phase == gibsonv1alpha1.TenantIdentityPhaseReady &&
		ti.Status.ObservedGeneration == ti.Generation
	if !alreadyReady {
		if err := r.markIdentityProvisioning(ctx, &ti); err != nil {
			return ctrl.Result{}, err
		}
	}

	res, err := r.Provisioner.Provision(ctx, identity.Request{
		TenantID:    ti.Spec.TenantID,
		DisplayName: ti.Spec.DisplayName,
		KnownOrgID:  ti.Status.ZitadelOrgID,
	})
	if err != nil {
		log.Error(err, "identity provision failed", "tenant", ti.Spec.TenantID)
		r.emitIdentity(&ti, "Warning", "ProvisionFailed", err.Error())
		if _, ferr := r.failIdentity(ctx, &ti, err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		// Return the provision error so controller-runtime backs off.
		return ctrl.Result{}, err
	}

	r.markIdentityReady(ctx, &ti, res)
	r.emitIdentity(&ti, "Normal", "Provisioned", "tenant identity is ready")
	log.V(1).Info("tenant identity ready", "tenant", ti.Spec.TenantID, "org", res.OrgID)

	return ctrl.Result{RequeueAfter: identityResyncInterval}, nil
}

// reconcileIdentityDelete tears down the per-tenant Zitadel org via the
// idempotent Deprovision path, then removes the finalizer. Deprovision is
// best-effort: a NotFound is treated as success (already gone) by the
// provisioner itself, and any other error keeps the finalizer so the controller
// retries with backoff.
func (r *TenantIdentityReconciler) reconcileIdentityDelete(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantidentity", ti.Name, "phase", "delete")

	if !controllerutil.ContainsFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer) {
		return ctrl.Result{}, nil
	}

	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseDeprovisioning
	ti.Status.Ready = false
	_ = r.patchIdentityStatus(ctx, ti, base)

	if r.Provisioner != nil {
		if err := r.Provisioner.Deprovision(ctx, ti.Status.ZitadelOrgID); err != nil && !errors.Is(err, clients.ErrNotFound) {
			log.Error(err, "identity deprovision failed; keeping finalizer for retry", "tenant", ti.Spec.TenantID)
			r.emitIdentity(ti, "Warning", "DeprovisionFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	patch := client.MergeFrom(ti.DeepCopy())
	if controllerutil.RemoveFinalizer(ti, gibsonv1alpha1.TenantIdentityFinalizer) {
		if err := r.Patch(ctx, ti, patch); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("finalizer removed; tenant identity deprovisioned", "tenant", ti.Spec.TenantID)
	}
	return ctrl.Result{}, nil
}

// markIdentityProvisioning records the in-flight phase via Status().Patch. It
// returns an error only when the patch itself fails — callers that guard on
// alreadyReady propagate it so the reconcile retries rather than continuing
// with stale in-cluster state.
func (r *TenantIdentityReconciler) markIdentityProvisioning(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity) error {
	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseProvisioning
	ti.Status.LastError = ""
	return r.patchIdentityStatus(ctx, ti, base)
}

// markIdentityReady records the ready state: org id/slug recorded, aggregate
// Ready true, every component ready, and the Ready condition flipped True. The
// org id/slug are written the SAME way the saga writes Tenant.Status, so
// downstream readers see identical data regardless of codepath.
func (r *TenantIdentityReconciler) markIdentityReady(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity, res identity.Result) {
	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseReady
	ti.Status.Ready = true
	ti.Status.LastError = ""
	ti.Status.ZitadelOrgID = res.OrgID
	ti.Status.ZitadelOrgSlug = res.Slug
	ti.Status.ObservedGeneration = ti.Generation
	ti.Status.Components = readyIdentityComponents(ti)
	setIdentityReadyCondition(ti, metav1.ConditionTrue, "Provisioned", "tenant identity is ready")
	_ = r.patchIdentityStatus(ctx, ti, base)
}

// failIdentity records a failed reconcile in status without mutating spec.
func (r *TenantIdentityReconciler) failIdentity(ctx context.Context, ti *gibsonv1alpha1.TenantIdentity, msg string) (ctrl.Result, error) {
	base := ti.DeepCopy()
	ti.Status.Phase = gibsonv1alpha1.TenantIdentityPhaseFailed
	ti.Status.Ready = false
	ti.Status.LastError = msg
	setIdentityReadyCondition(ti, metav1.ConditionFalse, "ProvisionFailed", msg)
	_ = r.patchIdentityStatus(ctx, ti, base)
	return ctrl.Result{}, nil
}

// patchIdentityStatus persists status via a merge-patch off the captured base.
// Using Patch (not Update) avoids resourceVersion conflicts with the Tenant
// saga, which patches Tenant status concurrently. The error is returned so
// that callers which guard on observed phase (e.g. markIdentityProvisioning in
// the alreadyReady guard) can propagate it; callers that write terminal state
// (markIdentityReady, failIdentity) log and continue as before.
func (r *TenantIdentityReconciler) patchIdentityStatus(ctx context.Context, ti, base *gibsonv1alpha1.TenantIdentity) error {
	if err := r.Status().Patch(ctx, ti, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "tenantidentity status patch failed", "tenant", ti.Spec.TenantID)
		return err
	}
	return nil
}

// emitIdentity records a Kubernetes event on the TenantIdentity. No-ops when the
// recorder is nil (tests).
func (r *TenantIdentityReconciler) emitIdentity(ti *gibsonv1alpha1.TenantIdentity, eventType, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(ti, nil, eventType, reason, reason, "%s", msg)
}

// readyIdentityComponents returns the per-component ready conditions. The
// zitadel-org component always participates (the operator always provisions the
// org). The oidc-client component participates only when the spec requests one;
// since the operator does not itself mint the Zitadel OIDC application in this
// slice (gibson#803 scope: per-tenant OIDC clients are minted daemon-side), a
// requested oidc-client is reported ready once the org backing it exists.
func readyIdentityComponents(ti *gibsonv1alpha1.TenantIdentity) []gibsonv1alpha1.TenantIdentityComponentCondition {
	now := metav1.Now()
	ready := func(name string) gibsonv1alpha1.TenantIdentityComponentCondition {
		return gibsonv1alpha1.TenantIdentityComponentCondition{Name: name, State: "ready", LastUpdated: now}
	}
	comps := []gibsonv1alpha1.TenantIdentityComponentCondition{ready("zitadel-org")}
	if len(ti.Spec.OIDCClients) > 0 {
		comps = append(comps, ready("oidc-client"))
	}
	return comps
}

// setIdentityReadyCondition upserts the aggregate Ready condition.
func setIdentityReadyCondition(ti *gibsonv1alpha1.TenantIdentity, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               gibsonv1alpha1.ConditionTenantIdentityReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: ti.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range ti.Status.Conditions {
		if ti.Status.Conditions[i].Type == cond.Type {
			// Preserve LastTransitionTime when status is unchanged.
			if ti.Status.Conditions[i].Status == status {
				cond.LastTransitionTime = ti.Status.Conditions[i].LastTransitionTime
			}
			ti.Status.Conditions[i] = cond
			return
		}
	}
	ti.Status.Conditions = append(ti.Status.Conditions, cond)
}

// SetupWithManager registers the controller with the manager.
//
// GenerationChangedPredicate filters out status-only patch events: status
// writes do not bump metadata.generation, so they no longer re-trigger a
// reconcile. This stops the status-patch → re-trigger → markIdentityProvisioning
// churn that prevented the phase from ever settling on Ready (gibson#1140).
// Spec changes (generation bump), creates, and deletes still reconcile
// immediately; the 10-minute RequeueAfter handles drift-correction resyncs.
func (r *TenantIdentityReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenantidentity-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.TenantIdentity{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("tenantidentity").
		Complete(r)
}
