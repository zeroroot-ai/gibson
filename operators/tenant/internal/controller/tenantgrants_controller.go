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
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/grants"
)

// grantsResyncInterval re-reconciles a Ready TenantGrants periodically so drift
// in the underlying FGA store (a tuple deleted out-of-band) is corrected without
// waiting for an external event. The grants.Provisioner is idempotent +
// drift-correcting (write-if-absent), so a periodic re-run is cheap when every
// tuple is already in place.
const grantsResyncInterval = 10 * time.Minute

// TenantGrantsReconciler reconciles a TenantGrants object. It is the declarative
// replacement for the imperative RegisterTenantWithPlatform saga step: it writes
// the tenant's platform-level FGA tuples by delegating to the shared
// grants.Provisioner. That provisioner wraps the SAME fga.Client the Tenant saga
// uses (and the saga's RegisterTenantWithPlatform step now calls the same
// grants.PlatformRegistrationTuple + provisioner core), so there is exactly one
// tuple-writing codepath (ADR-0027); this controller is a second, declarative
// caller of it, not a parallel reimplementation. It drift-corrects on every
// reconcile (re-writing any declared tuple deleted out-of-band).
type TenantGrantsReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Provisioner is the shared tenant-grants pipeline. Always non-nil in
	// production (cmd/main.go always returns grants.New(...)); a nil here fails
	// loud so a misconfigured operator crash-loops rather than silently
	// no-op'ing grant provisioning.
	Provisioner grants.Provisioner
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantgrants,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantgrants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantgrants/finalizers,verbs=update

// Reconcile drives a TenantGrants toward its desired state. The flow:
//
//	delete path  → run the finalizer teardown (Deprovision), then drop the
//	               finalizer once the tuples are gone.
//	provision    → ensure finalizer, call Provisioner.Provision (idempotent +
//	               drift-correcting), then write per-component + aggregate status.
//
// Status is the ONLY persisted output of this controller. Following the known
// saga hazard (steps re-run every reconcile and only Status().Patch sticks),
// the controller never mutates spec; it writes desired observed state to the
// status subresource.
func (r *TenantGrantsReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantgrants", req.NamespacedName)

	var tg gibsonv1alpha1.TenantGrants
	if err := r.Get(ctx, req.NamespacedName, &tg); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.Provisioner == nil {
		// Fail loud: a nil provisioner means operator wiring passed nil
		// explicitly. Record the error in status and requeue with backoff.
		log.Error(clients.ErrInvalidInput, "grants provisioner unset (operator misconfigured)")
		return r.failGrants(ctx, &tg, "grants provisioner unset (operator misconfigured)")
	}

	// Deletion path: run teardown, then drop the finalizer.
	if !tg.DeletionTimestamp.IsZero() {
		return r.reconcileGrantsDelete(ctx, &tg)
	}

	// Ensure finalizer so teardown runs before the CR is GC'd.
	if !controllerutil.ContainsFinalizer(&tg, gibsonv1alpha1.TenantGrantsFinalizer) {
		controllerutil.AddFinalizer(&tg, gibsonv1alpha1.TenantGrantsFinalizer)
		if err := r.Update(ctx, &tg); err != nil {
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
	alreadyReady := tg.Status.Phase == gibsonv1alpha1.TenantGrantsPhaseReady &&
		tg.Status.ObservedGeneration == tg.Generation
	if !alreadyReady {
		if err := r.markGrantsProvisioning(ctx, &tg); err != nil {
			return ctrl.Result{}, err
		}
	}

	tuples := desiredTuples(&tg)
	if err := r.Provisioner.Provision(ctx, tuples); err != nil {
		log.Error(err, "tenant grants provision failed", "tenant", tg.Spec.TenantID)
		r.emitGrants(&tg, "Warning", "ProvisionFailed", err.Error())
		if _, ferr := r.failGrants(ctx, &tg, err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		// Return the provision error so controller-runtime backs off.
		return ctrl.Result{}, err
	}

	r.markGrantsReady(ctx, &tg, len(tuples))
	r.emitGrants(&tg, "Normal", "Provisioned", "tenant grants are ready")
	log.V(1).Info("tenant grants ready", "tenant", tg.Spec.TenantID, "tuples", len(tuples))

	return ctrl.Result{RequeueAfter: grantsResyncInterval}, nil
}

// reconcileGrantsDelete deletes the tenant's FGA tuples via the idempotent
// Deprovision path, then removes the finalizer. Deprovision is best-effort: a
// NotFound is treated as success (already gone) by the provisioner itself, and
// any other error keeps the finalizer so the controller retries with backoff.
func (r *TenantGrantsReconciler) reconcileGrantsDelete(ctx context.Context, tg *gibsonv1alpha1.TenantGrants) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantgrants", tg.Name, "phase", "delete")

	if !controllerutil.ContainsFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer) {
		return ctrl.Result{}, nil
	}

	base := tg.DeepCopy()
	tg.Status.Phase = gibsonv1alpha1.TenantGrantsPhaseDeprovisioning
	tg.Status.Ready = false
	_ = r.patchGrantsStatus(ctx, tg, base)

	if r.Provisioner != nil {
		if err := r.Provisioner.Deprovision(ctx, desiredTuples(tg)); err != nil && !errors.Is(err, clients.ErrNotFound) {
			log.Error(err, "tenant grants deprovision failed; keeping finalizer for retry", "tenant", tg.Spec.TenantID)
			r.emitGrants(tg, "Warning", "DeprovisionFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	patch := client.MergeFrom(tg.DeepCopy())
	if controllerutil.RemoveFinalizer(tg, gibsonv1alpha1.TenantGrantsFinalizer) {
		if err := r.Patch(ctx, tg, patch); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("finalizer removed; tenant grants deprovisioned", "tenant", tg.Spec.TenantID)
	}
	return ctrl.Result{}, nil
}

// desiredTuples projects the TenantGrants spec into the FGA tuples to reconcile:
// the canonical platform-registration tuple (unless disabled) plus any declared
// ExtraTuples. Centralised so Provision and Deprovision operate on the same set.
func desiredTuples(tg *gibsonv1alpha1.TenantGrants) []fga.Tuple {
	tuples := make([]fga.Tuple, 0, 1+len(tg.Spec.ExtraTuples))
	if tg.Spec.PlatformRegistration {
		tuples = append(tuples, grants.PlatformRegistrationTuple(tg.Spec.TenantID))
	}
	for _, t := range tg.Spec.ExtraTuples {
		tuples = append(tuples, fga.Tuple{User: t.User, Relation: t.Relation, Object: t.Object})
	}
	return tuples
}

// markGrantsProvisioning records the in-flight phase via Status().Patch. It
// returns an error only when the patch itself fails — callers that guard on
// alreadyReady propagate it so the reconcile retries rather than continuing
// with stale in-cluster state.
func (r *TenantGrantsReconciler) markGrantsProvisioning(ctx context.Context, tg *gibsonv1alpha1.TenantGrants) error {
	base := tg.DeepCopy()
	tg.Status.Phase = gibsonv1alpha1.TenantGrantsPhaseProvisioning
	tg.Status.LastError = ""
	return r.patchGrantsStatus(ctx, tg, base)
}

// markGrantsReady records the ready state: aggregate Ready true, applied-tuple
// count recorded, every participating component ready, and the Ready condition
// flipped True.
func (r *TenantGrantsReconciler) markGrantsReady(ctx context.Context, tg *gibsonv1alpha1.TenantGrants, applied int) {
	base := tg.DeepCopy()
	tg.Status.Phase = gibsonv1alpha1.TenantGrantsPhaseReady
	tg.Status.Ready = true
	tg.Status.LastError = ""
	tg.Status.AppliedTuples = applied
	tg.Status.ObservedGeneration = tg.Generation
	tg.Status.Components = readyGrantsComponents(tg)
	setGrantsReadyCondition(tg, metav1.ConditionTrue, "Provisioned", "tenant grants are ready")
	_ = r.patchGrantsStatus(ctx, tg, base)
}

// failGrants records a failed reconcile in status without mutating spec.
func (r *TenantGrantsReconciler) failGrants(ctx context.Context, tg *gibsonv1alpha1.TenantGrants, msg string) (ctrl.Result, error) {
	base := tg.DeepCopy()
	tg.Status.Phase = gibsonv1alpha1.TenantGrantsPhaseFailed
	tg.Status.Ready = false
	tg.Status.LastError = msg
	setGrantsReadyCondition(tg, metav1.ConditionFalse, "ProvisionFailed", msg)
	_ = r.patchGrantsStatus(ctx, tg, base)
	return ctrl.Result{}, nil
}

// patchGrantsStatus persists status via a merge-patch off the captured base.
// Using Patch (not Update) avoids resourceVersion conflicts with the Tenant
// saga, which patches Tenant status concurrently. The error is returned so
// that callers which guard on observed phase (e.g. markGrantsProvisioning in
// the alreadyReady guard) can propagate it; callers that write terminal state
// (markGrantsReady, failGrants) log and continue as before.
func (r *TenantGrantsReconciler) patchGrantsStatus(ctx context.Context, tg, base *gibsonv1alpha1.TenantGrants) error {
	if err := r.Status().Patch(ctx, tg, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "tenantgrants status patch failed", "tenant", tg.Spec.TenantID)
		return err
	}
	return nil
}

// emitGrants records a Kubernetes event on the TenantGrants. No-ops when the
// recorder is nil (tests).
func (r *TenantGrantsReconciler) emitGrants(tg *gibsonv1alpha1.TenantGrants, eventType, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(tg, nil, eventType, reason, reason, "%s", msg)
}

// readyGrantsComponents returns the per-component ready conditions. The
// platform-registration component participates whenever the spec requests it;
// the extra-tuples component participates only when ExtraTuples are declared.
func readyGrantsComponents(tg *gibsonv1alpha1.TenantGrants) []gibsonv1alpha1.TenantGrantsComponentCondition {
	now := metav1.Now()
	ready := func(name string) gibsonv1alpha1.TenantGrantsComponentCondition {
		return gibsonv1alpha1.TenantGrantsComponentCondition{Name: name, State: "ready", LastUpdated: now}
	}
	var comps []gibsonv1alpha1.TenantGrantsComponentCondition
	if tg.Spec.PlatformRegistration {
		comps = append(comps, ready("platform-registration"))
	}
	if len(tg.Spec.ExtraTuples) > 0 {
		comps = append(comps, ready("extra-tuples"))
	}
	return comps
}

// setGrantsReadyCondition upserts the aggregate Ready condition.
func setGrantsReadyCondition(tg *gibsonv1alpha1.TenantGrants, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               gibsonv1alpha1.ConditionTenantGrantsReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: tg.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range tg.Status.Conditions {
		if tg.Status.Conditions[i].Type == cond.Type {
			// Preserve LastTransitionTime when status is unchanged.
			if tg.Status.Conditions[i].Status == status {
				cond.LastTransitionTime = tg.Status.Conditions[i].LastTransitionTime
			}
			tg.Status.Conditions[i] = cond
			return
		}
	}
	tg.Status.Conditions = append(tg.Status.Conditions, cond)
}

// SetupWithManager registers the controller with the manager.
//
// GenerationChangedPredicate filters out status-only patch events: status
// writes do not bump metadata.generation, so they no longer re-trigger a
// reconcile. This stops the status-patch → re-trigger → markGrantsProvisioning
// churn that prevented the phase from ever settling on Ready (gibson#1140).
// Spec changes (generation bump), creates, and deletes still reconcile
// immediately; the 10-minute RequeueAfter handles drift-correction resyncs.
func (r *TenantGrantsReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenantgrants-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.TenantGrants{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("tenantgrants").
		Complete(r)
}
