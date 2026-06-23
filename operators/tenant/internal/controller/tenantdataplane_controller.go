/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"errors"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
)

// dataPlaneResyncInterval re-reconciles a Ready TenantDataPlane periodically
// so drift in the underlying stores (a deleted Neo4j StatefulSet, a dropped
// Postgres role) is corrected without waiting for an external event. The
// dataplane.Provisioner is idempotent, so a periodic re-run is cheap when
// everything is already in place.
const dataPlaneResyncInterval = 10 * time.Minute

// TenantDataPlaneReconciler reconciles a TenantDataPlane object. It is the
// declarative replacement for the imperative DataPlaneProvisioned saga step:
// it composes the per-tenant CNPG Postgres, Neo4j, and Redis (plus vector
// index and KEK init) stores by delegating to the shared dataplane.Provisioner
// pipeline. The same pipeline backs the Tenant saga today, so there is exactly
// one provisioning codepath (ADR-0027); this controller is a second, declarative
// caller of it, not a parallel reimplementation.
type TenantDataPlaneReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Provisioner is the shared data-plane pipeline. Always non-nil in
	// production (buildDataPlaneProvisioner in cmd/main.go always returns
	// dataplane.New(cfg)); a nil here fails loud so a misconfigured operator
	// crash-loops rather than silently no-op'ing provisioning.
	Provisioner dataplane.Provisioner
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantdataplanes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantdataplanes/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantdataplanes/finalizers,verbs=update

// Reconcile drives a TenantDataPlane toward its desired state. The flow:
//
//	delete path  → run the finalizer teardown (Deprovision), then drop the
//	               finalizer once the stores are gone.
//	provision    → ensure finalizer, call Provisioner.Provision (idempotent +
//	               drift-correcting), then write per-store + aggregate status.
//
// Status is the ONLY persisted output of this controller. Following the known
// saga hazard (steps re-run every reconcile and only Status().Patch sticks),
// the controller never mutates spec; it writes desired observed state to the
// status subresource and lets the owned stores carry the rest.
func (r *TenantDataPlaneReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantdataplane", req.NamespacedName)

	var tdp gibsonv1alpha1.TenantDataPlane
	if err := r.Get(ctx, req.NamespacedName, &tdp); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.Provisioner == nil {
		// Fail loud: a nil provisioner means operator wiring passed nil
		// explicitly. Record the error in status and requeue with backoff.
		log.Error(clients.ErrInvalidInput, "data-plane provisioner unset (operator misconfigured)")
		return r.fail(ctx, &tdp, "data-plane provisioner unset (operator misconfigured)")
	}

	// Deletion path: run teardown, then drop the finalizer.
	if !tdp.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &tdp)
	}

	// Ensure finalizer so teardown runs before the CR is GC'd.
	if !controllerutil.ContainsFinalizer(&tdp, gibsonv1alpha1.TenantDataPlaneFinalizer) {
		controllerutil.AddFinalizer(&tdp, gibsonv1alpha1.TenantDataPlaneFinalizer)
		if err := r.Update(ctx, &tdp); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("added finalizer")
		return ctrl.Result{Requeue: true}, nil
	}

	// Provision (idempotent + drift-correcting). Mark Provisioning before the
	// call so observers see progress; the pipeline itself also patches the
	// Tenant status for backward compatibility.
	r.markProvisioning(ctx, &tdp)

	if err := r.Provisioner.Provision(ctx, tdp.Spec.TenantID); err != nil {
		log.Error(err, "data-plane provision failed", "tenant", tdp.Spec.TenantID)
		r.emit(&tdp, "Warning", "ProvisionFailed", err.Error())
		if _, ferr := r.fail(ctx, &tdp, err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		// Return the provision error so controller-runtime backs off.
		return ctrl.Result{}, err
	}

	r.markReady(ctx, &tdp)
	r.emit(&tdp, "Normal", "Provisioned", "all requested data-plane stores are ready")
	log.V(1).Info("data-plane ready", "tenant", tdp.Spec.TenantID)

	return ctrl.Result{RequeueAfter: dataPlaneResyncInterval}, nil
}

// reconcileDelete tears down the per-tenant stores via the idempotent
// Deprovision path, then removes the finalizer. Deprovision is best-effort:
// a NotFound is treated as success (already gone), and any other error keeps
// the finalizer so the controller retries with backoff.
func (r *TenantDataPlaneReconciler) reconcileDelete(ctx context.Context, tdp *gibsonv1alpha1.TenantDataPlane) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantdataplane", tdp.Name, "phase", "delete")

	if !controllerutil.ContainsFinalizer(tdp, gibsonv1alpha1.TenantDataPlaneFinalizer) {
		return ctrl.Result{}, nil
	}

	base := tdp.DeepCopy()
	tdp.Status.Phase = gibsonv1alpha1.TenantDataPlanePhaseDeprovisioning
	tdp.Status.Ready = false
	r.patchStatus(ctx, tdp, base)

	if r.Provisioner != nil {
		if err := r.Provisioner.Deprovision(ctx, tdp.Spec.TenantID); err != nil && !errors.Is(err, clients.ErrNotFound) {
			log.Error(err, "data-plane deprovision failed; keeping finalizer for retry", "tenant", tdp.Spec.TenantID)
			r.emit(tdp, "Warning", "DeprovisionFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	patch := client.MergeFrom(tdp.DeepCopy())
	if controllerutil.RemoveFinalizer(tdp, gibsonv1alpha1.TenantDataPlaneFinalizer) {
		if err := r.Patch(ctx, tdp, patch); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("finalizer removed; data plane deprovisioned", "tenant", tdp.Spec.TenantID)
	}
	return ctrl.Result{}, nil
}

// markProvisioning records the in-flight phase via Status().Patch.
func (r *TenantDataPlaneReconciler) markProvisioning(ctx context.Context, tdp *gibsonv1alpha1.TenantDataPlane) {
	base := tdp.DeepCopy()
	tdp.Status.Phase = gibsonv1alpha1.TenantDataPlanePhaseProvisioning
	tdp.Status.LastError = ""
	r.patchStatus(ctx, tdp, base)
}

// markReady records the ready state: aggregate Ready true, every requested
// store ready, and the Ready condition flipped True.
func (r *TenantDataPlaneReconciler) markReady(ctx context.Context, tdp *gibsonv1alpha1.TenantDataPlane) {
	base := tdp.DeepCopy()
	tdp.Status.Phase = gibsonv1alpha1.TenantDataPlanePhaseReady
	tdp.Status.Ready = true
	tdp.Status.LastError = ""
	tdp.Status.ObservedGeneration = tdp.Generation
	tdp.Status.Stores = readyStores(tdp.Spec.Stores)
	setReadyCondition(tdp, metav1.ConditionTrue, "Provisioned", "all requested data-plane stores are ready")
	r.patchStatus(ctx, tdp, base)
}

// fail records a failed reconcile in status without mutating spec.
func (r *TenantDataPlaneReconciler) fail(ctx context.Context, tdp *gibsonv1alpha1.TenantDataPlane, msg string) (ctrl.Result, error) {
	base := tdp.DeepCopy()
	tdp.Status.Phase = gibsonv1alpha1.TenantDataPlanePhaseFailed
	tdp.Status.Ready = false
	tdp.Status.LastError = msg
	setReadyCondition(tdp, metav1.ConditionFalse, "ProvisionFailed", msg)
	r.patchStatus(ctx, tdp, base)
	return ctrl.Result{}, nil
}

// patchStatus persists status via a merge-patch off the captured base. Using
// Patch (not Update) avoids resourceVersion conflicts with the dataplane
// pipeline, which also patches Tenant status concurrently. Errors are logged,
// not propagated — a lost status write must not strand the reconcile.
func (r *TenantDataPlaneReconciler) patchStatus(ctx context.Context, tdp, base *gibsonv1alpha1.TenantDataPlane) {
	if err := r.Status().Patch(ctx, tdp, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "tenantdataplane status patch failed", "tenant", tdp.Spec.TenantID)
	}
}

// emit records a Kubernetes event on the TenantDataPlane. No-ops when the
// recorder is nil (tests).
func (r *TenantDataPlaneReconciler) emit(tdp *gibsonv1alpha1.TenantDataPlane, eventType, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(tdp, nil, eventType, reason, reason, "%s", msg)
}

// readyStores returns the per-store ready conditions for the requested set.
// A store is included only when its toggle is true (matching the pipeline,
// which skips a store whose sub-provisioner is unset). KEK init always
// participates because the pipeline always runs it.
func readyStores(sel gibsonv1alpha1.TenantDataPlaneStores) []gibsonv1alpha1.TenantDataPlaneStoreCondition {
	now := metav1.Now()
	ready := func(name string) gibsonv1alpha1.TenantDataPlaneStoreCondition {
		return gibsonv1alpha1.TenantDataPlaneStoreCondition{Name: name, State: "ready", LastUpdated: now}
	}
	var out []gibsonv1alpha1.TenantDataPlaneStoreCondition
	if sel.Postgres {
		out = append(out, ready("postgres"))
	}
	if sel.Neo4j {
		out = append(out, ready("neo4j"))
	}
	if sel.Redis {
		out = append(out, ready("redis"))
	}
	if sel.Vector {
		out = append(out, ready("vector"))
	}
	out = append(out, ready("kek"))
	return out
}

// setReadyCondition upserts the aggregate Ready condition.
func setReadyCondition(tdp *gibsonv1alpha1.TenantDataPlane, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               gibsonv1alpha1.ConditionDataPlaneReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: tdp.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range tdp.Status.Conditions {
		if tdp.Status.Conditions[i].Type == cond.Type {
			// Preserve LastTransitionTime when status is unchanged.
			if tdp.Status.Conditions[i].Status == status {
				cond.LastTransitionTime = tdp.Status.Conditions[i].LastTransitionTime
			}
			tdp.Status.Conditions[i] = cond
			return
		}
	}
	tdp.Status.Conditions = append(tdp.Status.Conditions, cond)
}

// SetupWithManager registers the controller with the manager.
func (r *TenantDataPlaneReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenantdataplane-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.TenantDataPlane{}).
		Named("tenantdataplane").
		Complete(r)
}
