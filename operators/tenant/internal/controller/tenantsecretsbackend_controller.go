// Copyright 2026 Zero Day AI, Inc.
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
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/secrets"
)

// secretsBackendResyncInterval re-reconciles a Ready TenantSecretsBackend
// periodically so drift in the underlying backend (a deleted Vault namespace, a
// dropped broker-config row) is corrected without waiting for an external
// event. The secrets.Provisioner is idempotent, so a periodic re-run is cheap
// when everything is already in place.
const secretsBackendResyncInterval = 10 * time.Minute

// TenantSecretsBackendReconciler reconciles a TenantSecretsBackend object. It
// is the declarative replacement for the imperative ProvisionSecretsBackend /
// ConfigureSecretsJWTAuth / TenantBrokerConfigWritten saga steps: it composes
// the per-tenant Vault namespace + JWT-auth role, the auth/jwt/config document,
// and the platform broker-config row by delegating to the shared
// secrets.Provisioner. That provisioner wraps the SAME vault.AdminClient +
// broker-config writer the Tenant saga uses today, so there is exactly one
// provisioning codepath (ADR-0027); this controller is a second, declarative
// caller of it, not a parallel reimplementation.
type TenantSecretsBackendReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Provisioner is the shared secrets-backend pipeline. Always non-nil in
	// production (buildSecretsProvisioner in cmd/main.go always returns
	// secrets.New(...)); a nil here fails loud so a misconfigured operator
	// crash-loops rather than silently no-op'ing provisioning.
	Provisioner secrets.Provisioner
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantsecretsbackends,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantsecretsbackends/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenantsecretsbackends/finalizers,verbs=update

// Reconcile drives a TenantSecretsBackend toward its desired state. The flow:
//
//	delete path  → run the finalizer teardown (Deprovision), then drop the
//	               finalizer once the backend is gone.
//	provision    → ensure finalizer, call Provisioner.Provision (idempotent +
//	               drift-correcting), then write per-component + aggregate status.
//
// Status is the ONLY persisted output of this controller. Following the known
// saga hazard (steps re-run every reconcile and only Status().Patch sticks),
// the controller never mutates spec; it writes desired observed state to the
// status subresource.
func (r *TenantSecretsBackendReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantsecretsbackend", req.NamespacedName)

	var tsb gibsonv1alpha1.TenantSecretsBackend
	if err := r.Get(ctx, req.NamespacedName, &tsb); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if r.Provisioner == nil {
		// Fail loud: a nil provisioner means operator wiring passed nil
		// explicitly. Record the error in status and requeue with backoff.
		log.Error(clients.ErrInvalidInput, "secrets provisioner unset (operator misconfigured)")
		return r.fail(ctx, &tsb, "secrets provisioner unset (operator misconfigured)")
	}

	// Deletion path: run teardown, then drop the finalizer.
	if !tsb.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &tsb)
	}

	// Ensure finalizer so teardown runs before the CR is GC'd.
	if !controllerutil.ContainsFinalizer(&tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer) {
		controllerutil.AddFinalizer(&tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer)
		if err := r.Update(ctx, &tsb); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("added finalizer")
		return ctrl.Result{Requeue: true}, nil
	}

	// Provision (idempotent + drift-correcting). Mark Provisioning before the
	// call so observers see progress.
	r.markProvisioning(ctx, &tsb)

	if err := r.Provisioner.Provision(ctx, tsb.Spec.TenantID); err != nil {
		log.Error(err, "secrets-backend provision failed", "tenant", tsb.Spec.TenantID)
		r.emit(&tsb, "Warning", "ProvisionFailed", err.Error())
		if _, ferr := r.fail(ctx, &tsb, err.Error()); ferr != nil {
			return ctrl.Result{}, ferr
		}
		// Return the provision error so controller-runtime backs off.
		return ctrl.Result{}, err
	}

	r.markReady(ctx, &tsb)
	r.emit(&tsb, "Normal", "Provisioned", "secrets backend is ready")
	log.V(1).Info("secrets backend ready", "tenant", tsb.Spec.TenantID)

	return ctrl.Result{RequeueAfter: secretsBackendResyncInterval}, nil
}

// reconcileDelete tears down the per-tenant secrets backend via the idempotent
// Deprovision path, then removes the finalizer. Deprovision is best-effort: a
// NotFound is treated as success (already gone) by the provisioner itself, and
// any other error keeps the finalizer so the controller retries with backoff.
func (r *TenantSecretsBackendReconciler) reconcileDelete(ctx context.Context, tsb *gibsonv1alpha1.TenantSecretsBackend) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenantsecretsbackend", tsb.Name, "phase", "delete")

	if !controllerutil.ContainsFinalizer(tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer) {
		return ctrl.Result{}, nil
	}

	base := tsb.DeepCopy()
	tsb.Status.Phase = gibsonv1alpha1.TenantSecretsBackendPhaseDeprovisioning
	tsb.Status.Ready = false
	r.patchStatus(ctx, tsb, base)

	if r.Provisioner != nil {
		if err := r.Provisioner.Deprovision(ctx, tsb.Spec.TenantID); err != nil && !errors.Is(err, clients.ErrNotFound) {
			log.Error(err, "secrets-backend deprovision failed; keeping finalizer for retry", "tenant", tsb.Spec.TenantID)
			r.emit(tsb, "Warning", "DeprovisionFailed", err.Error())
			return ctrl.Result{}, err
		}
	}

	patch := client.MergeFrom(tsb.DeepCopy())
	if controllerutil.RemoveFinalizer(tsb, gibsonv1alpha1.TenantSecretsBackendFinalizer) {
		if err := r.Patch(ctx, tsb, patch); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("finalizer removed; secrets backend deprovisioned", "tenant", tsb.Spec.TenantID)
	}
	return ctrl.Result{}, nil
}

// markProvisioning records the in-flight phase via Status().Patch.
func (r *TenantSecretsBackendReconciler) markProvisioning(ctx context.Context, tsb *gibsonv1alpha1.TenantSecretsBackend) {
	base := tsb.DeepCopy()
	tsb.Status.Phase = gibsonv1alpha1.TenantSecretsBackendPhaseProvisioning
	tsb.Status.LastError = ""
	r.patchStatus(ctx, tsb, base)
}

// markReady records the ready state: aggregate Ready true, every component
// ready, and the Ready condition flipped True.
func (r *TenantSecretsBackendReconciler) markReady(ctx context.Context, tsb *gibsonv1alpha1.TenantSecretsBackend) {
	base := tsb.DeepCopy()
	tsb.Status.Phase = gibsonv1alpha1.TenantSecretsBackendPhaseReady
	tsb.Status.Ready = true
	tsb.Status.LastError = ""
	tsb.Status.ObservedGeneration = tsb.Generation
	tsb.Status.Components = readyComponents()
	setSecretsBackendReadyCondition(tsb, metav1.ConditionTrue, "Provisioned", "secrets backend is ready")
	r.patchStatus(ctx, tsb, base)
}

// fail records a failed reconcile in status without mutating spec.
func (r *TenantSecretsBackendReconciler) fail(ctx context.Context, tsb *gibsonv1alpha1.TenantSecretsBackend, msg string) (ctrl.Result, error) {
	base := tsb.DeepCopy()
	tsb.Status.Phase = gibsonv1alpha1.TenantSecretsBackendPhaseFailed
	tsb.Status.Ready = false
	tsb.Status.LastError = msg
	setSecretsBackendReadyCondition(tsb, metav1.ConditionFalse, "ProvisionFailed", msg)
	r.patchStatus(ctx, tsb, base)
	return ctrl.Result{}, nil
}

// patchStatus persists status via a merge-patch off the captured base. Using
// Patch (not Update) avoids resourceVersion conflicts with the Tenant saga,
// which patches Tenant status concurrently. Errors are logged, not propagated —
// a lost status write must not strand the reconcile.
func (r *TenantSecretsBackendReconciler) patchStatus(ctx context.Context, tsb, base *gibsonv1alpha1.TenantSecretsBackend) {
	if err := r.Status().Patch(ctx, tsb, client.MergeFrom(base)); err != nil {
		logf.FromContext(ctx).Error(err, "tenantsecretsbackend status patch failed", "tenant", tsb.Spec.TenantID)
	}
}

// emit records a Kubernetes event on the TenantSecretsBackend. No-ops when the
// recorder is nil (tests).
func (r *TenantSecretsBackendReconciler) emit(tsb *gibsonv1alpha1.TenantSecretsBackend, eventType, reason, msg string) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(tsb, nil, eventType, reason, reason, "%s", msg)
}

// readyComponents returns the per-component ready conditions. The three
// components mirror the saga's three secrets-backend steps: the Vault namespace
// (+ JWT-auth role + KV mount), the auth/jwt/config document, and the platform
// broker-config row. All three always participate (the pipeline always runs
// them), so there is no per-component toggle.
func readyComponents() []gibsonv1alpha1.TenantSecretsBackendComponentCondition {
	now := metav1.Now()
	ready := func(name string) gibsonv1alpha1.TenantSecretsBackendComponentCondition {
		return gibsonv1alpha1.TenantSecretsBackendComponentCondition{Name: name, State: "ready", LastUpdated: now}
	}
	return []gibsonv1alpha1.TenantSecretsBackendComponentCondition{
		ready("vault-namespace"),
		ready("jwt-auth"),
		ready("broker-config"),
	}
}

// setSecretsBackendReadyCondition upserts the aggregate Ready condition.
func setSecretsBackendReadyCondition(tsb *gibsonv1alpha1.TenantSecretsBackend, status metav1.ConditionStatus, reason, msg string) {
	cond := metav1.Condition{
		Type:               gibsonv1alpha1.ConditionSecretsBackendCRReady,
		Status:             status,
		Reason:             reason,
		Message:            msg,
		ObservedGeneration: tsb.Generation,
		LastTransitionTime: metav1.Now(),
	}
	for i := range tsb.Status.Conditions {
		if tsb.Status.Conditions[i].Type == cond.Type {
			// Preserve LastTransitionTime when status is unchanged.
			if tsb.Status.Conditions[i].Status == status {
				cond.LastTransitionTime = tsb.Status.Conditions[i].LastTransitionTime
			}
			tsb.Status.Conditions[i] = cond
			return
		}
	}
	tsb.Status.Conditions = append(tsb.Status.Conditions, cond)
}

// SetupWithManager registers the controller with the manager.
func (r *TenantSecretsBackendReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenantsecretsbackend-controller")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.TenantSecretsBackend{}).
		Named("tenantsecretsbackend").
		Complete(r)
}
