/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"time"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// ctxKeyCorrelationID is the typed context key for storing the correlation ID
// threaded from the dashboard annotation through to runner log fields and audit.
type ctxKeyCorrelationID struct{}

// childRequeueInterval is how soon the Tenant reconciler comes back to advance
// dependency-ordered child creation/teardown (E8/gibson#805) when no watch event
// would otherwise wake it. The sub-CRD controllers reconcile independently; this
// short requeue lets the Tenant observe each child flipping Ready (or gone)
// without waiting for the long resync window.
const childRequeueInterval = 5 * time.Second

// TenantReconciler reconciles a Tenant object. Owns the full lifecycle
// saga: provisioning steps on create/update, finalizer-driven teardown on
// delete. Specific saga steps beyond namespace are contributed by other
// specs (tenant-lifecycle-flows for Zitadel/Stripe/FGA).
type TenantReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder events.EventRecorder

	// Runner executes provisioning and teardown sagas.
	Runner *saga.Runner

	// Audit emitter for structured lifecycle events.
	Audit audit.Emitter

	// Provisioning steps. Foundation contributes Namespace. Other specs
	// append additional steps via ProvisionSteps.
	ProvisionSteps []saga.Step

	// Teardown steps. Foundation contributes (reverse) Namespace removal.
	// Other specs append additional teardown steps.
	TeardownSteps []saga.Step

	// NamespaceProvisioner produces the namespace step.
	NamespaceProvisioner *NamespaceProvisioner

	// PlatformNamespace is where the operator itself runs.
	PlatformNamespace string

	// Deps is the unified saga.Deps bag forwarded to the runner so steps
	// that consult it (and ValidateAtStartup) see the same wiring. May
	// be nil in tests.
	Deps *saga.Deps

	// MigrationEmitter publishes gibson_tenant_migration_pending after
	// every successful Ready reconcile. Replaces the daemon's deleted
	// startup migration check (ADR-0023, gibson#208 S6). May be nil in
	// tests — emission is a no-op when unset.
	MigrationEmitter *dataplane.MigrationMetricEmitter
}

// kubebuilder:rbac markers — Spec secrets-blast-radius-reduction
// =================================================================
// Cluster-scope rules. Per-namespace resources (secrets, configmaps,
// services, persistentvolumeclaims, resourcequotas, statefulsets,
// networkpolicies, roles, rolebindings, leases) are NOT cluster-scope.
// They are granted via:
//   - templates/tenant-operator/release-namespace-rbac.yaml — Role +
//     RoleBinding in the chart's release namespace for the operator's
//     own bootstrap traffic (chart-rendered Secrets, controller-runtime
//     Lease, spire-jwks-exporter RBAC, etc.).
//   - At runtime, the operator's NamespaceProvisioner.ensureTenantNamespace
//     RBAC writes a per-tenant Role + RoleBinding inside the tenant's
//     namespace. OwnerRef = the tenant Namespace, so cleanup is
//     automatic on tenant delete. Kubebuilder markers cannot represent
//     dynamic per-tenant scope; that's a runtime concern.
// A CI guard (scripts/check-operator-rbac-scope.sh) fails the build if
// any of those resources reappear in this ClusterRole.
// =================================================================
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch

// Reconcile is the main reconcile loop.
func (r *TenantReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenant", req.Name)

	var tenant gibsonv1alpha1.Tenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// --- Correlation-ID propagation (Task 20.1) ---
	// Read the ID stamped by the dashboard on applyTenant. When absent (e.g.
	// CRs created directly via kubectl), generate a fresh UUID and warn so
	// operators know the ID was not dashboard-originated.
	corrID := ""
	if annotations := tenant.GetAnnotations(); annotations != nil {
		corrID = annotations[saga.AnnotationCorrelationID]
	}
	if corrID == "" {
		corrID = uuid.New().String()
		log.Info("missing correlation-id annotation, generated fresh one",
			"correlationId", corrID)
	}
	ctx = context.WithValue(ctx, ctxKeyCorrelationID{}, corrID)
	// Also store in the saga package's typed key so runner's correlationIDFromCtx
	// can read it even when called without the controller wrapper (e.g. tests).
	ctx = saga.CtxWithCorrelationID(ctx, corrID)
	log = log.WithValues("correlationId", corrID)

	// --- Deletion-flow short-circuit (#157) ---
	// When DeletionTimestamp is set, ALWAYS take the teardown path. We must
	// never enter the provision saga on a deleting tenant — a doomed
	// provision pass (e.g. Redis allocator exhausted, Neo4j aborting because
	// "tenant is being deleted") leaves a Blocked condition that would
	// strand the reconciler before it reaches finalizer removal. See
	// reconcileDelete for the saga-blocked recovery contract.
	if !tenant.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &tenant)
	}

	// Ensure finalizer.
	if !controllerutil.ContainsFinalizer(&tenant, gibsonv1alpha1.TenantFinalizer) {
		controllerutil.AddFinalizer(&tenant, gibsonv1alpha1.TenantFinalizer)
		if err := r.Update(ctx, &tenant); err != nil {
			return ctrl.Result{}, err
		}
		log.Info("added finalizer")
		return ctrl.Result{Requeue: true}, nil
	}

	// Capture status base from the SERVER state BEFORE any in-memory mutation,
	// so the closing merge-patch carries every status field this reconcile
	// changes — including a phase that the child-readiness gate resets back to
	// Provisioning (which would otherwise diff to nothing against a base that
	// already held Provisioning). Using Patch instead of Update avoids
	// conflicts on resourceVersion, which the dataplane pipeline bumps via its
	// own Status().Patch during the DataPlaneProvisioned step.
	statusBase := tenant.DeepCopy()

	// Normal provisioning.
	if tenant.Status.Phase == "" {
		tenant.Status.Phase = gibsonv1alpha1.TenantPhasePending
	}
	if tenant.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		tenant.Status.Phase = gibsonv1alpha1.TenantPhaseProvisioning
	}

	steps := r.provisioningSteps()
	// The retained saga now owns only the foundation steps that are NOT
	// modelled as owned sub-CRDs: the per-tenant namespace, the Redis
	// keyspace + tenant-name publish. The identity / secrets-backend / grants
	// / data-plane domains are owned by the four sub-CRDs the Tenant creates
	// in dependency order (E8/gibson#805). Running the saga to its terminal
	// phase here is fine: the runner stamps a Ready phase when its (now
	// shorter) step set completes, but the TENANT's Ready gate below is the
	// AND of (saga complete) AND (all four children Ready).
	result, err := r.Runner.Run(ctx, &tenant, steps, string(gibsonv1alpha1.TenantPhaseReady))

	// Dependency-ordered child orchestration (E8/gibson#805). Each child is
	// created with an ownerReference to this Tenant, in dependency order, only
	// once its predecessor reports Ready. The Tenant is Ready only when the
	// retained saga is done AND every child reports Status.Ready.
	childrenReady := false
	if err == nil {
		var childErr error
		childrenReady, childErr = r.reconcileChildren(ctx, &tenant)
		if childErr != nil {
			log.Error(childErr, "child orchestration failed")
			err = childErr
		}
	}

	// Compute the Tenant's effective phase: Ready only when the saga reached
	// its terminal phase AND all four children are Ready. Otherwise keep it in
	// Provisioning so the daemon/dashboard do not treat a half-provisioned
	// tenant as usable.
	if err == nil {
		if tenant.Status.Phase == gibsonv1alpha1.TenantPhaseReady && !childrenReady {
			tenant.Status.Phase = gibsonv1alpha1.TenantPhaseProvisioning
		}
	}

	// Always persist status, even on partial progress.
	if updateErr := r.Status().Patch(ctx, &tenant, client.MergeFrom(statusBase)); updateErr != nil {
		log.Error(updateErr, "status patch failed")
		if err == nil {
			return result, updateErr
		}
	}

	// Requeue until the children converge so the Tenant flips to Ready without
	// waiting for an unrelated watch event.
	if err == nil && !childrenReady && result.RequeueAfter == 0 && !result.Requeue {
		return ctrl.Result{RequeueAfter: childRequeueInterval}, nil
	}

	// Emit gibson_tenant_migration_pending after a successful Ready
	// reconcile. Replaces the daemon's deleted startup migration check
	// (ADR-0023, gibson#208 S6). Emission is best-effort: a probe
	// failure logs WARN and never propagates to the saga.
	if err == nil && tenant.Status.Phase == gibsonv1alpha1.TenantPhaseReady && r.MigrationEmitter != nil {
		if emitErr := r.MigrationEmitter.Emit(ctx, tenant.Name); emitErr != nil {
			log.Info("migration-pending probe failed (metric not updated)", "err", emitErr)
		}
	}

	return result, err
}

// reconcileDelete handles teardown of a Tenant with DeletionTimestamp set.
//
// Contract (issue #157):
//   - In-progress requeue: keep the finalizer; come back when the
//     cascade finishes.
//   - Transient error: keep the finalizer; come back with backoff.
//   - Saga blocked: REMOVE the finalizer anyway so the CR is GC'd.
//     Stranding the CR forever (the old behavior) means every deleted
//     tenant leaks namespaces, PVCs, Vault namespaces, etc., and the
//     only recovery is the destructive `kubectl patch -p
//     '[{"op":"remove","path":"/metadata/finalizers"}]'` which
//     bypasses EVERY teardown step. Removing the finalizer on blocked
//     leaves at most a single straggler resource (surfaced via the
//     per-step audit event and the orphan reaper).
//   - All teardown complete: remove the finalizer normally.
func (r *TenantReconciler) reconcileDelete(ctx context.Context, tenant *gibsonv1alpha1.Tenant) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenant", tenant.Name, "phase", "delete")

	tenant.Status.Phase = gibsonv1alpha1.TenantPhaseTerminating

	// Dependency-ordered child teardown (E8/gibson#805). Delete the owned
	// sub-CRDs in REVERSE dependency order, waiting for each child's own
	// finalizer to complete before deleting the next. This runs BEFORE the
	// retained teardown saga (which deletes the per-tenant namespace), so the
	// children are never force-removed out of order by a namespace cascade.
	//
	// A child cascade in progress requeues the Tenant (finalizer retained)
	// without ever entering the saga teardown — the namespace must outlive the
	// namespaced children.
	childrenGone, childErr := r.deleteChildrenInReverse(ctx, tenant)
	if childErr != nil {
		log.Error(childErr, "child teardown failed; keeping finalizer for retry")
		// Persist the Terminating phase before returning the error.
		base := tenant.DeepCopy()
		base.Status.Phase = gibsonv1alpha1.TenantPhaseProvisioning
		if perr := r.Status().Patch(ctx, tenant, client.MergeFrom(base)); perr != nil {
			log.Error(perr, "status patch failed during child teardown")
		}
		return ctrl.Result{}, childErr
	}
	if !childrenGone {
		// Child cascade still running. Requeue and keep the finalizer; do not
		// proceed to the namespace-deleting teardown saga yet.
		log.Info("child teardown in progress; waiting before namespace teardown")
		return ctrl.Result{RequeueAfter: childRequeueInterval}, nil
	}

	steps := r.teardownSteps()
	statusBase := tenant.DeepCopy()
	outcome := r.Runner.RunForDeletion(ctx, tenant, steps, string(gibsonv1alpha1.TenantPhaseTerminated))
	// Use Patch instead of Update so we don't conflict on resourceVersion
	// when the dataplane pipeline has bumped it via its own Status().Patch.
	if updateErr := r.Status().Patch(ctx, tenant, client.MergeFrom(statusBase)); updateErr != nil {
		log.Error(updateErr, "status patch failed during teardown")
		// Continue regardless — losing a status write must not strand
		// the finalizer (#157). The next reconcile will retry the status
		// write if the CR still exists.
	}

	// In-progress requeue: a teardown step returned done=false. The
	// finalizer stays so the controller comes back when the cascade
	// finishes (e.g. namespace finalizing, StatefulSet draining).
	if outcome.Result.RequeueAfter > 0 {
		return outcome.Result, nil
	}

	// Transient error: requeue with backoff. Keep the finalizer until
	// the transient cause clears or the step budget is exhausted (which
	// surfaces as outcome.Blocked below).
	if outcome.Err != nil && !outcome.Blocked {
		return outcome.Result, outcome.Err
	}

	// AllComplete OR Blocked → remove the finalizer.
	//
	// Why remove on Blocked: keeping the finalizer means the CR sits in
	// Terminating forever, the per-tenant namespace stays Active, and
	// the only recovery is `kubectl patch ... --type json -p
	// '[{"op":"remove",...}]'` which bypasses every other teardown step.
	// That's the bug described in #157. Instead we accept that a single
	// teardown step may leave a straggler (Vault namespace, Stripe
	// subscription, etc.); the orphan reaper and the per-step audit
	// events surface the leak so an operator can clean it up out of
	// band. The CR itself is no longer wedged.
	if outcome.Blocked {
		log.Info("teardown saga blocked; removing finalizer anyway to avoid stranding the CR (#157)",
			"err", outcome.Err)
	}

	// Remove finalizer via Patch so we do not hit a stale-object
	// conflict on the resourceVersion bumped by the Status().Patch above.
	patch := client.MergeFrom(tenant.DeepCopy())
	if controllerutil.RemoveFinalizer(tenant, gibsonv1alpha1.TenantFinalizer) {
		if err := r.Patch(ctx, tenant, patch); err != nil {
			if apierrors.IsConflict(err) {
				return ctrl.Result{Requeue: true}, nil
			}
			return ctrl.Result{}, err
		}
		log.Info("finalizer removed; tenant terminated")
	}
	return ctrl.Result{}, nil
}

// provisioningSteps assembles the ordered saga steps for provisioning.
// Foundation contributes Namespace; additional specs append here via
// ProvisionSteps injection.
func (r *TenantReconciler) provisioningSteps() []saga.Step {
	steps := []saga.Step{}
	if r.NamespaceProvisioner != nil {
		steps = append(steps, r.NamespaceProvisioner.Step())
	}
	steps = append(steps, r.ProvisionSteps...)
	return steps
}

// teardownSteps assembles teardown phases. Foundation contributes the
// namespace delete at the end; other specs prepend phases 1-3.
func (r *TenantReconciler) teardownSteps() []saga.Step {
	steps := make([]saga.Step, 0, len(r.TeardownSteps)+1)
	steps = append(steps, r.TeardownSteps...)
	steps = append(steps, &deleteNamespaceStep{
		StepBase: saga.StepBase{
			N:    "DeleteNamespace",
			C:    "NamespaceDeleted",
			Caps: []saga.ClientCapability{saga.CapabilityKubernetes},
		},
		client: r.Client,
	})
	return steps
}

// deleteNamespaceStep is the foundation teardown step: deletes the
// per-tenant K8s namespace and waits for NotFound (idempotent).
type deleteNamespaceStep struct {
	saga.StepBase
	client client.Client
}

func (s *deleteNamespaceStep) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, ok := obj.(*gibsonv1alpha1.Tenant)
	if !ok {
		return false, nil
	}
	if t.Status.Namespace == "" {
		return true, nil
	}
	return deleteNamespace(ctx, s.client, t.Status.Namespace)
}

// SetupWithManager sets up the controller with the Manager.
func (r *TenantReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Runner == nil {
		r.Runner = saga.NewRunner(r.Client, mgr.GetEventRecorder("tenant-operator"), mgr.GetLogger())
	}
	if r.Runner.Deps == nil {
		r.Runner.Deps = r.Deps
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenant-operator")
	}
	if r.NamespaceProvisioner == nil {
		r.NamespaceProvisioner = NewNamespaceProvisioner(r.Client, r.PlatformNamespace, nil)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.Tenant{}).
		Named("tenant").
		Complete(r)
}
