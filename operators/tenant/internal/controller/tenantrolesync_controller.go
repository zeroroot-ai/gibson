// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"time"

	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// DefaultTenantRoleSyncInterval is TENANT_ROLE_SYNC_INTERVAL's default (owner
// decision D6): the drift timer repairs a tenant's role tuples at most this
// often.
const DefaultTenantRoleSyncInterval = 60 * time.Second

// tenantRoleUnmappedRequeue is how soon a Tenant with no Zitadel org yet is
// requeued. Short, because the org usually appears within a few reconciles
// of the TenantIdentity controller.
const tenantRoleUnmappedRequeue = 30 * time.Second

// TenantRoleSyncReconciler runs tenantrole.Syncer.Sync for every Tenant on a
// timer (ADR-0093 decision 3). It is the drift-repair half of the one sync:
// the daemon runs Sync inline after each role write; this reconciler catches
// everything else — a tuple removed by hand, a grant that changed while the
// daemon was down, a tenant whose Owner grant never synced.
type TenantRoleSyncReconciler struct {
	client.Client
	Recorder events.EventRecorder
	Syncer   *tenantrole.Syncer
	Interval time.Duration // defaults to DefaultTenantRoleSyncInterval
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=tenants,verbs=get;list;watch

// Reconcile syncs one Tenant's role tuples and always requeues at r.Interval,
// so this is a timer, not an edge-triggered controller. It never writes
// Tenant status — the Tenant reconciler owns that, and a second writer would
// race it.
func (r *TenantRoleSyncReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx).WithValues("tenant", req.Name)
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultTenantRoleSyncInterval
	}

	var tenant gibsonv1alpha1.Tenant
	if err := r.Get(ctx, req.NamespacedName, &tenant); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err) //nolint:wrapcheck // every reconciler in this package returns IgnoreNotFound bare; controller-runtime retries on the sentinel form
	}

	if !tenant.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}

	if tenant.Status.ZitadelOrgID == "" {
		log.V(1).Info("tenant has no zitadel org yet; requeueing")
		return ctrl.Result{RequeueAfter: tenantRoleUnmappedRequeue}, nil
	}

	if r.Syncer == nil {
		log.Error(nil, "tenant role syncer unset (operator misconfigured)")
		return ctrl.Result{RequeueAfter: interval}, nil
	}

	syncCtx := tenantrole.WithCaller(ctx, "tenant-operator")
	res, err := r.Syncer.Sync(syncCtx, tenantrole.Tenant{ID: tenant.Name, OrgID: tenant.Status.ZitadelOrgID})
	if err != nil {
		if errors.Is(err, tenantrole.ErrOwnerConflict) {
			log.Info("tenant role sync: owner conflict, reporting only", "tenant", tenant.Name)
			r.emit(&tenant, "Warning", "TenantRoleOwnerConflict",
				"a tenant role sync would leave the tenant without exactly one Owner; no change was made")
			return ctrl.Result{RequeueAfter: interval}, nil
		}
		log.Error(err, "tenant role sync failed", "tenant", tenant.Name)
		return ctrl.Result{RequeueAfter: interval}, nil
	}

	if len(res.Written) > 0 || len(res.Deleted) > 0 {
		log.Info("tenant roles repaired", "tenant", tenant.Name, "written", len(res.Written), "deleted", len(res.Deleted))
		r.emit(&tenant, "Normal", "TenantRolesRepaired",
			"wrote %d and deleted %d tenant role tuple(s)", len(res.Written), len(res.Deleted))
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

func (r *TenantRoleSyncReconciler) emit(tenant *gibsonv1alpha1.Tenant, eventType, reason, msgFmt string, args ...any) {
	if r.Recorder == nil {
		return
	}
	r.Recorder.Eventf(tenant, nil, eventType, reason, reason, msgFmt, args...)
}

// SetupWithManager registers the controller with the manager. It watches
// every Tenant so a create or a status.zitadelOrgID change re-triggers a
// sync sooner than the timer would; every other reconcile is the RequeueAfter
// timer itself.
func (r *TenantRoleSyncReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorder("tenantrolesync-controller")
	}
	if r.Interval <= 0 {
		r.Interval = DefaultTenantRoleSyncInterval
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&gibsonv1alpha1.Tenant{},
			builder.WithPredicates(tenantRoleSyncPredicate())).
		Named("tenantrolesync").
		Complete(r) //nolint:wrapcheck // every SetupWithManager in this package returns Complete bare
}

// tenantRoleSyncPredicate passes creates and any update where
// status.zitadelOrgID changed (including from empty to set), so a freshly
// provisioned tenant is synced promptly rather than waiting out the timer.
func tenantRoleSyncPredicate() predicate.Predicate {
	return predicate.Funcs{
		CreateFunc: func(event.CreateEvent) bool { return true },
		UpdateFunc: func(e event.UpdateEvent) bool {
			oldT, oldOK := e.ObjectOld.(*gibsonv1alpha1.Tenant)
			newT, newOK := e.ObjectNew.(*gibsonv1alpha1.Tenant)
			if !oldOK || !newOK {
				return true
			}
			return oldT.Status.ZitadelOrgID != newT.Status.ZitadelOrgID
		},
		DeleteFunc:  func(event.DeleteEvent) bool { return false },
		GenericFunc: func(event.GenericEvent) bool { return false },
	}
}
