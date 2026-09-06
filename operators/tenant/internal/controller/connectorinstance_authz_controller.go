// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
)

// connectorAuthzFinalizer blocks ConnectorInstance deletion until the
// tenant-operator has removed the connector's FGA component tuples. It is
// distinct from the connector-operator's runtime-cleanup finalizer — the two
// controllers own different concerns on the same CR.
const connectorAuthzFinalizer = "gibson.zeroroot.ai/connector-authz"

// connectorTenantNamespacePrefix mirrors the platform convention: every
// tenant namespace is "tenant-<id>" (see the daemon's ConnectorService and
// internal/infra/reconciler's catalog source).
const connectorTenantNamespacePrefix = "tenant-"

// ConnectorInstanceAuthzReconciler converges the FGA component tuples for a
// ConnectorInstance (ADR-0067, gibson#1548). The connector-operator owns the
// runtime (ToolHive, NetworkPolicy, secrets); this controller owns the authz
// tuples, because the tenant-operator is the single FGA writer in the
// operator plane. The seeded posture is plugin parity: an owner tuple (which
// computes member-level direct read/write/execute) plus tenant_enabled (the
// tenant catalog gate).
type ConnectorInstanceAuthzReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	FGA    fga.Client
}

// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=connectorinstances,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=gibson.zeroroot.ai,resources=connectorinstances/finalizers,verbs=update

// Reconcile converges the FGA component tuples for one ConnectorInstance:
// seed on an active CR, remove behind the finalizer on delete.
func (r *ConnectorInstanceAuthzReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var ci connectorv1alpha1.ConnectorInstance
	if err := r.Get(ctx, req.NamespacedName, &ci); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("connector authz: get %s: %w", req.NamespacedName, err)
	}

	tenantID, ok := strings.CutPrefix(ci.Namespace, connectorTenantNamespacePrefix)
	if !ok || tenantID == "" {
		// Not a tenant namespace — nothing to authorize.
		return ctrl.Result{}, nil
	}
	// The CR name is the catalog id (Entry.BuildConnectorInstance).
	catalogID := ci.Name

	if !ci.DeletionTimestamp.IsZero() {
		if controllerutil.ContainsFinalizer(&ci, connectorAuthzFinalizer) {
			// Tuples must be gone before the CR may go — returning the error
			// requeues with backoff and keeps the finalizer in place.
			if err := fga.DeleteConnectorComponentGrants(ctx, r.FGA, catalogID, tenantID); err != nil {
				return ctrl.Result{}, fmt.Errorf("connector authz: remove tuples for %s: %w", catalogID, err)
			}
			controllerutil.RemoveFinalizer(&ci, connectorAuthzFinalizer)
			if err := r.Update(ctx, &ci); err != nil {
				return ctrl.Result{}, fmt.Errorf("connector authz: drop finalizer on %s: %w", catalogID, err)
			}
			log.Info("connector authz tuples removed",
				"connector", catalogID, "tenant", tenantID)
		}
		return ctrl.Result{}, nil
	}

	if !controllerutil.ContainsFinalizer(&ci, connectorAuthzFinalizer) {
		controllerutil.AddFinalizer(&ci, connectorAuthzFinalizer)
		if err := r.Update(ctx, &ci); err != nil {
			return ctrl.Result{}, fmt.Errorf("connector authz: add finalizer on %s: %w", catalogID, err)
		}
	}

	if err := fga.WriteConnectorComponentGrants(ctx, r.FGA, catalogID, tenantID); err != nil {
		return ctrl.Result{}, fmt.Errorf("connector authz: seed tuples for %s: %w", catalogID, err)
	}
	// Reseed away the retired plugin-object borrow (ADR-0067): stale
	// pre-cutover stores may still carry it, and nothing writes it any more.
	if err := fga.DeleteLegacyConnectorInvokeTuple(ctx, r.FGA, catalogID, tenantID); err != nil {
		return ctrl.Result{}, fmt.Errorf("connector authz: drop legacy invoke tuple for %s: %w", catalogID, err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller under its own name so it never
// collides with the connector-operator's runtime controller for the same CRD.
func (r *ConnectorInstanceAuthzReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("connectorinstance-authz").
		For(&connectorv1alpha1.ConnectorInstance{}).
		Complete(r); err != nil {
		return fmt.Errorf("connector authz: setup: %w", err)
	}
	return nil
}
