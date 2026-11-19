// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/fga"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
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

// annotationAuthzGeneration holds the generation of the ConnectorInstance
// whose grants this controller last wrote. A pass at the same generation is
// an idempotent re-check and writes no new audit record (gibson#583).
const annotationAuthzGeneration = "gibson.zeroroot.ai/authz-observed-generation"

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

	// Audit writes the record of each FGA grant change before the change
	// (gibson#583). Required.
	Audit *audit.SagaEmitter

	// Recorder emits the event of a blocked finalizer. Required.
	Recorder events.EventRecorder
}

// connectorAuthzBlockedRequeue is the wait before the controller checks again a
// finalizer that a 404 of the model blocks. The error return of a reconcile
// requeues with a backoff that grows and then stays near 1000 seconds, with a
// log line each time. A person has to act, so the wait is fixed and long.
const connectorAuthzBlockedRequeue = 10 * time.Minute

// warn emits a Warning event on the ConnectorInstance.
func (r *ConnectorInstanceAuthzReconciler) warn(ci *connectorv1alpha1.ConnectorInstance, reason, msg string) {
	r.Recorder.Eventf(ci, nil, "Warning", reason, reason, "%s", msg)
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
	if r.Audit == nil {
		return ctrl.Result{}, fmt.Errorf("connector authz: %w", saga.ErrNoAudit)
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
			ev := audit.ObjectEvent(audit.ActionConnectorGrantsDelete, &ci, map[string]string{"connector": catalogID})
			err := r.Audit.Change(ctx, ev, func() error {
				return fga.DeleteConnectorComponentGrants(ctx, r.FGA, catalogID, tenantID)
			})
			switch {
			case err == nil:
			case errors.Is(err, fga.ErrStoreNotFound):
				// A 404 for the STORE: the store does not exist, so its tuples
				// do not exist, and the finalizer may complete. A 404 for a tuple
				// cannot happen, because the delete ignores an absent tuple.
				log.Info("the FGA store does not exist; the connector tuples are gone",
					"connector", catalogID, "tenant", tenantID)
			case errors.Is(err, clients.ErrNotFound):
				// Any other 404 is the authorization model, not the tuples: they
				// may be there, so the finalizer stays. Retrying at once cannot
				// help, so the controller stops the backoff, says why, and checks
				// again later. A person fixes the model or the store address.
				r.warn(&ci, "FGATuplesBlocked", fmt.Sprintf(
					"the connector tuples cannot be removed: FGA answered 404 and the store exists, so the model is missing: %v", err))
				return ctrl.Result{RequeueAfter: connectorAuthzBlockedRequeue}, nil
			default:
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

	write := func() error {
		if err := fga.WriteConnectorComponentGrants(ctx, r.FGA, catalogID, tenantID); err != nil {
			return fmt.Errorf("connector authz: seed tuples for %s: %w", catalogID, err)
		}
		// Reseed away the retired plugin-object borrow (ADR-0067): stale
		// pre-cutover stores may still carry it, and nothing writes it any more.
		if err := fga.DeleteLegacyConnectorInvokeTuple(ctx, r.FGA, catalogID, tenantID); err != nil {
			return fmt.Errorf("connector authz: drop legacy invoke tuple for %s: %w", catalogID, err)
		}
		return nil
	}
	generation := strconv.FormatInt(ci.Generation, 10)
	if ci.Annotations[annotationAuthzGeneration] == generation {
		// Settled at this generation: an idempotent re-check, no new record.
		return ctrl.Result{}, write()
	}
	ev := audit.ObjectEvent(audit.ActionConnectorGrantsWrite, &ci, map[string]string{"connector": catalogID, "generation": generation})
	if err := r.Audit.Change(ctx, ev, write); err != nil {
		return ctrl.Result{}, fmt.Errorf("write the grants of ConnectorInstance %s/%s: %w", ci.Namespace, ci.Name, err)
	}
	if ci.Annotations == nil {
		ci.Annotations = map[string]string{}
	}
	ci.Annotations[annotationAuthzGeneration] = generation
	if err := r.Update(ctx, &ci); err != nil {
		return ctrl.Result{}, fmt.Errorf("connector authz: mark generation on %s: %w", catalogID, err)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the controller under its own name so it never
// collides with the connector-operator's runtime controller for the same CRD.
func (r *ConnectorInstanceAuthzReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Audit == nil {
		return fmt.Errorf("connector authz: %w", saga.ErrNoAudit)
	}
	if r.Recorder == nil {
		return errors.New("connector authz: Recorder is required")
	}
	if err := ctrl.NewControllerManagedBy(mgr).
		Named("connectorinstance-authz").
		For(&connectorv1alpha1.ConnectorInstance{}).
		Complete(r); err != nil {
		return fmt.Errorf("connector authz: setup: %w", err)
	}
	return nil
}
