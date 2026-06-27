// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// tenant_admin_ops_controller.go — operator-pull admin tenant CRUD reconcile
// loop (gibson#964, enables dashboard#855).
//
// dashboard#855 removes the dashboard's last Kubernetes consumer — the admin
// CRD tool (app/actions/crd/tenant.ts) that let a platform admin
// provision/update/delete a tenant by writing the Tenant CR directly from the
// web tier. Instead the daemon's AdminTenantService records the admin's intent
// in a Postgres queue (tenant_admin_ops, migration 018) and this runnable drains
// it: it lists pending ops over the operator's existing SPIFFE-mTLS daemon client
// (ADR-0002) and applies each to the Tenant CR (create / patch spec / delete),
// then acks.
//
// This is the admin sibling of PendingProvisioningRunnable
// (pending_provisioning_controller.go, gibson#948): same operator-pull shape, but
// for the three cross-tenant admin CRUD operations rather than self-serve signup.
//
// ADR-0023 is preserved: the daemon never touches Kubernetes. All Tenant-CR
// mutation happens here in the operator, which already holds tenants
// create/update/delete RBAC (tenant_controller.go +kubebuilder:rbac).
//
// Idempotency (the load-bearing invariant): every apply is idempotent — provision
// no-ops if the CR exists, update converges, delete no-ops if the CR is absent.
// The op is acked only AFTER it is applied; a crash between apply and ack
// re-lists the op next pass and the idempotent apply makes the re-apply a no-op.
package controller

import (
	"context"
	"fmt"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// defaultTenantAdminOpsInterval is how often the runnable drains the daemon's
// admin tenant-op queue.
const defaultTenantAdminOpsInterval = 15 * time.Second

// TenantAdminOpsClient is the slice of the daemon client the runnable needs.
// provision.EntitlementsGRPCClient satisfies it; tests pass a stub.
type TenantAdminOpsClient interface {
	ListPendingTenantOps(ctx context.Context) ([]provision.TenantAdminOp, error)
	AckTenantOp(ctx context.Context, opID string) error
}

// TenantAdminOpsRunnable is a manager.Runnable that periodically drains the
// daemon's admin tenant-op queue, applying each op (provision/update/delete) to
// a Tenant CR and acking it. Implements controller-runtime's manager.Runnable.
type TenantAdminOpsRunnable struct {
	Client client.Client
	Daemon TenantAdminOpsClient
	// Interval between queue drains. Zero uses defaultTenantAdminOpsInterval.
	Interval time.Duration
}

// NeedLeaderElection ensures only the lead replica drains the queue, so two
// replicas never race to apply the same op.
func (r *TenantAdminOpsRunnable) NeedLeaderElection() bool { return true }

// Start runs the drain loop until the manager context is cancelled.
func (r *TenantAdminOpsRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultTenantAdminOpsInterval
	}
	logger := log.FromContext(ctx).WithName("tenant-admin-ops")
	logger.Info("starting operator-pull admin tenant-CRUD drain loop", "interval", interval.String())

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := r.drain(ctx); err != nil {
				// Transient daemon-unreachable / DB errors: log and retry next
				// tick. Never fail the manager — a daemon blip must not crash
				// the operator.
				logger.Error(err, "admin-tenant-ops drain pass failed; retrying next tick")
			}
		}
	}
}

// drain lists pending ops and applies each (apply + ack). One bad op does not
// abort the pass: per-op errors are logged and the loop continues, so a single
// malformed op cannot wedge the whole queue.
func (r *TenantAdminOpsRunnable) drain(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("tenant-admin-ops")
	ops, err := r.Daemon.ListPendingTenantOps(ctx)
	if err != nil {
		return fmt.Errorf("list pending tenant ops: %w", err)
	}
	for i := range ops {
		op := ops[i]
		if err := r.reconcileOne(ctx, op); err != nil {
			logger.Error(err, "failed to apply admin tenant op; will retry", "op_id", op.OpID, "op_type", op.OpType, "tenant_id", op.TenantID)
			continue
		}
	}
	return nil
}

// reconcileOne applies one admin op to its Tenant CR, then acks it. Apply is
// idempotent; the ack runs only after a successful apply so a crash between the
// two re-lists the op and the idempotent re-apply is a no-op.
func (r *TenantAdminOpsRunnable) reconcileOne(ctx context.Context, op provision.TenantAdminOp) error {
	if op.OpID == "" {
		return fmt.Errorf("admin op has empty op_id")
	}
	if op.TenantID == "" {
		return fmt.Errorf("admin op %q has empty tenant_id", op.OpID)
	}

	switch op.OpType {
	case "provision":
		if err := r.applyProvision(ctx, op); err != nil {
			return fmt.Errorf("provision %q: %w", op.TenantID, err)
		}
	case "update":
		if err := r.applyUpdate(ctx, op); err != nil {
			return fmt.Errorf("update %q: %w", op.TenantID, err)
		}
	case "delete":
		if err := r.applyDelete(ctx, op); err != nil {
			return fmt.Errorf("delete %q: %w", op.TenantID, err)
		}
	default:
		// Unknown op type can never converge — ack it so it leaves the queue
		// rather than wedging every drain. Logged at the call site.
		return r.ack(ctx, op.OpID)
	}

	return r.ack(ctx, op.OpID)
}

// ack marks an op done via the daemon. Wraps for a consistent error message.
func (r *TenantAdminOpsRunnable) ack(ctx context.Context, opID string) error {
	if err := r.Daemon.AckTenantOp(ctx, opID); err != nil {
		return fmt.Errorf("ack tenant op %q: %w", opID, err)
	}
	return nil
}

// applyProvision creates the Tenant CR for a provision op. Mirrors exactly what
// the dashboard's applyTenant wrote (src/lib/k8s/tenants.ts) and what
// PendingProvisioningRunnable.createTenant builds: cluster-scoped,
// metadata.name=slug, spec {displayName, owner, tier}. Idempotent: an existing
// CR (by name) is a no-op (AlreadyExists treated as success).
func (r *TenantAdminOpsRunnable) applyProvision(ctx context.Context, op provision.TenantAdminOp) error {
	logger := log.FromContext(ctx).WithName("tenant-admin-ops")

	var existing gibsonv1alpha1.Tenant
	getErr := r.Client.Get(ctx, client.ObjectKey{Name: op.TenantID}, &existing)
	switch {
	case getErr == nil:
		logger.Info("Tenant CR already exists; provision is a no-op", "tenant_id", op.TenantID)
		return nil
	case apierrors.IsNotFound(getErr):
		// fall through to create
	default:
		return fmt.Errorf("get Tenant CR %q: %w", op.TenantID, getErr)
	}

	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: op.TenantID},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: op.DisplayName,
			Owner:       op.OwnerEmail,
			Tier:        gibsonv1alpha1.TenantTier(op.Tier),
		},
	}
	if err := r.Client.Create(ctx, tenant); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	logger.Info("created Tenant CR from admin provision op", "tenant_id", op.TenantID, "tier", op.Tier)
	return nil
}

// applyUpdate patches Tenant.spec.tier / spec.displayName for the fields the op
// marks set, leaving unset fields untouched. Mirrors the dashboard's
// updateTenantAction patchTenant({spec:{tier?,displayName?}}). Idempotent: if the
// spec already holds the target values the Update is still issued but converges.
// A missing Tenant CR (NotFound) is treated as success — there is nothing to
// patch, and an update racing a delete must not wedge the queue.
func (r *TenantAdminOpsRunnable) applyUpdate(ctx context.Context, op provision.TenantAdminOp) error {
	logger := log.FromContext(ctx).WithName("tenant-admin-ops")

	var tenant gibsonv1alpha1.Tenant
	if err := r.Client.Get(ctx, client.ObjectKey{Name: op.TenantID}, &tenant); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Tenant CR not found; update is a no-op", "tenant_id", op.TenantID)
			return nil
		}
		return fmt.Errorf("get Tenant CR %q: %w", op.TenantID, err)
	}

	changed := false
	if op.TierSet && string(tenant.Spec.Tier) != op.Tier {
		tenant.Spec.Tier = gibsonv1alpha1.TenantTier(op.Tier)
		changed = true
	}
	if op.DisplayNameSet && tenant.Spec.DisplayName != op.DisplayName {
		tenant.Spec.DisplayName = op.DisplayName
		changed = true
	}
	if !changed {
		logger.Info("Tenant CR already matches update op; no patch needed", "tenant_id", op.TenantID)
		return nil
	}
	if err := r.Client.Update(ctx, &tenant); err != nil {
		return fmt.Errorf("update Tenant CR %q: %w", op.TenantID, err)
	}
	logger.Info("patched Tenant CR from admin update op", "tenant_id", op.TenantID, "tier_set", op.TierSet, "display_name_set", op.DisplayNameSet)
	return nil
}

// applyDelete deletes the Tenant CR for a delete op, triggering the existing
// finalizer's teardown. Mirrors the dashboard's deleteTenantAction
// deleteTenant(). Idempotent: an already-absent CR (NotFound) is a no-op success.
func (r *TenantAdminOpsRunnable) applyDelete(ctx context.Context, op provision.TenantAdminOp) error {
	logger := log.FromContext(ctx).WithName("tenant-admin-ops")

	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: op.TenantID}}
	if err := r.Client.Delete(ctx, tenant); err != nil {
		if apierrors.IsNotFound(err) {
			logger.Info("Tenant CR not found; delete is a no-op", "tenant_id", op.TenantID)
			return nil
		}
		return fmt.Errorf("delete Tenant CR %q: %w", op.TenantID, err)
	}
	logger.Info("deleted Tenant CR from admin delete op (finalizer teardown runs)", "tenant_id", op.TenantID)
	return nil
}

// SetupWithManager registers the runnable with the manager. The daemon client
// may be nil (operator booted without GIBSON_DAEMON_GRPC_ADDRESS); the caller
// guards that and logs operator-pull admin CRUD as disabled.
func (r *TenantAdminOpsRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Daemon == nil {
		return fmt.Errorf("tenant-admin-ops: Daemon client is nil")
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	return mgr.Add(r)
}
