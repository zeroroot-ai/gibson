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

// pending_provisioning_controller.go — operator-pull tenant provisioning
// reconcile loop (E9, gibson#948, enables dashboard#813).
//
// The daemon owns a pending-provisioning queue (platform Postgres). Instead of
// the dashboard creating the Tenant CR directly (a standing cluster-write
// privilege on the web tier), the daemon's Signup handler enqueues the tenant
// and this runnable drains the queue: it lists pending records over the
// operator's existing SPIFFE-mTLS daemon client (ADR-0002), creates the Tenant
// CR for each (the same spec shape the dashboard used to write), and acks each
// record back to the daemon.
//
// ADR-0023 is preserved: the daemon never touches Kubernetes. All Tenant-CR
// creation happens here in the operator, which already holds `tenants` create
// RBAC (tenant_controller.go +kubebuilder:rbac).
//
// Idempotency / no-double-create (the load-bearing invariant): before creating
// a Tenant CR the runnable checks whether one already exists by name
// (apierrors.IsAlreadyExists is also treated as success). It acks only AFTER the
// CR is ensured present. A crash between create and ack simply re-lists the row
// next pass; the existence check turns the re-create into a no-op, so the row is
// re-acked rather than re-provisioned. The ack RPC is itself idempotent.
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

// AnnotationStripeCustomerID is stamped on the Tenant CR when the pending
// record carries a pre-created Stripe customer, so the billing reconciler
// adopts the existing customer rather than creating a new one. Byte-identical
// to the dashboard's ANNOTATION_STRIPE_CUSTOMER_ID (src/lib/k8s/tenants.ts) so
// the operator-created CR is indistinguishable from the dashboard-created one.
const AnnotationStripeCustomerID = "gibson.zeroroot.ai/stripe-customer-id"

// defaultPendingProvisioningInterval is how often the runnable drains the
// daemon's pending-provisioning queue.
const defaultPendingProvisioningInterval = 15 * time.Second

// PendingProvisioningClient is the slice of the daemon client the runnable
// needs. provision.EntitlementsGRPCClient satisfies it; tests pass a stub.
type PendingProvisioningClient interface {
	ListPendingTenantProvisioning(ctx context.Context) ([]provision.PendingTenant, error)
	AckTenantProvisioned(ctx context.Context, tenantID string) error
}

// PendingProvisioningRunnable is a manager.Runnable that periodically drains the
// daemon's pending-tenant-provisioning queue, creating one Tenant CR per record
// and acking it. Implements controller-runtime's manager.Runnable.
type PendingProvisioningRunnable struct {
	Client client.Client
	Daemon PendingProvisioningClient
	// Interval between queue drains. Zero uses defaultPendingProvisioningInterval.
	Interval time.Duration
}

// NeedLeaderElection ensures only the lead replica drains the queue, so two
// replicas never race to create the same Tenant CR (the existence check would
// make the loser a no-op anyway, but single-writer is cleaner).
func (r *PendingProvisioningRunnable) NeedLeaderElection() bool { return true }

// Start runs the drain loop until the manager context is cancelled.
func (r *PendingProvisioningRunnable) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = defaultPendingProvisioningInterval
	}
	logger := log.FromContext(ctx).WithName("pending-provisioning")
	logger.Info("starting operator-pull tenant-provisioning drain loop", "interval", interval.String())

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
				logger.Error(err, "pending-provisioning drain pass failed; retrying next tick")
			}
		}
	}
}

// drain lists pending records and reconciles each (create-CR + ack). One bad
// record does not abort the pass: per-record errors are logged and the loop
// continues, so a single malformed row cannot wedge the whole queue.
func (r *PendingProvisioningRunnable) drain(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("pending-provisioning")
	pending, err := r.Daemon.ListPendingTenantProvisioning(ctx)
	if err != nil {
		return fmt.Errorf("list pending tenant provisioning: %w", err)
	}
	for i := range pending {
		p := pending[i]
		if err := r.reconcileOne(ctx, p); err != nil {
			logger.Error(err, "failed to provision pending tenant; will retry", "tenant_id", p.TenantID)
			continue
		}
	}
	return nil
}

// reconcileOne ensures the Tenant CR for one pending record exists, then acks
// the record. Idempotent: an existing CR (by name) is left untouched; the ack
// runs either way so the record leaves the queue.
func (r *PendingProvisioningRunnable) reconcileOne(ctx context.Context, p provision.PendingTenant) error {
	logger := log.FromContext(ctx).WithName("pending-provisioning")
	if p.TenantID == "" {
		return fmt.Errorf("pending record has empty tenant_id")
	}

	// Existence check first — the load-bearing no-double-create guard. A crash
	// between a prior create and its ack re-lists this row; finding the CR
	// already present makes the re-create a no-op so we proceed straight to ack.
	var existing gibsonv1alpha1.Tenant
	getErr := r.Client.Get(ctx, client.ObjectKey{Name: p.TenantID}, &existing)
	switch {
	case getErr == nil:
		logger.Info("Tenant CR already exists; skipping create", "tenant_id", p.TenantID)
	case apierrors.IsNotFound(getErr):
		if err := r.createTenant(ctx, p); err != nil {
			return fmt.Errorf("create Tenant CR %q: %w", p.TenantID, err)
		}
		logger.Info("created Tenant CR from pending-provisioning record", "tenant_id", p.TenantID, "tier", p.Tier)
	default:
		return fmt.Errorf("get Tenant CR %q: %w", p.TenantID, getErr)
	}

	// Ack AFTER the CR is ensured present. If this ack fails, the record stays
	// pending and is retried; the existence check above makes the retry a no-op.
	if err := r.Daemon.AckTenantProvisioned(ctx, p.TenantID); err != nil {
		return fmt.Errorf("ack tenant provisioned %q: %w", p.TenantID, err)
	}
	return nil
}

// createTenant builds and creates the Tenant CR from a pending record. The spec
// shape mirrors exactly what the dashboard's applyTenant wrote
// (src/lib/k8s/tenants.ts): cluster-scoped, metadata.name=slug, spec
// displayName/owner/tier, and the stripe-customer-id annotation when present.
// AlreadyExists is treated as success (a concurrent create won the race).
func (r *PendingProvisioningRunnable) createTenant(ctx context.Context, p provision.PendingTenant) error {
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.TenantID,
		},
		Spec: gibsonv1alpha1.TenantSpec{
			DisplayName: p.WorkspaceName,
			Owner:       p.OwnerEmail,
			Tier:        gibsonv1alpha1.TenantTier(p.Tier),
		},
	}
	if p.StripeCustomerID != "" {
		tenant.ObjectMeta.Annotations = map[string]string{
			AnnotationStripeCustomerID: p.StripeCustomerID,
		}
	}
	if err := r.Client.Create(ctx, tenant); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return err
	}
	return nil
}

// SetupWithManager registers the runnable with the manager. The daemon client
// may be nil (operator booted without GIBSON_DAEMON_GRPC_ADDRESS); in that case
// the runnable is not registered and operator-pull provisioning is disabled —
// logged by the caller.
func (r *PendingProvisioningRunnable) SetupWithManager(mgr manager.Manager) error {
	if r.Daemon == nil {
		return fmt.Errorf("pending-provisioning: Daemon client is nil")
	}
	if r.Client == nil {
		r.Client = mgr.GetClient()
	}
	return mgr.Add(r)
}
