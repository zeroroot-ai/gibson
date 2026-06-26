// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

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
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
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

	// Ensure the founding-owner TenantMember CR exists (dashboard#855). This is
	// what lets the dashboard drop its applyTenantMember signup write. The member
	// is Namespaced in the tenant's `tenant-<slug>` namespace, which the Tenant
	// reconcile's NamespaceProvisioner creates asynchronously — so on the first
	// drain the namespace may not exist yet. In that case ensureFoundingMember
	// returns an error and we skip the ack below: the record stays pending and
	// the next drain retries (the Tenant existence-check above makes the
	// re-create a no-op), converging once the namespace appears. Only after BOTH
	// the Tenant CR and the founding member are ensured present do we ack.
	if err := r.ensureFoundingMember(ctx, p); err != nil {
		return fmt.Errorf("ensure founding member for %q: %w", p.TenantID, err)
	}

	// Ack AFTER the CR is ensured present. If this ack fails, the record stays
	// pending and is retried; the existence check above makes the retry a no-op.
	if err := r.Daemon.AckTenantProvisioned(ctx, p.TenantID); err != nil {
		return fmt.Errorf("ack tenant provisioned %q: %w", p.TenantID, err)
	}
	return nil
}

// ensureFoundingMember creates the founding-owner TenantMember CR for a pending
// record, idempotently. It mirrors EXACTLY what the dashboard's applyTenantMember
// used to write at signup (app/actions/signup.ts, dashboard#855), so the existing
// TenantMember reconciler wires the founding owner into the Zitadel org just as
// before:
//   - namespace: tenant-<slug>                  (tenantNamespace)
//   - name:      <slugify(owner_email)>-owner   (foundingMemberName)
//   - spec:      { Email, Role: owner, TenantRef: {Name: slug},
//     AcceptedByUserID: owner_user_id }          (no InvitedByEmail)
//
// AcceptedByUserID pre-accepts the membership: the signup user IS the workspace
// owner, so the TenantMember reconciler promotes Invited→Active without an emailed
// invitation. (The invitation flow is for invitees, not the founding owner.)
//
// Idempotency: existence-check by name first; an existing member is a no-op, and
// AlreadyExists on create is treated as success. If the per-tenant namespace does
// not exist yet (the Tenant reconcile has not provisioned tenant-<slug>), the
// create fails NotFound and the error is returned (NOT swallowed) so reconcileOne
// skips the ack and retries on the next drain — converging once the namespace
// appears.
func (r *PendingProvisioningRunnable) ensureFoundingMember(ctx context.Context, p provision.PendingTenant) error {
	logger := log.FromContext(ctx).WithName("pending-provisioning")
	if p.OwnerEmail == "" {
		// No owner email → cannot build the founding member. Log and proceed to
		// ack: the tenant is still provisioned; a member can be added later. This
		// must not wedge the queue on a malformed record.
		logger.Info("pending record has empty owner_email; skipping founding-member create", "tenant_id", p.TenantID)
		return nil
	}

	namespace := tenantNamespace(p.TenantID)
	name := foundingMemberName(p.OwnerEmail)

	// Existence check first — the no-double-create guard. A crash between a prior
	// member-create and the ack re-lists this row; finding the member present
	// makes this a no-op and we proceed to ack.
	var existing gibsonv1alpha1.TenantMember
	getErr := r.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, &existing)
	switch {
	case getErr == nil:
		logger.Info("founding-owner TenantMember already exists; skipping create", "tenant_id", p.TenantID, "member", name)
		return nil
	case apierrors.IsNotFound(getErr):
		// fall through to create
	default:
		return fmt.Errorf("get TenantMember %s/%s: %w", namespace, name, getErr)
	}

	member := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:            p.OwnerEmail,
			Role:             gibsonv1alpha1.MemberRoleOwner,
			TenantRef:        corev1.LocalObjectReference{Name: p.TenantID},
			AcceptedByUserID: p.OwnerUserID,
		},
	}
	if err := r.Client.Create(ctx, member); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		// A NotFound here means the per-tenant namespace is not yet provisioned;
		// surfacing the error makes reconcileOne skip the ack and retry next
		// drain. Same for any transient create error.
		return fmt.Errorf("create TenantMember %s/%s: %w", namespace, name, err)
	}
	logger.Info("created founding-owner TenantMember from pending-provisioning record", "tenant_id", p.TenantID, "member", name)
	return nil
}

// tenantNamespace returns the per-tenant namespace name for a slug. Mirrors the
// dashboard's tenantNamespace (src/lib/k8s/tenants.ts) and the operator's
// `tenant-<slug>` namespace convention (internal/tenant/namespace.go).
func tenantNamespace(slug string) string {
	return "tenant-" + slug
}

// foundingMemberName builds the founding-owner TenantMember CR name from the
// owner email, byte-identical to the dashboard's `${slugify(email)}-owner`
// (app/actions/signup.ts) so the operator-created member is indistinguishable
// from the dashboard-created one.
func foundingMemberName(email string) string {
	return slugifyEmail(email) + "-owner"
}

// slugifyEmail mirrors the dashboard's slugify (app/actions/signup.ts):
// lowercase → replace every non-[a-z0-9-] rune with '-' → collapse runs of '-' →
// strip leading/trailing '-' → truncate to 63 chars. (No trim-after-truncate, to
// match the dashboard's `.slice(0, 63)` exactly.)
func slugifyEmail(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := collapseDashes(b.String())
	out = strings.Trim(out, "-")
	if len(out) > 63 {
		out = out[:63]
	}
	return out
}

// collapseDashes replaces every run of consecutive '-' with a single '-'.
func collapseDashes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	prevDash := false
	for i := range len(s) {
		if s[i] == '-' {
			if !prevDash {
				b.WriteByte('-')
			}
			prevDash = true
			continue
		}
		b.WriteByte(s[i])
		prevDash = false
	}
	return b.String()
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
