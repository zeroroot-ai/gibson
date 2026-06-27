// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// E8/gibson#805 — finalizer-based teardown + dependency-ordered reconciliation.
//
// The Tenant reconciler owns the four declarative sub-CRDs (TenantIdentity,
// TenantSecretsBackend, TenantGrants, TenantDataPlane) instead of the imperative
// saga steps that previously provisioned/compensated each domain inline. The
// sub-CRDs carry their own finalizers + idempotent provisioners (#801–#804), so
// teardown is structural: the Tenant finalizer deletes the children in REVERSE
// dependency order and waits for each child's own finalizer to complete before
// proceeding, and an ownerReference back to the Tenant provides a GC safety net.
//
// Dependency order is derived from the saga's provision step sequence (the order
// the steps ran today IS the dependency order):
//
//	EnsureZitadelOrg            → TenantIdentity        (no Req)
//	ProvisionSecretsBackend     → TenantSecretsBackend  (Req EnsureZitadelOrg)
//	ConfigureSecretsJWTAuth     → TenantSecretsBackend
//	RegisterTenantWithPlatform  → TenantGrants          (FGA-only)
//	DataPlaneProvisioned        → TenantDataPlane        (Req PublishTenantName)
//	TenantBrokerConfigWritten   → TenantSecretsBackend  (broker row; platform PG)
//
// Collapsing the saga steps onto their owning sub-CRD and preserving the saga's
// literal sequence gives the child creation order:
//
//	Identity → SecretsBackend → Grants → DataPlane
//
// Teardown is the strict reverse:
//
//	DataPlane → Grants → SecretsBackend → Identity
//
// Each child is created only once its predecessor reports Status.Ready, so the
// dependency edges are enforced structurally rather than by saga Req strings.

// childKind enumerates the four owned sub-CRD domains in CREATION (dependency)
// order. Teardown walks this slice in reverse.
type childKind int

const (
	childIdentity childKind = iota
	childSecretsBackend
	childGrants
	childDataPlane
)

// childCreationOrder is the dependency-ordered list of owned sub-CRD domains.
// Index order encodes the creation order; teardown reverses it.
var childCreationOrder = []childKind{
	childIdentity,
	childSecretsBackend,
	childGrants,
	childDataPlane,
}

// childName is the deterministic name a Tenant gives each owned sub-CRD. Keyed
// on the tenant id so the child is unique-per-tenant and idempotently resolvable
// across reconciles. The sub-CRDs are Namespaced; they live in the tenant's own
// namespace (status.namespace) so they share its lifecycle.
func childName(tenant *gibsonv1alpha1.Tenant) string {
	return tenant.Name
}

// tenantOwnerRef returns the controller ownerReference pointing the child at its
// Tenant. The Tenant is cluster-scoped; cross-namespace ownerRefs do not drive
// Kubernetes GC, so this ref is a provenance/safety-net marker. Ordered teardown
// is performed explicitly by the Tenant finalizer (deleteChildrenInReverse).
func tenantOwnerRef(tenant *gibsonv1alpha1.Tenant) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         gibsonv1alpha1.GroupVersion.String(),
		Kind:               "Tenant",
		Name:               tenant.Name,
		UID:                tenant.UID,
		BlockOwnerDeletion: ptr.To(false),
		Controller:         ptr.To(false),
	}
}

// newChild builds the desired child object for a given kind. The spec mirrors
// the values the saga derived from the Tenant (tenant id + display name); the
// sub-CRD controllers delegate to the SAME provisioners the saga used, so
// behaviour is preserved (ADR-0027, one codepath).
func newChild(kind childKind, tenant *gibsonv1alpha1.Tenant) client.Object {
	ns := tenant.Status.Namespace
	meta := metav1.ObjectMeta{
		Name:            childName(tenant),
		Namespace:       ns,
		OwnerReferences: []metav1.OwnerReference{tenantOwnerRef(tenant)},
	}
	switch kind {
	case childIdentity:
		return &gibsonv1alpha1.TenantIdentity{
			ObjectMeta: meta,
			Spec: gibsonv1alpha1.TenantIdentitySpec{
				TenantID:    tenant.Name,
				DisplayName: tenant.Spec.DisplayName,
			},
		}
	case childSecretsBackend:
		return &gibsonv1alpha1.TenantSecretsBackend{
			ObjectMeta: meta,
			Spec:       gibsonv1alpha1.TenantSecretsBackendSpec{TenantID: tenant.Name},
		}
	case childGrants:
		return &gibsonv1alpha1.TenantGrants{
			ObjectMeta: meta,
			Spec: gibsonv1alpha1.TenantGrantsSpec{
				TenantID:             tenant.Name,
				PlatformRegistration: true,
			},
		}
	case childDataPlane:
		return &gibsonv1alpha1.TenantDataPlane{
			ObjectMeta: meta,
			Spec:       gibsonv1alpha1.TenantDataPlaneSpec{TenantID: tenant.Name},
		}
	default:
		return nil
	}
}

// emptyChild returns a zero-valued child object of the given kind, used as the
// Get/Delete target.
func emptyChild(kind childKind) client.Object {
	switch kind {
	case childIdentity:
		return &gibsonv1alpha1.TenantIdentity{}
	case childSecretsBackend:
		return &gibsonv1alpha1.TenantSecretsBackend{}
	case childGrants:
		return &gibsonv1alpha1.TenantGrants{}
	case childDataPlane:
		return &gibsonv1alpha1.TenantDataPlane{}
	default:
		return nil
	}
}

// childReady reports the aggregate Ready of a child object. Each sub-CRD exposes
// a scalar Status.Ready flipped True only when every component is provisioned.
func childReady(obj client.Object) bool {
	switch c := obj.(type) {
	case *gibsonv1alpha1.TenantIdentity:
		return c.Status.Ready
	case *gibsonv1alpha1.TenantSecretsBackend:
		return c.Status.Ready
	case *gibsonv1alpha1.TenantGrants:
		return c.Status.Ready
	case *gibsonv1alpha1.TenantDataPlane:
		return c.Status.Ready
	default:
		return false
	}
}

// childKindName is the human-readable name of a child kind for logs/events.
func childKindName(kind childKind) string {
	switch kind {
	case childIdentity:
		return "TenantIdentity"
	case childSecretsBackend:
		return "TenantSecretsBackend"
	case childGrants:
		return "TenantGrants"
	case childDataPlane:
		return "TenantDataPlane"
	default:
		return "unknown"
	}
}

// reconcileChildren ensures every owned sub-CRD exists, created in dependency
// order: each child is created only after its predecessor reports Ready. It
// returns allReady=true once all four children report Status.Ready.
//
// Idempotent + resumable: a child that already exists is left untouched (its own
// controller drift-corrects); a not-yet-ready predecessor short-circuits so the
// next child is not created until the dependency is satisfied. Partial failure
// (e.g. apiserver hiccup mid-create) requeues and converges on the next pass.
//
// The tenant's namespace (status.namespace) must be populated before children
// can be created — children are Namespaced and live in the tenant namespace.
func (r *TenantReconciler) reconcileChildren(ctx context.Context, tenant *gibsonv1alpha1.Tenant) (allReady bool, err error) {
	if tenant.Status.Namespace == "" {
		// Namespace step has not run yet; children cannot be placed. Not an
		// error — the retained provision saga creates the namespace, and the
		// next reconcile will place the children.
		return false, nil
	}

	allReady = true
	for _, kind := range childCreationOrder {
		ready, ensureErr := r.ensureChild(ctx, kind, tenant)
		if ensureErr != nil {
			return false, ensureErr
		}
		if !ready {
			// Dependency not yet satisfied. Stop here: the next child must not
			// be created until this one is Ready (structural ordering).
			return false, nil
		}
	}
	return allReady, nil
}

// ensureChild creates the child of the given kind if absent and reports whether
// it is Ready. A freshly created child is not Ready yet, so the caller treats
// that as "dependency pending" and requeues.
func (r *TenantReconciler) ensureChild(ctx context.Context, kind childKind, tenant *gibsonv1alpha1.Tenant) (ready bool, err error) {
	existing := emptyChild(kind)
	key := types.NamespacedName{Name: childName(tenant), Namespace: tenant.Status.Namespace}
	getErr := r.Get(ctx, key, existing)
	switch {
	case getErr == nil:
		return childReady(existing), nil
	case apierrors.IsNotFound(getErr):
		desired := newChild(kind, tenant)
		if createErr := r.Create(ctx, desired); createErr != nil {
			if apierrors.IsAlreadyExists(createErr) {
				// Lost a create race; re-read on the next pass.
				return false, nil
			}
			return false, fmt.Errorf("create %s for tenant %q: %w", childKindName(kind), tenant.Name, createErr)
		}
		// Freshly created → not Ready yet; requeue.
		return false, nil
	default:
		return false, fmt.Errorf("get %s for tenant %q: %w", childKindName(kind), tenant.Name, getErr)
	}
}

// deleteChildrenInReverse deletes the owned sub-CRDs in REVERSE dependency order
// (DataPlane → Grants → SecretsBackend → Identity), waiting for each child's own
// finalizer to complete (the child object fully gone) before deleting the next.
//
// Returns done=true only when every child is gone. A child still present (either
// not yet deleted, or mid-finalization) yields done=false so the Tenant
// reconciler requeues and the cascade continues. Each NotFound is treated as
// success (already gone) — idempotent and resumable across reconciles.
//
// This runs in the Tenant finalizer BEFORE the retained teardown saga deletes
// the per-tenant namespace, so the children are never force-removed out of order
// by a namespace cascade.
func (r *TenantReconciler) deleteChildrenInReverse(ctx context.Context, tenant *gibsonv1alpha1.Tenant) (done bool, err error) {
	if tenant.Status.Namespace == "" {
		// No namespace ⇒ no children were ever placed.
		return true, nil
	}

	for i := len(childCreationOrder) - 1; i >= 0; i-- {
		kind := childCreationOrder[i]
		gone, delErr := r.deleteChild(ctx, kind, tenant)
		if delErr != nil {
			return false, delErr
		}
		if !gone {
			// This child is still present (delete issued, finalizer running).
			// Do NOT proceed to the next child — teardown must stay ordered.
			return false, nil
		}
	}
	return true, nil
}

// deleteChild issues a delete for the child of the given kind and reports
// whether it is fully gone. A NotFound (already gone, or finalizer completed)
// is success. A present object that is not yet deleting has Delete issued; a
// present object that is already deleting (DeletionTimestamp set) is waited on.
func (r *TenantReconciler) deleteChild(ctx context.Context, kind childKind, tenant *gibsonv1alpha1.Tenant) (gone bool, err error) {
	existing := emptyChild(kind)
	key := types.NamespacedName{Name: childName(tenant), Namespace: tenant.Status.Namespace}
	getErr := r.Get(ctx, key, existing)
	if apierrors.IsNotFound(getErr) {
		return true, nil
	}
	if getErr != nil {
		return false, fmt.Errorf("get %s for tenant %q: %w", childKindName(kind), tenant.Name, getErr)
	}
	if existing.GetDeletionTimestamp().IsZero() {
		if delErr := r.Delete(ctx, existing); delErr != nil {
			if apierrors.IsNotFound(delErr) {
				return true, nil
			}
			return false, fmt.Errorf("delete %s for tenant %q: %w", childKindName(kind), tenant.Name, delErr)
		}
	}
	// Present (deleting or just issued) → its finalizer is still running.
	return false, nil
}
