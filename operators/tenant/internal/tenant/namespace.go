// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package tenant resolves per-tenant Kubernetes-resource coordinates.
// Single source of truth for "which namespace does tenant <id>'s
// per-tenant resources live in"; eliminates the n.ns vs tenantNS
// divergence class that produced tenant-operator#57 (Neo4j dataplane
// creating per-tenant resources in the operator namespace because the
// code path used `n.ns` while Provision() had correctly computed
// tenantNS but never threaded it through).
//
// PRD module: zeroroot-ai/tenant-operator#76 Module 2 / issue #84.
package tenant

import (
	"context"
	"fmt"

	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	gtenant "github.com/zeroroot-ai/gibson/pkg/platform/tenant"
	"github.com/zeroroot-ai/sdk/auth"
)

// NamespaceFor returns the per-tenant Kubernetes namespace for tenantID.
//
// Resolution order:
//  1. If a Tenant CR exists and its Status.Namespace is set (the
//     ProvisionNamespace saga step writes this), return that value as-is.
//     This is the source of truth — it's what the operator's namespace
//     reconciler actually created.
//  2. Otherwise fall back to the runtime-canonical derivation
//     "tenant-<slug>", matching what:
//     - internal/controller/tenant_namespace.go (ProvisionNamespace) creates
//     - helm/gibson-operators per-tenant ClusterRole is RoleBound to
//     - every existing live cluster has
//
// Note on SDK divergence: gtenant.Names.Namespace() in the SDK returns
// just the slug ("acme") per spec tenant-provisioning-unification R1.5,
// but the operator + chart use "tenant-<slug>" in practice. That cross-
// repo contract drift is tracked separately; this resolver matches
// runtime reality, not the stale SDK comment.
//
// Returns a wrapped error if the tenantID fails sanitisation
// (auth.NewTenantID validation). Returns a non-nil namespace + nil err
// even when the CR lookup fails — the fallback is intentional, since
// every code path here is "I need a namespace string to read or write a
// per-tenant resource".
func NamespaceFor(ctx context.Context, c client.Client, tenantID string) (string, error) {
	id, err := auth.NewTenantID(tenantID)
	if err != nil {
		return "", fmt.Errorf("tenant: %w", err)
	}
	derived := derivedNamespace(id)
	if c == nil {
		return derived, nil
	}
	var cr gibsonv1alpha1.Tenant
	if getErr := c.Get(ctx, client.ObjectKey{Name: tenantID}, &cr); getErr == nil {
		if cr.Status.Namespace != "" {
			return cr.Status.Namespace, nil
		}
	}
	// CR missing OR Status.Namespace empty — derived is safe.
	return derived, nil
}

// NamespaceForKnownID is the no-cluster-lookup variant for callers that
// already have a sanitised auth.TenantID and do NOT want to hit the
// API server (tests, very-early startup, hot loops). Returns the
// runtime-canonical derivation only.
func NamespaceForKnownID(id auth.TenantID) string {
	return derivedNamespace(id)
}

// derivedNamespace is the single private helper that encodes the
// "tenant-<slug>" runtime convention. If/when the cross-repo contract
// reconciles to the SDK's bare-slug form, this is the one place to
// change.
func derivedNamespace(id auth.TenantID) string {
	return "tenant-" + gtenant.FromTenantID(id).Slug()
}
