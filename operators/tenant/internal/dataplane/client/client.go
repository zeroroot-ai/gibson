/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// Package client provides a per-tenant-scoped wrapper around the
// controller-runtime manager client. Its only job is to make the
// "wrote a per-tenant resource into the operator's release namespace"
// bug class — the n.ns vs tenantNS divergence that produced
// tenant-operator#57 (Neo4j dataplane writing per-tenant resources into
// the operator namespace) — statically impossible by failing the call
// loudly when it happens.
//
// Every K8s kind the operator manipulates inside per-tenant namespaces
// (Secret, ConfigMap, PVC, Service, StatefulSet, NetworkPolicy, Role,
// RoleBinding — the same set the manager-cache parity test from
// tenant-operator#81 locks) goes through this client. A Get/Create/
// Update/Patch/Delete whose target namespace equals the operator's
// release namespace returns a wrapped error with a pointer to this
// package and tenant-operator#86; tests and the runtime see identical
// behaviour.
//
// Cluster-scope or operator-ns reads (e.g. the chart-mounted
// tenant-neo4j-template ConfigMap that lives in the gibson namespace,
// or a Get on the Tenant CR) MUST go through Unscoped() with a comment
// explaining the legitimate use.
//
// PRD module: zeroroot-ai/tenant-operator#76 Module 3 / issue #86.
package client

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// Client wraps a controller-runtime client and asserts that every
// per-tenant kind is targeted at a namespace that is NOT the operator's
// release namespace.
//
// It embeds the controller-runtime Client interface so call sites that
// already use ctrlclient.Client.Status(), .RESTMapper(), .Scheme(), etc.
// keep compiling — only the 5 write/read methods are overridden to add
// the assertion. Method promotion means c.Get/c.Create/c.Update/c.Patch/
// c.Delete resolve to the override; callers can no longer accidentally
// bypass the check unless they explicitly reach for c.Unscoped().
type Client struct {
	ctrlclient.Client

	// operatorNamespace is the namespace the operator pod runs in
	// (POD_NAMESPACE → OPERATOR_NAMESPACE → "gibson"; see
	// webhook.LookupNamespace for the canonical resolver). Any per-tenant
	// kind targeted at this namespace is a programmer bug and the wrapper
	// rejects the call.
	operatorNamespace string
}

// New wraps inner with the operator-namespace assertion. operatorNamespace
// must be the live release namespace; pass an empty string only in tests
// that don't care about the assertion.
func New(inner ctrlclient.Client, operatorNamespace string) *Client {
	return &Client{Client: inner, operatorNamespace: operatorNamespace}
}

// Unscoped returns the underlying controller-runtime client without the
// per-tenant assertion. Use ONLY for legitimate operator-ns or cluster-
// scope reads; comment every call site with the reason.
//
// Legitimate callers today:
//   - dataplane/neo4j.go: reads the tenant-neo4j-template ConfigMap from
//     the gibson namespace (chart-mounted, see neo4jTemplateNamespace).
//   - dataplane/neo4j.go / neo4j_upgrade.go: Get on the Tenant CR, which
//     is cluster-scoped from the operator's POV (no Namespace).
func (c *Client) Unscoped() ctrlclient.Client { return c.Client }

// PerTenantKinds returns the canonical list of K8s kinds the operator is
// only supposed to touch inside per-tenant namespaces. This is the
// SINGLE source of truth shared with:
//
//   - the wrapper's per-call guard (perTenantKind below uses this list);
//   - cmd/main.go's manager Cache.DisableFor configuration (a sibling
//     cmd/cache_disable_for.go list MUST hold the same set, locked by
//     TestCacheKindParity_WrapperVsManager in cmd/).
//
// Adding a new in-tenant-namespace kind requires updating this slice
// and the chart's per-tenant ClusterRole at
// deploy/helm/gibson-operators/templates/tenant-operator/
// tenant-namespace-cluster-role.yaml. The cache-parity test will fail
// loudly if the cmd-side list drifts; the chart-side counterpart is
// enforced by tenant-operator#76 PRD Module 7 / deploy#181.
func PerTenantKinds() []ctrlclient.Object {
	return []ctrlclient.Object{
		&corev1.ConfigMap{},
		&corev1.Secret{},
		&corev1.PersistentVolumeClaim{},
		&corev1.Service{},
		&appsv1.StatefulSet{},
		&networkingv1.NetworkPolicy{},
		&rbacv1.Role{},
		&rbacv1.RoleBinding{},
	}
}

// perTenantKind returns true if o is one of the kinds in PerTenantKinds.
// Implemented as a type-switch (not a reflect.TypeOf loop) because the
// switch compiles to a constant-time dispatch — this fires on EVERY
// dataplane client call, so the hot-path matters.
func perTenantKind(o ctrlclient.Object) bool {
	switch o.(type) {
	case *corev1.ConfigMap, *corev1.Secret, *corev1.PersistentVolumeClaim,
		*corev1.Service, *appsv1.StatefulSet, *networkingv1.NetworkPolicy,
		*rbacv1.Role, *rbacv1.RoleBinding:
		return true
	}
	return false
}

// guard returns a non-nil error when (a) obj is a per-tenant kind and
// (b) namespace equals the operator's release namespace. The empty
// namespace case is passed through — controller-runtime will reject it
// itself with the standard "an empty namespace may not be set" error.
func (c *Client) guard(obj ctrlclient.Object, namespace, op string) error {
	if !perTenantKind(obj) {
		return nil
	}
	if c.operatorNamespace == "" {
		return nil
	}
	if namespace == c.operatorNamespace {
		return fmt.Errorf(
			"dataplane/client: refusing %s of %T in operator namespace %q — "+
				"per-tenant kinds must live in tenant namespaces "+
				"(see tenant-operator#86); use Unscoped() if this is "+
				"intentional and document why",
			op, obj, namespace,
		)
	}
	return nil
}

// Get rejects per-tenant-kind reads targeted at the operator namespace.
// Implementations that ARE supposed to read from the operator namespace
// (e.g. tenant-neo4j-template ConfigMap from gibson ns) must use
// Unscoped().Get instead.
func (c *Client) Get(ctx context.Context, key ctrlclient.ObjectKey, obj ctrlclient.Object, opts ...ctrlclient.GetOption) error {
	if err := c.guard(obj, key.Namespace, "Get"); err != nil {
		return err
	}
	return c.Client.Get(ctx, key, obj, opts...)
}

// Create rejects per-tenant-kind creates targeted at the operator namespace.
func (c *Client) Create(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
	if err := c.guard(obj, obj.GetNamespace(), "Create"); err != nil {
		return err
	}
	return c.Client.Create(ctx, obj, opts...)
}

// Update rejects per-tenant-kind updates targeted at the operator namespace.
func (c *Client) Update(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.UpdateOption) error {
	if err := c.guard(obj, obj.GetNamespace(), "Update"); err != nil {
		return err
	}
	return c.Client.Update(ctx, obj, opts...)
}

// Patch rejects per-tenant-kind patches targeted at the operator namespace.
func (c *Client) Patch(ctx context.Context, obj ctrlclient.Object, patch ctrlclient.Patch, opts ...ctrlclient.PatchOption) error {
	if err := c.guard(obj, obj.GetNamespace(), "Patch"); err != nil {
		return err
	}
	return c.Client.Patch(ctx, obj, patch, opts...)
}

// Delete rejects per-tenant-kind deletes targeted at the operator namespace.
func (c *Client) Delete(ctx context.Context, obj ctrlclient.Object, opts ...ctrlclient.DeleteOption) error {
	if err := c.guard(obj, obj.GetNamespace(), "Delete"); err != nil {
		return err
	}
	return c.Client.Delete(ctx, obj, opts...)
}
