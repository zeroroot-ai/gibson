// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// cache_disable_for.go — single source of truth for which K8s types the
// operator's controller-runtime manager cache must NOT informer-watch
// cluster-wide. Extracted from main.go so a unit test in
// cache_disable_for_test.go can lock the invariant.
//
// Why this matters: controller-runtime's typed cache lazily registers a
// cluster-wide LIST/WATCH informer the first time client.Get/List sees a
// kind. The operator only holds those verbs at the per-tenant Role level
// (spec: secrets-blast-radius-reduction Phase 1.1, mirrored by
// deploy/helm/gibson-operators/templates/tenant-operator/cluster-role.yaml).
// A type that's used through the manager client but NOT in DisableFor
// here causes the reflector to retry the cluster-scope LIST forever,
// the cache to never sync, and every reconciler to silently never
// dispatch. Diagnosed today as tenant-operator#49 (PVC), #57 (Service +
// StatefulSet — Neo4j dataplane), and tracked under #76 PRD Module 2.

package main

import (
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// perTenantNamespaceCacheDisableTypes lists every K8s kind the operator
// instantiates through the manager client that lives in per-tenant
// namespaces (or otherwise outside the operator's cluster-scope RBAC).
// Each MUST be in the manager's Cache.DisableFor list.
//
// Adding a new in-tenant-namespace kind to operator code (e.g. an Ingress,
// a HorizontalPodAutoscaler) requires both (a) appending to this list and
// (b) granting verbs in the per-tenant ClusterRole at
// deploy/helm/gibson-operators/templates/tenant-operator/tenant-namespace-cluster-role.yaml.
// TestCacheDisableForParity enforces (a); the chart-side counterpart is
// a deploy-repo CI concern (tenant-operator#76 PRD Module 7).
func perTenantNamespaceCacheDisableTypes() []client.Object {
	return []client.Object{
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
