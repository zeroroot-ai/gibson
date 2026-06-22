/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/saga"
)

// Operator ServiceAccount identity. The Helm chart creates this SA in
// the platform namespace and binds it to the manager-role ClusterRole.
// Per-tenant-namespace Roles bind the same SA so the operator can read
// and mutate Secrets only inside Gibson-owned namespaces.
const (
	defaultOperatorSAName      = "tenant-operator"
	defaultOperatorSANamespace = "gibson-platform"

	// envOperatorSAName / envOperatorSANamespace let the chart override
	// the defaults without recompiling. The chart sets these via the
	// Deployment spec.
	envOperatorSAName      = "OPERATOR_SERVICE_ACCOUNT_NAME"
	envOperatorSANamespace = "OPERATOR_SERVICE_ACCOUNT_NAMESPACE"

	// tenantOperatorRoleName is the per-tenant-namespace Role granting
	// the operator the verbs it needs on every per-tenant resource it
	// manages inside that namespace. Spec
	// secrets-blast-radius-reduction Phase 1.2 expanded the rules from
	// secrets-only to the full 8-resource set (secrets, configmaps,
	// services, PVCs, resourcequotas, statefulsets, networkpolicies,
	// roles+rolebindings).
	//
	// Backwards-compat: the previous name `gibson-tenant-operator-secrets`
	// is preserved as a Role const so the chart's pre-upgrade backfill
	// Job can identify and delete the old narrow Role on existing
	// tenant namespaces.
	tenantOperatorRoleName        = "gibson-tenant-operator"
	tenantOperatorRoleBindingName = "gibson-tenant-operator"
	legacyTenantSecretRoleName    = "gibson-tenant-operator-secrets"

	// tenantOperatorNamespaceClusterRole is the chart-rendered
	// ClusterRole every per-tenant RoleBinding references. Holds the
	// 8-resource rule set (secrets / configmaps / services / PVCs /
	// resourcequotas / statefulsets / networkpolicies / roles +
	// rolebindings) the operator needs inside each tenant namespace.
	//
	// The operator binds this ClusterRole into the tenant namespace via
	// a RoleBinding rather than minting a tenant-local Role: that keeps
	// the chart's "spec secrets-blast-radius-reduction" intent (Role
	// rules aren't editable at runtime by a compromised operator) while
	// avoiding the bootstrap chicken-and-egg where the operator can't
	// CREATE a per-tenant Role without cluster-wide roles/create +
	// escalate permissions.
	//
	// Chart template: helm/gibson-operators/templates/tenant-operator/
	// tenant-namespace-cluster-role.yaml. Must stay name-aligned with
	// the chart.
	tenantOperatorNamespaceClusterRole = "gibson-tenant-operator-tenant-namespace"
)

// Annotation keys the operator writes on tenant namespaces so downstream
// controllers (AgentEnrollment/TenantMember) and the mutating
// admission webhook can resolve the parent Tenant without needing a cluster-
// scoped Get on every child reconcile.
const (
	// AnnotationOwnerTenantUID is the parent Tenant.metadata.uid.
	AnnotationOwnerTenantUID = "gibson.zeroroot.ai/owner-tenant-uid"
	// AnnotationOwnerTenantName is the parent Tenant.metadata.name.
	AnnotationOwnerTenantName = "gibson.zeroroot.ai/owner-tenant-name"
)

// NamespaceProvisioner holds the configuration needed for the
// namespace/NetworkPolicy/ResourceQuota provisioning step.
//
// It satisfies saga.Step so the runner can drive it directly without an
// adapter — the embedded saga.StepBase supplies the boilerplate methods.
type NamespaceProvisioner struct {
	saga.StepBase

	Client            client.Client
	PlatformNamespace string // e.g. "gibson-platform"
	DaemonPorts       []int  // e.g. {50002, 50100, 8080}
}

// NewNamespaceProvisioner builds a step-shaped NamespaceProvisioner with
// the canonical Name + Condition + capability declarations.
func NewNamespaceProvisioner(c client.Client, platformNamespace string, daemonPorts []int) *NamespaceProvisioner {
	return &NamespaceProvisioner{
		StepBase: saga.StepBase{
			N:    "ProvisionNamespace",
			C:    gibsonv1alpha1.ConditionNamespaceProvisioned,
			Caps: []saga.ClientCapability{saga.CapabilityKubernetes},
		},
		Client:            c,
		PlatformNamespace: platformNamespace,
		DaemonPorts:       daemonPorts,
	}
}

// Step is kept for backward compatibility with existing callers — it
// returns the receiver, since the receiver itself implements saga.Step.
func (p *NamespaceProvisioner) Step() saga.Step { return p }

// Provision implements saga.Step.
func (p *NamespaceProvisioner) Provision(ctx context.Context, obj saga.ConditionedObject, _ *saga.Deps) (bool, error) {
	t, ok := obj.(*gibsonv1alpha1.Tenant)
	if !ok {
		return false, fmt.Errorf("ProvisionNamespace: expected *Tenant, got %T", obj)
	}
	nsName := fmt.Sprintf("tenant-%s", t.Name)

	if err := p.ensureNamespace(ctx, t, nsName); err != nil {
		return false, fmt.Errorf("ensure namespace: %w", err)
	}
	// Order matters: the per-tenant RoleBinding must exist BEFORE the
	// NetworkPolicy create, because the operator's cluster-scope RBAC
	// deliberately omits networkpolicies. The RoleBinding points at the
	// chart-rendered ClusterRole `gibson-tenant-operator-tenant-namespace`,
	// which grants the operator the verbs it needs inside this namespace.
	// Without the binding being created first, the next step's NP create
	// fails RBAC and the saga loops.
	if err := p.ensureTenantNamespaceRBAC(ctx, nsName); err != nil {
		return false, fmt.Errorf("ensure tenant-namespace RBAC: %w", err)
	}
	if err := p.ensureNetworkPolicy(ctx, nsName); err != nil {
		return false, fmt.Errorf("ensure networkpolicy: %w", err)
	}
	// Per-tenant K8s ResourceQuota was removed by spec
	// plans-and-quotas-simplification: per-tenant resource consumption is
	// bounded by daemon quota enforcement (concurrent_missions /
	// concurrent_agents) plus the fixed shape of operator-managed data-plane
	// infra. The chart's remove-orphan-resource-quotas pre-upgrade Job
	// deletes any leftover gibson-tenant-quota objects from prior installs.

	// Record namespace in status for later phases and UI.
	t.Status.Namespace = nsName
	return true, nil
}

func (p *NamespaceProvisioner) ensureNamespace(ctx context.Context, t *gibsonv1alpha1.Tenant, nsName string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: nsName,
			Labels: map[string]string{
				"gibson.zeroroot.ai/tenant":     t.Name,
				"gibson.zeroroot.ai/managed-by": "tenant-operator",
				"gibson.zeroroot.ai/tier":       string(t.Spec.Tier),
			},
			Annotations: map[string]string{
				"gibson.zeroroot.ai/tenant-display-name": t.Spec.DisplayName,
				"gibson.zeroroot.ai/tenant-owner":        t.Spec.Owner,
				AnnotationOwnerTenantUID:                 string(t.UID),
				AnnotationOwnerTenantName:                t.Name,
			},
		},
	}
	existing := &corev1.Namespace{}
	err := p.Client.Get(ctx, types.NamespacedName{Name: nsName}, existing)
	if apierrors.IsNotFound(err) {
		return p.Client.Create(ctx, ns)
	}
	if err != nil {
		return err
	}
	// Merge labels/annotations without clobbering user additions.
	changed := mergeMap(existing.Labels, ns.Labels)
	if mergeMap(existing.Annotations, ns.Annotations) {
		changed = true
	}
	if changed {
		return p.Client.Update(ctx, existing)
	}
	return nil
}

func (p *NamespaceProvisioner) ensureNetworkPolicy(ctx context.Context, nsName string) error {
	platformNs := p.PlatformNamespace
	if platformNs == "" {
		platformNs = "gibson-platform"
	}
	daemonPorts := p.DaemonPorts
	if len(daemonPorts) == 0 {
		daemonPorts = []int{50002, 50100, 8080}
	}
	peers := []networkingv1.NetworkPolicyPeer{{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": platformNs},
		},
	}}
	ports := make([]networkingv1.NetworkPolicyPort, 0, len(daemonPorts)+1)
	for _, port := range daemonPorts {
		p := intstr.FromInt(port)
		proto := corev1.ProtocolTCP
		ports = append(ports, networkingv1.NetworkPolicyPort{Protocol: &proto, Port: &p})
	}
	// DNS
	dnsPort := intstr.FromInt(53)
	protoTCP := corev1.ProtocolTCP
	protoUDP := corev1.ProtocolUDP
	kubeSystemPeer := networkingv1.NetworkPolicyPeer{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		},
	}
	// Neo4j bolt port — the daemon dials 7687 from the platform namespace for
	// per-tenant graph sessions. Must be opened inbound here because the
	// default-deny policy otherwise blocks all cross-namespace ingress and
	// every graph query fails with ConnectivityError timeout.
	neo4jBoltPort := intstr.FromInt(7687)

	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gibson-tenant-default-deny",
			Namespace: nsName,
			Labels:    map[string]string{"gibson.zeroroot.ai/managed-by": "tenant-operator"},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				// Intra-namespace: allow all pods in the tenant namespace to
				// talk to each other (Neo4j ← init sidecar, operator probes, etc.).
				{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{},
					}},
				},
				// Cross-namespace: allow the daemon pod in the platform namespace
				// to reach Neo4j on bolt port 7687. The AND of namespaceSelector +
				// podSelector means "only daemon pods in the platform namespace" —
				// neither alone is sufficient for least-privilege.
				{
					From: []networkingv1.NetworkPolicyPeer{{
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"kubernetes.io/metadata.name": platformNs},
						},
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"app.kubernetes.io/component": "daemon"},
						},
					}},
					Ports: []networkingv1.NetworkPolicyPort{{
						Protocol: &protoTCP,
						Port:     &neo4jBoltPort,
					}},
				},
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To:    peers,
					Ports: ports,
				},
				{
					To: []networkingv1.NetworkPolicyPeer{kubeSystemPeer},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &protoUDP, Port: &dnsPort},
						{Protocol: &protoTCP, Port: &dnsPort},
					},
				},
			},
		},
	}

	existing := &networkingv1.NetworkPolicy{}
	err := p.Client.Get(ctx, types.NamespacedName{Namespace: nsName, Name: np.Name}, existing)
	if apierrors.IsNotFound(err) {
		return p.Client.Create(ctx, np)
	}
	if err != nil {
		return err
	}
	existing.Spec = np.Spec
	existing.Labels = np.Labels
	return p.Client.Update(ctx, existing)
}

// mergeMap merges src into dst, returning true if dst changed.
func mergeMap(dst, src map[string]string) bool {
	if dst == nil {
		return false
	}
	changed := false
	for k, v := range src {
		if existing, ok := dst[k]; !ok || existing != v {
			dst[k] = v
			changed = true
		}
	}
	return changed
}

// ensureTenantNamespaceRBAC provisions the per-namespace Role + RoleBinding
// that grants the operator's ServiceAccount the minimal Secret verbs it
// actually exercises (create, get, delete) — scoped to this tenant
// namespace only. Replaces the cluster-wide secrets ClusterRole grant
// removed from tenant_controller.go's kubebuilder markers.
//
// Verbs enumerated below match the controller code paths today:
//   - Create: tenantmember_controller.go:193 (invitation Secret issue).
//   - Get:    tenantmember_controller.go:234 (invitation resend read-back).
//   - Delete: tenantmember_controller.go:271, :287 (invitation burn).
//
// Add new verbs here only after confirming a code path uses them; do
// not pre-emptively grant list/watch/patch/update.
func (p *NamespaceProvisioner) ensureTenantNamespaceRBAC(ctx context.Context, nsName string) error {
	saName := os.Getenv(envOperatorSAName)
	if saName == "" {
		saName = defaultOperatorSAName
	}
	saNamespace := os.Getenv(envOperatorSANamespace)
	if saNamespace == "" {
		saNamespace = p.PlatformNamespace
	}
	if saNamespace == "" {
		saNamespace = defaultOperatorSANamespace
	}

	// Bind the chart-rendered ClusterRole into this namespace. The
	// previous design minted a per-tenant Role (with the rule set
	// returned by perTenantNamespaceRules), but that required the
	// operator to hold cluster-wide roles/create + escalate — a wide
	// privilege the chart's secrets-blast-radius-reduction spec
	// intentionally withheld. A RoleBinding referencing a fixed
	// ClusterRole needs only `rolebindings/create` + `clusterroles/bind`
	// (and only for THIS one ClusterRole name), preserving the spec's
	// narrowing while letting the saga bootstrap.
	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      tenantOperatorRoleBindingName,
			Namespace: nsName,
			Labels: map[string]string{
				"gibson.zeroroot.ai/managed-by": "tenant-operator",
			},
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      saName,
			Namespace: saNamespace,
		}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     tenantOperatorNamespaceClusterRole,
		},
	}
	if err := p.upsertRoleBinding(ctx, rb); err != nil {
		return fmt.Errorf("upsert RoleBinding %s/%s: %w", nsName, tenantOperatorRoleBindingName, err)
	}

	// Best-effort delete the legacy narrow Role+RoleBinding from
	// pre-spec installs AND the per-tenant Role from the earlier
	// "mint a tenant-local Role" design. Idempotent: NotFound is success.
	_ = p.Client.Delete(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name: tenantOperatorRoleName, Namespace: nsName,
	}})
	_ = p.Client.Delete(ctx, &rbacv1.Role{ObjectMeta: metav1.ObjectMeta{
		Name: legacyTenantSecretRoleName, Namespace: nsName,
	}})
	_ = p.Client.Delete(ctx, &rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
		Name: legacyTenantSecretRoleName + "-binding", Namespace: nsName,
	}})
	return nil
}

// TenantNamespaceForBackfill returns the per-tenant namespace name used by
// the operator. Exposed so the cmd/backfill-rbac binary can compute the
// same name without duplicating the logic. Stays in sync with the inline
// `tenant-<name>` convention in Provision().
func TenantNamespaceForBackfill(t *gibsonv1alpha1.Tenant) string {
	return fmt.Sprintf("tenant-%s", t.Name)
}

// EnsureTenantNamespaceRBACPublic is the package-exported entry point for
// the backfill binary. Wraps the unexported method so the binary can run
// outside the saga flow on existing tenants.
func (p *NamespaceProvisioner) EnsureTenantNamespaceRBACPublic(ctx context.Context, nsName string) error {
	return p.ensureTenantNamespaceRBAC(ctx, nsName)
}

// The operator's per-tenant rule set lives in the chart-rendered
// ClusterRole `gibson-tenant-operator-tenant-namespace`. See
// helm/gibson-operators/templates/tenant-operator/tenant-namespace-cluster-role.yaml.
//
// Eight resource families — full CRUD on all of them:
//
//	core/v1                  secrets, configmaps, services, persistentvolumeclaims, resourcequotas
//	apps/v1                  statefulsets
//	networking.k8s.io/v1     networkpolicies
//	rbac.authorization.k8s.io/v1  roles, rolebindings
//
// Adding a new resource family the operator manages inside tenant
// namespaces means editing that ClusterRole template (and, if the
// resource is governed by an admission-time check, also adjusting
// the chart's ext-authz / FGA tuple seeds).

// upsertRoleBinding creates the RoleBinding when absent, otherwise patches
// Subjects+RoleRef+Labels. RoleRef is immutable in Kubernetes; if the
// existing binding's RoleRef differs we recreate.
func (p *NamespaceProvisioner) upsertRoleBinding(ctx context.Context, want *rbacv1.RoleBinding) error {
	existing := &rbacv1.RoleBinding{}
	err := p.Client.Get(ctx, types.NamespacedName{Namespace: want.Namespace, Name: want.Name}, existing)
	if apierrors.IsNotFound(err) {
		return p.Client.Create(ctx, want)
	}
	if err != nil {
		return err
	}
	if existing.RoleRef != want.RoleRef {
		// RoleRef is immutable; delete + recreate.
		if err := p.Client.Delete(ctx, existing); err != nil {
			return fmt.Errorf("delete RoleBinding for RoleRef change: %w", err)
		}
		return p.Client.Create(ctx, want)
	}
	existing.Subjects = want.Subjects
	existing.Labels = want.Labels
	return p.Client.Update(ctx, existing)
}
