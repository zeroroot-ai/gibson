// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
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

// The daemon pod's identifying label in the platform namespace. Both the
// Neo4j ingress rule and the daemon egress rule select on it, so they are
// named once — a NetworkPolicy peer that drops the pod selector silently
// widens to the whole namespace, and that is not visible at a glance.
const (
	daemonComponentLabel = "app.kubernetes.io/component"
	daemonComponentValue = "daemon"
)

// defaultDaemonEgressPorts are the daemon ports a tenant-namespace workload may
// dial. Keep this list minimal — every entry is a hole in the tenant's
// default-deny egress:
//
//   - 50002 — daemon gRPC API (config default GRPCAddress "localhost:50002").
//     NOTE: the Helm chart publishes the daemon's gRPC Service on 50051, so
//     this default is stale for chart-based installs. It is left as-is here
//     because the operator's DaemonPorts field is the intended override point
//     and correcting the number is a deploy-side change, not an operator one.
//   - 50100 — registration gRPC listener (infra/config: RegistrationPort).
//   - 8080  — daemon health/readiness HTTP (daemon.go: healthPort default).
//     Egress to a health endpoint is not something a tenant workload needs;
//     it is a candidate for removal once a cluster confirms nothing dials it.
//
// Narrowing the list is a separate change from narrowing the peer, and is
// tracked as follow-up on gibson#1229.
var defaultDaemonEgressPorts = []int{50002, 50100, 8080}

func (p *NamespaceProvisioner) ensureNetworkPolicy(ctx context.Context, nsName string) error {
	platformNs := p.PlatformNamespace
	if platformNs == "" {
		platformNs = "gibson-platform"
	}
	daemonPorts := p.DaemonPorts
	if len(daemonPorts) == 0 {
		daemonPorts = defaultDaemonEgressPorts
	}
	// Egress peer for the daemon ports. NamespaceSelector AND PodSelector — a
	// namespaceSelector on its own permits egress to EVERY pod in the platform
	// namespace on these ports, not just the daemon. The platform namespace
	// also holds Postgres, Redis, OpenFGA, Zitadel, OpenBao and Envoy, so the
	// broad form let any tenant workload probe the platform's own datastores.
	// This mirrors the Neo4j ingress rule below, which already ANDs the two.
	daemonPeer := []networkingv1.NetworkPolicyPeer{{
		NamespaceSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"kubernetes.io/metadata.name": platformNs},
		},
		PodSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{daemonComponentLabel: daemonComponentValue},
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
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "gibson-tenant-default-deny",
			Namespace: nsName,
			Labels:    map[string]string{"gibson.zeroroot.ai/managed-by": "tenant-operator"},
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Every pod in the tenant namespace EXCEPT the per-tenant
			// Neo4j pod, which is governed solely by its own
			// tenant-<slug>-neo4j-bolt policy (gibson#1255, ADR-0012).
			//
			// This exclusion is load-bearing, not cosmetic. Kubernetes
			// unions the effect of every policy that selects a pod, so
			// while this policy still selected the Neo4j pod its
			// intra-namespace allow-all rule below re-admitted every
			// tenant-namespace pod to bolt:7687 and the dedicated policy
			// contributed nothing. Widening this selector back to {}
			// silently un-does the restriction.
			//
			// NotIn also matches pods that carry no component label at
			// all (apimachinery labels.Requirement: absent key satisfies
			// NotIn), so nothing else loses its default-deny posture.
			PodSelector: metav1.LabelSelector{
				MatchExpressions: []metav1.LabelSelectorRequirement{{
					Key:      "app.kubernetes.io/component",
					Operator: metav1.LabelSelectorOpNotIn,
					Values:   []string{dataplane.ComponentTenantNeo4j},
				}},
			},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				// Intra-namespace: allow all pods in the tenant namespace to
				// talk to each other (Neo4j ← init sidecar, operator probes, etc.).
				{
					From: []networkingv1.NetworkPolicyPeer{{
						PodSelector: &metav1.LabelSelector{},
					}},
				},
				// The daemon → Neo4j bolt:7687 rule that used to live here
				// has moved to the dedicated per-tenant policy built by
				// dataplane.buildNeo4jNetworkPolicy (gibson#1255). It would
				// be dead config here: this policy no longer selects the
				// Neo4j pod (see PodSelector above), so a bolt rule on it
				// would grant nothing while reading as though it did.
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To:    daemonPeer,
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
