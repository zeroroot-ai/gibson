// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	gtenant "github.com/zeroroot-ai/gibson/pkg/platform/tenant"
)

// Label keys and values shared between the per-tenant Neo4j workload and
// the NetworkPolicy that fronts it. A NetworkPolicy keyed on a label the
// pod does not actually carry selects nothing and is indistinguishable
// from a working policy, so both sides read these constants rather than
// repeating string literals.
const (
	// labelKeyName / labelKeyComponent / labelKeyInstance are the
	// standard Kubernetes recommended labels the per-tenant Neo4j
	// resources carry.
	labelKeyName      = "app.kubernetes.io/name"
	labelKeyComponent = "app.kubernetes.io/component"
	labelKeyInstance  = "app.kubernetes.io/instance"

	// labelKeyTenant is the Gibson-owned tenant marker.
	labelKeyTenant = "gibson.zeroroot.ai/tenant"

	// labelKeyManagedBy marks objects the tenant-operator owns.
	labelKeyManagedBy = "gibson.zeroroot.ai/managed-by"

	// ComponentTenantNeo4j is the app.kubernetes.io/component value on
	// every per-tenant Neo4j object (StatefulSet, pod template, Service,
	// PVC, Secret, NetworkPolicy). The namespace-wide
	// gibson-tenant-default-deny policy excludes pods carrying this value
	// so the dedicated bolt policy below is the ONLY policy selecting the
	// Neo4j pod — see internal/controller/tenant_namespace.go.
	ComponentTenantNeo4j = "tenant-neo4j"

	// ComponentDaemon is the app.kubernetes.io/component value on the
	// gibson daemon StatefulSet's pod template. Verified against
	// deploy/helm/gibson-workloads/templates/gibson/statefulset.yaml.
	//
	// Beware the naming divergence in this platform: the daemon's
	// *Service* is "gibson-gibson-workloads" and a bare "gibson" Service
	// is Neo4j. Pod labels — not Service names — are what a podSelector
	// matches, and `app.kubernetes.io/component: daemon` is carried by
	// exactly one workload in the platform namespace.
	ComponentDaemon = "daemon"

	// ComponentTenantOperator is the app.kubernetes.io/component value on
	// the tenant-operator Deployment's pod template. Verified against
	// deploy/helm/gibson-operators/templates/tenant-operator/deployment.yaml.
	//
	// The operator is admitted as a second bolt peer (ADR-0012, gibson#1262)
	// because ProductionVersionReader.Neo4j dials each tenant's bolt endpoint
	// from the operator to read the :_SchemaVersion node for the
	// gibson_tenant_migration_pending metric. This does not widen the trust
	// boundary the policy narrows: the operator already reads every tenant's
	// NEO4J_AUTH Secret and constructs the bolt driver with it, so it already
	// holds the (unconditionally admin, on Neo4j Community) credential. The
	// peer only aligns the network layer with a code path that already exists.
	ComponentTenantOperator = "tenant-operator"

	// labelKeyNamespaceName is the label the Kubernetes apiserver stamps
	// on every Namespace (NamespaceDefaultLabelName, GA since 1.22). It
	// is the only namespace label guaranteed to exist without chart
	// cooperation, so cross-namespace peers select on it.
	labelKeyNamespaceName = "kubernetes.io/metadata.name"

	// kubeSystemNamespace hosts CoreDNS.
	kubeSystemNamespace = "kube-system"

	// dnsPort is the CoreDNS service port.
	dnsPort = 53
)

// neo4jLabels returns the label set stamped on every per-tenant Neo4j
// object AND used as the NetworkPolicy podSelector. Both call sites read
// this one function so the policy can never drift into selecting nothing.
func neo4jLabels(tenantID, tenantNS string) map[string]string {
	return map[string]string{
		labelKeyName:      "neo4j",
		labelKeyComponent: ComponentTenantNeo4j,
		labelKeyInstance:  tenantNS,
		labelKeyTenant:    tenantID,
	}
}

// buildNeo4jNetworkPolicy returns the NetworkPolicy that fronts a tenant's
// Neo4j pod: bolt ingress from the gibson daemon only, egress denied
// except DNS.
//
// Why this exists (ADR-0012, gibson#1255). This is defence in depth, NOT
// the primary control. The primary control is that the graph projector is
// the sole writer. The policy earns its place because Neo4j Community
// edition has no in-database RBAC — whoever holds the bolt credential is
// effectively admin on that database — so the cluster network layer is the
// only place any restriction can be expressed at all.
//
// IMPORTANT: this policy is INERT until the CNI enforces NetworkPolicy.
// The AWS VPC CNI addon ships with enableNetworkPolicy off, and kind's
// default CNI does not implement NetworkPolicy either. Nothing here is
// protecting anything today; it takes effect the moment enforcement is
// turned on, and not before.
//
// Peer semantics that matter: each ingress peer carries BOTH a
// NamespaceSelector and a PodSelector, which Kubernetes ANDs together
// ("daemon pods in the platform namespace"). The two peers in the From
// list are ORed with each other, admitting the daemon OR the operator —
// but neither peer's own namespace+pod pair may be split into two From
// entries, which would OR them instead and admit every pod in the
// platform namespace plus every so-labelled pod cluster-wide.
//
// Two peers, not one (ADR-0012, gibson#1262): the daemon is the single
// writer, and the tenant-operator is admitted as a read-only second peer
// so its migration-version probe (ProductionVersionReader.Neo4j) can reach
// bolt under an enforcing CNI. See the ComponentTenantOperator note for why
// this does not widen the boundary — the operator already holds the bolt
// credential it reads from the tenant's NEO4J_AUTH Secret.
//
// Egress: the issue asks for default-deny. A literal zero-rule egress
// block would also cut DNS, and the Neo4j JVM resolves its own advertised
// address at startup — that would brick every tenant graph on the day
// enforcement is enabled, with no prior signal because the policy is inert
// until then. DNS to kube-system is therefore the single exception, which
// is the same shape the namespace-wide policy already uses and grants no
// route to any tenant's data.
func buildNeo4jNetworkPolicy(names gtenant.Names, tenantID, tenantNS, platformNS string) *networkingv1.NetworkPolicy {
	if platformNS == "" {
		platformNS = neo4jTemplateNamespace
	}

	protoTCP := corev1.ProtocolTCP
	protoUDP := corev1.ProtocolUDP
	bolt := intstr.FromInt(neo4jBoltPort)
	dns := intstr.FromInt(dnsPort)

	labels := neo4jLabels(tenantID, tenantNS)
	policyLabels := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		policyLabels[k] = v
	}
	policyLabels[labelKeyManagedBy] = "tenant-operator"

	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      names.Neo4jNetworkPolicy(),
			Namespace: tenantNS,
			Labels:    policyLabels,
		},
		Spec: networkingv1.NetworkPolicySpec{
			// Selects the Neo4j pod, and only the Neo4j pod.
			PodSelector: metav1.LabelSelector{MatchLabels: labels},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{{
				From: []networkingv1.NetworkPolicyPeer{
					{
						// AND — see the peer-semantics note above. Do not
						// split this into two From entries. The daemon: the
						// single writer.
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{labelKeyNamespaceName: platformNS},
						},
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{labelKeyComponent: ComponentDaemon},
						},
					},
					{
						// AND — the tenant-operator: read-only migration-version
						// probe (ADR-0012, gibson#1262). Same platform namespace,
						// operator component. Do not split into two From entries.
						NamespaceSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{labelKeyNamespaceName: platformNS},
						},
						PodSelector: &metav1.LabelSelector{
							MatchLabels: map[string]string{labelKeyComponent: ComponentTenantOperator},
						},
					},
				},
				Ports: []networkingv1.NetworkPolicyPort{{
					Protocol: &protoTCP,
					Port:     &bolt,
				}},
			}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{{
					NamespaceSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{labelKeyNamespaceName: kubeSystemNamespace},
					},
				}},
				Ports: []networkingv1.NetworkPolicyPort{
					{Protocol: &protoUDP, Port: &dns},
					{Protocol: &protoTCP, Port: &dns},
				},
			}},
		},
	}
}
