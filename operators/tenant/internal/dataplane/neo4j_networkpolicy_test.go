// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package dataplane

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	dpclient "github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane/client"
)

// ---------------------------------------------------------------------------
// A small NetworkPolicy evaluator.
//
// These tests deliberately do NOT assert on the policy struct field by
// field. A field-mirror test passes for any policy that happens to be
// shaped like the code that produced it, including one whose podSelector
// matches no pod at all — which on a live cluster is indistinguishable
// from a working policy. Instead the tests below ask the questions an
// operator would ask ("can THIS pod reach bolt on THAT pod?") and answer
// them with real apimachinery selector semantics, so any mutation of the
// selectors, the peer structure, or the ports changes an answer.
// ---------------------------------------------------------------------------

// podRef is a candidate traffic source or target.
type podRef struct {
	desc      string
	namespace string
	nsLabels  map[string]string
	podLabels map[string]string
}

// selects reports whether np's spec.podSelector selects pod. A policy only
// governs pods in its own namespace.
func selects(t *testing.T, np *networkingv1.NetworkPolicy, pod podRef) bool {
	t.Helper()
	if np.Namespace != pod.namespace {
		return false
	}
	sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		t.Fatalf("podSelector is not a valid selector: %v", err)
	}
	return sel.Matches(labels.Set(pod.podLabels))
}

// peerMatches implements networking.k8s.io/v1 NetworkPolicyPeer semantics:
// namespaceSelector and podSelector inside ONE peer are ANDed; a nil
// namespaceSelector means "the policy's own namespace".
func peerMatches(t *testing.T, peer networkingv1.NetworkPolicyPeer, policyNS string, src podRef) bool {
	t.Helper()
	if peer.IPBlock != nil {
		// Not modelled — no rule in this policy uses ipBlock.
		return false
	}
	if peer.NamespaceSelector == nil && peer.PodSelector == nil {
		return false
	}
	if peer.NamespaceSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.NamespaceSelector)
		if err != nil {
			t.Fatalf("peer namespaceSelector invalid: %v", err)
		}
		if !sel.Matches(labels.Set(src.nsLabels)) {
			return false
		}
	} else if src.namespace != policyNS {
		return false
	}
	if peer.PodSelector != nil {
		sel, err := metav1.LabelSelectorAsSelector(peer.PodSelector)
		if err != nil {
			t.Fatalf("peer podSelector invalid: %v", err)
		}
		if !sel.Matches(labels.Set(src.podLabels)) {
			return false
		}
	}
	return true
}

func portAllowed(ports []networkingv1.NetworkPolicyPort, port int, proto corev1.Protocol) bool {
	if len(ports) == 0 {
		return true // empty ports = every port
	}
	for _, p := range ports {
		if p.Protocol != nil && *p.Protocol != proto {
			continue
		}
		if p.Port == nil {
			return true
		}
		if int(p.Port.IntVal) == port {
			return true
		}
	}
	return false
}

// admitsIngress reports whether any policy in the set admits src → the
// selected pod on port. Kubernetes UNIONs every policy that selects the
// target pod, so the caller passes every policy in play.
func admitsIngress(t *testing.T, policies []*networkingv1.NetworkPolicy, target, src podRef, port int) bool {
	t.Helper()
	for _, np := range policies {
		if !selects(t, np, target) {
			continue
		}
		governsIngress := false
		for _, pt := range np.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeIngress {
				governsIngress = true
			}
		}
		if !governsIngress {
			continue
		}
		for _, rule := range np.Spec.Ingress {
			if !portAllowed(rule.Ports, port, corev1.ProtocolTCP) {
				continue
			}
			if len(rule.From) == 0 {
				return true // empty from = every source
			}
			for _, peer := range rule.From {
				if peerMatches(t, peer, np.Namespace, src) {
					return true
				}
			}
		}
	}
	return false
}

// admitsEgress is the mirror of admitsIngress for the outbound direction.
func admitsEgress(t *testing.T, np *networkingv1.NetworkPolicy, dst podRef, port int, proto corev1.Protocol) bool {
	t.Helper()
	for _, rule := range np.Spec.Egress {
		if !portAllowed(rule.Ports, port, proto) {
			continue
		}
		if len(rule.To) == 0 {
			return true
		}
		for _, peer := range rule.To {
			if peerMatches(t, peer, np.Namespace, dst) {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const (
	testPlatformNS = "gibson"
	testTenantID   = "acme"
	testTenantNS   = "tenant-acme"
)

func nsLabels(name string) map[string]string {
	return map[string]string{labelKeyNamespaceName: name}
}

// buildTestNeo4j runs the real provisioner build path so the NetworkPolicy
// and the StatefulSet under test come from the same code that runs in
// production. The Neo4j pod's labels are read back off the StatefulSet's
// pod template — never hand-written here — so a change that makes the
// policy's podSelector diverge from the pod's actual labels fails the
// "selects the Neo4j pod" assertion instead of silently passing.
func buildTestNeo4j(t *testing.T) (*appsv1.StatefulSet, *networkingv1.NetworkPolicy) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()

	n := &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(k8s, ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
	}}
	sts, _, _, _, np := n.buildResources(context.Background(), testTenantID, testTenantID, "team", testTenantNS, "pw")
	if sts == nil || np == nil {
		t.Fatal("buildResources returned nil StatefulSet or NetworkPolicy")
	}
	return sts, np
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestNeo4jNetworkPolicySelectsTheNeo4jPodOnly fails if the policy's
// podSelector drifts from the labels the Neo4j pod actually carries (which
// would select nothing and protect nothing), or if it widens to cover pods
// it must not govern.
func TestNeo4jNetworkPolicySelectsTheNeo4jPodOnly(t *testing.T) {
	t.Parallel()
	sts, np := buildTestNeo4j(t)

	neo4jPod := podRef{
		desc:      "this tenant's Neo4j pod",
		namespace: testTenantNS,
		nsLabels:  nsLabels(testTenantNS),
		podLabels: sts.Spec.Template.Labels,
	}
	if !selects(t, np, neo4jPod) {
		t.Fatalf("policy podSelector %v does not select the Neo4j pod labels %v — "+
			"a policy that selects nothing looks identical to a working one",
			np.Spec.PodSelector, sts.Spec.Template.Labels)
	}

	mustNotSelect := []podRef{
		{
			desc:      "an unrelated workload in the same tenant namespace",
			namespace: testTenantNS,
			nsLabels:  nsLabels(testTenantNS),
			podLabels: map[string]string{labelKeyName: "some-agent"},
		},
		{
			desc:      "another tenant's Neo4j pod",
			namespace: "tenant-evil",
			nsLabels:  nsLabels("tenant-evil"),
			podLabels: neo4jLabels("evil", "tenant-evil"),
		},
		{
			desc:      "the platform Neo4j in the platform namespace",
			namespace: testPlatformNS,
			nsLabels:  nsLabels(testPlatformNS),
			podLabels: map[string]string{labelKeyName: "neo4j", labelKeyComponent: "neo4j"},
		},
	}
	for _, pod := range mustNotSelect {
		if selects(t, np, pod) {
			t.Errorf("policy must not select %s", pod.desc)
		}
	}
}

// TestNeo4jNetworkPolicyAdmitsOnlyTheDaemonOnBolt drives the policy with a
// table of would-be clients. Each denied row corresponds to a concrete way
// the policy could be got wrong — most importantly, splitting the single
// namespaceSelector+podSelector peer into two `from` entries turns the AND
// into an OR and flips the "platform-namespace non-daemon" and
// "daemon-labelled pod in the tenant namespace" rows to allowed.
func TestNeo4jNetworkPolicyAdmitsOnlyTheDaemonOnBolt(t *testing.T) {
	t.Parallel()
	sts, np := buildTestNeo4j(t)

	target := podRef{
		namespace: testTenantNS,
		nsLabels:  nsLabels(testTenantNS),
		podLabels: sts.Spec.Template.Labels,
	}
	policies := []*networkingv1.NetworkPolicy{np}

	daemon := podRef{
		desc:      "the gibson daemon in the platform namespace",
		namespace: testPlatformNS,
		nsLabels:  nsLabels(testPlatformNS),
		podLabels: map[string]string{labelKeyComponent: ComponentDaemon},
	}

	cases := []struct {
		src   podRef
		port  int
		allow bool
	}{
		{src: daemon, port: neo4jBoltPort, allow: true},

		// Bolt is the only port opened; Neo4j's HTTP/browser port is not.
		{src: daemon, port: 7474, allow: false},

		// The tenant-operator is the second admitted peer (ADR-0012,
		// gibson#1262): it dials bolt to read :_SchemaVersion for the
		// migration-version metric. Same platform namespace, operator
		// component.
		{
			src: podRef{
				desc:      "the tenant-operator in the platform namespace",
				namespace: testPlatformNS,
				nsLabels:  nsLabels(testPlatformNS),
				podLabels: map[string]string{labelKeyComponent: ComponentTenantOperator},
			},
			port: neo4jBoltPort, allow: true,
		},
		// The operator peer is bolt-only, exactly like the daemon peer.
		{
			src: podRef{
				desc:      "the tenant-operator on Neo4j's HTTP/browser port",
				namespace: testPlatformNS,
				nsLabels:  nsLabels(testPlatformNS),
				podLabels: map[string]string{labelKeyComponent: ComponentTenantOperator},
			},
			port: 7474, allow: false,
		},
		// Operator label but in the tenant namespace, not the platform
		// namespace — catches an operator peer that dropped its
		// namespaceSelector (the AND collapsing to an OR).
		{
			src: podRef{
				desc:      "an operator-labelled pod inside the tenant namespace",
				namespace: testTenantNS,
				nsLabels:  nsLabels(testTenantNS),
				podLabels: map[string]string{labelKeyComponent: ComponentTenantOperator},
			},
			port: neo4jBoltPort, allow: false,
		},
		{
			src: podRef{
				desc:      "the dashboard in the platform namespace",
				namespace: testPlatformNS,
				nsLabels:  nsLabels(testPlatformNS),
				podLabels: map[string]string{labelKeyComponent: "dashboard"},
			},
			port: neo4jBoltPort, allow: false,
		},

		// Carries the daemon label but lives in the tenant namespace —
		// exactly what an attacker who can create a pod would try.
		// Catches a peer list that drops the namespaceSelector.
		{
			src: podRef{
				desc:      "a daemon-labelled pod inside the tenant namespace",
				namespace: testTenantNS,
				nsLabels:  nsLabels(testTenantNS),
				podLabels: map[string]string{labelKeyComponent: ComponentDaemon},
			},
			port: neo4jBoltPort, allow: false,
		},
		{
			src: podRef{
				desc:      "a daemon-labelled pod in an unrelated namespace",
				namespace: "default",
				nsLabels:  nsLabels("default"),
				podLabels: map[string]string{labelKeyComponent: ComponentDaemon},
			},
			port: neo4jBoltPort, allow: false,
		},

		// Co-tenant workloads. This is the class ADR-0012 cares about.
		{
			src: podRef{
				desc:      "an unrelated pod in the same tenant namespace",
				namespace: testTenantNS,
				nsLabels:  nsLabels(testTenantNS),
				podLabels: map[string]string{labelKeyName: "some-agent"},
			},
			port: neo4jBoltPort, allow: false,
		},
		{
			src: podRef{
				desc:      "another tenant's Neo4j pod",
				namespace: "tenant-evil",
				nsLabels:  nsLabels("tenant-evil"),
				podLabels: neo4jLabels("evil", "tenant-evil"),
			},
			port: neo4jBoltPort, allow: false,
		},
	}

	for _, tc := range cases {
		got := admitsIngress(t, policies, target, tc.src, tc.port)
		if got != tc.allow {
			t.Errorf("bolt-port %d from %s: admitted=%v, want %v", tc.port, tc.src.desc, got, tc.allow)
		}
	}
}

// TestNeo4jNetworkPolicyEgressIsDeniedExceptDNS pins the egress posture:
// PolicyTypes must declare Egress (without it the block is inert) and only
// DNS to kube-system may pass.
func TestNeo4jNetworkPolicyEgressIsDeniedExceptDNS(t *testing.T) {
	t.Parallel()
	_, np := buildTestNeo4j(t)

	governsEgress := false
	for _, pt := range np.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			governsEgress = true
		}
	}
	if !governsEgress {
		t.Fatal("policyTypes must include Egress; without it no egress is restricted at all")
	}

	kubeSystem := podRef{
		namespace: kubeSystemNamespace,
		nsLabels:  nsLabels(kubeSystemNamespace),
		podLabels: map[string]string{"k8s-app": "kube-dns"},
	}
	if !admitsEgress(t, np, kubeSystem, dnsPort, corev1.ProtocolUDP) {
		t.Error("DNS egress to kube-system must be allowed; a total block would fail Neo4j startup name resolution")
	}

	denied := []struct {
		desc  string
		dst   podRef
		port  int
		proto corev1.Protocol
	}{
		{
			desc: "another tenant's Neo4j",
			dst: podRef{
				namespace: "tenant-evil",
				nsLabels:  nsLabels("tenant-evil"),
				podLabels: neo4jLabels("evil", "tenant-evil"),
			},
			port: neo4jBoltPort, proto: corev1.ProtocolTCP,
		},
		{
			desc: "the platform namespace",
			dst: podRef{
				namespace: testPlatformNS,
				nsLabels:  nsLabels(testPlatformNS),
				podLabels: map[string]string{labelKeyComponent: ComponentDaemon},
			},
			port: 50051, proto: corev1.ProtocolTCP,
		},
		{
			desc: "kube-system on a non-DNS port",
			dst: podRef{
				namespace: kubeSystemNamespace,
				nsLabels:  nsLabels(kubeSystemNamespace),
				podLabels: map[string]string{"k8s-app": "kube-dns"},
			},
			port: 443, proto: corev1.ProtocolTCP,
		},
	}
	for _, tc := range denied {
		if admitsEgress(t, np, tc.dst, tc.port, tc.proto) {
			t.Errorf("egress to %s (port %d) must be denied", tc.desc, tc.port)
		}
	}
}

// TestNeo4jNetworkPolicyPlatformNamespaceIsHonoured guards the naming trap:
// if PlatformNamespace is misread the policy still renders and still looks
// correct, but admits nothing. Two different platform namespaces must
// produce two different verdicts for the same daemon pod.
func TestNeo4jNetworkPolicyPlatformNamespaceIsHonoured(t *testing.T) {
	t.Parallel()
	names, err := tenantNames(testTenantID)
	if err != nil {
		t.Fatalf("tenantNames: %v", err)
	}
	np := buildNeo4jNetworkPolicy(names, testTenantID, testTenantNS, "gibson-platform")

	target := podRef{
		namespace: testTenantNS,
		nsLabels:  nsLabels(testTenantNS),
		podLabels: neo4jLabels(testTenantID, testTenantNS),
	}
	inConfigured := podRef{
		desc:      "daemon in gibson-platform",
		namespace: "gibson-platform",
		nsLabels:  nsLabels("gibson-platform"),
		podLabels: map[string]string{labelKeyComponent: ComponentDaemon},
	}
	inOther := podRef{
		desc:      "daemon in gibson",
		namespace: testPlatformNS,
		nsLabels:  nsLabels(testPlatformNS),
		podLabels: map[string]string{labelKeyComponent: ComponentDaemon},
	}
	policies := []*networkingv1.NetworkPolicy{np}

	if !admitsIngress(t, policies, target, inConfigured, neo4jBoltPort) {
		t.Error("daemon in the configured platform namespace must be admitted")
	}
	if admitsIngress(t, policies, target, inOther, neo4jBoltPort) {
		t.Error("daemon in a DIFFERENT namespace must not be admitted")
	}
}

// TestNeo4jNetworkPolicyIsAppliedAndIdempotent covers the reconcile path:
// the policy is created alongside the StatefulSet, a second Provision pass
// does not error, and a hand-edited spec is reconciled back.
func TestNeo4jNetworkPolicyIsAppliedAndIdempotent(t *testing.T) {
	t.Parallel()
	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, appsv1.AddToScheme, networkingv1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("AddToScheme: %v", err)
		}
	}
	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	n := &Neo4jProvisioner{cfg: Neo4jConfig{
		K8sClient:         dpclient.New(k8s, ""),
		VaultClient:       newRecordingVaultAdmin(),
		PlatformNamespace: testPlatformNS,
	}}
	ctx := context.Background()

	if err := n.applyResources(ctx, testTenantID, testTenantID, "team", testTenantNS, "pw"); err != nil {
		t.Fatalf("first applyResources: %v", err)
	}

	names, err := tenantNames(testTenantID)
	if err != nil {
		t.Fatalf("tenantNames: %v", err)
	}
	key := types.NamespacedName{Namespace: testTenantNS, Name: names.Neo4jNetworkPolicy()}

	got := &networkingv1.NetworkPolicy{}
	if err := k8s.Get(ctx, key, got); err != nil {
		t.Fatalf("NetworkPolicy not created alongside the StatefulSet: %v", err)
	}

	// Drift: someone widens the policy to admit everything.
	got.Spec.Ingress = []networkingv1.NetworkPolicyIngressRule{{}}
	if err := k8s.Update(ctx, got); err != nil {
		t.Fatalf("seed drift: %v", err)
	}

	if err := n.applyResources(ctx, testTenantID, testTenantID, "team", testTenantNS, "pw"); err != nil {
		t.Fatalf("second applyResources (idempotency): %v", err)
	}

	reconciled := &networkingv1.NetworkPolicy{}
	if err := k8s.Get(ctx, key, reconciled); err != nil {
		t.Fatalf("get after reconcile: %v", err)
	}
	target := podRef{
		namespace: testTenantNS,
		nsLabels:  nsLabels(testTenantNS),
		podLabels: neo4jLabels(testTenantID, testTenantNS),
	}
	anyPod := podRef{
		desc:      "an unrelated tenant-namespace pod",
		namespace: testTenantNS,
		nsLabels:  nsLabels(testTenantNS),
		podLabels: map[string]string{labelKeyName: "some-agent"},
	}
	if admitsIngress(t, []*networkingv1.NetworkPolicy{reconciled}, target, anyPod, neo4jBoltPort) {
		t.Error("a widened ingress rule must be reconciled away — the policy is the security boundary")
	}

	// Deprovision removes it with the tenant.
	if err := n.Deprovision(ctx, testTenantID); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if err := k8s.Get(ctx, key, &networkingv1.NetworkPolicy{}); err == nil {
		t.Error("NetworkPolicy must be deleted with the tenant")
	}
}
