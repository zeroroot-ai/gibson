// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
)

// podLabels are the labels of one pod of a connector, as ToolHive v0.12.1
// writes them. The proxy pod gets labelsForMCPServer or
// labelsForMCPRemoteProxy (cmd/thv-operator/controllers). The MCP server pod
// gets the labels of the runner: app, toolhive, toolhive-name,
// toolhive-basename, toolhive-transport and toolhive-port (upstream pkg/labels and
// the Kubernetes runtime). It has no app.kubernetes.io label.
type podLabels struct {
	role   string
	labels labels.Set
}

func proxyPod(ci *connectorv1alpha1.ConnectorInstance) podLabels {
	name := "mcpserver"
	if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeRemote {
		name = "mcpremoteproxy"
	}
	return podLabels{role: "proxy pod", labels: labels.Set{
		"app":                        name,
		"app.kubernetes.io/name":     name,
		"app.kubernetes.io/instance": ci.Name,
		"toolhive":                   "true",
		"toolhive-name":              ci.Name,
	}}
}

func serverPod(ci *connectorv1alpha1.ConnectorInstance) podLabels {
	return podLabels{role: "server pod", labels: labels.Set{
		"app":                                ci.Name,
		"toolhive":                           "true",
		"toolhive-name":                      ci.Name,
		"toolhive-basename":                  ci.Name,
		"toolhive-transport":                 "streamable-http",
		"toolhive-port":                      "8080",
		"statefulset.kubernetes.io/pod-name": ci.Name + "-0",
	}}
}

// podsOf returns the pods that a connector of this shape runs. A Remote
// connector has no server pod, because the runner deploys no workload for a
// remote URL (upstream ToolHive v0.12.1, in the runner source).
func podsOf(ci *connectorv1alpha1.ConnectorInstance) []podLabels {
	if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeRemote {
		return []podLabels{proxyPod(ci)}
	}
	return []podLabels{proxyPod(ci), serverPod(ci)}
}

// ciliumSelects reports whether the endpointSelector of a policy matches the
// pod.
func ciliumSelects(t *testing.T, u *unstructured.Unstructured, pod podLabels) bool {
	t.Helper()
	raw, found, err := unstructured.NestedMap(u.Object, "spec", "endpointSelector")
	if err != nil || !found {
		t.Fatalf("policy %s has no endpointSelector: %v", u.GetName(), err)
	}
	var sel metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &sel); err != nil {
		t.Fatalf("policy %s selector: %v", u.GetName(), err)
	}
	s, err := metav1.LabelSelectorAsSelector(&sel)
	if err != nil {
		t.Fatalf("policy %s selector: %v", u.GetName(), err)
	}
	return s.Matches(pod.labels)
}

// Addresses of the fixture. The pod and the service ranges are the cluster
// ranges. The issuer pod is inside the pod range.
var (
	testClusterCIDRs = []string{"10.244.0.0/16", "10.96.0.0/12"}
	issuerAddr       = netip.MustParseAddr("10.244.1.7")
	// b3Addrs are addresses that review B3 denies to a proxy: the cloud
	// metadata address, loopback, a private host outside the cluster ranges,
	// CGNAT and link-local.
	b3Addrs = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("10.200.0.1"), netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("172.20.0.5"), netip.MustParseAddr("100.64.0.9"),
	}
)

// denies reports whether an egressDeny rule of the policy covers the address:
// the address is in a cidr and in none of its except prefixes.
func denies(t *testing.T, u *unstructured.Unstructured, addr netip.Addr) bool {
	t.Helper()
	deny, _, _ := unstructured.NestedSlice(u.Object, "spec", "egressDeny")
	for _, r := range deny {
		sets, _ := r.(map[string]interface{})["toCIDRSet"].([]interface{})
		for _, raw := range sets {
			rule := raw.(map[string]interface{})
			if !netip.MustParsePrefix(rule["cidr"].(string)).Contains(addr) {
				continue
			}
			carved := false
			ex, _ := rule["except"].([]interface{})
			for _, e := range ex {
				if netip.MustParsePrefix(e.(string)).Contains(addr) {
					carved = true
				}
			}
			if !carved {
				return true
			}
		}
	}
	return false
}

// proxyFindings lists each fault of the policies for the pod. A deny rule that
// selects the pod and covers the issuer blocks the pod. A pod that has a
// deny-free path to an address of review B3 drops that protection.
func proxyFindings(t *testing.T, policies []*unstructured.Unstructured, pod podLabels) []string {
	t.Helper()
	return append(issuerBlocks(t, policies, pod), b3Gaps(t, policies, pod)...)
}

// issuerBlocks lists each policy whose deny rule selects the pod and covers
// the issuer.
func issuerBlocks(t *testing.T, policies []*unstructured.Unstructured, pod podLabels) []string {
	t.Helper()
	var out []string
	for _, u := range policies {
		if ciliumSelects(t, u, pod) && denies(t, u, issuerAddr) {
			out = append(out, fmt.Sprintf("%s selects the %s and denies the issuer %s", u.GetName(), pod.role, issuerAddr))
		}
	}
	return out
}

// b3Gaps lists each address of review B3 that no deny rule covers for the pod.
func b3Gaps(t *testing.T, policies []*unstructured.Unstructured, pod podLabels) []string {
	t.Helper()
	var out []string
	for _, addr := range b3Addrs {
		covered := false
		for _, u := range policies {
			if ciliumSelects(t, u, pod) && denies(t, u, addr) {
				covered = true
			}
		}
		if !covered {
			out = append(out, fmt.Sprintf("no deny rule covers %s for the %s (review B3)", addr, pod.role))
		}
	}
	return out
}

// ciliumPoliciesOf returns each CiliumNetworkPolicy that the operator writes
// for a connector.
func ciliumPoliciesOf(t *testing.T, ci *connectorv1alpha1.ConnectorInstance) []*unstructured.Unstructured {
	t.Helper()
	egress, err := desiredCiliumEgressPolicy(ci, testClusterCIDRs)
	if err != nil {
		t.Fatalf("egress policy: %v", err)
	}
	return []*unstructured.Unstructured{
		egress,
		desiredProxyAPIServerPolicy(ci),
		desiredProxyIssuerPolicy(ci, "spire"),
	}
}

// The deny rules of the connector never block the proxy pod from the issuer,
// and they cover the addresses of review B3 for each pod that has a host list
// (gibson#1694). A Hosted proxy pod has no deny rule. A Remote proxy pod has
// the carve-out.
func TestEgressDenyRulesFitEachShape(t *testing.T) {
	for name, ci := range map[string]*connectorv1alpha1.ConnectorInstance{
		"Hosted": hostedInstance("gh", "tenant-acme"),
		"Remote": remoteInstance("gl", "tenant-acme"),
	} {
		ci.Spec.EgressAllow = []string{"api.example.com:443"}
		pols := ciliumPoliciesOf(t, ci)
		proxy := proxyPod(ci)
		for _, u := range pols {
			if ciliumSelects(t, u, proxy) && denies(t, u, issuerAddr) {
				t.Errorf("%s: %s denies the issuer for the proxy pod", name, u.GetName())
			}
		}
		if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeHosted {
			if v := denyViolations(t, pols, proxy); len(v) > 0 {
				t.Errorf("%s: %v", name, v)
			}
		}
		// The pod that holds the host list drops no protection of review B3.
		holder := proxy
		if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeHosted {
			holder = serverPod(ci)
		}
		if v := b3Gaps(t, pols, holder); len(v) > 0 {
			t.Errorf("%s: %v", name, v)
		}
	}
}

// denyViolations lists each policy with an egressDeny rule that selects the
// pod, for a shape whose proxy pod must have no deny rule.
func denyViolations(t *testing.T, policies []*unstructured.Unstructured, pod podLabels) []string {
	t.Helper()
	var out []string
	for _, u := range policies {
		deny, _, _ := unstructured.NestedSlice(u.Object, "spec", "egressDeny")
		if len(deny) > 0 && ciliumSelects(t, u, pod) {
			out = append(out, fmt.Sprintf("%s selects the %s", u.GetName(), pod.role))
		}
	}
	return out
}

// Each pod that must reach a private address has an allow rule for it, and
// the pod that runs third-party code has no API or issuer access.
func TestEgressPoliciesSelectTheRightPods(t *testing.T) {
	for _, ci := range []*connectorv1alpha1.ConnectorInstance{
		hostedInstance("gh", "tenant-acme"), remoteInstance("gl", "tenant-acme"),
	} {
		ci.Spec.EgressAllow = []string{"api.example.com:443"}
		pols := ciliumPoliciesOf(t, ci)
		egress, apiserver, issuer := pols[0], pols[1], pols[2]
		proxy := proxyPod(ci)
		if !ciliumSelects(t, apiserver, proxy) || !ciliumSelects(t, issuer, proxy) {
			t.Errorf("%s: the proxy pod has no rule for the kube-apiserver or the issuer", ci.Spec.Shape)
		}
		if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeHosted {
			if ciliumSelects(t, apiserver, serverPod(ci)) || ciliumSelects(t, issuer, serverPod(ci)) {
				t.Errorf("Hosted: the server pod runs third-party code and gets API or issuer access")
			}
			if !ciliumSelects(t, egress, serverPod(ci)) || ciliumSelects(t, egress, proxy) {
				t.Errorf("Hosted: the host list policy must select the server pod and not the proxy pod")
			}
		} else if !ciliumSelects(t, egress, proxy) {
			t.Errorf("Remote: the proxy calls the vendor host and has no allow rule for it")
		}
	}
}

// The Remote deny covers the metadata, loopback and outside private
// addresses, and does not cover the issuer in the pod range or an address in
// the service range.
func TestRemoteProxyDenyCarvesOutTheClusterRanges(t *testing.T) {
	ci := remoteInstance("gl", "tenant-acme")
	ci.Spec.EgressAllow = []string{"api.example.com:443"}
	egress, err := desiredCiliumEgressPolicy(ci, testClusterCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range b3Addrs {
		if !denies(t, egress, a) {
			t.Errorf("the deny does not cover %s", a)
		}
	}
	for _, a := range []string{"10.244.1.7", "10.244.255.254", "10.96.0.1", "10.100.3.3"} {
		if denies(t, egress, netip.MustParseAddr(a)) {
			t.Errorf("the deny covers the cluster address %s", a)
		}
	}
}

// A cluster range that is not a CIDR gives an error, and so no proxy.
func TestRemoteProxyDenyRefusesABadClusterRange(t *testing.T) {
	ci := remoteInstance("gl", "tenant-acme")
	ci.Spec.EgressAllow = []string{"api.example.com:443"}
	if _, err := desiredCiliumEgressPolicy(ci, []string{"10.244.0.0/16", "not-a-cidr"}); err == nil {
		t.Error("a bad cluster range gave no error")
	}
}

// The failing fixtures. Each one is a policy that the check must flag.
func TestProxyFindingsFlagTheFaults(t *testing.T) {
	ci := remoteInstance("gl", "tenant-acme")
	ci.Spec.EgressAllow = []string{"api.example.com:443"}
	proxy := proxyPod(ci)
	base, err := desiredCiliumEgressPolicy(ci, testClusterCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	set := func(deny []interface{}, selector map[string]interface{}) *unstructured.Unstructured {
		u := base.DeepCopy()
		spec := u.Object["spec"].(map[string]interface{})
		delete(spec, "egressDeny")
		if deny != nil {
			spec["egressDeny"] = deny
		}
		if selector != nil {
			spec["endpointSelector"] = selector
		}
		return u
	}
	allPrivate := func() []interface{} {
		var cidrs []interface{}
		for _, d := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10"} {
			cidrs = append(cidrs, map[string]interface{}{"cidr": d})
		}
		return []interface{}{map[string]interface{}{"toCIDRSet": cidrs}}
	}
	for name, c := range map[string]struct {
		policy *unstructured.Unstructured
		want   string
	}{
		"deny without carve-out blocks the issuer": {set(allPrivate(), nil), "denies the issuer"},
		"no deny drops review B3":                  {set(nil, nil), "review B3"},
		"the old selector with the old deny":       {set(allPrivate(), map[string]interface{}{"matchLabels": map[string]interface{}{"toolhive-name": ci.Name}}), "denies the issuer"},
	} {
		found := false
		for _, f := range proxyFindings(t, []*unstructured.Unstructured{c.policy}, proxy) {
			if strings.Contains(f, c.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the check did not flag %q", name, c.want)
		}
	}
	if len(proxyFindings(t, []*unstructured.Unstructured{base}, proxy)) != 0 {
		t.Errorf("the check flags the real policy: %v", proxyFindings(t, []*unstructured.Unstructured{base}, proxy))
	}
}

// The labels of the fixture follow the label functions of ToolHive. If the
// selector of the proxy ever matched the server pod, the API policy would
// give third-party code access to the API.
func TestProxySelectorDoesNotMatchTheServerPod(t *testing.T) {
	ci := hostedInstance("gh", "tenant-acme")
	for _, u := range []*unstructured.Unstructured{desiredProxyAPIServerPolicy(ci), desiredProxyIssuerPolicy(ci, "spire")} {
		if ciliumSelects(t, u, serverPod(ci)) {
			t.Errorf("%s selects the server pod", u.GetName())
		}
	}
}
