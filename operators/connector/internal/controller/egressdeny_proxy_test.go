// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"fmt"
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
// toolhive-basename, toolhive-transport and toolhive-port (pkg/labels and
// pkg/container/kubernetes). It has no app.kubernetes.io label.
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
// remote URL (ToolHive v0.12.1, pkg/runner/runner.go).
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

// denyViolations lists each policy with an egressDeny rule that selects the
// pod. A deny rule wins over every allow rule, so it must not select a pod
// that has to reach the kube-apiserver or the issuer.
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

// ciliumPoliciesOf returns each CiliumNetworkPolicy that the operator writes
// for a connector.
func ciliumPoliciesOf(t *testing.T, ci *connectorv1alpha1.ConnectorInstance) []*unstructured.Unstructured {
	t.Helper()
	egress, err := desiredCiliumEgressPolicy(ci, []string{"10.244.0.0/16", "10.96.0.0/12"})
	if err != nil {
		t.Fatalf("egress policy: %v", err)
	}
	return []*unstructured.Unstructured{
		egress,
		desiredProxyAPIServerPolicy(ci),
		desiredProxyIssuerPolicy(ci, "spire"),
	}
}

// The deny rule of the connector never selects the proxy pod, because the
// proxy pod must reach the kube-apiserver, the SPIRE issuer and the server
// pod, and they are private addresses (gibson#1694).
func TestNoEgressDenySelectsTheProxyPod(t *testing.T) {
	for name, ci := range map[string]*connectorv1alpha1.ConnectorInstance{
		"Hosted": hostedInstance("gh", "tenant-acme"),
		"Remote": remoteInstance("gl", "tenant-acme"),
	} {
		ci.Spec.EgressAllow = []string{"api.example.com:443"}
		if v := denyViolations(t, ciliumPoliciesOf(t, ci), proxyPod(ci)); len(v) > 0 {
			t.Errorf("%s: %v", name, v)
		}
	}
}

// Each pod that must reach a private address has an allow rule for it, and
// each pod that runs third-party code has the deny rule.
func TestEgressPoliciesSelectTheRightPods(t *testing.T) {
	hosted := hostedInstance("gh", "tenant-acme")
	remote := remoteInstance("gl", "tenant-acme")
	for _, ci := range []*connectorv1alpha1.ConnectorInstance{hosted, remote} {
		ci.Spec.EgressAllow = []string{"api.example.com:443"}
		pols := ciliumPoliciesOf(t, ci)
		egress, apiserver, issuer := pols[0], pols[1], pols[2]
		proxy := proxyPod(ci)
		if !ciliumSelects(t, apiserver, proxy) || !ciliumSelects(t, issuer, proxy) {
			t.Errorf("%s: the proxy pod has no rule for the kube-apiserver or the issuer", ci.Spec.Shape)
		}
		for _, pod := range podsOf(ci) {
			if pod.role == "server pod" {
				if ciliumSelects(t, apiserver, pod) || ciliumSelects(t, issuer, pod) {
					t.Errorf("%s: the server pod runs third-party code and gets API or issuer access", ci.Spec.Shape)
				}
			}
		}
		deny, _, _ := unstructured.NestedSlice(egress.Object, "spec", "egressDeny")
		switch ci.Spec.Shape {
		case connectorv1alpha1.ConnectorShapeHosted:
			if !ciliumSelects(t, egress, serverPod(ci)) || len(deny) == 0 {
				t.Errorf("Hosted: the server pod is not under the host list and the deny rule")
			}
			if ciliumSelects(t, egress, proxy) {
				t.Errorf("Hosted: the host list policy selects the proxy pod")
			}
		case connectorv1alpha1.ConnectorShapeRemote:
			if !ciliumSelects(t, egress, proxy) {
				t.Errorf("Remote: the proxy calls the vendor host and has no allow rule for it")
			}
			if len(deny) != 0 {
				t.Errorf("Remote: the egress policy carries a deny rule")
			}
		}
	}
}

// The failing fixture. The selector of gibson#1694 matched every pod with the
// label toolhive-name. The check must flag it for each shape.
func TestDenyCheckFlagsTheOldSelector(t *testing.T) {
	for _, ci := range []*connectorv1alpha1.ConnectorInstance{
		hostedInstance("gh", "tenant-acme"), remoteInstance("gl", "tenant-acme"),
	} {
		ci.Spec.EgressAllow = []string{"api.example.com:443"}
		old, err := desiredCiliumEgressPolicy(ci, nil)
		if err != nil {
			t.Fatal(err)
		}
		spec := old.Object["spec"].(map[string]interface{})
		spec["endpointSelector"] = map[string]interface{}{
			"matchLabels": map[string]interface{}{"toolhive-name": ci.Name},
		}
		spec["egressDeny"] = []interface{}{map[string]interface{}{
			"toCIDRSet": []interface{}{map[string]interface{}{"cidr": "10.0.0.0/8"}},
		}}
		if v := denyViolations(t, []*unstructured.Unstructured{old}, proxyPod(ci)); len(v) == 0 {
			t.Errorf("%s: the check does not flag the old selector", ci.Spec.Shape)
		}
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
