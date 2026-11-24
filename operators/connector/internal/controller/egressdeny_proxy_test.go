// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	connectorv1alpha1 "github.com/zeroroot-ai/gibson/operators/connector/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/internal/ciliumegress"
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

// Addresses of the fixture. A CIDR rule never selects a pod, so no pod address
// matters here. With policyCIDRMatchMode nodes, a CIDR rule matches a node
// address, and the kube-apiserver of a kind cluster runs on one (gibson#1694).
var (
	apiserverNodeAddr = netip.MustParseAddr("172.18.0.2")
	// b3Addrs are addresses that review B3 denies: the cloud metadata
	// address, loopback and a private host inside the VPC of the cluster.
	b3Addrs = []netip.Addr{
		netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("127.0.0.1"),
		netip.MustParseAddr("10.40.1.1"),
	}
	testClusterCIDRs = []string{"10.40.0.0/16"}
)

// denies reports whether an egressDeny rule of the policy covers the address.
func denies(t *testing.T, u *unstructured.Unstructured, addr netip.Addr) bool {
	t.Helper()
	deny, _, _ := unstructured.NestedSlice(u.Object, "spec", "egressDeny")
	for _, r := range deny {
		sets, _ := r.(map[string]interface{})["toCIDRSet"].([]interface{})
		for _, raw := range sets {
			rule := raw.(map[string]interface{})
			if netip.MustParsePrefix(rule["cidr"].(string)).Contains(addr) {
				return true
			}
		}
	}
	return false
}

// apiserverBlocks lists each policy whose deny rule selects the pod and covers
// the address of the kube-apiserver.
func apiserverBlocks(t *testing.T, policies []*unstructured.Unstructured, pod podLabels) []string {
	t.Helper()
	var out []string
	for _, u := range policies {
		if ciliumSelects(t, u, pod) && denies(t, u, apiserverNodeAddr) {
			out = append(out, fmt.Sprintf("%s selects the %s and denies the apiserver %s", u.GetName(), pod.role, apiserverNodeAddr))
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
	pols := []*unstructured.Unstructured{egress, desiredProxyIssuerPolicy(ci, "spire")}
	// The reconcile writes the API server policy for a Hosted connector only.
	if ci.Spec.Shape == connectorv1alpha1.ConnectorShapeHosted {
		pols = append(pols, desiredProxyAPIServerPolicy(ci))
	}
	return pols
}

// The reconcile writes no API server policy for a Remote connector, and it
// deletes one that an earlier version wrote.
func TestReconcileProxyAPIServerPolicy_RemoteHasNone(t *testing.T) {
	ctx := context.Background()
	ci := remoteInstance("gl", "tenant-acme")
	ci.UID = "uid-gl"
	stale := desiredProxyAPIServerPolicy(ci)
	if err := controllerutil.SetControllerReference(ci, stale, newReconciler(t).Scheme); err != nil {
		t.Fatal(err)
	}
	r := newReconciler(t, stale)
	if err := r.reconcileProxyAPIServerPolicy(ctx, ci); err != nil {
		t.Fatal(err)
	}
	u := ciliumegress.NewPolicy()
	err := r.Get(ctx, types.NamespacedName{Namespace: "tenant-acme", Name: proxyAPIServerPolicyName(ci)}, u)
	if !apierrors.IsNotFound(err) {
		t.Errorf("the API server policy of a Remote connector exists: %v", err)
	}
	if err := r.reconcileProxyAPIServerPolicy(ctx, ci); err != nil {
		t.Errorf("a second reconcile fails: %v", err)
	}
}

// The Hosted proxy pod is under no deny rule that covers the apiserver. The
// Hosted server pod and the Remote proxy pod are denied the addresses of
// review B3 (gibson#1694).
func TestEgressDenyRulesFitEachShape(t *testing.T) {
	hosted := hostedInstance("gh", "tenant-acme")
	remote := remoteInstance("gl", "tenant-acme")
	hosted.Spec.EgressAllow = []string{"api.example.com:443"}
	remote.Spec.EgressAllow = []string{"api.example.com:443"}
	hp, rp := ciliumPoliciesOf(t, hosted), ciliumPoliciesOf(t, remote)
	if v := apiserverBlocks(t, hp, proxyPod(hosted)); len(v) > 0 {
		t.Errorf("Hosted proxy: %v", v)
	}
	if v := b3Gaps(t, hp, serverPod(hosted)); len(v) > 0 {
		t.Errorf("Hosted server: %v", v)
	}
	if v := b3Gaps(t, rp, proxyPod(remote)); len(v) > 0 {
		t.Errorf("Remote proxy: %v", v)
	}
	if v := b3Gaps(t, hp, proxyPod(hosted)); len(v) != len(b3Addrs) {
		t.Errorf("Hosted proxy has a deny rule: %v", v)
	}
}

// The real reconcile writes the API server policy for a Hosted connector and
// none for a Remote connector.
func TestReconcileWritesAnAPIServerPolicyForHostedOnly(t *testing.T) {
	ctx := context.Background()
	for _, ci := range []*connectorv1alpha1.ConnectorInstance{hostedInstance("gh", "tenant-acme"), remoteInstance("gl", "tenant-acme")} {
		r := newReconciler(t)
		if err := r.reconcileProxyAPIServerPolicy(ctx, ci); err != nil {
			t.Fatal(err)
		}
		u := ciliumegress.NewPolicy()
		err := r.Get(ctx, types.NamespacedName{Namespace: ci.Namespace, Name: proxyAPIServerPolicyName(ci)}, u)
		hosted := ci.Spec.Shape == connectorv1alpha1.ConnectorShapeHosted
		if hosted && err != nil {
			t.Errorf("Hosted: no API server policy: %v", err)
		}
		if !hosted && !apierrors.IsNotFound(err) {
			t.Errorf("Remote: API server policy exists: %v", err)
		}
		if hosted && ciliumSelects(t, u, serverPod(ci)) {
			t.Errorf("Hosted: the API server policy selects the server pod")
		}
	}
}

// A policy with the same name and no owner reference is not ours. The
// reconcile of a Remote connector leaves it, and sends no Delete when the
// policy is absent.
func TestReconcileProxyAPIServerPolicy_RemoteKeepsAForeignPolicy(t *testing.T) {
	ctx := context.Background()
	ci := remoteInstance("gl", "tenant-acme")
	ci.UID = "uid-gl"
	foreign := desiredProxyAPIServerPolicy(ci)
	r := newReconciler(t, foreign)
	if err := r.reconcileProxyAPIServerPolicy(ctx, ci); err != nil {
		t.Fatal(err)
	}
	if err := r.Get(ctx, client.ObjectKeyFromObject(foreign), ciliumegress.NewPolicy()); err != nil {
		t.Errorf("the foreign policy is gone: %v", err)
	}
}

// The failing fixtures. Each one is a policy that the check must flag.
func TestChecksFlagTheFaults(t *testing.T) {
	hosted := hostedInstance("gh", "tenant-acme")
	hosted.Spec.EgressAllow = []string{"api.example.com:443"}
	remote := remoteInstance("gl", "tenant-acme")
	remote.Spec.EgressAllow = []string{"api.example.com:443"}
	old, err := desiredCiliumEgressPolicy(hosted, testClusterCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	old.Object["spec"].(map[string]interface{})["endpointSelector"] = map[string]interface{}{
		"matchLabels": map[string]interface{}{"toolhive-name": hosted.Name},
	}
	if v := apiserverBlocks(t, []*unstructured.Unstructured{old}, proxyPod(hosted)); len(v) == 0 {
		t.Error("the old selector is not flagged for denying the apiserver to the Hosted proxy")
	}
	none, err := desiredCiliumEgressPolicy(remote, testClusterCIDRs)
	if err != nil {
		t.Fatal(err)
	}
	delete(none.Object["spec"].(map[string]interface{}), "egressDeny")
	if v := b3Gaps(t, []*unstructured.Unstructured{none}, proxyPod(remote)); len(v) != len(b3Addrs) {
		t.Errorf("no deny on the Remote proxy is not flagged for B3: %v", v)
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
