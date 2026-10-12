// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/zeroroot-ai/gibson/operators/internal/ciliumegress"
)

// fqdnRules returns each toFQDNs entry of a policy as "matchName=host:port"
// or "matchPattern=pattern:port", and checks that the first rule is the DNS
// rule to kube-dns.
func fqdnRules(t *testing.T, u *unstructured.Unstructured) []string {
	t.Helper()
	egress, _, err := unstructured.NestedSlice(u.Object, "spec", "egress")
	if err != nil || len(egress) == 0 {
		t.Fatalf("policy has no egress: %v", err)
	}
	dns := egress[0].(map[string]interface{})
	if _, ok := dns["toEndpoints"]; !ok {
		t.Fatalf("the first egress rule is not the DNS rule to kube-dns: %v", dns)
	}
	var out []string
	for _, raw := range egress[1:] {
		rule := raw.(map[string]interface{})
		fqdn := rule["toFQDNs"].([]interface{})[0].(map[string]interface{})
		port := rule["toPorts"].([]interface{})[0].(map[string]interface{})["ports"].([]interface{})[0].(map[string]interface{})["port"].(string)
		for k, v := range fqdn {
			out = append(out, k+"="+v.(string)+":"+port)
		}
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The policy names each host of the list on its port, after the DNS rule.
func TestDesiredCiliumEgressPolicy(t *testing.T) {
	ci := hostedInstance("gh", "tenant-acme")
	for name, c := range map[string]struct {
		allow []string
		want  []string
	}{
		"one host": {[]string{"api.github.com:443"}, []string{"matchName=api.github.com:443"}},
		"many hosts": {
			[]string{"api.github.com:443", "*.slack.com:443", "api.osv.dev", "git.example.com:8443"},
			[]string{"matchName=api.github.com:443", "matchPattern=*.slack.com:443", "matchName=api.osv.dev:443", "matchName=git.example.com:8443"},
		},
	} {
		ci.Spec.EgressAllow = c.allow
		u, err := desiredCiliumEgressPolicy(ci)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := fqdnRules(t, u); !equalStrings(got, c.want) {
			t.Errorf("%s: rules = %v, want %v", name, got, c.want)
		}
		sel, _, _ := unstructured.NestedStringMap(u.Object, "spec", "endpointSelector", "matchLabels")
		if sel["toolhive-name"] != "gh" || u.GetName() != "connector-gh-egress" {
			t.Errorf("%s: selector = %v, name = %q", name, sel, u.GetName())
		}
	}
	for _, bad := range []string{"", "api.github.com:http", "api.github.com:0", "https://api.github.com", ":443"} {
		ci.Spec.EgressAllow = []string{bad}
		if _, err := desiredCiliumEgressPolicy(ci); !errors.Is(err, ciliumegress.ErrBadEntry) {
			t.Errorf("entry %q: err = %v, want ciliumegress.ErrBadEntry", bad, err)
		}
	}
}

// The owned NetworkPolicy has no egress rule to an address block, so it adds
// no public egress to the host list of the Cilium policy.
func TestNetworkPolicyHasNoPublicEgress(t *testing.T) {
	np := desiredNetworkPolicy(hostedInstance("gh", "tenant-acme"))
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.IPBlock != nil {
				t.Errorf("egress rule to the address block %s: a public egress rule would win over the host list", peer.IPBlock.CIDR)
			}
		}
	}
}

// The owned NetworkPolicy opens no egress to the daemon namespace: a
// connector runs third-party MCP server code, and the daemon admits no
// connector pod (charts#519).
func TestNetworkPolicyHasNoDaemonEgress(t *testing.T) {
	np := desiredNetworkPolicy(hostedInstance("gh", "tenant-acme"))
	for _, rule := range np.Spec.Egress {
		for _, peer := range rule.To {
			if peer.NamespaceSelector == nil {
				continue
			}
			if ns := peer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]; ns == daemonNamespace {
				t.Errorf("egress rule to the daemon namespace %q on %d port(s): no runner calls the daemon",
					ns, len(rule.Ports))
			}
		}
	}
}

// The reconcile creates the policy, updates it when the list changes, and
// deletes it when the list becomes empty. A connector with an empty list has
// no policy, so it reaches no public host.
func TestReconcileCiliumEgressPolicy(t *testing.T) {
	ctx := context.Background()
	r := newReconciler(t)
	ci := hostedInstance("gh", "tenant-acme")
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "connector-gh-egress"}
	get := func() (*unstructured.Unstructured, error) {
		u := ciliumegress.NewPolicy()
		return u, r.Get(ctx, key, u)
	}

	if err := r.reconcileCiliumEgressPolicy(ctx, ci); err != nil {
		t.Fatalf("empty list: %v", err)
	}
	if _, err := get(); !apierrors.IsNotFound(err) {
		t.Fatalf("empty list: a policy exists (err = %v)", err)
	}

	ci.Spec.EgressAllow = []string{"api.github.com:443"}
	if err := r.reconcileCiliumEgressPolicy(ctx, ci); err != nil {
		t.Fatalf("create: %v", err)
	}
	u, err := get()
	if err != nil {
		t.Fatalf("create: no policy: %v", err)
	}
	if got := fqdnRules(t, u); !equalStrings(got, []string{"matchName=api.github.com:443"}) {
		t.Errorf("create: rules = %v", got)
	}

	ci.Spec.EgressAllow = []string{"api.github.com:443", "uploads.github.com:443"}
	if err := r.reconcileCiliumEgressPolicy(ctx, ci); err != nil {
		t.Fatalf("update: %v", err)
	}
	if u, err = get(); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := fqdnRules(t, u); len(got) != 2 {
		t.Errorf("update: rules = %v, want two hosts", got)
	}

	ci.Spec.EgressAllow = nil
	if err := r.reconcileCiliumEgressPolicy(ctx, ci); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := get(); !apierrors.IsNotFound(err) {
		t.Fatalf("delete: the policy is still there (err = %v)", err)
	}

	ci.Spec.EgressAllow = []string{"not a host"}
	if err := r.reconcileCiliumEgressPolicy(ctx, ci); !errors.Is(err, ciliumegress.ErrBadEntry) {
		t.Fatalf("bad entry: err = %v, want ciliumegress.ErrBadEntry", err)
	}
}

// The MCP server pod of a Hosted connector meets the restricted standard:
// the MCPServer carries the pod template with the seccomp profile, a non-root
// user and no capability on the mcp container (gibson#767).
func TestMCPServerPodTemplateMeetsRestricted(t *testing.T) {
	r := newReconciler(t)
	th, err := r.desiredToolHive(hostedInstance("gh", "tenant-acme"))
	if err != nil {
		t.Fatal(err)
	}
	podSpec, found, _ := unstructured.NestedMap(th.Object, "spec", "podTemplateSpec", "spec")
	if !found {
		t.Fatal("the MCPServer has no podTemplateSpec")
	}
	if nonRoot, _, _ := unstructured.NestedBool(podSpec, "securityContext", "runAsNonRoot"); !nonRoot {
		t.Error("runAsNonRoot is not true")
	}
	if p, _, _ := unstructured.NestedString(podSpec, "securityContext", "seccompProfile", "type"); p != "RuntimeDefault" {
		t.Errorf("pod seccomp = %q", p)
	}
	containers, _, _ := unstructured.NestedSlice(podSpec, "containers")
	if len(containers) != 1 {
		t.Fatalf("containers = %v", containers)
	}
	c := containers[0].(map[string]interface{})
	if c["name"] != "mcp" {
		t.Errorf("container name = %v, want mcp", c["name"])
	}
	if esc, _, _ := unstructured.NestedBool(c, "securityContext", "allowPrivilegeEscalation"); esc {
		t.Error("allowPrivilegeEscalation is true")
	}
	drop, _, _ := unstructured.NestedStringSlice(c, "securityContext", "capabilities", "drop")
	if len(drop) != 1 || drop[0] != "ALL" {
		t.Errorf("drop = %v, want [ALL]", drop)
	}
	if p, _, _ := unstructured.NestedString(c, "securityContext", "seccompProfile", "type"); p != "RuntimeDefault" {
		t.Errorf("container seccomp = %q", p)
	}
}

// selects reports whether the endpoint selector of a policy matches a pod
// with the given labels.
func selects(t *testing.T, u *unstructured.Unstructured, podLabels map[string]string) bool {
	t.Helper()
	raw, _, err := unstructured.NestedMap(u.Object, "spec", "endpointSelector")
	if err != nil {
		t.Fatalf("endpointSelector: %v", err)
	}
	var ls metav1.LabelSelector
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(raw, &ls); err != nil {
		t.Fatalf("convert endpointSelector: %v", err)
	}
	sel, err := metav1.LabelSelectorAsSelector(&ls)
	if err != nil {
		t.Fatalf("endpointSelector as selector: %v", err)
	}
	return sel.Matches(labels.Set(podLabels))
}

// The API server policy selects the ToolHive proxy pod of the connector, and
// neither its MCP server pod nor a pod of another connector. Its one egress
// rule is the entity kube-apiserver (gibson#1119). The labels are the ones
// ToolHive v0.12.1 sets: labelsForMCPServer and labelsForMCPRemoteProxy on
// the proxy, and app=<name>, toolhive-name=<name> on the server pod.
func TestDesiredProxyAPIServerPolicy(t *testing.T) {
	u := desiredProxyAPIServerPolicy(hostedInstance("gh", "tenant-acme"))
	if u.GetName() != "connector-gh-proxy-apiserver" || u.GetNamespace() != "tenant-acme" {
		t.Fatalf("name = %s/%s", u.GetNamespace(), u.GetName())
	}
	for name, c := range map[string]struct {
		labels map[string]string
		want   bool
	}{
		"the MCPServer proxy": {map[string]string{
			"app": "mcpserver", "app.kubernetes.io/name": "mcpserver", "app.kubernetes.io/instance": "gh",
			"toolhive": "true", "toolhive-name": "gh",
		}, true},
		"the MCPRemoteProxy proxy": {map[string]string{
			"app": "mcpremoteproxy", "app.kubernetes.io/name": "mcpremoteproxy", "app.kubernetes.io/instance": "gh",
			"toolhive": "true", "toolhive-name": "gh",
		}, true},
		"the MCP server pod": {map[string]string{"app": "gh", "toolhive": "true", "toolhive-name": "gh"}, false},
		"the proxy of another connector": {map[string]string{
			"app.kubernetes.io/name": "mcpserver", "toolhive-name": "slack",
		}, false},
	} {
		if got := selects(t, u, c.labels); got != c.want {
			t.Errorf("%s: selected = %v, want %v", name, got, c.want)
		}
	}
	egress, _, _ := unstructured.NestedSlice(u.Object, "spec", "egress")
	if len(egress) != 1 {
		t.Fatalf("egress = %v, want one rule", egress)
	}
	rule := egress[0].(map[string]interface{})
	ents, _ := rule["toEntities"].([]interface{})
	if len(rule) != 1 || len(ents) != 1 || ents[0] != "kube-apiserver" {
		t.Errorf("egress rule = %v, want only toEntities [kube-apiserver]", rule)
	}
}

// The reconcile creates the API server policy for every connector, with or
// without a host list, and an update keeps it.
func TestReconcileProxyAPIServerPolicy(t *testing.T) {
	ctx := context.Background()
	r := newReconciler(t)
	ci := hostedInstance("gh", "tenant-acme")
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "connector-gh-proxy-apiserver"}
	for _, step := range []string{"create", "update"} {
		if err := r.reconcileProxyAPIServerPolicy(ctx, ci); err != nil {
			t.Fatalf("%s: %v", step, err)
		}
		u := ciliumegress.NewPolicy()
		if err := r.Get(ctx, key, u); err != nil {
			t.Fatalf("%s: no policy: %v", step, err)
		}
		if len(u.GetOwnerReferences()) != 1 {
			t.Errorf("%s: owner references = %v", step, u.GetOwnerReferences())
		}
	}
}

// A failed write of the API server policy fails the reconcile, and the
// instance reads Failed.
func TestReconcile_ProxyAPIServerPolicyErrorIsFailed(t *testing.T) {
	ci := hostedInstance("hosted-fixture", "tenant-acme")
	ci.Finalizers = []string{finalizer}
	r := failCreateOfKind(t, ciliumegress.Kind, ci)
	key := types.NamespacedName{Namespace: "tenant-acme", Name: "hosted-fixture"}

	_, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err == nil || !strings.Contains(err.Error(), "create proxy api server policy") {
		t.Fatalf("err = %v, want the create error of the API server policy", err)
	}
	assertFailed(t, r, key)
}

// Each failure of the API server policy reconcile surfaces with its step.
func TestReconcileProxyAPIServerPolicy_Errors(t *testing.T) {
	ctx := context.Background()
	ci := hostedInstance("gh", "tenant-acme")

	noScheme := &ConnectorInstanceReconciler{Client: newReconciler(t).Client, Scheme: runtime.NewScheme()}
	if err := noScheme.reconcileProxyAPIServerPolicy(ctx, ci); err == nil || !strings.Contains(err.Error(), "owner ref") {
		t.Errorf("owner ref: err = %v", err)
	}

	if err := failGetReconciler(t).reconcileProxyAPIServerPolicy(ctx, ci); err == nil ||
		!strings.Contains(err.Error(), "get proxy api server policy") {
		t.Errorf("get: err = %v", err)
	}

	s := testScheme(t)
	existing := desiredProxyAPIServerPolicy(ci)
	cl := fake.NewClientBuilder().WithScheme(s).WithObjects(existing).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.UpdateOption) error {
				return errReconcileBoom
			},
		}).Build()
	r := &ConnectorInstanceReconciler{Client: cl, Scheme: s}
	if err := r.reconcileProxyAPIServerPolicy(ctx, ci); err == nil ||
		!strings.Contains(err.Error(), "update proxy api server policy") {
		t.Errorf("update: err = %v", err)
	}
}
