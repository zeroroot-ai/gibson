// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

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
