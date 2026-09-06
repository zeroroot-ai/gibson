// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/dataplane"
)

// TestDefaultDenyExcludesTenantNeo4j is the other half of gibson#1255.
//
// Kubernetes UNIONs every NetworkPolicy that selects a pod. The
// namespace-wide gibson-tenant-default-deny policy carries an
// intra-namespace allow-all ingress rule, so for as long as it also
// selected the per-tenant Neo4j pod, the dedicated bolt policy was
// cancelled out and every co-tenant pod could still open bolt. The
// dedicated policy would have looked correct in `kubectl get netpol` and
// protected nothing.
//
// This test fails if the default-deny podSelector is ever widened back to
// {} (or to anything that matches the Neo4j pod).
func TestDefaultDenyExcludesTenantNeo4j(t *testing.T) {
	t.Parallel()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	p := &NamespaceProvisioner{Client: cl, PlatformNamespace: "gibson"}

	const nsName = "tenant-acme"
	ctx := context.Background()
	if err := p.ensureNetworkPolicy(ctx, nsName); err != nil {
		t.Fatalf("ensureNetworkPolicy: %v", err)
	}

	np := &networkingv1.NetworkPolicy{}
	if err := cl.Get(ctx, types.NamespacedName{
		Namespace: nsName, Name: "gibson-tenant-default-deny",
	}, np); err != nil {
		t.Fatalf("default-deny NetworkPolicy not created: %v", err)
	}

	sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	if err != nil {
		t.Fatalf("podSelector invalid: %v", err)
	}

	neo4jPod := labels.Set{
		"app.kubernetes.io/name":      "neo4j",
		"app.kubernetes.io/component": dataplane.ComponentTenantNeo4j,
		"app.kubernetes.io/instance":  nsName,
		"gibson.zeroroot.ai/tenant":   "acme",
	}
	if sel.Matches(neo4jPod) {
		t.Error("gibson-tenant-default-deny must NOT select the per-tenant Neo4j pod — " +
			"its intra-namespace allow-all rule would union away the dedicated bolt policy")
	}

	// Everything else in the tenant namespace keeps its default-deny
	// posture, including pods that carry no component label at all.
	stillGoverned := []labels.Set{
		{"app.kubernetes.io/name": "some-agent"},
		{"app.kubernetes.io/component": "sandbox"},
		{},
	}
	for _, pod := range stillGoverned {
		if !sel.Matches(pod) {
			t.Errorf("default-deny must still select pod with labels %v", pod)
		}
	}
}
