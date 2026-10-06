// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// Each tenant namespace enforces the restricted Pod Security standard: a new
// namespace gets the label, and an existing one gets it on the next reconcile,
// with its own labels kept (gibson#767).
func TestEnsureNamespace_EnforcesRestricted(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	ctx := context.Background()
	label := func(cl client.Client, name string) map[string]string {
		t.Helper()
		var ns corev1.Namespace
		if err := cl.Get(ctx, types.NamespacedName{Name: name}, &ns); err != nil {
			t.Fatalf("get namespace %s: %v", name, err)
		}
		return ns.Labels
	}

	fresh := fake.NewClientBuilder().WithScheme(scheme).Build()
	if err := (&NamespaceProvisioner{Client: fresh}).ensureNamespace(ctx, tenant, "tenant-acme"); err != nil {
		t.Fatalf("new namespace: %v", err)
	}
	if got := label(fresh, "tenant-acme")[podSecurityEnforceLabel]; got != podSecurityRestricted {
		t.Errorf("new namespace: %s = %q, want restricted", podSecurityEnforceLabel, got)
	}

	for name, labels := range map[string]map[string]string{
		"no labels":        nil,
		"user label":       {"team": "red"},
		"baseline enforce": {podSecurityEnforceLabel: "baseline"},
	} {
		existing := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "tenant-acme", Labels: labels}}
		cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(existing).Build()
		if err := (&NamespaceProvisioner{Client: cl}).ensureNamespace(ctx, tenant, "tenant-acme"); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := label(cl, "tenant-acme")
		if got[podSecurityEnforceLabel] != podSecurityRestricted {
			t.Errorf("%s: %s = %q, want restricted", name, podSecurityEnforceLabel, got[podSecurityEnforceLabel])
		}
		if name == "user label" && got["team"] != "red" {
			t.Errorf("user label: the label team was dropped: %v", got)
		}
	}
}
