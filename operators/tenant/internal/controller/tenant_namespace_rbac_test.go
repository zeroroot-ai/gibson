// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

func TestEnsureTenantNamespaceRBAC_BindsClusterRole(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	if err := gibsonv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme gibson: %v", err)
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	p := &NamespaceProvisioner{Client: cl, PlatformNamespace: "gibson"}

	if err := p.ensureTenantNamespaceRBAC(context.Background(), "tenant-test"); err != nil {
		t.Fatalf("ensureTenantNamespaceRBAC: %v", err)
	}

	// RoleBinding must exist and point at the chart-rendered ClusterRole.
	// No per-tenant Role is minted any more (spec: keep the operator's
	// cluster-wide RBAC narrow by binding a fixed ClusterRole rather than
	// creating a fresh Role at runtime, which would require roles/create +
	// escalate cluster-wide).
	rb := &rbacv1.RoleBinding{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Namespace: "tenant-test", Name: tenantOperatorRoleBindingName,
	}, rb); err != nil {
		t.Fatalf("RoleBinding not created: %v", err)
	}
	if rb.RoleRef.Kind != "ClusterRole" {
		t.Errorf("RoleRef.Kind = %q, want ClusterRole", rb.RoleRef.Kind)
	}
	if rb.RoleRef.Name != tenantOperatorNamespaceClusterRole {
		t.Errorf("RoleRef.Name = %q, want %q", rb.RoleRef.Name, tenantOperatorNamespaceClusterRole)
	}
	if len(rb.Subjects) != 1 {
		t.Fatalf("Subjects len = %d, want 1", len(rb.Subjects))
	}
	if rb.Subjects[0].Name != defaultOperatorSAName {
		t.Errorf("Subject SA name = %q, want %q", rb.Subjects[0].Name, defaultOperatorSAName)
	}

	// And there must be NO per-tenant Role lying around.
	role := &rbacv1.Role{}
	err := cl.Get(context.Background(), types.NamespacedName{
		Namespace: "tenant-test", Name: tenantOperatorRoleName,
	}, role)
	if err == nil {
		t.Errorf("per-tenant Role unexpectedly created: %+v", role)
	}
}

func TestEnsureTenantNamespaceRBAC_Idempotent(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = gibsonv1alpha1.AddToScheme(scheme)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()
	p := &NamespaceProvisioner{Client: cl, PlatformNamespace: "gibson"}

	for i := range 3 {
		if err := p.ensureTenantNamespaceRBAC(context.Background(), "tenant-test"); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}

	rb := &rbacv1.RoleBinding{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Namespace: "tenant-test", Name: tenantOperatorRoleBindingName,
	}, rb); err != nil {
		t.Fatalf("RoleBinding not present after re-runs: %v", err)
	}
	if rb.RoleRef.Name != tenantOperatorNamespaceClusterRole {
		t.Errorf("RoleRef.Name = %q, want %q", rb.RoleRef.Name, tenantOperatorNamespaceClusterRole)
	}
}

// THE FIXTURE THIS EXISTS FOR: the daemon's connector-credential write is a
// RoleBinding in the tenant namespace, never a cluster-wide grant.
func TestEnsureTenantNamespaceRBAC_BindsTheConnectorOperatorInTheTenantNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	// A namespace from before gibson#663: the binding names the daemon.
	old := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Namespace: "tenant-test", Name: connectorCredsRoleBindingName},
		Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "gibson-gibson-workloads", Namespace: "gibson"}},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: connectorCredsClusterRole},
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(old).Build()
	p := &NamespaceProvisioner{Client: cl, PlatformNamespace: "gibson"}
	t.Setenv(envConnectorOperatorSAName, "connector-operator-sa-from-chart")
	if err := p.ensureTenantNamespaceRBAC(context.Background(), "tenant-test"); err != nil {
		t.Fatalf("ensureTenantNamespaceRBAC: %v", err)
	}
	rb := &rbacv1.RoleBinding{}
	if err := cl.Get(context.Background(), types.NamespacedName{
		Namespace: "tenant-test", Name: connectorCredsRoleBindingName,
	}, rb); err != nil {
		t.Fatalf("connector-creds RoleBinding not found: %v", err)
	}
	if rb.RoleRef.Kind != "ClusterRole" || rb.RoleRef.Name != connectorCredsClusterRole {
		t.Errorf("RoleRef = %+v, want ClusterRole/%s", rb.RoleRef, connectorCredsClusterRole)
	}
	want := []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: "connector-operator-sa-from-chart", Namespace: "gibson"}}
	if !reflect.DeepEqual(rb.Subjects, want) {
		t.Errorf("Subjects = %+v, want only the connector operator; the daemon must lose the grant", rb.Subjects)
	}
}
