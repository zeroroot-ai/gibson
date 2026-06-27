// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

func TestResolveTenantOwnerRef(t *testing.T) {
	const tenantUID = "7c3bc90a-4357-454b-9a8b-21cef92c22a0"

	tests := []struct {
		name       string
		namespace  *corev1.Namespace
		tenant     *gibsonv1alpha1.Tenant
		wantRef    *metav1.OwnerReference
		wantErrMsg string
	}{
		{
			name: "annotation present, tenant present",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "tenant-acme",
					Annotations: map[string]string{
						AnnotationOwnerTenantUID:  tenantUID,
						AnnotationOwnerTenantName: "acme",
					},
				},
			},
			tenant: &gibsonv1alpha1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID(tenantUID)},
			},
			wantRef: &metav1.OwnerReference{
				APIVersion:         "gibson.zeroroot.ai/v1alpha1",
				Kind:               "Tenant",
				Name:               "acme",
				UID:                types.UID(tenantUID),
				BlockOwnerDeletion: ptr.To(false),
				Controller:         ptr.To(false),
			},
		},
		{
			name: "annotation missing, falls back to name prefix + live Tenant UID",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        "tenant-acme",
					Annotations: map[string]string{},
				},
			},
			tenant: &gibsonv1alpha1.Tenant{
				ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID(tenantUID)},
			},
			wantRef: &metav1.OwnerReference{
				APIVersion:         "gibson.zeroroot.ai/v1alpha1",
				Kind:               "Tenant",
				Name:               "acme",
				UID:                types.UID(tenantUID),
				BlockOwnerDeletion: ptr.To(false),
				Controller:         ptr.To(false),
			},
		},
		{
			name: "no annotation, no tenant-prefix — returns (nil, nil)",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "random-ns"},
			},
			wantRef: nil,
		},
		{
			name: "annotation-less namespace, tenant deleted — returns (nil, nil)",
			namespace: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "tenant-ghost"},
			},
			wantRef: nil, // tenant not found → (nil, nil)
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme := setupScheme(t)
			b := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tc.namespace)
			if tc.tenant != nil {
				b = b.WithObjects(tc.tenant)
			}
			c := b.Build()

			got, err := ResolveTenantOwnerRef(context.Background(), c, tc.namespace.Name)
			if err != nil {
				if tc.wantErrMsg == "" {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if tc.wantRef == nil {
				if got != nil {
					t.Fatalf("want nil ref, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want ref %+v, got nil", tc.wantRef)
			}
			if got.APIVersion != tc.wantRef.APIVersion ||
				got.Kind != tc.wantRef.Kind ||
				got.Name != tc.wantRef.Name ||
				got.UID != tc.wantRef.UID {
				t.Errorf("ref mismatch:\n  want=%+v\n  got=%+v", tc.wantRef, got)
			}
			if got.BlockOwnerDeletion == nil || *got.BlockOwnerDeletion != false {
				t.Errorf("want BlockOwnerDeletion=false, got %v", got.BlockOwnerDeletion)
			}
			if got.Controller == nil || *got.Controller != false {
				t.Errorf("want Controller=false, got %v", got.Controller)
			}
		})
	}
}

func TestNamespaceProvisioner_Annotations(t *testing.T) {
	const tenantUID = "tuid-123"
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID(tenantUID)},
		Spec:       gibsonv1alpha1.TenantSpec{DisplayName: "Acme", Owner: "alice@acme.io", Tier: "free"},
	}

	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	p := &NamespaceProvisioner{Client: c}
	if err := p.ensureNamespace(context.Background(), tenant, "tenant-acme"); err != nil {
		t.Fatalf("ensureNamespace: %v", err)
	}
	var ns corev1.Namespace
	if err := c.Get(context.Background(), types.NamespacedName{Name: "tenant-acme"}, &ns); err != nil {
		t.Fatalf("get ns: %v", err)
	}
	if got := ns.Annotations[AnnotationOwnerTenantUID]; got != tenantUID {
		t.Errorf("uid annotation: want %q, got %q", tenantUID, got)
	}
	if got := ns.Annotations[AnnotationOwnerTenantName]; got != "acme" {
		t.Errorf("name annotation: want %q, got %q", "acme", got)
	}
}
