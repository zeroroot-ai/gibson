// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package webhook

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/controller"
)

const testUID = "tuid-webhook-test"

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := networkingv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func tenantNamespace(uid, name string) *corev1.Namespace {
	return &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tenant-" + name,
			Annotations: map[string]string{
				controller.AnnotationOwnerTenantUID:  uid,
				controller.AnnotationOwnerTenantName: name,
			},
		},
	}
}

func request(t *testing.T, raw []byte, op admissionv1.Operation, ns string) admission.Request {
	t.Helper()
	return admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: op,
			Namespace: ns,
			Kind:      metav1.GroupVersionKind{Group: "gibson.zeroroot.ai", Version: "v1alpha1", Kind: "AgentEnrollment"},
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

func marshalAE(t *testing.T, ae *gibsonv1alpha1.AgentEnrollment) []byte {
	t.Helper()
	raw, err := json.Marshal(ae)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestWebhook_StampsOwnerRefOnCreate(t *testing.T) {
	ns := tenantNamespace(testUID, "acme")
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme", UID: types.UID(testUID)},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(ns, tenant).Build()
	m := NewOwnerRefMutator(c)

	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "scanner-01", Namespace: "tenant-acme"},
	}
	resp := m.Handle(context.Background(), request(t, marshalAE(t, ae), admissionv1.Create, "tenant-acme"))

	if !resp.Allowed {
		t.Fatalf("expected Allowed, got %+v", resp)
	}
	if resp.PatchType == nil || *resp.PatchType != admissionv1.PatchTypeJSONPatch {
		t.Fatalf("want JSON patch, got %v", resp.PatchType)
	}
	if !strings.Contains(string(resp.Patch), `"Tenant"`) || !strings.Contains(string(resp.Patch), "acme") {
		t.Fatalf("patch should reference Tenant/acme, got: %s", string(resp.Patch))
	}
}

func TestWebhook_NoPatchWhenOwnerRefAlreadyPresent(t *testing.T) {
	ns := tenantNamespace(testUID, "acme")
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(ns).Build()
	m := NewOwnerRefMutator(c)

	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{
			Name: "scanner-01", Namespace: "tenant-acme",
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "gibson.zeroroot.ai/v1alpha1",
				Kind:       "Tenant",
				Name:       "existing",
				UID:        "existing-uid",
			}},
		},
	}
	resp := m.Handle(context.Background(), request(t, marshalAE(t, ae), admissionv1.Create, "tenant-acme"))
	if !resp.Allowed {
		t.Fatalf("expected Allowed, got %+v", resp)
	}
	if len(resp.Patch) != 0 {
		t.Fatalf("should not patch when ownerRef already present; got: %s", string(resp.Patch))
	}
}

func TestWebhook_AllowsWhenAnnotationMissing(t *testing.T) {
	// Non-tenant namespace → ResolveTenantOwnerRef returns nil — webhook
	// allows through. Reconciler backfill will try when the CR reconciles.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "random-ns"}}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(ns).Build()
	m := NewOwnerRefMutator(c)

	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "scanner-01", Namespace: "random-ns"},
	}
	resp := m.Handle(context.Background(), request(t, marshalAE(t, ae), admissionv1.Create, "random-ns"))
	if !resp.Allowed {
		t.Fatalf("expected Allowed, got %+v", resp)
	}
	if len(resp.Patch) != 0 {
		t.Fatalf("should not patch when parent unresolvable; got: %s", string(resp.Patch))
	}
}

func TestWebhook_NotCreateIsNoOp(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	m := NewOwnerRefMutator(c)
	ae := &gibsonv1alpha1.AgentEnrollment{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "tenant-acme"},
	}
	resp := m.Handle(context.Background(), request(t, marshalAE(t, ae), admissionv1.Update, "tenant-acme"))
	if !resp.Allowed {
		t.Fatalf("expected Allowed (no-op) on UPDATE, got %+v", resp)
	}
	if len(resp.Patch) != 0 {
		t.Fatalf("UPDATE should not produce a patch; got: %s", string(resp.Patch))
	}
}

func TestWebhook_MalformedObjectAllows(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	m := NewOwnerRefMutator(c)
	resp := m.Handle(context.Background(), request(t, []byte("not json"), admissionv1.Create, "tenant-acme"))
	if !resp.Allowed {
		t.Fatalf("expected Allowed with warning on decode failure, got %+v", resp)
	}
}
