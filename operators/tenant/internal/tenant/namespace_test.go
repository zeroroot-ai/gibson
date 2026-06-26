// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package tenant

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

// scheme with our CRD registered so the fake client can round-trip.
func testScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	return s
}

// TestNamespaceFor_StatusWins covers the source-of-truth case: when the
// Tenant CR's Status.Namespace is set, NamespaceFor MUST return that
// exact string — never the derived form.
func TestNamespaceFor_StatusWins(t *testing.T) {
	cr := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
		Status:     gibsonv1alpha1.TenantStatus{Namespace: "tenant-acme-renamed-by-status"},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(cr).Build()

	got, err := NamespaceFor(context.Background(), c, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "tenant-acme-renamed-by-status" {
		t.Errorf("Status.Namespace must win; got %q", got)
	}
}

// TestNamespaceFor_DerivedFallback covers the case where the CR exists
// but Status.Namespace is empty (e.g. reconciler runs before
// ProvisionNamespace's status write commits).
func TestNamespaceFor_DerivedFallback(t *testing.T) {
	cr := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).WithObjects(cr).Build()

	got, err := NamespaceFor(context.Background(), c, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "tenant-acme" {
		t.Errorf("derived fallback expected, got %q", got)
	}
}

// TestNamespaceFor_MissingCR covers the case where the CR isn't in the
// cluster yet (very early Provision call, tests without a cluster).
func TestNamespaceFor_MissingCR(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()

	got, err := NamespaceFor(context.Background(), c, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "tenant-acme" {
		t.Errorf("missing CR should derive; got %q", got)
	}
}

// TestNamespaceFor_NilClient supports test/hot-loop callers that don't
// want to hit the API server — derived form returned.
func TestNamespaceFor_NilClient(t *testing.T) {
	got, err := NamespaceFor(context.Background(), nil, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "tenant-acme" {
		t.Errorf("nil client should derive; got %q", got)
	}
}

// TestNamespaceFor_InvalidTenantID — the function gates on TenantID
// validation. Uppercase, empty, etc. fail loudly so callers don't
// silently produce malformed namespace strings.
func TestNamespaceFor_InvalidTenantID(t *testing.T) {
	for _, bad := range []string{"", "Acme", "tenant with spaces", "../escape"} {
		t.Run(bad, func(t *testing.T) {
			_, err := NamespaceFor(context.Background(), nil, bad)
			if err == nil {
				t.Errorf("expected error for invalid tenantID %q, got nil", bad)
			}
		})
	}
}
