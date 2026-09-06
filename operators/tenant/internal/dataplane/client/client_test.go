// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package client

import (
	"context"
	"fmt"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const operatorNS = "gibson"

func testScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := corev1.AddToScheme(s); err != nil {
		t.Fatalf("corev1.AddToScheme: %v", err)
	}
	if err := appsv1.AddToScheme(s); err != nil {
		t.Fatalf("appsv1.AddToScheme: %v", err)
	}
	if err := networkingv1.AddToScheme(s); err != nil {
		t.Fatalf("networkingv1.AddToScheme: %v", err)
	}
	if err := rbacv1.AddToScheme(s); err != nil {
		t.Fatalf("rbacv1.AddToScheme: %v", err)
	}
	return s
}

func newWrappedClient(t *testing.T) *Client {
	inner := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	return New(inner, operatorNS)
}

// perTenantKindSamples produces one zero-value instance of every kind the
// wrapper guards. The test table below uses this so every kind is
// exercised against every method.
func perTenantKindSamples() []ctrlclient.Object {
	return []ctrlclient.Object{
		&corev1.ConfigMap{},
		&corev1.Secret{},
		&corev1.PersistentVolumeClaim{},
		&corev1.Service{},
		&appsv1.StatefulSet{},
		&networkingv1.NetworkPolicy{},
		&rbacv1.Role{},
		&rbacv1.RoleBinding{},
	}
}

// inOperatorNS clones obj and sets a non-empty name + the operator
// namespace so the call reaches the guard with the exact shape that
// reproduces the bug class behind tenant-operator#57 (per-tenant kind
// targeted at the operator ns by mistake).
func inOperatorNS(obj ctrlclient.Object) ctrlclient.Object {
	out := obj.DeepCopyObject().(ctrlclient.Object)
	out.SetName("x") // non-empty so K8s API validation passes
	out.SetNamespace(operatorNS)
	return out
}

// TestCreate_RejectsOperatorNamespace asserts every per-tenant kind is
// rejected on Create when the target namespace equals the operator's
// release namespace.
func TestCreate_RejectsOperatorNamespace(t *testing.T) {
	c := newWrappedClient(t)
	for _, sample := range perTenantKindSamples() {
		t.Run(typeLabel(sample), func(t *testing.T) {
			obj := inOperatorNS(sample)
			err := c.Create(context.Background(), obj)
			if err == nil {
				t.Fatalf("expected refusal, got nil")
			}
			if !strings.Contains(err.Error(), "operator namespace") {
				t.Errorf("error must mention 'operator namespace', got: %v", err)
			}
			if !strings.Contains(err.Error(), "tenant-operator#86") {
				t.Errorf("error must reference #86 for future readers, got: %v", err)
			}
		})
	}
}

// TestUpdate_RejectsOperatorNamespace mirrors the Create test for Update.
func TestUpdate_RejectsOperatorNamespace(t *testing.T) {
	c := newWrappedClient(t)
	for _, sample := range perTenantKindSamples() {
		t.Run(typeLabel(sample), func(t *testing.T) {
			obj := inOperatorNS(sample)
			err := c.Update(context.Background(), obj)
			if err == nil || !strings.Contains(err.Error(), "operator namespace") {
				t.Errorf("expected refusal on Update, got: %v", err)
			}
		})
	}
}

// TestDelete_RejectsOperatorNamespace mirrors for Delete.
func TestDelete_RejectsOperatorNamespace(t *testing.T) {
	c := newWrappedClient(t)
	for _, sample := range perTenantKindSamples() {
		t.Run(typeLabel(sample), func(t *testing.T) {
			obj := inOperatorNS(sample)
			err := c.Delete(context.Background(), obj)
			if err == nil || !strings.Contains(err.Error(), "operator namespace") {
				t.Errorf("expected refusal on Delete, got: %v", err)
			}
		})
	}
}

// TestGet_RejectsOperatorNamespace exercises the read path.
func TestGet_RejectsOperatorNamespace(t *testing.T) {
	c := newWrappedClient(t)
	for _, sample := range perTenantKindSamples() {
		t.Run(typeLabel(sample), func(t *testing.T) {
			obj := sample.DeepCopyObject().(ctrlclient.Object)
			key := ctrlclient.ObjectKey{Name: "x", Namespace: operatorNS}
			err := c.Get(context.Background(), key, obj)
			if err == nil || !strings.Contains(err.Error(), "operator namespace") {
				t.Errorf("expected refusal on Get, got: %v", err)
			}
		})
	}
}

// TestPatch_RejectsOperatorNamespace exercises Patch.
func TestPatch_RejectsOperatorNamespace(t *testing.T) {
	c := newWrappedClient(t)
	for _, sample := range perTenantKindSamples() {
		t.Run(typeLabel(sample), func(t *testing.T) {
			obj := inOperatorNS(sample)
			err := c.Patch(context.Background(), obj, ctrlclient.RawPatch(types.MergePatchType, []byte("{}")))
			if err == nil || !strings.Contains(err.Error(), "operator namespace") {
				t.Errorf("expected refusal on Patch, got: %v", err)
			}
		})
	}
}

// TestCreate_AllowsTenantNamespace confirms per-tenant kinds CAN be
// written when the namespace is a tenant namespace (the happy path).
func TestCreate_AllowsTenantNamespace(t *testing.T) {
	inner := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	c := New(inner, operatorNS)
	obj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "neo4j-auth", Namespace: "tenant-acme"},
	}
	if err := c.Create(context.Background(), obj); err != nil {
		t.Fatalf("create in tenant ns must succeed; got %v", err)
	}
}

// TestUnscoped_BypassesGuard documents that Unscoped() is the
// intentional escape hatch and lets a write to the operator ns through.
// Callers that use this MUST comment their reason.
func TestUnscoped_BypassesGuard(t *testing.T) {
	inner := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	c := New(inner, operatorNS)
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-neo4j-template", Namespace: operatorNS},
	}
	// e.g. the chart-mounted ConfigMap that lives in the gibson ns
	if err := c.Unscoped().Create(context.Background(), cm); err != nil {
		t.Fatalf("Unscoped().Create must bypass guard; got %v", err)
	}
}

// TestNonGuardedKindPasses confirms the wrapper is a no-op for kinds
// that AREN'T in the per-tenant set (e.g. Pod, which the operator only
// reads diagnostically — see TestCacheDisableForParity allowlist).
func TestNonGuardedKindPasses(t *testing.T) {
	inner := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	c := New(inner, operatorNS)
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "diag", Namespace: operatorNS},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "main", Image: "busybox"}},
		},
	}
	if err := c.Create(context.Background(), pod); err != nil {
		t.Fatalf("non-guarded kind must pass through; got %v", err)
	}
}

// TestZeroOperatorNamespace is a permissive-fallback test: when New is
// constructed with operatorNamespace="" (test fixtures that don't care),
// the guard never fires. Documented behaviour so test setup is simple.
func TestZeroOperatorNamespace(t *testing.T) {
	inner := fake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	c := New(inner, "")
	obj := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "anywhere"},
	}
	if err := c.Create(context.Background(), obj); err != nil {
		t.Fatalf("zero operatorNamespace must short-circuit guard; got %v", err)
	}
}

func typeLabel(o ctrlclient.Object) string {
	return strings.TrimPrefix(fmt.Sprintf("%T", o), "*")
}

// TestGuard_ErrorNeverContainsSecretData is a regression test for
// gibson#1444. The guard reports on objects that routinely hold live
// tenant credentials — a *corev1.Secret here carries the per-tenant Neo4j
// password — so the refusal error must describe the object by kind and
// never by value.
//
// The guard previously formatted the object itself with %T. That printed
// only the dynamic type, so it did not leak, but it kept a live Secret in
// the argument list of a formatting call, one verb change away from
// writing tenant credentials into the operator's logs. This test fails if
// anyone reintroduces the object as a format argument.
func TestGuard_ErrorNeverContainsSecretData(t *testing.T) {
	// Not a credential: a canary string this test asserts never appears in
	// the guard's error. It has to look like a password for the assertion to
	// mean anything.
	const password = "s3cr3t-neo4j-password-do-not-log" //nolint:gosec // G101: test canary, not a real secret

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-neo4j", Namespace: operatorNS},
		StringData: map[string]string{
			"password":   password,
			"NEO4J_AUTH": "neo4j/" + password,
		},
		Data: map[string][]byte{"password": []byte(password)},
	}

	c := newWrappedClient(t)
	for _, tc := range []struct {
		op   string
		call func() error
	}{
		{"Create", func() error { return c.Create(context.Background(), secret) }},
		{"Update", func() error { return c.Update(context.Background(), secret) }},
		{"Delete", func() error { return c.Delete(context.Background(), secret) }},
		{"Get", func() error {
			return c.Get(context.Background(),
				types.NamespacedName{Name: secret.Name, Namespace: operatorNS}, secret)
		}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatalf("expected refusal, got nil")
			}
			msg := err.Error()
			if strings.Contains(msg, password) {
				t.Fatalf("refusal error leaked the Secret's password: %s", msg)
			}
			// The diagnostic must still identify what was refused.
			if !strings.Contains(msg, "Secret") {
				t.Errorf("error must name the kind, got: %s", msg)
			}
		})
	}
}
