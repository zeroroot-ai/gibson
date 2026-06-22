/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// --- ReservedNamesProvider stub ---

type stubProvider struct {
	exact  []string
	prefix []string
	err    error
}

func (s *stubProvider) ReservedNames(_ context.Context) ([]string, []string, error) {
	return s.exact, s.prefix, s.err
}

func TestTenantValidator_ValidateCreate_ReservedExact(t *testing.T) {
	v := &TenantValidator{
		ReservedNames: &stubProvider{exact: []string{"acme-corp"}},
	}
	_, err := v.ValidateCreate(context.Background(), validTenant())
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("expected reserved-name rejection, got %v", err)
	}
}

func TestTenantValidator_ValidateCreate_ReservedPrefix(t *testing.T) {
	v := &TenantValidator{
		ReservedNames: &stubProvider{prefix: []string{"acme-"}},
	}
	_, err := v.ValidateCreate(context.Background(), validTenant())
	if err == nil || !strings.Contains(err.Error(), "reserved prefix") {
		t.Fatalf("expected reserved-prefix rejection, got %v", err)
	}
}

func TestTenantValidator_ValidateCreate_NotReserved(t *testing.T) {
	v := &TenantValidator{
		ReservedNames: &stubProvider{
			exact:  []string{"default", "kube-system"},
			prefix: []string{"kube-"},
		},
	}
	_, err := v.ValidateCreate(context.Background(), validTenant())
	if err != nil {
		t.Fatalf("expected non-reserved tenant to pass, got %v", err)
	}
}

func TestTenantValidator_ValidateCreate_NilProvider_NoOp(t *testing.T) {
	v := &TenantValidator{}
	_, err := v.ValidateCreate(context.Background(), validTenant())
	if err != nil {
		t.Fatalf("expected nil-provider to pass, got %v", err)
	}
}

func TestTenantValidator_ValidateCreate_ProviderError_FailOpen(t *testing.T) {
	// Provider error must not block creation — the dashboard signup form
	// is the secondary gate and the daemon's downstream admission also
	// rejects reserved names.
	v := &TenantValidator{
		ReservedNames: &stubProvider{err: context.DeadlineExceeded},
	}
	_, err := v.ValidateCreate(context.Background(), validTenant())
	if err != nil {
		t.Fatalf("expected provider error to be failure-open, got %v", err)
	}
}

// --- ConfigMapReservedNames tests ---

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatalf("scheme: %v", err)
	}
	return s
}

func TestConfigMapReservedNames_NotFound(t *testing.T) {
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	p := NewConfigMapReservedNames(c, "gibson", 0)
	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on NotFound, got %v", err)
	}
	if len(exact) != 0 || len(prefix) != 0 {
		t.Fatalf("expected empty, got exact=%v prefix=%v", exact, prefix)
	}
}

func TestConfigMapReservedNames_ParsesAndCaches(t *testing.T) {
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: ReservedNamesConfigMap, Namespace: "gibson"},
		Data: map[string]string{
			"exact":  "default\n# comment\n\nkube-system",
			"prefix": "kube-\nsystem-",
		},
	}
	c := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(cm).Build()
	p := NewConfigMapReservedNames(c, "gibson", 0)
	exact, prefix, err := p.ReservedNames(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !equal(exact, []string{"default", "kube-system"}) {
		t.Errorf("exact: %v", exact)
	}
	if !equal(prefix, []string{"kube-", "system-"}) {
		t.Errorf("prefix: %v", prefix)
	}
}

func equal(a, b []string) bool {
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
