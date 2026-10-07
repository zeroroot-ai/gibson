// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package rbac

import (
	"context"
	"errors"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

func newClient(t *testing.T) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).
		WithObjects(&gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}).Build()
}

func bindings(t *testing.T, c client.Client) int {
	t.Helper()
	var l rbacv1.RoleBindingList
	if err := c.List(context.Background(), &l, client.InNamespace("tenant-acme")); err != nil {
		t.Fatal(err)
	}
	return len(l.Items)
}

// One record per change: the first run changes the RoleBindings after its
// record, and a second run finds them current and writes no record
// (gibson#583).
func TestRun_RecordsEachChangeOnce(t *testing.T) {
	c := newClient(t)
	sink := &audittest.Sink{}
	opts := Options{Workers: 1, OperatorNamespace: "gibson", Audit: sink.Emitter(t)}
	for range 2 {
		if err := Run(context.Background(), c, opts); err != nil {
			t.Fatalf("Run: %v", err)
		}
	}
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionBackfill || got[0].TenantID != "acme" || got[0].Fields["backfill"] != "rbac" {
		t.Fatalf("records = %+v, want one record of the one change", got)
	}
	if bindings(t, c) != 2 {
		t.Fatalf("RoleBindings = %d, want 2", bindings(t, c))
	}
}

// With no record, no RoleBinding changes.
func TestRun_FailedRecordStopsTheChange(t *testing.T) {
	c := newClient(t)
	opts := Options{Workers: 1, OperatorNamespace: "gibson", Audit: (&audittest.Sink{Err: errors.New("daemon down")}).Emitter(t)}
	if err := Run(context.Background(), c, opts); err == nil {
		t.Fatal("Run returned no error with no audit record")
	}
	if n := bindings(t, c); n != 0 {
		t.Fatalf("RoleBindings = %d, want none with no record", n)
	}
	if err := Run(context.Background(), c, Options{}); !errors.Is(err, audit.ErrNoSink) {
		t.Fatalf("Run with no emitter = %v, want ErrNoSink", err)
	}
}
