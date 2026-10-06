// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tiermigrate

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/operators/internal/audit"
	"github.com/zeroroot-ai/gibson/operators/internal/audit/audittest"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
)

func newClient(t *testing.T) client.Client {
	t.Helper()
	s := runtime.NewScheme()
	if err := gibsonv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(s).WithObjects(
		&gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "legacy"}, Spec: gibsonv1alpha1.TenantSpec{Tier: "solo"}},
		&gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "current"}, Spec: gibsonv1alpha1.TenantSpec{Tier: "team"}},
	).Build()
}

func tierOf(t *testing.T, c client.Client, name string) string {
	t.Helper()
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: name}, &got); err != nil {
		t.Fatal(err)
	}
	return string(got.Spec.Tier)
}

// One record per tier change, before the change; a canonical tier gets none
// (gibson#583).
func TestRun_RecordsEachTierChange(t *testing.T) {
	c := newClient(t)
	sink := &audittest.Sink{}
	if err := Run(context.Background(), c, Options{Workers: 1, Audit: sink.Emitter(t)}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got := sink.Events()
	if len(got) != 1 || got[0].Action != audit.ActionBackfill || got[0].TenantID != "legacy" ||
		got[0].Fields["from"] != "solo" || got[0].Fields["to"] != "team" {
		t.Fatalf("records = %+v", got)
	}
	if tierOf(t, c, "legacy") != "team" {
		t.Fatalf("tier = %q, want team", tierOf(t, c, "legacy"))
	}
}

// With no record, the tier does not change.
func TestRun_FailedRecordStopsTheTierChange(t *testing.T) {
	c := newClient(t)
	if err := Run(context.Background(), c, Options{Workers: 1, Audit: (&audittest.Sink{Err: errors.New("daemon down")}).Emitter(t)}); err == nil {
		t.Fatal("Run returned no error with no audit record")
	}
	if tierOf(t, c, "legacy") != "solo" {
		t.Fatalf("tier = %q, want solo with no record", tierOf(t, c, "legacy"))
	}
}
