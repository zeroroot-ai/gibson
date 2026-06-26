// Copyright 2026 Zero Day AI, Inc.
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package controller

import (
	"context"
	"errors"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// stubReporter records the report it received and returns a fixed billing flag.
type stubReporter struct {
	billingActive bool
	err           error
	got           provision.TenantStatusReport
	calls         int
}

func (s *stubReporter) ReportTenantStatus(_ context.Context, r provision.TenantStatusReport) (bool, error) {
	s.calls++
	s.got = r
	return s.billingActive, s.err
}

func tenantWithStatus() *gibsonv1alpha1.Tenant {
	t := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	t.Status.Phase = gibsonv1alpha1.TenantPhaseProvisioning
	t.Status.DataPlane.Ready = false
	t.Status.DataPlane.Stores.Postgres.State = "ready"
	t.Status.DataPlane.Stores.Redis.State = "provisioning"
	t.Status.ZitadelOrgSlug = "acme-org"
	t.Status.Billing.CustomerID = "cus_9"
	return t
}

func TestReportStatusToDaemon_NoopReporter_NoStamp(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	// NoopTenantStatusReporter is what main.go injects when report-back is
	// disabled (no daemon address). It must no-op: never stamp the annotation,
	// never panic.
	r := &TenantReconciler{Client: c, StatusReporter: NoopTenantStatusReporter{}}
	r.reportStatusToDaemon(context.Background(), tenant)

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if _, ok := got.Annotations[AnnotationBillingActive]; ok {
		t.Errorf("noop reporter must not stamp billing-active")
	}
}

func TestReportStatusToDaemon_MapsStatusFields(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	rep := &stubReporter{billingActive: false}
	r := &TenantReconciler{Client: c, StatusReporter: rep}

	r.reportStatusToDaemon(context.Background(), tenant)

	if rep.calls != 1 {
		t.Fatalf("expected 1 report call, got %d", rep.calls)
	}
	g := rep.got
	if g.TenantID != "acme" || g.Phase != "Provisioning" || g.DataPlaneReady {
		t.Errorf("unexpected report: %+v", g)
	}
	if g.StorePostgres != "ready" || g.StoreRedis != "provisioning" {
		t.Errorf("unexpected store states: %+v", g)
	}
	if g.ZitadelOrgSlug != "acme-org" || g.StripeCustomerID != "cus_9" {
		t.Errorf("unexpected org/stripe: %+v", g)
	}
}

func TestReportStatusToDaemon_StripeCustomerIDFallback(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	// Billing.CustomerID empty → reporter falls back to Status.StripeCustomerID.
	tenant.Status.Billing.CustomerID = ""
	tenant.Status.StripeCustomerID = "cus_fallback"
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	rep := &stubReporter{}
	r := &TenantReconciler{Client: c, StatusReporter: rep}

	r.reportStatusToDaemon(context.Background(), tenant)

	if rep.got.StripeCustomerID != "cus_fallback" {
		t.Errorf("expected fallback to Status.StripeCustomerID, got %q", rep.got.StripeCustomerID)
	}
}

func TestReportStatusToDaemon_BillingActive_StampsAnnotation(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	r := &TenantReconciler{Client: c, StatusReporter: &stubReporter{billingActive: true}}

	r.reportStatusToDaemon(context.Background(), tenant)

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.Annotations[AnnotationBillingActive] != "true" {
		t.Errorf("expected billing-active annotation stamped, got %q", got.Annotations[AnnotationBillingActive])
	}
}

func TestReportStatusToDaemon_BillingInactive_NoAnnotation(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	r := &TenantReconciler{Client: c, StatusReporter: &stubReporter{billingActive: false}}

	r.reportStatusToDaemon(context.Background(), tenant)

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if _, ok := got.Annotations[AnnotationBillingActive]; ok {
		t.Errorf("did not expect billing-active annotation when billing inactive")
	}
}

func TestReportStatusToDaemon_ReportError_NoStamp_NoPanic(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	r := &TenantReconciler{Client: c, StatusReporter: &stubReporter{billingActive: true, err: errors.New("daemon down")}}

	// Best-effort: a report error must not panic and must not stamp the annotation.
	r.reportStatusToDaemon(context.Background(), tenant)

	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if _, ok := got.Annotations[AnnotationBillingActive]; ok {
		t.Errorf("did not expect annotation when report errored")
	}
}

func TestEnsureBillingActiveAnnotation_Idempotent(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	tenant.Annotations = map[string]string{AnnotationBillingActive: "true"}
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	r := &TenantReconciler{Client: c}

	// Already set → no-op, returns nil without a patch.
	if err := r.ensureBillingActiveAnnotation(context.Background(), tenant); err != nil {
		t.Fatalf("expected no-op nil, got %v", err)
	}
}
