// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

// stubReporter records the report it received.
type stubReporter struct {
	err   error
	got   provision.TenantStatusReport
	calls int
}

func (s *stubReporter) ReportTenantStatus(_ context.Context, r provision.TenantStatusReport) error {
	s.calls++
	s.got = r
	return s.err
}

func tenantWithStatus() *gibsonv1alpha1.Tenant {
	t := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	t.Status.Phase = gibsonv1alpha1.TenantPhaseProvisioning
	t.Status.DataPlane.Ready = false
	t.Status.DataPlane.Stores.Postgres.State = "ready"
	t.Status.DataPlane.Stores.Redis.State = "provisioning"
	t.Status.ZitadelOrgSlug = "acme-org"
	return t
}

// The report changes nothing on the Tenant CR. The platform holds no billing
// state (D54).
func assertNoAnnotations(t *testing.T, c client.Client) {
	t.Helper()
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), client.ObjectKey{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if len(got.Annotations) != 0 {
		t.Errorf("the report stamped annotations: %v", got.Annotations)
	}
}

func TestReportStatusToDaemon_NoopReporter(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	// NoopTenantStatusReporter is what main.go injects when report-back is
	// disabled (no daemon address). It must no-op and never panic.
	r := &TenantReconciler{Client: c, StatusReporter: NoopTenantStatusReporter{}}
	r.reportStatusToDaemon(context.Background(), tenant)
	assertNoAnnotations(t, c)
}

func TestReportStatusToDaemon_MapsStatusFields(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	rep := &stubReporter{}
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
	if g.ZitadelOrgSlug != "acme-org" {
		t.Errorf("unexpected org: %+v", g)
	}
	assertNoAnnotations(t, c)
}

func TestReportStatusToDaemon_ReportError_NoPanic(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	r := &TenantReconciler{Client: c, StatusReporter: &stubReporter{err: errors.New("daemon down")}}

	// Best-effort: a report error must not panic.
	r.reportStatusToDaemon(context.Background(), tenant)
	assertNoAnnotations(t, c)
}

// recordingReporter keeps every report, in order.
type recordingReporter struct {
	reports []provision.TenantStatusReport
	err     error
}

func (s *recordingReporter) ReportTenantStatus(_ context.Context, r provision.TenantStatusReport) error {
	s.reports = append(s.reports, r)
	return s.err
}

// TestReconcileDelete_ReportsTeardownToTheDaemon proves a tenant in deletion
// is reported (gibson#661). Before this, only the provisioning path reported,
// so tenant_status kept the last "Ready, data plane ready" row of a deleted
// tenant, and every reader of that table went on serving it.
func TestReconcileDelete_ReportsTeardownToTheDaemon(t *testing.T) {
	now := metav1.Now()
	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "leaving", Finalizers: []string{gibsonv1alpha1.TenantFinalizer}, DeletionTimestamp: &now},
		Spec:       gibsonv1alpha1.TenantSpec{DisplayName: "Leaving", Owner: "owner@leaving.com", Tier: gibsonv1alpha1.TenantPlanTeam},
	}
	// The state the last provisioning report left behind.
	tenant.Status.Phase = gibsonv1alpha1.TenantPhaseReady
	tenant.Status.DataPlane.Ready = true
	tenant.Status.Namespace = "tenant-leaving"

	r, c := newFakeReconciler(t, tenant)
	rep := &recordingReporter{}
	r.StatusReporter = rep

	if _, err := r.reconcileDelete(context.Background(), tenant); err != nil {
		t.Fatalf("reconcileDelete: %v", err)
	}
	_ = c

	if len(rep.reports) == 0 {
		t.Fatal("the deletion path reported nothing to the daemon")
	}
	first := rep.reports[0]
	if first.TenantID != "leaving" || first.Phase != string(gibsonv1alpha1.TenantPhaseTerminating) || first.DataPlaneReady {
		t.Errorf("first report = %+v, want leaving, Terminating, data plane not ready", first)
	}
	for i, got := range rep.reports {
		if got.DataPlaneReady {
			t.Errorf("report %d says the data plane is ready during teardown: %+v", i, got)
		}
		if got.Phase != string(gibsonv1alpha1.TenantPhaseTerminating) && got.Phase != string(gibsonv1alpha1.TenantPhaseTerminated) {
			t.Errorf("report %d has phase %q, want a teardown phase", i, got.Phase)
		}
	}
}

// TestReportTeardownToDaemon_IsBestEffortAndStampsNothing proves a daemon
// error does not fail the deletion, and that a teardown report stamps
// nothing on the Tenant CR.
func TestReportTeardownToDaemon_IsBestEffortAndStampsNothing(t *testing.T) {
	scheme := setupScheme(t)
	tenant := tenantWithStatus()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()
	rep := &recordingReporter{err: errors.New("daemon down")}
	r := &TenantReconciler{Client: c, StatusReporter: rep}

	r.reportTeardownToDaemon(context.Background(), tenant, gibsonv1alpha1.TenantPhaseTerminated)

	if len(rep.reports) != 1 || rep.reports[0].Phase != string(gibsonv1alpha1.TenantPhaseTerminated) || rep.reports[0].DataPlaneReady {
		t.Fatalf("reports = %+v, want one Terminated report with the data plane not ready", rep.reports)
	}
	if rep.reports[0].ZitadelOrgSlug != "acme-org" {
		t.Errorf("the teardown report dropped identity fields: %+v", rep.reports[0])
	}
	assertNoAnnotations(t, c)
}
