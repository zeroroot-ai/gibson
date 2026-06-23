/*
Copyright 2026 Zero Day AI.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

// tenant_status_report_test.go — the operator→daemon status-mirror reporting
// (dashboard#855): the Tenant reconcile reports phase/ready/zitadel/dataPlane;
// the founding-owner TenantMember reports owner_member_ready on Active.
package controller

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/provision"
)

// stubStatusReporter records ReportTenantStatus calls.
type stubStatusReporter struct {
	reports []provision.TenantStatusReport
	err     error
}

func (s *stubStatusReporter) ReportTenantStatus(_ context.Context, r provision.TenantStatusReport) error {
	s.reports = append(s.reports, r)
	return s.err
}

func TestReportTenantStatus_MirrorsTenantCRStatus(t *testing.T) {
	rep := &stubStatusReporter{}
	r := &TenantReconciler{StatusReporter: rep}

	tenant := &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	}
	tenant.Status.Phase = gibsonv1alpha1.TenantPhaseReady
	tenant.Status.ZitadelOrgID = "org-123"
	tenant.Status.DataPlane.Ready = true

	r.reportTenantStatus(context.Background(), tenant)

	if len(rep.reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(rep.reports))
	}
	got := rep.reports[0]
	if got.TenantID != "acme" || got.Phase != "Ready" || !got.Ready ||
		got.ZitadelOrgID != "org-123" || !got.DataPlaneReady {
		t.Errorf("unexpected report: %+v", got)
	}
	if got.OwnerMemberReady {
		t.Errorf("Tenant reconcile must report owner_member_ready=false (member path owns it)")
	}
}

func TestReportTenantStatus_NoopReporter_NoOp(t *testing.T) {
	// SetupWithManager defaults StatusReporter to the noop when no daemon client
	// is wired; the helper carries no `== nil` branch, so it must run cleanly
	// against the null object.
	r := &TenantReconciler{StatusReporter: noopTenantStatusReporter{}}
	r.reportTenantStatus(context.Background(), &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	})
}

func TestReportTenantStatus_ReporterError_DoesNotPanic(t *testing.T) {
	rep := &stubStatusReporter{err: errors.New("daemon unreachable")}
	r := &TenantReconciler{StatusReporter: rep}
	// Best-effort: a report error is logged, never propagated/panics.
	r.reportTenantStatus(context.Background(), &gibsonv1alpha1.Tenant{
		ObjectMeta: metav1.ObjectMeta{Name: "acme"},
	})
	if len(rep.reports) != 1 {
		t.Errorf("expected the report to have been attempted")
	}
}

func TestReportOwnerMemberReady_OwnerActive_ReportsTrue(t *testing.T) {
	scheme := setupScheme(t)
	// Seed the live Tenant CR so the member path enriches the report with its
	// current status (rather than clobbering phase/ready with empties).
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.Phase = gibsonv1alpha1.TenantPhaseReady
	tenant.Status.ZitadelOrgID = "org-123"
	tenant.Status.DataPlane.Ready = true
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	rep := &stubStatusReporter{}
	r := &TenantMemberReconciler{Client: c, StatusReporter: rep}

	tm := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-acme-test-owner", Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "owner@acme.test",
			Role:      gibsonv1alpha1.MemberRoleOwner,
			TenantRef: corev1.LocalObjectReference{Name: "acme"},
		},
	}
	r.reportOwnerMemberReady(context.Background(), tm)

	if len(rep.reports) != 1 {
		t.Fatalf("expected 1 report, got %d", len(rep.reports))
	}
	got := rep.reports[0]
	if got.TenantID != "acme" || !got.OwnerMemberReady {
		t.Errorf("expected owner_member_ready=true for acme, got %+v", got)
	}
	// Enriched from the live Tenant CR (so the upsert does not regress these).
	if got.Phase != "Ready" || !got.Ready || got.ZitadelOrgID != "org-123" || !got.DataPlaneReady {
		t.Errorf("expected report enriched from live Tenant status, got %+v", got)
	}
}

func TestReportOwnerMemberReady_ReporterError_DoesNotPanic(t *testing.T) {
	scheme := setupScheme(t)
	tenant := &gibsonv1alpha1.Tenant{ObjectMeta: metav1.ObjectMeta{Name: "acme"}}
	tenant.Status.Phase = gibsonv1alpha1.TenantPhaseReady
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(tenant).Build()

	rep := &stubStatusReporter{err: errors.New("daemon unreachable")}
	r := &TenantMemberReconciler{Client: c, StatusReporter: rep}
	tm := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-acme-test-owner", Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email: "owner@acme.test", Role: gibsonv1alpha1.MemberRoleOwner,
			TenantRef: corev1.LocalObjectReference{Name: "acme"},
		},
	}
	// Best-effort: a report error is logged, never propagated.
	r.reportOwnerMemberReady(context.Background(), tm)
	if len(rep.reports) != 1 {
		t.Errorf("expected the report to have been attempted")
	}
}

// TestReportOwnerMemberReady_TenantMissing_ReportsReadinessOnly: when the live
// Tenant CR cannot be read, the report still carries owner_member_ready=true
// (the enrich step is skipped, not fatal).
func TestReportOwnerMemberReady_TenantMissing_ReportsReadinessOnly(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build() // no Tenant CR
	rep := &stubStatusReporter{}
	r := &TenantMemberReconciler{Client: c, StatusReporter: rep}
	tm := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-acme-test-owner", Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email: "owner@acme.test", Role: gibsonv1alpha1.MemberRoleOwner,
			TenantRef: corev1.LocalObjectReference{Name: "acme"},
		},
	}
	r.reportOwnerMemberReady(context.Background(), tm)
	if len(rep.reports) != 1 || !rep.reports[0].OwnerMemberReady {
		t.Fatalf("expected owner_member_ready=true even with Tenant CR missing, got %+v", rep.reports)
	}
	if rep.reports[0].Phase != "" {
		t.Errorf("expected empty phase when Tenant CR unreadable, got %q", rep.reports[0].Phase)
	}
}

func TestReportOwnerMemberReady_NonOwner_NoReport(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	rep := &stubStatusReporter{}
	r := &TenantMemberReconciler{Client: c, StatusReporter: rep}

	tm := &gibsonv1alpha1.TenantMember{
		ObjectMeta: metav1.ObjectMeta{Name: "member-x", Namespace: "tenant-acme"},
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Email:     "member@acme.test",
			Role:      gibsonv1alpha1.MemberRoleMember,
			TenantRef: corev1.LocalObjectReference{Name: "acme"},
		},
	}
	r.reportOwnerMemberReady(context.Background(), tm)
	if len(rep.reports) != 0 {
		t.Errorf("expected no report for a non-owner member, got %d", len(rep.reports))
	}
}

func TestReportOwnerMemberReady_NoopReporter_NoOp(t *testing.T) {
	scheme := setupScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()
	r := &TenantMemberReconciler{Client: c, StatusReporter: noopTenantStatusReporter{}}
	// owner role + noop reporter: runs cleanly (Tenant CR absent → enrich skipped).
	r.reportOwnerMemberReady(context.Background(), &gibsonv1alpha1.TenantMember{
		Spec: gibsonv1alpha1.TenantMemberSpec{
			Role:      gibsonv1alpha1.MemberRoleOwner,
			TenantRef: corev1.LocalObjectReference{Name: "acme"},
		},
	})
}
