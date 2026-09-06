// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"errors"
	"sync"
	"testing"

	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/tenant/api/v1alpha1"
	"github.com/zeroroot-ai/gibson/operators/tenant/internal/mail"
)

// fakeMailSender records every SendWelcome call and can be told to fail, so
// the tests can assert the exactly-once contract and the best-effort
// failure path without an SMTP server.
type fakeMailSender struct {
	mu       sync.Mutex
	welcomes []mail.WelcomeMessage
	err      error
}

func (f *fakeMailSender) SendInvitation(context.Context, mail.InvitationMessage) error { return nil }

func (f *fakeMailSender) SendWelcome(_ context.Context, msg mail.WelcomeMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.welcomes = append(f.welcomes, msg)
	return f.err
}

func (f *fakeMailSender) calls() []mail.WelcomeMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]mail.WelcomeMessage, len(f.welcomes))
	copy(out, f.welcomes)
	return out
}

// welcomeTenant is the child-orchestration tenant plus the founding owner
// address the welcome email is addressed to.
func welcomeTenant(owner string) *gibsonv1alpha1.Tenant {
	tenant := childOrchestrationTenant()
	tenant.Spec.Owner = owner
	return tenant
}

// driveTenantToReady runs the reconciles that walk a fresh Tenant through
// finalizer → namespace → the four children, flipping each child Ready as its
// predecessor converges, and returns with the Tenant at phase Ready.
func driveTenantToReady(t *testing.T, r *TenantReconciler, c client.Client) {
	t.Helper()
	reconcileTenant(t, r) // finalizer
	reconcileTenant(t, r) // namespace + Identity
	markIdentityReadyFlag(t, c)
	reconcileTenant(t, r)
	markSecretsReadyFlag(t, c)
	reconcileTenant(t, r)
	markGrantsReadyFlag(t, c)
	reconcileTenant(t, r)
	markDataPlaneReadyFlag(t, c)
	reconcileTenant(t, r) // flips Ready

	got := getWelcomeTenant(t, c)
	if got.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		t.Fatalf("setup: tenant phase got %q, want Ready", got.Status.Phase)
	}
}

func getWelcomeTenant(t *testing.T, c client.Client) *gibsonv1alpha1.Tenant {
	t.Helper()
	var got gibsonv1alpha1.Tenant
	if err := c.Get(context.Background(), types.NamespacedName{Name: "acme"}, &got); err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	return &got
}

// TestWelcomeEmail_SentOnceAtReadyTransition proves the workspace-ready
// welcome mail goes out when the Tenant reaches Ready, addressed to the
// founding owner, with the persisted WelcomeEmailSent condition as the
// idempotence record. gibson#1447.
func TestWelcomeEmail_SentOnceAtReadyTransition(t *testing.T) {
	sender := &fakeMailSender{}
	r, c := newChildOrchestrationReconciler(t, welcomeTenant("owner@acme.com"))
	r.Mail = sender
	r.DashboardBaseURL = "https://app.zeroroot.ai"

	driveTenantToReady(t, r, c)

	calls := sender.calls()
	if len(calls) != 1 {
		t.Fatalf("SendWelcome called %d times, want exactly 1", len(calls))
	}
	if calls[0].To != "owner@acme.com" {
		t.Errorf("To got %q, want the founding owner owner@acme.com", calls[0].To)
	}
	if calls[0].TenantName != "Acme Inc" {
		t.Errorf("TenantName got %q, want the tenant display name %q", calls[0].TenantName, "Acme Inc")
	}
	if calls[0].DashboardURL != "https://app.zeroroot.ai" {
		t.Errorf("DashboardURL got %q, want the injected dashboard base URL", calls[0].DashboardURL)
	}

	got := getWelcomeTenant(t, c)
	if !apimeta.IsStatusConditionTrue(got.Status.Conditions, gibsonv1alpha1.ConditionWelcomeEmailSent) {
		t.Fatalf("condition %q must be persisted True after a successful send; conditions=%+v",
			gibsonv1alpha1.ConditionWelcomeEmailSent, got.Status.Conditions)
	}
}

// TestWelcomeEmail_NotResentOnSubsequentReconciles is the idempotence gate.
// Reconcile re-runs on every watch event; an unguarded send mails the owner
// on each pass (the tenant-operator#354 class).
func TestWelcomeEmail_NotResentOnSubsequentReconciles(t *testing.T) {
	sender := &fakeMailSender{}
	r, c := newChildOrchestrationReconciler(t, welcomeTenant("owner@acme.com"))
	r.Mail = sender

	driveTenantToReady(t, r, c)
	if got := len(sender.calls()); got != 1 {
		t.Fatalf("SendWelcome called %d times on the Ready transition, want 1", got)
	}

	for range 3 {
		reconcileTenant(t, r)
	}

	if got := len(sender.calls()); got != 1 {
		t.Fatalf("SendWelcome called %d times after 3 extra Ready reconciles, want 1", got)
	}
}

// TestWelcomeEmail_SendFailureLeavesConditionUnsetAndTenantReady asserts the
// best-effort contract: an SMTP failure must not fail the reconcile nor flip
// the tenant out of Ready, and must NOT record the condition, so the next
// reconcile retries.
func TestWelcomeEmail_SendFailureLeavesConditionUnsetAndTenantReady(t *testing.T) {
	sender := &fakeMailSender{err: errors.New("smtp: connection refused")}
	r, c := newChildOrchestrationReconciler(t, welcomeTenant("owner@acme.com"))
	r.Mail = sender

	driveTenantToReady(t, r, c)

	got := getWelcomeTenant(t, c)
	if got.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		t.Errorf("phase got %q, want Ready — a mail failure must not flip the tenant out of Ready", got.Status.Phase)
	}
	if apimeta.IsStatusConditionTrue(got.Status.Conditions, gibsonv1alpha1.ConditionWelcomeEmailSent) {
		t.Fatalf("condition %q must stay unset after a failed send so the next reconcile retries",
			gibsonv1alpha1.ConditionWelcomeEmailSent)
	}
	if n := len(sender.calls()); n != 1 {
		t.Fatalf("SendWelcome called %d times, want 1 attempt", n)
	}

	// The retry lands on the next pass, and once it succeeds the condition
	// is recorded so no third mail goes out.
	sender.mu.Lock()
	sender.err = nil
	sender.mu.Unlock()
	reconcileTenant(t, r)
	if n := len(sender.calls()); n != 2 {
		t.Fatalf("SendWelcome called %d times, want a retry after the failure", n)
	}
	reconcileTenant(t, r)
	if n := len(sender.calls()); n != 2 {
		t.Fatalf("SendWelcome called %d times after the retry succeeded, want it to stop at 2", n)
	}
}

// TestWelcomeEmail_EmptyOwnerIsNoOp mirrors
// TestEnsureFoundingMember_EmptyOwnerEmail_NoOp: a Tenant with no owner
// address has nobody to welcome, and must not blow up the reconcile.
func TestWelcomeEmail_EmptyOwnerIsNoOp(t *testing.T) {
	sender := &fakeMailSender{}
	r, c := newChildOrchestrationReconciler(t, welcomeTenant(""))
	r.Mail = sender

	driveTenantToReady(t, r, c)

	if n := len(sender.calls()); n != 0 {
		t.Fatalf("SendWelcome called %d times for a tenant with no owner, want 0", n)
	}
	got := getWelcomeTenant(t, c)
	if apimeta.IsStatusConditionTrue(got.Status.Conditions, gibsonv1alpha1.ConditionWelcomeEmailSent) {
		t.Errorf("condition %q must not be set when no mail was sent", gibsonv1alpha1.ConditionWelcomeEmailSent)
	}
}

// TestWelcomeEmail_NilMailerIsNoOp keeps the reconcile working for operators
// booted without a mailer (and for every other test in this package that
// leaves Mail unset).
func TestWelcomeEmail_NilMailerIsNoOp(t *testing.T) {
	r, c := newChildOrchestrationReconciler(t, welcomeTenant("owner@acme.com"))

	driveTenantToReady(t, r, c)

	got := getWelcomeTenant(t, c)
	if got.Status.Phase != gibsonv1alpha1.TenantPhaseReady {
		t.Errorf("phase got %q, want Ready with no mailer wired", got.Status.Phase)
	}
	if apimeta.IsStatusConditionTrue(got.Status.Conditions, gibsonv1alpha1.ConditionWelcomeEmailSent) {
		t.Errorf("condition %q must not be set when no mailer is wired", gibsonv1alpha1.ConditionWelcomeEmailSent)
	}
}

// TestWelcomeEmail_ConditionRecordsGenerationAndTime documents the shape of
// the persisted guard so a future refactor cannot silently degrade it to a
// non-durable in-memory flag.
func TestWelcomeEmail_ConditionRecordsGenerationAndTime(t *testing.T) {
	sender := &fakeMailSender{}
	r, c := newChildOrchestrationReconciler(t, welcomeTenant("owner@acme.com"))
	r.Mail = sender

	driveTenantToReady(t, r, c)

	got := getWelcomeTenant(t, c)
	cond := apimeta.FindStatusCondition(got.Status.Conditions, gibsonv1alpha1.ConditionWelcomeEmailSent)
	if cond == nil {
		t.Fatalf("condition %q not found; conditions=%+v", gibsonv1alpha1.ConditionWelcomeEmailSent, got.Status.Conditions)
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("condition status got %q, want True", cond.Status)
	}
	if cond.Reason == "" {
		t.Error("condition Reason must be set — the API server rejects an empty reason")
	}
	if cond.LastTransitionTime.IsZero() {
		t.Error("condition LastTransitionTime must be set")
	}
}
