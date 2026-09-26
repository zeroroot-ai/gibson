// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package controller

import (
	"context"
	"strings"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	gibsonv1alpha1 "github.com/zeroroot-ai/gibson/operators/platform/api/v1alpha1"
	zitadel "github.com/zeroroot-ai/gibson/operators/platform/internal/clients/zitadel"
)

// fakeSignInPolicyZitadel is a minimal in-memory zitadel.Client used to
// drive reconcileZitadelProject's sign-in-policy step (EnsureDomainPolicy +
// EnsureLoginPolicy) without a real Zitadel or a network round trip. It lets
// the test flip the "live" state between reconciles to prove drift repair.
type fakeSignInPolicyZitadel struct {
	zitadel.Client // embed: only the methods below are exercised by this test

	projectID             string
	userLoginMustBeDomain bool
	loginLive             zitadel.LoginPolicy

	domainCalls int
	loginCalls  int
}

func (f *fakeSignInPolicyZitadel) EnsureProject(_ context.Context, _ string) (string, error) {
	return f.projectID, nil
}

func (f *fakeSignInPolicyZitadel) EnsureProjectRoles(_ context.Context, _ string, _ []tenantrole.Def) (bool, error) {
	return false, nil
}

func (f *fakeSignInPolicyZitadel) EnsureDomainPolicy(_ context.Context, want zitadel.DomainPolicy) (bool, error) {
	f.domainCalls++
	if f.userLoginMustBeDomain == want.UserLoginMustBeDomain {
		return false, nil
	}
	f.userLoginMustBeDomain = want.UserLoginMustBeDomain
	return true, nil
}

func (f *fakeSignInPolicyZitadel) EnsureLoginPolicy(_ context.Context, want zitadel.LoginPolicy) ([]string, error) {
	f.loginCalls++
	var corrected []string
	if f.loginLive.ForceMFA != want.ForceMFA {
		corrected = append(corrected, "forceMfa")
	}
	if !stringSlicesEqual(f.loginLive.SecondFactors, want.SecondFactors) {
		corrected = append(corrected, "secondFactors")
	}
	f.loginLive = want
	return corrected, nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		if !seen[s] {
			return false
		}
	}
	return true
}

func newSignInPolicyTestBootstrap() *gibsonv1alpha1.PlatformBootstrap {
	return &gibsonv1alpha1.PlatformBootstrap{
		ObjectMeta: metav1.ObjectMeta{Name: "gibson"},
		Spec: gibsonv1alpha1.PlatformBootstrapSpec{
			Zitadel: gibsonv1alpha1.ZitadelSpec{
				Issuer:        "https://app.example.com",
				AdminTokenRef: gibsonv1alpha1.SecretKeyRef{Name: "iam-admin-pat", Namespace: defaultChildNamespace, Key: "pat"},
				Project:       gibsonv1alpha1.ZitadelProjectSpec{Name: "gibson", EnsureExists: true},
			},
		},
	}
}

func newSignInPolicyReconciler(t *testing.T, factory ZitadelClientFactory) *PlatformBootstrapReconciler {
	t.Helper()
	s := mustScheme(t)
	pat := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "iam-admin-pat", Namespace: defaultChildNamespace},
		Data:       map[string][]byte{"pat": []byte("fake-pat")},
	}
	cli := fake.NewClientBuilder().WithScheme(s).WithObjects(pat).Build()
	return &PlatformBootstrapReconciler{
		Client:         cli,
		Scheme:         s,
		Recorder:       record.NewFakeRecorder(16),
		ZitadelFactory: factory,
	}
}

// TestReconcileZitadelProject_SignInPolicy pins the ADR-0093 section 9 /
// decision 1 enforcement: the first reconcile corrects a drifted policy and
// emits SignInPolicyCorrected, a steady-state reconcile against an
// unchanged policy emits nothing more, and a later reconcile against a
// policy that has drifted again (an admin turned forceMfa off, or added a
// disallowed second factor) corrects it a second time. This is the
// drift-repair property the issue asks for — no chart change, no CRD
// field, just the operator re-asserting the policy on every reconcile.
func TestReconcileZitadelProject_SignInPolicy(t *testing.T) {
	fakeZ := &fakeSignInPolicyZitadel{
		projectID: "PROJ-1",
		// Fresh-instance-shaped drift: MFA off, wrong factor set, org-scoped
		// usernames.
		userLoginMustBeDomain: true,
		loginLive:             zitadel.LoginPolicy{ForceMFA: false, SecondFactors: []string{"SECOND_FACTOR_TYPE_OTP"}},
	}
	r := newSignInPolicyReconciler(t, func(_, _ string) zitadel.Client { return fakeZ })
	pb := newSignInPolicyTestBootstrap()

	if _, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}

	if fakeZ.domainCalls != 1 || fakeZ.loginCalls != 1 {
		t.Fatalf("domainCalls=%d loginCalls=%d, want 1 and 1", fakeZ.domainCalls, fakeZ.loginCalls)
	}
	if fakeZ.userLoginMustBeDomain {
		t.Fatal("userLoginMustBeDomain still true, want the operator to have flipped it to false")
	}
	if !fakeZ.loginLive.ForceMFA {
		t.Fatal("forceMfa still false, want the operator to have turned it on")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if cond == nil || cond.Status != metav1.ConditionTrue {
		t.Fatalf("ZitadelProjectReady = %+v, want True", cond)
	}
	if got := drainEvents(r.Recorder); countCorrected(got) != 2 {
		t.Fatalf("expected 2 SignInPolicyCorrected events (domain + login), got %v", got)
	}

	// Second reconcile: nothing drifted, so no further corrections.
	if _, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileZitadelProject (steady state): %v", err)
	}
	if got := drainEvents(r.Recorder); countCorrected(got) != 0 {
		t.Fatalf("steady-state reconcile emitted corrections: %v", got)
	}

	// Drift again: an admin (or a bug) flips forceMfa off and adds a
	// disallowed second factor directly against Zitadel. The next
	// reconcile must correct it again — this is the "runs again every
	// time" property, not a one-shot fix.
	fakeZ.loginLive = zitadel.LoginPolicy{ForceMFA: false, SecondFactors: []string{"SECOND_FACTOR_TYPE_OTP", "SECOND_FACTOR_TYPE_OTP_SMS"}}
	if _, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard()); err != nil {
		t.Fatalf("reconcileZitadelProject (re-drifted): %v", err)
	}
	if !fakeZ.loginLive.ForceMFA {
		t.Fatal("forceMfa still false after the second drift, want it corrected again")
	}
	if got := drainEvents(r.Recorder); countCorrected(got) != 1 {
		t.Fatalf("expected exactly 1 SignInPolicyCorrected event on re-drift (login only), got %v", got)
	}
}

// TestReconcileZitadelProject_SignInPolicy_PermanentError proves a
// permanent EnsureLoginPolicy error sets ZitadelProjectReady=False (not
// Unknown) and does not requeue for retry.
func TestReconcileZitadelProject_SignInPolicy_PermanentError(t *testing.T) {
	fakeZ := &erroringSignInPolicyZitadel{projectID: "PROJ-1", err: zitadel.WrapPermanent(context.DeadlineExceeded)}
	r := newSignInPolicyReconciler(t, func(_, _ string) zitadel.Client { return fakeZ })
	pb := newSignInPolicyTestBootstrap()

	res, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("expected no requeue on a permanent error, got %+v", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ZitadelPermanentError" {
		t.Fatalf("ZitadelProjectReady = %+v, want False/ZitadelPermanentError", cond)
	}
}

// TestReconcileZitadelProject_SignInPolicy_TransientError proves a
// transient EnsureLoginPolicy error sets ZitadelProjectReady=Unknown and
// requeues.
func TestReconcileZitadelProject_SignInPolicy_TransientError(t *testing.T) {
	fakeZ := &erroringSignInPolicyZitadel{projectID: "PROJ-1", err: zitadel.ErrRateLimited}
	r := newSignInPolicyReconciler(t, func(_, _ string) zitadel.Client { return fakeZ })
	pb := newSignInPolicyTestBootstrap()

	res, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	if res.IsZero() {
		t.Fatal("expected a requeue on a transient error, got zero Result")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "ZitadelTransientError" {
		t.Fatalf("ZitadelProjectReady = %+v, want Unknown/ZitadelTransientError", cond)
	}
}

// TestReconcileZitadelProject_DomainPolicy_PermanentError proves a
// permanent EnsureDomainPolicy error sets ZitadelProjectReady=False (not
// Unknown) and does not requeue for retry, and never reaches
// EnsureLoginPolicy.
func TestReconcileZitadelProject_DomainPolicy_PermanentError(t *testing.T) {
	fakeZ := &erroringDomainPolicyZitadel{projectID: "PROJ-1", err: zitadel.WrapPermanent(context.DeadlineExceeded)}
	r := newSignInPolicyReconciler(t, func(_, _ string) zitadel.Client { return fakeZ })
	pb := newSignInPolicyTestBootstrap()

	res, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	if !res.IsZero() {
		t.Fatalf("expected no requeue on a permanent error, got %+v", res)
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if cond == nil || cond.Status != metav1.ConditionFalse || cond.Reason != "ZitadelPermanentError" {
		t.Fatalf("ZitadelProjectReady = %+v, want False/ZitadelPermanentError", cond)
	}
	if fakeZ.loginCalls != 0 {
		t.Fatalf("EnsureLoginPolicy called %d times, want 0 (domain policy failed first)", fakeZ.loginCalls)
	}
}

// TestReconcileZitadelProject_DomainPolicy_TransientError proves a
// transient EnsureDomainPolicy error sets ZitadelProjectReady=Unknown and
// requeues.
func TestReconcileZitadelProject_DomainPolicy_TransientError(t *testing.T) {
	fakeZ := &erroringDomainPolicyZitadel{projectID: "PROJ-1", err: zitadel.ErrRateLimited}
	r := newSignInPolicyReconciler(t, func(_, _ string) zitadel.Client { return fakeZ })
	pb := newSignInPolicyTestBootstrap()

	res, err := r.reconcileZitadelProject(context.Background(), pb, logr.Discard())
	if err != nil {
		t.Fatalf("reconcileZitadelProject: %v", err)
	}
	if res.IsZero() {
		t.Fatal("expected a requeue on a transient error, got zero Result")
	}
	cond := findCondition(pb.Status.Conditions, gibsonv1alpha1.ConditionZitadelProjectReady)
	if cond == nil || cond.Status != metav1.ConditionUnknown || cond.Reason != "ZitadelTransientError" {
		t.Fatalf("ZitadelProjectReady = %+v, want Unknown/ZitadelTransientError", cond)
	}
}

// erroringSignInPolicyZitadel succeeds EnsureDomainPolicy (no-op) then
// fails EnsureLoginPolicy with the configured error, to exercise
// reconcileZitadelProject's permanent/transient branches for the sign-in
// policy step.
type erroringSignInPolicyZitadel struct {
	zitadel.Client
	projectID string
	err       error
}

func (f *erroringSignInPolicyZitadel) EnsureProject(_ context.Context, _ string) (string, error) {
	return f.projectID, nil
}

func (f *erroringSignInPolicyZitadel) EnsureDomainPolicy(_ context.Context, _ zitadel.DomainPolicy) (bool, error) {
	return false, nil
}

func (f *erroringSignInPolicyZitadel) EnsureLoginPolicy(_ context.Context, _ zitadel.LoginPolicy) ([]string, error) {
	return nil, f.err
}

// erroringDomainPolicyZitadel fails EnsureDomainPolicy with the configured
// error, to exercise reconcileZitadelProject's permanent/transient
// branches for the domain-policy step. loginCalls proves the reconciler
// never reaches EnsureLoginPolicy once the domain policy step fails.
type erroringDomainPolicyZitadel struct {
	zitadel.Client
	projectID  string
	err        error
	loginCalls int
}

func (f *erroringDomainPolicyZitadel) EnsureProject(_ context.Context, _ string) (string, error) {
	return f.projectID, nil
}

func (f *erroringDomainPolicyZitadel) EnsureDomainPolicy(_ context.Context, _ zitadel.DomainPolicy) (bool, error) {
	return false, f.err
}

func (f *erroringDomainPolicyZitadel) EnsureLoginPolicy(_ context.Context, _ zitadel.LoginPolicy) ([]string, error) {
	f.loginCalls++
	return nil, nil
}

// drainEvents reads every currently-buffered event off a
// record.NewFakeRecorder channel without blocking.
func drainEvents(rec record.EventRecorder) []string {
	fr, ok := rec.(*record.FakeRecorder)
	if !ok {
		return nil
	}
	var out []string
	for {
		select {
		case e := <-fr.Events:
			out = append(out, e)
		default:
			return out
		}
	}
}

func countCorrected(events []string) int {
	n := 0
	for _, e := range events {
		if strings.Contains(e, "SignInPolicyCorrected") {
			n++
		}
	}
	return n
}

func (f *erroringSignInPolicyZitadel) EnsureProjectRoles(_ context.Context, _ string, _ []tenantrole.Def) (bool, error) {
	return false, nil
}

func (f *erroringDomainPolicyZitadel) EnsureProjectRoles(_ context.Context, _ string, _ []tenantrole.Def) (bool, error) {
	return false, nil
}
