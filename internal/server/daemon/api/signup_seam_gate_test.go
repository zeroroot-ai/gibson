// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_seam_gate_test.go — tests for the signup seam gate on SignupService
// (deploy ADR-0006, gibson#1088).
//
// The gate runs first, before validation and before any side effect, on all
// three RPCs. These tests verify that:
//  1. PolicyAdminOnly (or the zero value) denies with codes.PermissionDenied —
//     the self-hosted fail-safe.
//  2. PolicySelfServe lets the request through to the handler proper.
//  3. Nothing in the request can change the boot-time policy.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// newSignupServer builds a DaemonServer with the self-serve gate open and an
// IdP client wired, but no verification store, mailer or limiter. That is
// enough to test the gate itself; the handlers' own dependencies are exercised
// through the harness in signup_service_test.go.
func newSignupServer(t *testing.T, idpc *fakeIDPClient) *DaemonServer {
	t.Helper()
	s := &DaemonServer{logger: testSlogLogger}
	s.idpAdminClient = idpc
	s.signupPolicy = signup.PolicySelfServe
	return s
}

// TestSignup_AdminOnlyPolicy_PermissionDenied verifies that when the signup
// policy is explicitly PolicyAdminOnly, Signup returns codes.PermissionDenied.
func TestSignup_AdminOnlyPolicy_PermissionDenied(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			t.Fatal("IDP should not be called when signup is admin-only")
			return idp.CreateHumanUserResult{}, nil
		},
	}
	s := newSignupServer(t, idpc)
	s.signupPolicy = signup.PolicyAdminOnly

	_, err := s.Signup(context.Background(), validSignupReq())
	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied", got)
	}
}

// TestSignup_DefaultPolicy_PermissionDenied verifies that a DaemonServer with
// no WithSignupPolicy call (zero-value signupPolicy = "") defaults to
// fail-closed (PolicyAdminOnly). This is the "misconfigured SaaS deploy fails
// closed" invariant.
func TestSignup_DefaultPolicy_PermissionDenied(t *testing.T) {
	s := &DaemonServer{
		logger: testSlogLogger,
		// signupPolicy is zero value ("") — must behave as PolicyAdminOnly.
	}

	_, err := s.Signup(context.Background(), validSignupReq())
	if err == nil {
		t.Fatal("expected PermissionDenied, got nil")
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied (zero-value policy must fail closed)", got)
	}
}

// TestSignupSeamGate_AppliesToEveryRPC keeps the gate in front of the whole
// service, not just the completion RPC. RequestEmailVerification sends mail and
// RedeemEmailVerification mints sessions; an admin-only deployment must not
// expose either.
func TestSignupSeamGate_AppliesToEveryRPC(t *testing.T) {
	s := &DaemonServer{logger: testSlogLogger} // zero-value policy = admin-only

	if _, err := s.RequestEmailVerification(context.Background(), validRequestReq()); status.Code(err) != codes.PermissionDenied {
		t.Errorf("RequestEmailVerification = %v, want PermissionDenied", err)
	}
	if _, err := s.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{Token: "t"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("RedeemEmailVerification = %v, want PermissionDenied", err)
	}
	if _, err := s.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
		VerifiedSessionToken: "s", StripeCustomerId: "cus_1",
	}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("AttachSignupCustomer = %v, want PermissionDenied", err)
	}
}

// TestSignup_SeamGate_ErrorMessageMentionsAdminProvision verifies that the
// PermissionDenied error message directs operators to use AdminProvisionTenant,
// so a self-hosted operator knows what to do.
func TestSignup_SeamGate_ErrorMessageMentionsAdminProvision(t *testing.T) {
	s := &DaemonServer{logger: testSlogLogger}
	// zero-value signupPolicy = "", treated as PolicyAdminOnly

	_, err := s.Signup(context.Background(), validSignupReq())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	msg := err.Error()
	if !containsSubstring(msg, "AdminProvisionTenant") {
		t.Errorf("error message should mention AdminProvisionTenant for operator guidance, got: %q", msg)
	}
}

// TestSignup_PolicyImmutableToRequestInput proves that the resolved signup
// policy (set once at daemon boot via WithSignupPolicy) cannot be altered by
// any content in the incoming request.
//
// This is the negative-test guarantee for the signup seam (gibson#1094,
// deploy ADR-0006): only the environment drives the policy; request data is
// inert.
func TestSignup_PolicyImmutableToRequestInput(t *testing.T) {
	// Starts with PolicyAdminOnly — a self-hosted deployment where
	// SIGNUP_SELF_SERVE was absent at boot.
	s := &DaemonServer{logger: testSlogLogger}

	variants := []*tenantv1.SignupRequest{
		{AttemptId: testAttemptID, VerifiedSessionToken: "sess-a", Password: "p@ssw0rd!"},
		{AttemptId: "11111111-2222-3333-4444-555555555555", VerifiedSessionToken: "sess-b", Password: "another!"},
		// Empty body — still denied, not a panic or Unimplemented.
		{},
	}

	for i, req := range variants {
		_, err := s.Signup(context.Background(), req)
		if err == nil {
			t.Errorf("variant %d: expected PermissionDenied, got nil (policy must be env-only)", i)
			continue
		}
		if got := status.Code(err); got != codes.PermissionDenied {
			t.Errorf("variant %d: status = %v, want PermissionDenied (request cannot change boot-time policy)", i, got)
		}
	}

	// Flip to SelfServe (what WithSignupPolicy does at boot when
	// SIGNUP_SELF_SERVE is set). The transition comes from the environment
	// alone; no request field can reproduce it at call time.
	s.signupPolicy = signup.PolicySelfServe

	// The gate now passes. RequestEmailVerification is the observable proof:
	// with no limiter wired it fails CLOSED with Unavailable, which is a
	// different refusal from the gate's PermissionDenied.
	//
	// Signup is deliberately NOT used for this assertion — without a redeemed
	// verification it also answers PermissionDenied, and that denial is the
	// verification requirement rather than the seam gate.
	_, err := s.RequestEmailVerification(context.Background(), validRequestReq())
	if status.Code(err) == codes.PermissionDenied {
		t.Errorf("after the policy was set to SelfServe the seam gate still fired; the request must not be able to override the env-set policy")
	}
}

// containsSubstring is a local helper to avoid importing strings in this test file.
func containsSubstring(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || s != "" && findSub(s, sub))
}

func findSub(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
