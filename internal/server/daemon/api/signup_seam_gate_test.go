package api

// signup_seam_gate_test.go — tests for the signup seam gate in
// SignupService.Signup (deploy ADR-0006, gibson#1088).
//
// These tests verify that:
//  1. A DaemonServer with signupPolicy = PolicyAdminOnly (or zero value) returns
//     codes.PermissionDenied from Signup — self-hosted fail-safe.
//  2. A DaemonServer with signupPolicy = PolicySelfServe proceeds to the normal
//     handler logic — SaaS profile.
//  3. The zero-value DaemonServer (no WithSignupPolicy called) defaults to
//     fail-closed (PolicyAdminOnly), i.e. PermissionDenied.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

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
// fail-closed (PolicyAdminOnly) and returns codes.PermissionDenied.
// This is the "misconfigured SaaS deploy fails closed" invariant.
//
// NOTE: this test constructs DaemonServer directly (bypassing newSignupServer
// which sets PolicySelfServe for convenience) to test the raw zero-value default.
func TestSignup_DefaultPolicy_PermissionDenied(t *testing.T) {
	// Construct directly with zero-value signupPolicy — do NOT use newSignupServer
	// here because that helper sets PolicySelfServe.
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

// TestSignup_SelfServePolicy_Proceeds verifies that when the signup policy is
// PolicySelfServe, the handler proceeds past the gate and into the normal IDP
// provisioning logic (SaaS profile — existing happy-path behavior unchanged).
func TestSignup_SelfServePolicy_Proceeds(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{UserID: "user-owner", AlreadyExisted: false}, nil
		},
	}
	s := newSignupServer(t, idpc)
	s.signupPolicy = signup.PolicySelfServe

	resp, err := s.Signup(context.Background(), validSignupReq())
	if err != nil {
		t.Fatalf("Signup with PolicySelfServe: unexpected error: %v", err)
	}
	if resp.GetTenantId() == "" {
		t.Errorf("expected non-empty TenantId in response")
	}
}

// TestSignup_WithSignupPolicy_SelfServe verifies that the fluent
// WithSignupPolicy option method correctly sets PolicySelfServe, allowing
// the Signup handler to proceed.
func TestSignup_WithSignupPolicy_SelfServe(t *testing.T) {
	idpc := &fakeIDPClient{
		createHumanFn: func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
			return idp.CreateHumanUserResult{UserID: "user-wired", AlreadyExisted: false}, nil
		},
	}
	s := newSignupServer(t, idpc).WithSignupPolicy(signup.PolicySelfServe)

	req := validSignupReq()
	resp, err := s.Signup(context.Background(), req)
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if resp.GetTenantId() != "acme-red-team" {
		t.Errorf("TenantId = %q, want acme-red-team", resp.GetTenantId())
	}
}

// TestSignup_WithSignupPolicy_AdminOnly verifies that explicitly setting
// AdminOnly via WithSignupPolicy blocks signup with PermissionDenied.
func TestSignup_WithSignupPolicy_AdminOnly(t *testing.T) {
	idpc := &fakeIDPClient{}
	s := newSignupServer(t, idpc).WithSignupPolicy(signup.PolicyAdminOnly)

	_, err := s.Signup(context.Background(), validSignupReq())
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("status code = %v, want PermissionDenied after explicit AdminOnly", got)
	}
}

// TestSignup_SeamGate_ErrorMessageMentionsAdminProvision verifies that the
// PermissionDenied error message directs operators to use AdminProvisionTenant,
// so a self-hosted operator knows what to do.
func TestSignup_SeamGate_ErrorMessageMentionsAdminProvision(t *testing.T) {
	s := &DaemonServer{logger: testSlogLogger}
	// zero-value signupPolicy = "", treated as PolicyAdminOnly

	_, err := s.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId:     testAttemptID,
		OwnerEmail:    "admin@selfhosted.example",
		WorkspaceName: "Self Hosted Corp",
		Tier:          "team",
		Password:      "p@ssw0rd!",
	})
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
// any content in the incoming request. Multiple calls with different request
// payloads must all observe the same policy that was set at startup.
//
// This is the negative-test guarantee for the signup seam (gibson#1094,
// deploy ADR-0006): only the environment drives the policy; request data is
// inert.
func TestSignup_PolicyImmutableToRequestInput(t *testing.T) {
	// Set up a server that starts with PolicyAdminOnly — simulates a self-hosted
	// deployment where SIGNUP_SELF_SERVE was absent at boot.
	s := &DaemonServer{
		logger: testSlogLogger,
		// signupPolicy zero value = "" treated as PolicyAdminOnly.
	}

	variants := []*tenantv1.SignupRequest{
		// Normal request
		{
			AttemptId:     testAttemptID,
			OwnerEmail:    "owner@example.com",
			WorkspaceName: "Corp A",
			Tier:          "team",
			Password:      "p@ssw0rd!",
		},
		// Request carrying a different attempt_id — still no policy override.
		{
			AttemptId:     "11111111-2222-3333-4444-555555555555",
			OwnerEmail:    "attacker@evil.example",
			WorkspaceName: "Bypass Attempt",
			Tier:          "enterprise",
			Password:      "hax0r!",
		},
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

	// Flip the server to SelfServe (simulates what WithSignupPolicy does at boot
	// when SIGNUP_SELF_SERVE is set). The policy comes from env alone; no request
	// field can reproduce this transition at call time.
	s.signupPolicy = signup.PolicySelfServe

	// All subsequent calls must now pass the gate — the policy is now self-serve
	// because the env was set at boot, not because of anything in the request.
	proceedReq := &tenantv1.SignupRequest{
		AttemptId:     testAttemptID,
		OwnerEmail:    "owner@saas.example",
		WorkspaceName: "SaaS Corp",
		Tier:          "team",
		Password:      "p@ssw0rd!",
	}
	// No IDP client is wired here, so the call will fail after the gate — but
	// the gate itself must not return PermissionDenied (the gate passed).
	_, err := s.Signup(context.Background(), proceedReq)
	if status.Code(err) == codes.PermissionDenied {
		t.Errorf("after policy set to SelfServe, Signup still returned PermissionDenied; request must not be able to override the env-set policy")
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
