// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// signup_plan_gate_test.go — regression tests for the server-side plan gate on
// SignupService.Signup and for the billing read on the provisioning drain
// (GHSA-455w-vgc7-79f4).
//
// Before the fix the ONLY validation of the requested tier was "is it the
// empty string": a signup naming any plan — including the contact-sales
// on-prem plan — was forwarded verbatim into the provisioning queue, and
// nothing anywhere read the billing-active flag before that tenant was built.
package api

import (
	"context"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
)

// requestVerifiedSession drives phase 1 and 2 of the flow
// (RequestEmailVerification and RedeemEmailVerification) and returns the
// resulting verified session token.
//
// The plan gate resolves against the verification row, not the Signup
// request — SignupRequest carries no tier,
// exactly so a caller cannot self-select a paid tier on the completion call.
// So exercising the gate means routing the tier through phase 1 (the
// RequestEmailVerification tier field) rather than stapling it onto Signup.
func requestVerifiedSession(t *testing.T, h *signupHarness, tier string) string {
	t.Helper()
	req := validRequestReq()
	req.Tier = tier
	if _, err := h.srv.RequestEmailVerification(context.Background(), req); err != nil {
		t.Fatalf("RequestEmailVerification(tier=%q): %v", tier, err)
	}
	if len(h.mail.verifications) == 0 {
		t.Fatalf("RequestEmailVerification(tier=%q) sent no mail", tier)
	}
	token := tokenFromLink(t, h.mail.verifications[len(h.mail.verifications)-1].ContinueURL)

	resp, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{
		Token: token, ClientIp: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("RedeemEmailVerification(tier=%q): %v", tier, err)
	}
	return resp.GetVerifiedSessionToken()
}

// signupWithSession completes Signup for a session obtained from
// requestVerifiedSession.
func signupWithSession(t *testing.T, h *signupHarness, session string) (*tenantv1.SignupResponse, error) {
	t.Helper()
	return h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId:            testAttemptID,
		VerifiedSessionToken: session,
		Password:             "s3cret-passw0rd!",
	})
}

// planGateHarness returns a signup harness whose IdP fails the test if it is
// reached — the plan gate must refuse BEFORE any account is provisioned.
func planGateHarness(t *testing.T) *signupHarness {
	t.Helper()
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		t.Fatal("plan gate must refuse before the IdP is called")
		return idp.CreateHumanUserResult{}, nil
	}
	return h
}

// TestSignup_RejectsNonCanonicalTier pins that an unrecognised plan id is a
// hard reject rather than being forwarded to the operator.
func TestSignup_RejectsNonCanonicalTier(t *testing.T) {
	for _, tier := range []string{
		"enterprise-plus", // invented
		"Enterprise",      // wrong case
		"free",            // legacy id
		"pro",             // legacy id
		"../enterprise",
	} {
		t.Run(tier, func(t *testing.T) {
			h := planGateHarness(t)
			session := requestVerifiedSession(t, h, tier)

			_, err := signupWithSession(t, h, session)
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("Signup(tier=%q) code = %v, want InvalidArgument", tier, got)
			}
		})
	}
}

// TestSignup_RejectsContactSalesPlan is the direct free-enterprise-tier
// regression: enterprise-deploy is priced contact-sales and has no trial, and must never be reachable through self-serve signup.
func TestSignup_RejectsContactSalesPlan(t *testing.T) {
	h := planGateHarness(t)
	session := requestVerifiedSession(t, h, "enterprise-deploy")

	_, err := signupWithSession(t, h, session)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("Signup(tier=enterprise-deploy) code = %v, want PermissionDenied", got)
	}
}

// TestSignup_PaidPlanNeedsTheStepWhenEntitlementsRequired covers rule 3 of the
// gate: on a deployment that enforces entitlements, a paid plan needs the
// external signup step. With no step configured, nothing can confirm it.
func TestSignup_PaidPlanNeedsTheStepWhenEntitlementsRequired(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "true")
	h := planGateHarness(t)
	session := requestVerifiedSession(t, h, "enterprise")

	_, err := signupWithSession(t, h, session)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("Signup(tier=enterprise, no step) code = %v, want PermissionDenied", got)
	}
}

// TestSignup_PaidPlanAllowedOnPremWithoutStep pins ADR-0074: the seam is
// bypassable on-prem, so a self-hosted install (entitlements knob unset) signs
// up with no step.
func TestSignup_PaidPlanAllowedOnPremWithoutStep(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	session := requestVerifiedSession(t, h, "team")

	resp, err := signupWithSession(t, h, session)
	if err != nil {
		t.Fatalf("on-prem signup without a step must succeed, got: %v", err)
	}
	if resp.GetStepUrl() != "" || resp.GetStepToken() != "" {
		t.Fatalf("a signup with no step configured got step_url %q and a token", resp.GetStepUrl())
	}
}

// TestSignup_AcceptsCanonicalSelfServePlans guards against the gate being too
// tight: every self-serve plan must still be requestable.
func TestSignup_AcceptsCanonicalSelfServePlans(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "true")
	for _, tier := range []string{"team", "org", "enterprise"} {
		t.Run(tier, func(t *testing.T) {
			h := newSignupHarness(t)
			h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
				return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
			}
			h.srv.WithSignupStepURL("https://step.example/start")
			session := requestVerifiedSession(t, h, tier)

			resp, err := signupWithSession(t, h, session)
			if err != nil {
				t.Fatalf("Signup(tier=%q) must succeed, got: %v", tier, err)
			}
			if resp.GetStepUrl() != "https://step.example/start" || resp.GetStepToken() == "" {
				t.Fatalf("Signup(tier=%q) with a step configured returned no step", tier)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Provisioning drain
// ---------------------------------------------------------------------------

// TestWithholdPendingTenant is the decision table for the drain gate.
func TestWithholdPendingTenant(t *testing.T) {
	tests := []struct {
		name         string
		tier         string
		enforce      bool
		wantWithheld bool
	}{
		{"self-hosted never withholds", "enterprise-plus", false, false},
		{"a canonical plan drains", "enterprise", true, false},
		{"unpriceable tier is withheld", "enterprise-plus", true, true},
		{"empty tier is withheld", "", true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, withheld := withholdPendingTenant(tc.tier, tc.enforce)
			if withheld != tc.wantWithheld {
				t.Fatalf("withhold = %v (%q), want %v", withheld, reason, tc.wantWithheld)
			}
			if withheld && reason == "" {
				t.Error("a withheld row must carry a reason for the operator log")
			}
		})
	}
}

// TestListPendingTenantProvisioning_SelfHostedDrainsEverything pins ADR-0074:
// with the entitlements knob unset the queue drains unchanged, even a tier
// that does not resolve.
func TestListPendingTenantProvisioning_SelfHostedDrainsEverything(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	rows := sqlmock.NewRows([]string{
		"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier",
	}).AddRow("acme", "u-2", "owner@acme.test", "Acme Inc", "enterprise-plus")
	mock.ExpectQuery("FROM pending_tenant_provisioning").WillReturnRows(rows)

	resp, err := srv.ListPendingTenantProvisioning(context.Background(),
		&daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetPending()) != 1 {
		t.Fatalf("self-hosted must drain every pending row, got %d", len(resp.GetPending()))
	}
}
