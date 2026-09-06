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

// requestVerifiedSession drives phase 1 and 2 of the flow (RequestEmailVerification,
// RedeemEmailVerification, and — when stripeCustomerID is non-empty —
// AttachSignupCustomer) and returns the resulting verified session token.
//
// The plan gate resolves against the verification row, not the Signup
// request — SignupRequest carries neither a tier nor a billing-customer id,
// exactly so a caller cannot self-select a paid tier on the completion call.
// So exercising the gate means routing the tier through phase 1 (the
// RequestEmailVerification tier field) rather than stapling it onto Signup.
func requestVerifiedSession(t *testing.T, h *signupHarness, tier, stripeCustomerID string) string {
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
	session := resp.GetVerifiedSessionToken()

	if stripeCustomerID != "" {
		if _, err := h.srv.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
			VerifiedSessionToken: session,
			StripeCustomerId:     stripeCustomerID,
		}); err != nil {
			t.Fatalf("AttachSignupCustomer(tier=%q): %v", tier, err)
		}
	}
	return session
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
			session := requestVerifiedSession(t, h, tier, "cus_1")

			_, err := signupWithSession(t, h, session)
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("Signup(tier=%q) code = %v, want InvalidArgument", tier, got)
			}
		})
	}
}

// TestSignup_RejectsContactSalesPlan is the direct free-enterprise-tier
// regression: enterprise-deploy is priced contact-sales, has no Stripe product
// and no trial, and must never be reachable through self-serve signup.
func TestSignup_RejectsContactSalesPlan(t *testing.T) {
	h := planGateHarness(t)
	session := requestVerifiedSession(t, h, "enterprise-deploy", "cus_1")

	_, err := signupWithSession(t, h, session)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("Signup(tier=enterprise-deploy) code = %v, want PermissionDenied", got)
	}
}

// TestSignup_PaidPlanRequiresBillingCustomerWhenEntitlementsRequired covers
// rule 3 of the gate: on a deployment that enforces entitlements (the SaaS
// overlay), a paid plan may not be requested without having gone through
// payment setup.
func TestSignup_PaidPlanRequiresBillingCustomerWhenEntitlementsRequired(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "true")
	h := planGateHarness(t)
	session := requestVerifiedSession(t, h, "enterprise", "")

	_, err := signupWithSession(t, h, session)
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Fatalf("Signup(tier=enterprise, no customer) code = %v, want PermissionDenied", got)
	}
}

// TestSignup_PaidPlanAllowedOnPremWithoutBilling pins ADR-0006: the billing
// seam is bypassable on-prem, so a self-hosted install (entitlements knob
// unset) must not need a Stripe customer to sign up.
func TestSignup_PaidPlanAllowedOnPremWithoutBilling(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "")
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	session := requestVerifiedSession(t, h, "team", "")

	if _, err := signupWithSession(t, h, session); err != nil {
		t.Fatalf("on-prem signup without a billing customer must succeed, got: %v", err)
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
			session := requestVerifiedSession(t, h, tier, "cus_1")

			if _, err := signupWithSession(t, h, session); err != nil {
				t.Fatalf("Signup(tier=%q) must succeed, got: %v", tier, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Provisioning drain — the billing-active read
// ---------------------------------------------------------------------------

// TestWithholdPendingTenant is the decision table for the drain gate.
func TestWithholdPendingTenant(t *testing.T) {
	tests := []struct {
		name           string
		tier           string
		billingActive  bool
		enforceBilling bool
		wantWithheld   bool
	}{
		{"self-hosted never withholds", "enterprise", false, false, false},
		{"paid plan without billing is withheld", "enterprise", false, true, true},
		{"paid plan with billing drains", "enterprise", true, true, false},
		{"cheapest paid plan is gated too", "team", false, true, true},
		{"unpriceable tier is withheld", "enterprise-plus", true, true, true},
		{"empty tier is withheld", "", true, true, true},
		{"contact-sales plan is not Stripe-billed and drains", "enterprise-deploy", false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reason, withheld := withholdPendingTenant(tc.tier, tc.billingActive, tc.enforceBilling)
			if withheld != tc.wantWithheld {
				t.Fatalf("withhold = %v (%q), want %v", withheld, reason, tc.wantWithheld)
			}
			if withheld && reason == "" {
				t.Error("a withheld row must carry a reason for the operator log")
			}
		})
	}
}

// TestListPendingTenantProvisioning_WithholdsUnpaidPaidTier is the end-to-end
// regression: a tenant queued at a paid plan is not handed to the operator
// until billing_active is recorded. Before the fix billing_active had no reader
// anywhere on the provisioning path.
func TestListPendingTenantProvisioning_WithholdsUnpaidPaidTier(t *testing.T) {
	t.Setenv(entitlements.RequiredKnob, "true")

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	expectEnsureTenantStatusTable(mock)
	rows := sqlmock.NewRows([]string{
		"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier",
		"stripe_customer_id", "billing_active",
	}).
		AddRow("paid", "u-1", "owner@paid.test", "Paid Inc", "enterprise", "cus_1", true).
		AddRow("unpaid", "u-2", "owner@unpaid.test", "Unpaid Inc", "enterprise", "cus_2", false)
	mock.ExpectQuery("FROM pending_tenant_provisioning p").WillReturnRows(rows)

	resp, err := srv.ListPendingTenantProvisioning(context.Background(),
		&daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetPending()) != 1 {
		t.Fatalf("expected only the paid tenant to drain, got %d rows: %+v", len(resp.GetPending()), resp.GetPending())
	}
	if got := resp.GetPending()[0].GetTenantId(); got != "paid" {
		t.Errorf("drained tenant = %q, want \"paid\"", got)
	}
}

// TestListPendingTenantProvisioning_SelfHostedDrainsEverything pins ADR-0006:
// with the entitlements knob unset there is no billing to enforce and the
// queue drains unchanged.
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
	expectEnsureTenantStatusTable(mock)
	rows := sqlmock.NewRows([]string{
		"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier",
		"stripe_customer_id", "billing_active",
	}).AddRow("unpaid", "u-2", "owner@unpaid.test", "Unpaid Inc", "enterprise", "", false)
	mock.ExpectQuery("FROM pending_tenant_provisioning p").WillReturnRows(rows)

	resp, err := srv.ListPendingTenantProvisioning(context.Background(),
		&daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetPending()) != 1 {
		t.Fatalf("self-hosted must drain every pending row, got %d", len(resp.GetPending()))
	}
}
