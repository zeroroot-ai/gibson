// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// signup_plan_optional_test.go pins that a signup needs no plan
// (gibson#1531, step 1). Gibson does not judge the plan id. It keeps the plan
// id that the caller gave and passes it to the queue and the external signup
// step. The external signup step depends only on the config of the install.
package api

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// requestVerifiedSession drives phase 1 and 2 of the flow
// (RequestEmailVerification and RedeemEmailVerification) and returns the
// resulting verified session token.
//
// The plan id comes from the verification row, not from the Signup request.
// So a test routes the plan id through phase 1 (the RequestEmailVerification
// tier field). An empty tier means no plan.
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

// signupHarnessWithOwner returns a signup harness whose IdP creates the owner.
func signupHarnessWithOwner(t *testing.T) *signupHarness {
	t.Helper()
	h := newSignupHarness(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{UserID: "user-owner"}, nil
	}
	return h
}

// TestSignup_PlanIsOptional pins that Signup accepts any plan id, and no plan
// at all. The plan id goes unchanged to the response and to the queue row.
// Gibson refuses no plan id: the component that runs the external signup
// step decides what a plan id means.
func TestSignup_PlanIsOptional(t *testing.T) {
	for _, tier := range []string{"", "team", "enterprise-deploy", "any-plan"} {
		t.Run("tier="+tier, func(t *testing.T) {
			h := signupHarnessWithOwner(t)
			session := requestVerifiedSession(t, h, tier)

			resp, err := signupWithSession(t, h, session)
			if err != nil {
				t.Fatalf("Signup(tier=%q) must succeed, got: %v", tier, err)
			}
			if resp.GetPlanId() != tier {
				t.Errorf("plan_id = %q, want %q", resp.GetPlanId(), tier)
			}
			row, ok := h.queue.row(resp.GetTenantId())
			if !ok {
				t.Fatal("the signup queued no tenant")
			}
			if row.tier != tier || row.status != "pending" {
				t.Errorf("queued row = %+v, want tier %q and status pending", row, tier)
			}
		})
	}
}

// TestSignup_StepDependsOnlyOnTheConfig pins that the external signup step
// depends on the config of the install, never on the plan. With a step URL,
// every signup waits for the step, with a plan or without one. With no step
// URL, no signup waits.
func TestSignup_StepDependsOnlyOnTheConfig(t *testing.T) {
	for _, tier := range []string{"", "team"} {
		t.Run("step configured, tier="+tier, func(t *testing.T) {
			h := signupHarnessWithOwner(t)
			h.srv.WithSignupStepURL("https://step.example/start")
			session := requestVerifiedSession(t, h, tier)

			resp, err := signupWithSession(t, h, session)
			if err != nil {
				t.Fatalf("Signup(tier=%q): %v", tier, err)
			}
			if resp.GetStepUrl() != "https://step.example/start" || resp.GetStepToken() == "" {
				t.Fatalf("Signup(tier=%q) with a step configured returned no step", tier)
			}
			row, ok := h.queue.row(resp.GetTenantId())
			if !ok || row.status != "waiting_step" || row.tier != tier {
				t.Errorf("queued row = %+v, want status waiting_step and tier %q", row, tier)
			}
		})
		t.Run("no step, tier="+tier, func(t *testing.T) {
			h := signupHarnessWithOwner(t)
			session := requestVerifiedSession(t, h, tier)

			resp, err := signupWithSession(t, h, session)
			if err != nil {
				t.Fatalf("Signup(tier=%q): %v", tier, err)
			}
			if resp.GetStepUrl() != "" || resp.GetStepToken() != "" {
				t.Fatalf("a signup with no step configured got step_url %q and a token", resp.GetStepUrl())
			}
			row, ok := h.queue.row(resp.GetTenantId())
			if !ok || row.status != "pending" {
				t.Errorf("queued row = %+v, want status pending", row)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Provisioning drain
// ---------------------------------------------------------------------------

// TestListPendingTenantProvisioning_DrainsEveryPendingRow pins that the queue
// withholds no row for its tier, even a tier that does not resolve.
func TestListPendingTenantProvisioning_DrainsEveryPendingRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	rows := sqlmock.NewRows([]string{
		"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier", "audit_record_id", "created_at",
	}).AddRow("acme", "u-2", "owner@acme.test", "Acme Inc", "enterprise-plus", "", time.Now())
	mock.ExpectQuery("FROM pending_tenant_provisioning").WillReturnRows(rows)

	resp, err := srv.ListPendingTenantProvisioning(context.Background(),
		&daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetPending()) != 1 {
		t.Fatalf("the queue must drain every pending row, got %d", len(resp.GetPending()))
	}
}
