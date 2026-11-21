// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// signup_session_test.go holds the helpers that drive a signup to a verified
// session, and pins that the external signup step depends only on the config
// of the install. The product has no plan (gibson#1531).
package api

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// requestVerifiedSession drives phase 1 and 2 of the flow
// (RequestEmailVerification and RedeemEmailVerification) and returns the
// resulting verified session token.
func requestVerifiedSession(t *testing.T, h *signupHarness) string {
	t.Helper()
	if _, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq()); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if len(h.mail.verifications) == 0 {
		t.Fatal("RequestEmailVerification sent no mail")
	}
	token := tokenFromLink(t, h.mail.verifications[len(h.mail.verifications)-1].ContinueURL)

	resp, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{
		Token: token, ClientIp: "203.0.113.7",
	})
	if err != nil {
		t.Fatalf("RedeemEmailVerification: %v", err)
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

// TestSignup_StepDependsOnlyOnTheConfig pins that the external signup step
// depends on the config of the install. With a step URL, every signup waits
// for the step. With no step URL, no signup waits. The response carries no
// plan id.
func TestSignup_StepDependsOnlyOnTheConfig(t *testing.T) {
	t.Run("step configured", func(t *testing.T) {
		h := signupHarnessWithOwner(t)
		h.srv.WithSignupStepURL("https://step.example/start")
		session := requestVerifiedSession(t, h)

		resp, err := signupWithSession(t, h, session)
		if err != nil {
			t.Fatalf("Signup: %v", err)
		}
		if resp.GetStepUrl() != "https://step.example/start" || resp.GetStepToken() == "" {
			t.Fatal("Signup with a step configured returned no step")
		}
		if resp.GetPlanId() != "" {
			t.Errorf("plan_id = %q, want empty: the product has no plan", resp.GetPlanId())
		}
		row, ok := h.queue.row(resp.GetTenantId())
		if !ok || row.status != "waiting_step" {
			t.Errorf("queued row = %+v, want status waiting_step", row)
		}
	})
	t.Run("no step", func(t *testing.T) {
		h := signupHarnessWithOwner(t)
		session := requestVerifiedSession(t, h)

		resp, err := signupWithSession(t, h, session)
		if err != nil {
			t.Fatalf("Signup: %v", err)
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
