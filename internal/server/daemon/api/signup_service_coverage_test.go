// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

// signup_service_coverage_test.go — the handler branches the rest of the
// suite does not reach: what happens when the identity directory itself is
// broken (as opposed to merely saying "no such user"), and the store-level
// failure paths of RedeemEmailVerification, AttachSignupCustomer and Signup
// that require a store returning something other than
// ErrSignupVerificationNotFound or success.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// TestExistingSignupUserID_NoIdPClientMeansNoAccount — a daemon that somehow
// reached this handler with no directory wired must treat every address as
// unregistered rather than panic or misroute.
func TestExistingSignupUserID_NoIdPClientMeansNoAccount(t *testing.T) {
	s := &DaemonServer{logger: testSlogLogger}
	if got := s.existingSignupUserID(context.Background(), "owner@example.com"); got != "" {
		t.Errorf("existingSignupUserID with no idp client = %q, want empty", got)
	}
}

// TestExistingSignupUserID_DirectoryFailureFallsBackToSend — a directory that
// cannot answer is not license to disclose anything or skip the send; it must
// be treated as "no account" so the caller still gets a verification link.
func TestExistingSignupUserID_DirectoryFailureFallsBackToSend(t *testing.T) {
	idp := &fakeIDPClient{findUserFn: func(_ context.Context, _ string) (string, error) {
		return "", errors.New("directory unreachable")
	}}
	s := &DaemonServer{logger: testSlogLogger, idpAdminClient: idp}
	if got := s.existingSignupUserID(context.Background(), "owner@example.com"); got != "" {
		t.Errorf("existingSignupUserID on a directory failure = %q, want empty (treated as no account)", got)
	}
}

// TestRequestEmailVerification_CooldownLookupFailureRefuses — the resend
// cooldown cannot be evaluated without reading the store; a broken read must
// refuse rather than silently skip the cooldown check.
func TestRequestEmailVerification_CooldownLookupFailureRefuses(t *testing.T) {
	h := newSignupHarness(t)
	h.store.lastSentErr = errors.New("connection reset")

	_, err := h.srv.RequestEmailVerification(context.Background(), validRequestReq())
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable when the cooldown lookup fails", err)
	}
}

// TestRedeemEmailVerification_StoreFailureIsUnavailable — a store error that
// is NOT "not found" (a broken connection, say) must not be folded into the
// same opaque denial redemption otherwise always returns; that denial is
// reserved for "this token does not redeem", not "we could not check".
func TestRedeemEmailVerification_StoreFailureIsUnavailable(t *testing.T) {
	h := newSignupHarness(t)
	h.store.redeemErr = errors.New("connection reset")

	_, err := h.srv.RedeemEmailVerification(context.Background(), &tenantv1.RedeemEmailVerificationRequest{
		Token: "whatever", ClientIp: "203.0.113.7",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable on a store failure", err)
	}
}

// TestAttachSignupCustomer_Validation covers the handler's own guards: no
// store wired, and a missing customer id.
func TestAttachSignupCustomer_Validation(t *testing.T) {
	t.Run("no store wired", func(t *testing.T) {
		h := newSignupHarness(t)
		h.srv.signupVerifications = nil
		_, err := h.srv.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
			VerifiedSessionToken: "sess-1", StripeCustomerId: "cus_123",
		})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("status = %v, want Unavailable with no store wired", err)
		}
	})

	t.Run("missing customer id", func(t *testing.T) {
		h := newSignupHarness(t)
		session := h.requestAndRedeem(t)
		_, err := h.srv.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
			VerifiedSessionToken: session,
		})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("status = %v, want InvalidArgument with no stripe_customer_id", err)
		}
	})
}

// TestAttachSignupCustomer_StoreFailureIsUnavailable mirrors the redemption
// case: a store error that is not ErrSignupVerificationNotFound must not read
// as "no such session".
func TestAttachSignupCustomer_StoreFailureIsUnavailable(t *testing.T) {
	h := newSignupHarness(t)
	h.store.attachErr = errors.New("connection reset")

	_, err := h.srv.AttachSignupCustomer(context.Background(), &tenantv1.AttachSignupCustomerRequest{
		VerifiedSessionToken: "sess-whatever", StripeCustomerId: "cus_123",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable on a store failure", err)
	}
}

// TestSignup_NoIdPClientIsUnavailable — provisioning an owner identity is
// unreachable without a directory to write it to.
func TestSignup_NoIdPClientIsUnavailable(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.srv.idpAdminClient = nil

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable with no identity provider configured", err)
	}
}

// TestSignup_ClaimCompletionStoreFailureIsUnavailable — same distinction as
// redemption: a broken store read must not be reported the same way as a
// session that is genuinely spent or expired.
func TestSignup_ClaimCompletionStoreFailureIsUnavailable(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.store.claimErr = errors.New("connection reset")

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("status = %v, want Unavailable on a store failure", err)
	}
}

// TestSignup_MarkConsumedFailureIsLoggedNotFatal — by the time MarkConsumed
// runs, the owner exists and the tenant is enqueued; failing the RPC here
// would tell an already-succeeded caller to retry work that is done. The
// call must still report success.
func TestSignup_MarkConsumedFailureIsLoggedNotFatal(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.store.markConsumedErr = errors.New("connection reset")

	resp, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	if err != nil {
		t.Fatalf("Signup: %v, want success even though consuming the session failed to persist", err)
	}
	if resp == nil {
		t.Fatal("expected a response")
	}
}
