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

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	commonpb "github.com/zeroroot-ai/sdk/api/gen/gibson/common/v1"
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

// A signup whose workspace name gives a tenant id in use is refused before
// the owner account exists, so no account is left without a workspace. The
// status carries the reason that a client branches on.
func TestSignup_ATakenNameIsRefusedBeforeTheAccount(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.queue.rows = append(h.queue.rows, fakeQueueRow{
		tenantID: "acme-red-team", ownerUserID: "another-owner", status: "done",
	})

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	assertWorkspaceNameTaken(t, err)
	if len(h.idp.createHumanReqs) != 0 {
		t.Errorf("accounts created = %d, want none for a taken name", len(h.idp.createHumanReqs))
	}
	if row, _ := h.queue.row("acme-red-team"); row.ownerUserID != "another-owner" {
		t.Errorf("queued row = %+v, want the row of the other owner untouched", row)
	}
}

// Another signup can take the name between the check and the queue insert.
// Then the account of this call has no workspace, and it is deleted, so the
// person can start again with the same address.
func TestSignup_ANameTakenAfterTheCheckDeletesTheAccount(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		h.queue.rows = append(h.queue.rows, fakeQueueRow{
			tenantID: "acme-red-team", ownerUserID: "another-owner", status: "pending",
		})
		return idp.CreateHumanUserResult{UserID: "user-1"}, nil
	}

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	assertWorkspaceNameTaken(t, err)
	if len(h.idp.deletedUsers) != 1 || h.idp.deletedUsers[0] != "user-1" {
		t.Errorf("deleted users = %v, want the account of this call", h.idp.deletedUsers)
	}
}

// A failed delete of that account is logged, and the call still reports the
// taken name.
func TestSignup_AFailedDeleteStillReportsTheTakenName(t *testing.T) {
	h := newSignupHarness(t)
	session := h.requestAndRedeem(t)
	h.idp.deleteUserErr = errors.New("identity provider unreachable")
	h.idp.createHumanFn = func(_ context.Context, _ idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		h.queue.rows = append(h.queue.rows, fakeQueueRow{
			tenantID: "acme-red-team", ownerUserID: "another-owner", status: "pending",
		})
		return idp.CreateHumanUserResult{UserID: "user-1"}, nil
	}

	_, err := h.srv.Signup(context.Background(), &tenantv1.SignupRequest{
		AttemptId: testAttemptID, VerifiedSessionToken: session, Password: "s3cret-passw0rd!",
	})
	assertWorkspaceNameTaken(t, err)
}

// assertWorkspaceNameTaken checks the code and the ErrorDetail reason of a
// taken workspace name.
func assertWorkspaceNameTaken(t *testing.T, err error) {
	t.Helper()
	st := status.Convert(err)
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", st.Code())
	}
	for _, d := range st.Details() {
		if ed, ok := d.(*commonpb.ErrorDetail); ok && ed.GetReason() == workspaceNameTakenReason {
			return
		}
	}
	t.Fatalf("details = %v, want the reason %s", st.Details(), workspaceNameTakenReason)
}
