// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// signup_approval_service_test.go — the admin-approval registration rung
// (ADR-0006, gibson#22).
//
// The rung's whole claim is that a self-hosted install with no mail server can
// have a working front door without opening an unverified one. These tests pin
// the three halves of that claim: registration needs no transport, a registered
// account cannot be used, and only an administrator's decision turns it into a
// tenant.
package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

const approvalAttemptID = "11111111-2222-4333-8444-555555555555"

// approvalHarness is the signup harness on the approval rung, with the mail
// transport deliberately UNWIRED. Every test here runs against a daemon that
// cannot send a message, because that is the deployment the rung exists for.
func newApprovalHarness(t *testing.T) (*signupHarness, *fakeAuditWriter) {
	t.Helper()
	h := newSignupHarness(t)
	h.srv.signupPolicy = signup.PolicyApproval
	h.srv.signupMailer = nil
	auditWriter := &fakeAuditWriter{}
	h.srv.tenantAdminAuditWriter = auditWriter
	return h, auditWriter
}

func registerRequest() *tenantv1.RegisterRequest {
	return &tenantv1.RegisterRequest{
		AttemptId:      approvalAttemptID,
		OwnerEmail:     "Owner@Example.com",
		WorkspaceName:  "Acme Research",
		Tier:           "team",
		OwnerFirstName: "Ada",
		OwnerLastName:  "Lovelace",
		Password:       "correct horse battery staple",
	}
}

func adminCtx(subject string) context.Context {
	return auth.WithIdentity(context.Background(), auth.Identity{Subject: subject})
}

// The headline claim: registration succeeds with NO mail transport configured
// at all. Today the same install cannot sign anyone up, because every path to
// provisioning runs through an emailed token.
func TestRegister_SucceedsWithNoMailTransport(t *testing.T) {
	h, _ := newApprovalHarness(t)

	resp, err := h.srv.Register(context.Background(), registerRequest())
	if err != nil {
		t.Fatalf("Register with no mail transport must succeed: %v", err)
	}
	if resp.GetRegistrationId() == "" {
		t.Fatal("Register must return the id an administrator decides on")
	}
	if len(h.mail.verifications) != 0 || len(h.mail.collisions) != 0 {
		t.Errorf("the approval rung must send nothing; verifications=%d notices=%d",
			len(h.mail.verifications), len(h.mail.collisions))
	}
}

// A newly registered user is CREATED but cannot sign in. The account holds the
// password so the daemon does not have to, and it is deactivated so the
// credential is useless until an administrator approves.
func TestRegister_CreatesADeactivatedAccountAndNoTenant(t *testing.T) {
	h, _ := newApprovalHarness(t)

	if _, err := h.srv.Register(context.Background(), registerRequest()); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if len(h.idp.createHumanReqs) != 1 {
		t.Fatalf("owner accounts created = %d, want 1", len(h.idp.createHumanReqs))
	}
	created := h.idp.createHumanReqs[0]
	if created.Email != "owner@example.com" {
		t.Errorf("owner email = %q, want the normalized address", created.Email)
	}
	if created.EmailVerified {
		t.Error("nothing has proven this address; claiming a verification the daemon did not perform is a lie to the identity provider")
	}
	if len(h.idp.deactivated) != 1 {
		t.Fatalf("deactivations = %v, want the new account put beyond use", h.idp.deactivated)
	}
	if len(h.idp.deletedUsers) != 0 {
		t.Errorf("no account may be deleted on the happy path, got %v", h.idp.deletedUsers)
	}

	pending, err := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{})
	if err != nil {
		t.Fatalf("AdminListPendingRegistrations: %v", err)
	}
	if len(pending.GetRegistrations()) != 1 {
		t.Fatalf("pending registrations = %d, want 1", len(pending.GetRegistrations()))
	}
	got := pending.GetRegistrations()[0]
	if got.GetOwnerEmail() != "owner@example.com" || got.GetWorkspaceName() != "Acme Research" {
		t.Errorf("queue entry = %+v, want the registered address and workspace", got)
	}
	if got.GetRegisteredAt() == "" {
		t.Error("an administrator deciding a queue needs to see when each entry arrived")
	}
}

// If the account cannot be put beyond use it is DELETED. An account nobody
// approved that can sign in is the one outcome this rung must never produce.
func TestRegister_DeletesTheAccountWhenItCannotBeDeactivated(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.deactivateErr = errors.New("identity provider refused")

	_, err := h.srv.Register(context.Background(), registerRequest())
	if err == nil {
		t.Fatal("a registration whose account stays active must fail")
	}
	if len(h.idp.deletedUsers) != 1 {
		t.Fatalf("deleted accounts = %v, want the still-active account removed", h.idp.deletedUsers)
	}
	pending, _ := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{})
	if len(pending.GetRegistrations()) != 0 {
		t.Errorf("no registration may be queued when the account was removed, got %d",
			len(pending.GetRegistrations()))
	}
}

// A registration the store could not record names an account no administrator
// will ever decide, so the account goes too.
func TestRegister_DeletesTheAccountWhenTheRegistrationCannotBeRecorded(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.store.issuePendingErr = errors.New("platform postgres down")

	if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if len(h.idp.deletedUsers) != 1 {
		t.Fatalf("deleted accounts = %v, want the orphaned account removed", h.idp.deletedUsers)
	}
}

// An address that already has an account is refused, and no credential is
// written to it. Same rule as the open rung's completion step.
func TestRegister_ExistingAccountIsRefused(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.createHumanFn = func(context.Context, idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, idp.ErrAlreadyExists
	}

	_, err := h.srv.Register(context.Background(), registerRequest())
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", status.Code(err))
	}
}

func TestRegister_ValidatesItsInput(t *testing.T) {
	cases := []struct {
		name  string
		mutfn func(*tenantv1.RegisterRequest)
	}{
		{"no attempt id", func(r *tenantv1.RegisterRequest) { r.AttemptId = "" }},
		{"attempt id is not a uuid", func(r *tenantv1.RegisterRequest) { r.AttemptId = "nope" }},
		{"malformed email", func(r *tenantv1.RegisterRequest) { r.OwnerEmail = "not-an-address" }},
		{"no workspace name", func(r *tenantv1.RegisterRequest) { r.WorkspaceName = "" }},
		{"workspace name yields no slug", func(r *tenantv1.RegisterRequest) { r.WorkspaceName = "///" }},
		{"no tier", func(r *tenantv1.RegisterRequest) { r.Tier = "" }},
		{"no password", func(r *tenantv1.RegisterRequest) { r.Password = "" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _ := newApprovalHarness(t)
			req := registerRequest()
			c.mutfn(req)
			if _, err := h.srv.Register(context.Background(), req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
			}
			if len(h.idp.createHumanReqs) != 0 {
				t.Error("a rejected request must create no account")
			}
		})
	}
}

// A plan no self-serve registration may have is refused at the door rather
// than filling an administrator's queue with a decision they cannot make.
func TestRegister_RefusesAPlanThatIsNotSelfServe(t *testing.T) {
	h, _ := newApprovalHarness(t)
	req := registerRequest()
	req.Tier = "enterprise-deploy"

	if _, err := h.srv.Register(context.Background(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if len(h.idp.createHumanReqs) != 0 {
		t.Error("a refused plan must create no account")
	}
}

// Approval is what provisions: it lets the owner sign in and enqueues the
// tenant, and it is attributable to the administrator who made it.
func TestAdminApproveRegistration_ActivatesTheOwnerAndProvisions(t *testing.T) {
	h, auditWriter := newApprovalHarness(t)
	reg, err := h.srv.Register(context.Background(), registerRequest())
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	resp, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()})
	if err != nil {
		t.Fatalf("AdminApproveRegistration: %v", err)
	}
	if resp.GetTenantId() != "acme-research" {
		t.Errorf("tenant_id = %q, want the slug of the workspace name", resp.GetTenantId())
	}
	if resp.GetPlanId() != "team" {
		t.Errorf("plan_id = %q, want the plan the gate resolved", resp.GetPlanId())
	}
	if len(h.idp.reactivated) != 1 {
		t.Fatalf("reactivations = %v, want the approved owner able to sign in", h.idp.reactivated)
	}
	if h.idp.reactivated[0] != resp.GetOwnerUserId() {
		t.Errorf("reactivated %q, want the registration's own owner %q",
			h.idp.reactivated[0], resp.GetOwnerUserId())
	}

	// The decision is attributable.
	var decision *auditDecision
	for i := range auditWriter.events {
		if auditWriter.events[i].Action == "signup_registration.approved" {
			decision = &auditDecision{auditWriter.events[i].ActorID, auditWriter.events[i].TargetID}
		}
	}
	if decision == nil {
		t.Fatal("an approval must be recorded in the audit trail")
	}
	if decision.actor != "admin-1" || decision.target != reg.GetRegistrationId() {
		t.Errorf("audit event = %+v, want admin-1 deciding %s", decision, reg.GetRegistrationId())
	}

	// The queue is empty: a decided registration is not pending.
	pending, _ := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{})
	if len(pending.GetRegistrations()) != 0 {
		t.Errorf("pending after approval = %d, want 0", len(pending.GetRegistrations()))
	}
}

// auditDecision is the pair the approval test asserts on, kept small so the
// assertion reads as the claim rather than as field plumbing.
type auditDecision struct {
	actor  string
	target string
}

// Two administrators looking at the same queue cannot both approve one
// registration.
func TestAdminApproveRegistration_DecidesOnlyOnce(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	id := &tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"), id); err != nil {
		t.Fatalf("first approval: %v", err)
	}
	_, err := h.srv.AdminApproveRegistration(adminCtx("admin-2"), id)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("second approval code = %v, want FailedPrecondition", status.Code(err))
	}
}

// A claim whose work fails returns the registration to the queue, and leaves
// the owner unable to sign in. One transient failure must not spend a decision
// nobody can make again.
func TestAdminApproveRegistration_ReleasesTheClaimWhenTheWorkFails(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	h.idp.reactivateErr = errors.New("identity provider unreachable")

	_, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()})
	if err == nil {
		t.Fatal("an approval whose work failed must fail")
	}
	if len(h.store.releaseCalls) != 1 {
		t.Fatalf("release calls = %v, want the claim returned to the queue", h.store.releaseCalls)
	}
	pending, _ := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{})
	if len(pending.GetRegistrations()) != 1 {
		t.Errorf("pending after a failed approval = %d, want the registration back", len(pending.GetRegistrations()))
	}
}

// A rejected registration never becomes usable: the account stays deactivated
// and no tenant is enqueued.
func TestAdminRejectRegistration_LeavesTheAccountUnusable(t *testing.T) {
	h, auditWriter := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())

	if _, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
		&tenantv1.AdminRejectRegistrationRequest{
			RegistrationId: reg.GetRegistrationId(),
			Reason:         "not a colleague",
		}); err != nil {
		t.Fatalf("AdminRejectRegistration: %v", err)
	}
	if len(h.idp.reactivated) != 0 {
		t.Errorf("a rejected owner must never be reactivated, got %v", h.idp.reactivated)
	}
	pending, _ := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{})
	if len(pending.GetRegistrations()) != 0 {
		t.Errorf("pending after rejection = %d, want 0", len(pending.GetRegistrations()))
	}

	var found bool
	for _, ev := range auditWriter.events {
		if ev.Action == "signup_registration.rejected" && ev.ActorID == "admin-1" {
			found = true
			if !strings.Contains(string(ev.Metadata), "not a colleague") {
				t.Errorf("audit metadata = %s, want the administrator's reason", ev.Metadata)
			}
		}
	}
	if !found {
		t.Error("a rejection must be recorded in the audit trail")
	}
}

// A decision nobody can be named for is not attributable, which ADR-0006
// requires it to be.
func TestAdminRegistrationDecisions_RequireAnIdentity(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())

	if _, err := h.srv.AdminApproveRegistration(context.Background(),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("approve without an identity: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := h.srv.AdminRejectRegistration(context.Background(),
		&tenantv1.AdminRejectRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("reject without an identity: code = %v, want PermissionDenied", status.Code(err))
	}
}

func TestAdminRegistrationDecisions_ValidateTheirInput(t *testing.T) {
	h, _ := newApprovalHarness(t)

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("approve with no id: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
		&tenantv1.AdminRejectRegistrationRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("reject with no id: code = %v, want InvalidArgument", status.Code(err))
	}
	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: "no-such-registration"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("approve an unknown id: code = %v, want FailedPrecondition", status.Code(err))
	}
}

// A queue read that the store cannot answer is an error, not an empty queue:
// an administrator must not be shown "nothing to decide" because the database
// was down.
func TestAdminListPendingRegistrations_StoreFailureIsAnError(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.store.listPendingErr = errors.New("platform postgres down")

	if _, err := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
		&tenantv1.AdminListPendingRegistrationsRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

// ---------------------------------------------------------------------------
// One rung at a time
// ---------------------------------------------------------------------------

// The open rung is unchanged, and it is the SAME code that serves it: Register
// is refused there, exactly as the verification RPCs are refused on the
// approval rung. A deployment is on one rung, never on two.
func TestRungsAreExclusive(t *testing.T) {
	t.Run("open rung refuses Register", func(t *testing.T) {
		h := newSignupHarness(t) // PolicySelfServe
		if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
		}
	})

	t.Run("approval rung refuses the verification flow", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		if _, err := h.srv.RequestEmailVerification(context.Background(),
			&tenantv1.RequestEmailVerificationRequest{
				AttemptId: approvalAttemptID, OwnerEmail: "a@b.com",
				WorkspaceName: "W", Tier: "team",
			}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("RequestEmailVerification code = %v, want PermissionDenied", status.Code(err))
		}
		if _, err := h.srv.Signup(context.Background(),
			&tenantv1.SignupRequest{AttemptId: approvalAttemptID, Password: "x"}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("Signup code = %v, want PermissionDenied", status.Code(err))
		}
	})

	t.Run("closed rung refuses both", func(t *testing.T) {
		h := newSignupHarness(t)
		h.srv.signupPolicy = signup.PolicyAdminOnly
		if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.PermissionDenied {
			t.Errorf("Register code = %v, want PermissionDenied", status.Code(err))
		}
		if _, err := h.srv.Signup(context.Background(),
			&tenantv1.SignupRequest{AttemptId: approvalAttemptID, Password: "x"}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("Signup code = %v, want PermissionDenied", status.Code(err))
		}
	})
}

// ---------------------------------------------------------------------------
// Failure branches: every one of them must leave nothing usable behind
// ---------------------------------------------------------------------------

// A limiter that refuses stops the request before any account exists.
func TestRegister_RateLimitedBeforeAnyAccountExists(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.srv.WithSignupLimiter(denyLimiter{})

	if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted", status.Code(err))
	}
	if len(h.idp.createHumanReqs) != 0 {
		t.Error("a rate-limited request must create no account")
	}
}

// No store and no identity provider are both Unavailable, and both refuse
// before anything is created. A daemon that cannot record a registration must
// not make one.
func TestRegister_MissingDependenciesRefuse(t *testing.T) {
	t.Run("no store", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.srv.signupVerifications = nil
		if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
		if len(h.idp.createHumanReqs) != 0 {
			t.Error("no account may be created with nowhere to record it")
		}
	})
	t.Run("no identity provider", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.srv.idpAdminClient = nil
		if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
}

// An identity provider that cannot be reached is Unavailable, not Internal:
// the registrant may usefully try again.
func TestRegister_UnreachableIdentityProviderIsUnavailable(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.createHumanFn = func(context.Context, idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, idp.ErrUnreachable
	}

	if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
}

// Any other identity-provider failure is Internal, and the message is
// sanitized.
func TestRegister_OtherIdentityProviderFailuresAreInternal(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.idp.createHumanFn = func(context.Context, idp.CreateHumanUserRequest) (idp.CreateHumanUserResult, error) {
		return idp.CreateHumanUserResult{}, errors.New("bad request")
	}

	_, err := h.srv.Register(context.Background(), registerRequest())
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
	if strings.Contains(status.Convert(err).Message(), "bad request") {
		t.Error("the identity provider's own message must not reach the caller")
	}
}

// A rollback that itself fails is still a refusal. The account is named in the
// log for an operator to remove; the caller is told the registration failed.
func TestRegister_RollbackFailureStillRefuses(t *testing.T) {
	t.Run("deactivate then delete both fail", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.idp.deactivateErr = errors.New("refused")
		h.idp.deleteUserErr = errors.New("refused too")

		if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want Internal", status.Code(err))
		}
	})
	t.Run("record fails and delete fails", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.store.issuePendingErr = errors.New("postgres down")
		h.idp.deleteUserErr = errors.New("refused")

		if _, err := h.srv.Register(context.Background(), registerRequest()); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
}

// The admin RPCs refuse without their dependencies rather than answering with
// an empty queue or a half-done approval.
func TestAdminRegistrationRPCs_MissingDependenciesRefuse(t *testing.T) {
	t.Run("list with no store", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.srv.signupVerifications = nil
		if _, err := h.srv.AdminListPendingRegistrations(adminCtx("admin-1"),
			&tenantv1.AdminListPendingRegistrationsRequest{}); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
	t.Run("approve with no store", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.srv.signupVerifications = nil
		if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
			&tenantv1.AdminApproveRegistrationRequest{RegistrationId: "reg-1"}); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
	t.Run("approve with no identity provider", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.srv.idpAdminClient = nil
		if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
			&tenantv1.AdminApproveRegistrationRequest{RegistrationId: "reg-1"}); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
	t.Run("reject with no store", func(t *testing.T) {
		h, _ := newApprovalHarness(t)
		h.srv.signupVerifications = nil
		if _, err := h.srv.AdminRejectRegistration(adminCtx("admin-1"),
			&tenantv1.AdminRejectRegistrationRequest{RegistrationId: "reg-1"}); status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
}

// A store failure on a decision is Internal, and it is not "no such
// registration": an administrator must not be told their decision was already
// made when the database simply could not answer.
func TestAdminRegistrationDecisions_StoreFailureIsInternal(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	h.store.claimApprovalErr = errors.New("postgres down")

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

// An identity provider that cannot be reached during approval is Unavailable,
// and the registration returns to the queue.
func TestAdminApproveRegistration_UnreachableIdentityProviderReleasesTheClaim(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	h.idp.reactivateErr = idp.ErrUnreachable

	_, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable", status.Code(err))
	}
	if len(h.store.releaseCalls) != 1 {
		t.Errorf("release calls = %v, want the claim returned", h.store.releaseCalls)
	}
}

// A workspace name that no longer yields a slug means the row is corrupt, not
// that the administrator is wrong.
func TestAdminApproveRegistration_CorruptRowIsInternal(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	h.store.rows[reg.GetRegistrationId()].WorkspaceName = "///"

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
}

// The plan gate runs again at approval time, against the row rather than the
// request, so a tier that stopped being self-serve between registration and
// decision is refused rather than provisioned.
func TestAdminApproveRegistration_PlanGateRunsOnTheRow(t *testing.T) {
	h, _ := newApprovalHarness(t)
	reg, _ := h.srv.Register(context.Background(), registerRequest())
	h.store.rows[reg.GetRegistrationId()].Tier = "enterprise-deploy"

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied", status.Code(err))
	}
	if len(h.idp.reactivated) != 0 {
		t.Error("a refused plan must not let the owner sign in")
	}
}

// A decision made with no audit writer wired still lands: the row carries the
// decision, and the audit write is best-effort.
func TestAdminRegistrationDecisions_SurviveAMissingAuditWriter(t *testing.T) {
	h, _ := newApprovalHarness(t)
	h.srv.tenantAdminAuditWriter = nil
	reg, _ := h.srv.Register(context.Background(), registerRequest())

	if _, err := h.srv.AdminApproveRegistration(adminCtx("admin-1"),
		&tenantv1.AdminApproveRegistrationRequest{RegistrationId: reg.GetRegistrationId()}); err != nil {
		t.Fatalf("AdminApproveRegistration: %v", err)
	}
}
