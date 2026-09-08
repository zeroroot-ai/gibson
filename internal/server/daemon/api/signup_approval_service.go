// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — signup_approval_service.go implements the admin-approval
// registration rung (ADR-0006, gibson#22).
//
// # The problem this solves, in one sentence
//
// A self-hosted install with no mail server has no way for anyone to sign up,
// because every path to provisioning runs through an emailed token.
//
// # Why approval rather than open-and-unverified
//
// Email verification proves mailbox control on a PUBLIC signup surface. A
// self-hosted instance sits behind the customer's perimeter, where the
// operator already controls who can reach it. Dropping the proof entirely
// would contradict this platform's claim that every actor is identified and
// accountable to a human, so the human moves rather than disappears: an
// administrator approves each account. That costs one click and keeps the
// posture.
//
// # What a pending registration IS
//
// One signup_verification row in status pending_approval, plus one DEACTIVATED
// identity-provider user holding the password the registrant chose. That is
// the whole of it. No tenant, no billing object, no provisioning-queue row —
// those are what approval creates.
//
// The password goes straight to the identity provider, which is where
// credentials belong. The daemon never stores it, because a credential parked
// in the platform database across an approval that may take days is exactly
// the thing the open rung's ordering contract exists to avoid.
//
// # One code path, not two
//
// Approval performs the same two effects SignupService.Signup performs —
// resolve the plan, enqueue the tenant — through the same helper. The rungs
// differ in what authorizes provisioning (a redeemed mailbox token, or an
// administrator's decision), never in what provisioning does. There is no
// second completion path to rot (ADR-0027).
package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/audit"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/signup"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// approvalRungGate rejects the request unless the deployment runs the approval
// rung. It is the mirror of selfServeGate: exactly one rung is live, so a call
// meant for the other one is refused rather than quietly served.
func (s *DaemonServer) approvalRungGate() error {
	if s.signupPolicy != signup.PolicyApproval {
		return status.Error(codes.PermissionDenied,
			"registration by approval is not available on this deployment; contact your administrator to provision a tenant")
	}
	return nil
}

// Register implements SignupServiceServer for the approval rung.
//
// Side effects, in full: rate-limit counters, one deactivated
// identity-provider user, one signup_verification row in pending_approval.
// Nothing else.
//
// The account is created and then deactivated, because no identity provider
// creates a user that cannot sign in. If the deactivation fails the account is
// DELETED rather than left usable: an account nobody approved must not be able
// to sign in, and the registrant loses nothing, because they were never
// approved.
func (s *DaemonServer) Register(ctx context.Context, req *tenantv1.RegisterRequest) (*tenantv1.RegisterResponse, error) {
	if err := s.approvalRungGate(); err != nil {
		return nil, err
	}

	email, err := validateRegister(req)
	if err != nil {
		return nil, err
	}

	clientIP := normalizeSignupClientIP(req.GetClientIp())
	if err := s.checkSignupLimits(ctx, registerLimits(email, clientIP)...); err != nil {
		return nil, err
	}

	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "registration is temporarily unavailable; please try again shortly")
	}
	if s.idpAdminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity provider not configured")
	}

	// The plan gate runs at approval time, where it decides provisioning. It
	// runs here too, so a request for a plan no self-serve registration may
	// have is refused at the door instead of filling an administrator's queue.
	if _, err := s.resolveSignupPlan(req.GetTier(), ""); err != nil {
		return nil, err
	}

	// ---- create the owner account, then put it beyond use ----
	// EmailVerified is false, and it is the honest value: nothing has proven
	// this address. The approval rung's proof is the administrator, not the
	// mailbox, so claiming a verification the daemon did not perform would be
	// a lie told to the identity provider.
	created, err := s.idpAdminClient.CreateHumanUser(ctx, idp.CreateHumanUserRequest{
		Email:         email,
		GivenName:     req.GetOwnerFirstName(),
		FamilyName:    req.GetOwnerLastName(),
		Password:      req.GetPassword(),
		EmailVerified: false,
	})
	if err != nil {
		// NEVER log req.Password.
		s.logger.ErrorContext(ctx, "Register: create owner user failed",
			"attempt_id", req.GetAttemptId(), "error", err.Error())
		switch {
		case errors.Is(err, idp.ErrAlreadyExists):
			return nil, status.Error(codes.AlreadyExists,
				"an account already exists for this email address; please sign in instead")
		case errors.Is(err, idp.ErrUnreachable):
			return nil, status.Error(codes.Unavailable, "identity provider unreachable")
		default:
			return nil, status.Error(codes.Internal, "failed to register")
		}
	}

	if derr := s.idpAdminClient.DeactivateHumanUser(ctx, idp.HumanUserStateRequest{UserID: created.UserID}); derr != nil {
		s.logger.ErrorContext(ctx, "Register: deactivating the new owner failed; deleting the account",
			"attempt_id", req.GetAttemptId(), "error", derr.Error())
		if xerr := s.idpAdminClient.DeleteHumanUser(ctx, idp.HumanUserStateRequest{UserID: created.UserID}); xerr != nil {
			// An account that can sign in and that nobody approved is the one
			// outcome this rung must not produce. Say so at error level and
			// name the account, so an operator can remove it by hand.
			s.logger.ErrorContext(ctx, "Register: could not remove an owner account that stayed active; deactivate or delete it by hand",
				"owner_user_id", created.UserID, "error", xerr.Error())
		}
		return nil, status.Error(codes.Internal, "failed to register")
	}

	row, err := s.signupVerifications.IssuePendingApproval(ctx, IssueParams{
		AttemptID:      req.GetAttemptId(),
		Email:          email,
		WorkspaceName:  req.GetWorkspaceName(),
		Tier:           req.GetTier(),
		OwnerFirstName: req.GetOwnerFirstName(),
		OwnerLastName:  req.GetOwnerLastName(),
		ClientIPHash:   hashClientIP(clientIP),
	}, created.UserID)
	if err != nil {
		s.logger.ErrorContext(ctx, "Register: recording the pending registration failed",
			"attempt_id", req.GetAttemptId(), "error", err.Error())
		// The account exists and cannot sign in, but no queue entry names it,
		// so no administrator will ever decide it. Remove it.
		if xerr := s.idpAdminClient.DeleteHumanUser(ctx, idp.HumanUserStateRequest{UserID: created.UserID}); xerr != nil {
			s.logger.ErrorContext(ctx, "Register: could not remove the account of a registration that was never recorded",
				"owner_user_id", created.UserID, "error", xerr.Error())
		}
		return nil, status.Error(codes.Unavailable, "registration is temporarily unavailable; please try again shortly")
	}

	s.logger.InfoContext(ctx, "Register: registration awaiting administrator approval",
		"attempt_id", req.GetAttemptId(), "registration_id", row.ID)

	return &tenantv1.RegisterResponse{RegistrationId: row.ID}, nil
}

// validateRegister decides every rejection answerable from the request alone.
// Returns the normalized email on success.
func validateRegister(req *tenantv1.RegisterRequest) (string, error) {
	if req.GetAttemptId() == "" || !isUUID(req.GetAttemptId()) {
		return "", status.Error(codes.InvalidArgument, "attempt_id must be a valid UUID")
	}
	email := NormalizeSignupEmail(req.GetOwnerEmail())
	if email == "" || !signupEmailPattern.MatchString(email) {
		return "", status.Error(codes.InvalidArgument, "owner_email must be a valid email address")
	}
	if strings.TrimSpace(req.GetWorkspaceName()) == "" {
		return "", status.Error(codes.InvalidArgument, "workspace_name is required")
	}
	if signupSlugify(req.GetWorkspaceName()) == "" {
		return "", status.Error(codes.InvalidArgument, "workspace_name does not yield a valid tenant slug")
	}
	if strings.TrimSpace(req.GetTier()) == "" {
		return "", status.Error(codes.InvalidArgument, "tier is required")
	}
	if req.GetPassword() == "" {
		return "", status.Error(codes.InvalidArgument, "password is required")
	}
	return email, nil
}

// AdminListPendingRegistrations implements AdminTenantServiceServer.
//
// gibsoncheck:allow tenant-from-request — AdminTenantService: platform_operator on
// system_tenant at ext-authz. A registration has no tenant yet, which is the
// whole reason an administrator is deciding it.
func (s *DaemonServer) AdminListPendingRegistrations(ctx context.Context, req *tenantv1.AdminListPendingRegistrationsRequest) (*tenantv1.AdminListPendingRegistrationsResponse, error) {
	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	rows, err := s.signupVerifications.ListPendingApprovals(ctx, int(req.GetLimit()))
	if err != nil {
		s.logger.ErrorContext(ctx, "AdminListPendingRegistrations: query failed", "error", err.Error())
		return nil, status.Error(codes.Internal, "failed to read pending registrations")
	}
	resp := &tenantv1.AdminListPendingRegistrationsResponse{}
	for _, r := range rows {
		resp.Registrations = append(resp.Registrations, &tenantv1.PendingRegistration{
			RegistrationId: r.ID,
			OwnerEmail:     r.Email,
			WorkspaceName:  r.WorkspaceName,
			Tier:           r.Tier,
			OwnerFirstName: r.OwnerFirstName,
			OwnerLastName:  r.OwnerLastName,
			RegisteredAt:   r.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	return resp, nil
}

// AdminApproveRegistration implements AdminTenantServiceServer.
//
// The order is: claim the decision, then do the work it authorizes. Claiming
// first is what stops two administrators approving one registration; releasing
// the claim on failure is what stops a transient error spending a decision
// nobody can make again.
//
// gibsoncheck:allow tenant-from-request — AdminTenantService: platform_operator on
// system_tenant at ext-authz.
func (s *DaemonServer) AdminApproveRegistration(ctx context.Context, req *tenantv1.AdminApproveRegistrationRequest) (*tenantv1.AdminApproveRegistrationResponse, error) {
	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if s.idpAdminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity provider not configured")
	}
	if req.GetRegistrationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "registration_id is required")
	}
	decidedBy, err := signupDeciderID(ctx)
	if err != nil {
		return nil, err
	}

	row, err := s.signupVerifications.ClaimApproval(ctx, req.GetRegistrationId(), decidedBy)
	switch {
	case errors.Is(err, ErrSignupVerificationNotFound):
		return nil, status.Error(codes.FailedPrecondition,
			"this registration is no longer pending a decision")
	case err != nil:
		s.logger.ErrorContext(ctx, "AdminApproveRegistration: claim failed", "error", err.Error())
		return nil, status.Error(codes.Internal, "failed to approve the registration")
	}

	resp, aerr := s.applyRegistrationApproval(ctx, row)
	if aerr != nil {
		// Put the registration back in the queue so the decision can be made
		// again. A release that itself fails leaves a decided row with no
		// tenant, which is why it is logged at error level.
		if rerr := s.signupVerifications.ReleaseApproval(ctx, row.ID); rerr != nil {
			s.logger.ErrorContext(ctx, "AdminApproveRegistration: releasing the claimed registration failed; it will not return to the queue",
				"registration_id", row.ID, "error", rerr.Error())
		}
		return nil, aerr
	}

	s.recordRegistrationDecision(ctx, decidedBy, row, "signup_registration.approved", "")
	s.logger.InfoContext(ctx, "AdminApproveRegistration: tenant enqueued for operator-pull provisioning",
		"registration_id", row.ID, "tenant_id", resp.GetTenantId())
	return resp, nil
}

// applyRegistrationApproval is the work an approval authorizes: resolve the
// plan, let the owner sign in, and enqueue the tenant. Every error it returns
// is already a gRPC status, and every one of them means the claim must be
// released.
func (s *DaemonServer) applyRegistrationApproval(ctx context.Context, row SignupVerification) (*tenantv1.AdminApproveRegistrationResponse, error) {
	slug := signupSlugify(row.WorkspaceName)
	if slug == "" {
		s.logger.ErrorContext(ctx, "AdminApproveRegistration: registration yields no slug",
			"registration_id", row.ID)
		return nil, status.Error(codes.Internal, "failed to approve the registration")
	}

	// The same server-side plan gate the open rung runs, from the same
	// function. StripeCustomerID is empty on this rung, so a paid plan is
	// refused where the deployment enforces entitlements — which is correct:
	// nobody paid.
	plan, err := s.resolveSignupPlan(row.Tier, row.StripeCustomerID)
	if err != nil {
		s.logger.WarnContext(ctx, "AdminApproveRegistration: plan gate refused the registration",
			"registration_id", row.ID, "requested_tier", row.Tier, "error", err.Error())
		return nil, err
	}

	if err := s.idpAdminClient.ReactivateHumanUser(ctx, idp.HumanUserStateRequest{UserID: row.OwnerUserID}); err != nil {
		s.logger.ErrorContext(ctx, "AdminApproveRegistration: reactivating the owner failed",
			"registration_id", row.ID, "error", err.Error())
		if errors.Is(err, idp.ErrUnreachable) {
			return nil, status.Error(codes.Unavailable, "identity provider unreachable")
		}
		return nil, status.Error(codes.Internal, "failed to approve the registration")
	}

	if _, err := s.enqueuePendingTenantProvisioning(ctx, &daemonoperatorv1.PendingTenant{
		TenantId:      slug,
		OwnerUserId:   row.OwnerUserID,
		OwnerEmail:    row.Email,
		WorkspaceName: row.WorkspaceName,
		Tier:          plan.ID,
	}); err != nil {
		s.logger.ErrorContext(ctx, "AdminApproveRegistration: enqueue pending tenant provisioning failed",
			"registration_id", row.ID, "tenant_id", slug, "error", err.Error())
		// The owner can sign in now and has no workspace. Deactivate again so
		// the registration returns to the queue in the state it left it.
		if derr := s.idpAdminClient.DeactivateHumanUser(ctx, idp.HumanUserStateRequest{UserID: row.OwnerUserID}); derr != nil {
			s.logger.ErrorContext(ctx, "AdminApproveRegistration: could not deactivate the owner of a registration that was not provisioned",
				"owner_user_id", row.OwnerUserID, "error", derr.Error())
		}
		return nil, status.Error(codes.Internal, "failed to approve the registration")
	}

	return &tenantv1.AdminApproveRegistrationResponse{
		TenantId:    slug,
		OwnerUserId: row.OwnerUserID,
		PlanId:      plan.ID,
	}, nil
}

// AdminRejectRegistration implements AdminTenantServiceServer.
//
// The account stays deactivated. Rejection changes the record, not the
// account: the account was already beyond use from the moment it was created,
// and refusing it simply means it stays that way.
//
// gibsoncheck:allow tenant-from-request — AdminTenantService: platform_operator on
// system_tenant at ext-authz.
func (s *DaemonServer) AdminRejectRegistration(ctx context.Context, req *tenantv1.AdminRejectRegistrationRequest) (*tenantv1.AdminRejectRegistrationResponse, error) {
	if s.signupVerifications == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetRegistrationId() == "" {
		return nil, status.Error(codes.InvalidArgument, "registration_id is required")
	}
	decidedBy, err := signupDeciderID(ctx)
	if err != nil {
		return nil, err
	}

	row, err := s.signupVerifications.RejectRegistration(ctx, req.GetRegistrationId(), decidedBy)
	switch {
	case errors.Is(err, ErrSignupVerificationNotFound):
		return nil, status.Error(codes.FailedPrecondition,
			"this registration is no longer pending a decision")
	case err != nil:
		s.logger.ErrorContext(ctx, "AdminRejectRegistration: reject failed", "error", err.Error())
		return nil, status.Error(codes.Internal, "failed to reject the registration")
	}

	s.recordRegistrationDecision(ctx, decidedBy, row, "signup_registration.rejected", req.GetReason())
	s.logger.InfoContext(ctx, "AdminRejectRegistration: registration refused",
		"registration_id", row.ID)
	return &tenantv1.AdminRejectRegistrationResponse{}, nil
}

// signupDeciderID returns the acting administrator's subject. A decision with
// no name attached is not attributable, which ADR-0006 requires it to be, so
// an unattributable caller is refused rather than recorded as nobody.
func signupDeciderID(ctx context.Context) (string, error) {
	identity, err := auth.IdentityFromContext(ctx)
	if err != nil || identity.Subject == "" {
		return "", status.Error(codes.PermissionDenied, "no identity in context")
	}
	return identity.Subject, nil
}

// recordRegistrationDecision emits the audit event for one decision.
//
// Non-fatal, like every other audit write on this surface: the decision is
// already recorded on the registration row, and failing the call after the
// decision landed would tell the administrator to make it again.
//
// The event carries no credential material and no token. It names the
// administrator, the address they decided on and the workspace it asked for.
func (s *DaemonServer) recordRegistrationDecision(ctx context.Context, decidedBy string, row SignupVerification, action, reason string) {
	details := map[string]string{
		"owner_email":    row.Email,
		"workspace_name": row.WorkspaceName,
		"tier":           row.Tier,
	}
	if reason != "" {
		details["reason"] = reason
	}
	metadata, err := json.Marshal(details)
	if err != nil {
		// The decision is already recorded on the row; a metadata failure is
		// not a reason to fail the call.
		s.logger.WarnContext(ctx, "registration decision: audit metadata could not be encoded",
			"registration_id", row.ID, "error", err.Error())
		metadata = nil
	}
	if s.tenantAdminAuditWriter != nil {
		s.tenantAdminAuditWriter.Log(audit.Event{
			TenantID:   signupSlugify(row.WorkspaceName),
			ActorID:    decidedBy,
			ActorType:  "user",
			Action:     action,
			TargetType: "signup_registration",
			TargetID:   row.ID,
			Decision:   "allow",
			Metadata:   metadata,
		})
	}
}
