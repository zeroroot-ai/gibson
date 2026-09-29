// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_reset_mfa.go
//
// ResetUserMFA (hosted#206): recovery for a tenant member locked out of a
// lost authenticator device. With passkeys and authenticator apps as the
// only second factors (hosted#193), losing the device would otherwise lock
// the person out permanently, so an Owner or Admin can reset it for them.
//
// The coarse ext-authz gate (relation "admin" on the caller's own tenant,
// USER) is enforced before this handler runs — see the (gibson.auth.v1.authz)
// annotation on ResetUserMFA in user.proto. Because "admin" is derived from
// identity (object_deriver: tenant_from_identity), the gate proves the caller
// is an Owner or Admin of THEIR OWN tenant; it does not, by itself, prove the
// named target_user_id belongs to that same tenant. This handler closes that
// gap with one FGA "member" check before touching the IdP, which is also
// what stops a tenant-B admin from resetting a tenant-A user (the check fails
// and the RPC returns NotFound, never disclosing whether the id exists
// elsewhere).
//
// Unlike RevokeUserSessions, this is admin-only by design (the issue's own
// title: "Owners and Admins can reset a tenant user's MFA") — there is no
// self-service branch, even though owner/admin already covers "the Owner
// resets their own."
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// auditActionTenantUserMFAReset is the audit action string for ResetUserMFA.
// Recorded via the daemon's existing Redis Streams audit pipeline
// (s.auditLogger), which derives actor + tenant from context automatically —
// this satisfies the "who, whom, when" audit requirement without a bespoke
// audit path.
const auditActionTenantUserMFAReset = "tenant_user_mfa_reset"

// ResetUserMFA revokes the target's active sessions, clears every second
// factor and passkey Zitadel has on file for them, and emails the target
// their own sign-in link. See the package doc above and the proto comment
// for the authorization model.
func (s *DaemonServer) ResetUserMFA(ctx context.Context, req *tenantv1.ResetUserMFARequest) (*tenantv1.ResetUserMFAResponse, error) {
	caller, err := auth.IdentityFromContext(ctx)
	if err != nil || caller.Subject == "" {
		return nil, status.Error(codes.Unauthenticated, "no identity in context")
	}
	target := req.GetTargetUserId()
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "target_user_id required")
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if s.idpAdminClient == nil {
		return nil, status.Error(codes.Unavailable, "identity provider not configured")
	}
	if s.authorizer == nil {
		return nil, status.Error(codes.Unavailable, "authorization service not configured")
	}
	// A reset without its record is not performed. The record is what lets
	// the tenant see who reset whom and when (hosted#206), and the logger
	// was silently absent in production until the daemon wired it.
	if s.auditLogger == nil {
		return nil, status.Error(codes.Unavailable, "audit log not configured: an MFA reset is not performed without its record")
	}

	// The target must belong to the caller's own tenant. "member" is the
	// umbrella relation every role (owner/admin/writer/member) implies in
	// model.fga, matching what ListMembers enumerates — so this also allows
	// resetting the tenant's own Owner, per scope.
	targetInTenant, err := s.authorizer.Check(ctx, "user:"+target, "member", "tenant:"+tenant)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check target member: %v", err)
	}
	if !targetInTenant {
		return nil, status.Error(codes.NotFound, "user not found in tenant")
	}

	sessionsRes, err := s.idpAdminClient.RevokeUserSessions(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke sessions: %v", err)
	}
	// Ending the IdP sessions does not end the access tokens already issued:
	// they are signed JWTs, valid until they expire. The FGA revocation stamp
	// is what makes ext-authz refuse them now. A reset promises that the
	// target's old sessions are refused, so a failed stamp fails the call
	// (hosted#208).
	if err := s.stampSessionRevocation(ctx, target, tenant); err != nil {
		return nil, status.Errorf(codes.Internal, "revoke tokens: %v", err)
	}

	factorsRes, err := s.idpAdminClient.ClearHumanFactors(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "clear MFA factors: %v", err)
	}

	notified := false
	if s.mfaResetMailer != nil {
		targetEmail := s.resetMFATargetEmail(ctx, target)
		if targetEmail != "" {
			sendErr := s.mfaResetMailer.SendMFAReset(ctx, mailer.MFAResetEmail{
				To:        targetEmail,
				SignInURL: s.mfaResetSignInURL(),
			})
			if sendErr != nil {
				s.logger.WarnContext(ctx, "ResetUserMFA: notice email failed to send (reset still completed)",
					"target_user_id", target, "error", sendErr.Error())
			} else {
				notified = true
			}
		} else {
			s.logger.WarnContext(ctx, "ResetUserMFA: no email on file for target; notice not sent (reset still completed)",
				"target_user_id", target)
		}
	}

	s.auditLogger.Log(ctx, auditActionTenantUserMFAReset, "user", target, map[string]any{
		"target_user_id":      target,
		"sessions_terminated": sessionsRes.SessionsTerminated,
		"otp_cleared":         factorsRes.OTPCleared,
		"u2f_cleared":         factorsRes.U2FCleared,
		"passkeys_cleared":    factorsRes.PasskeysCleared,
		"notified":            notified,
	})

	return &tenantv1.ResetUserMFAResponse{
		SessionsTerminated: int32(sessionsRes.SessionsTerminated), //nolint:gosec // bounded by active session count
		OtpCleared:         factorsRes.OTPCleared,
		U2FCleared:         int32(factorsRes.U2FCleared),      //nolint:gosec // bounded by registered credential count
		PasskeysCleared:    int32(factorsRes.PasskeysCleared), //nolint:gosec // bounded by registered credential count
		Notified:           notified,
	}, nil
}

// resetMFATargetEmail resolves the target's own email address from the IdP
// profile. Returns "" (never an error) on any lookup failure: a directory
// hiccup must not fail a reset that already succeeded, it only means the
// notice cannot be addressed and the caller is told to follow up
// out-of-band via the notified=false response field.
func (s *DaemonServer) resetMFATargetEmail(ctx context.Context, targetUserID string) string {
	profile, err := s.idpAdminClient.GetUserProfile(ctx, targetUserID)
	if err != nil || profile == nil {
		return ""
	}
	return profile.Email
}
