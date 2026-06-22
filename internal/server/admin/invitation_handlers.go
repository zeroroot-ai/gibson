// Package admin — invitation_handlers.go
//
// MembershipService invitation RPC handlers (gibson#626). This slice
// (gibson#631) implements InviteMember + the pending-invitation store; the
// emailing (gibson#632), AcceptInvitation (gibson#633), and Resend/Cancel
// (gibson#634) handlers land alongside in later slices.
package admin

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// invitableRoles are the roles InviteMember accepts. owner is excluded —
// ownership transfers via TransferOwnership, not invitation.
var invitableRoles = map[string]struct{}{"admin": {}, "member": {}, "writer": {}}

// sendInvitationEmail builds the accept link and sends the invitation email.
// No-op (logs a warning, returns nil) when the mailer or base URL is
// unconfigured — the invitation record still exists and can be resent once mail
// is configured. The raw token rides the link only; it is never stored or
// returned over the RPC.
func (s *TenantAdminServer) sendInvitationEmail(ctx context.Context, tenantID, to, role, rawToken string, expiresAt time.Time) error {
	if s.inviteMailer == nil || s.inviteBaseURL == "" {
		s.logger.WarnContext(ctx, "invitation email not sent (mailer or base URL unconfigured)", "tenant", tenantID, "to", to)
		return nil
	}
	acceptURL := strings.TrimRight(s.inviteBaseURL, "/") + "/invite/" + rawToken
	return s.inviteMailer.SendInvitation(ctx, mailer.InvitationEmail{
		To:        to,
		AcceptURL: acceptURL,
		TenantID:  tenantID,
		Role:      role,
		ExpiresAt: expiresAt,
	})
}

// InviteMember creates (or refreshes) a pending invitation for an email address
// with a tenant role. It generates a random token, persists only its hash with
// a TTL, and surfaces the invitee in ListMembers as "invited". Emailing the
// accept link is gibson#632; redeeming is gibson#633.
func (s *TenantAdminServer) InviteMember(ctx context.Context, req *tenantv1.InviteMemberRequest) (*tenantv1.InviteMemberResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if req.GetEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "email required")
	}
	role := req.GetRole()
	if role == "" {
		role = "member"
	}
	if _, valid := invitableRoles[role]; !valid {
		return nil, status.Errorf(codes.InvalidArgument, "role %q not allowed; must be one of admin, member, writer", role)
	}
	if s.invitations == nil {
		return nil, status.Error(codes.Unavailable, "invitation store not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = tenant.String()
	}

	var invitedBy string
	if id, err := auth.IdentityFromContext(ctx); err == nil {
		invitedBy = id.Subject
	}

	// The raw token rides the accept email; only its hash is persisted (it is
	// never stored or returned over the RPC).
	token, hash, err := GenerateInvitationToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate invitation token: %v", err)
	}

	id, expiresAt, err := s.invitations.Issue(ctx, tenantID, req.GetEmail(), role, hash, invitedBy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue invitation: %v", err)
	}

	// Email the accept link (gibson#632). The invitation is already persisted +
	// idempotent on (tenant,email), so a send failure is recoverable via
	// ResendInvitation; surface it so the admin knows delivery didn't happen.
	if err := s.sendInvitationEmail(ctx, tenantID, req.GetEmail(), role, token, expiresAt); err != nil {
		return nil, status.Errorf(codes.Internal, "send invitation email: %v", err)
	}

	return &tenantv1.InviteMemberResponse{
		InvitationId: id,
		ExpiresAt:    timestamppb.New(expiresAt),
	}, nil
}

// AcceptInvitation redeems an invitation token: validates it, ensures the IdP
// user exists, projects full membership (FGA tuple + per-tenant Zitadel org
// membership, reusing the gibson#621 dual-write), and marks the invitation
// accepted. Unauthenticated — the token is the sole capability (gibson#633).
func (s *TenantAdminServer) AcceptInvitation(ctx context.Context, req *tenantv1.AcceptInvitationRequest) (*tenantv1.AcceptInvitationResponse, error) {
	if req.GetToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "token required")
	}
	if s.invitations == nil {
		return nil, status.Error(codes.Unavailable, "invitation store not configured")
	}
	if s.authorizer == nil || s.idpClient == nil {
		return nil, status.Error(codes.Unavailable, "membership backend not configured")
	}

	rec, err := s.invitations.GetByTokenHash(ctx, HashInvitationToken(req.GetToken()))
	if errors.Is(err, ErrInvitationNotFound) {
		return nil, status.Error(codes.PermissionDenied, "invalid or unknown invitation token")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up invitation: %v", err)
	}
	if rec.Status != "pending" {
		return nil, status.Errorf(codes.FailedPrecondition, "invitation is %s, not pending", rec.Status)
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, status.Error(codes.FailedPrecondition, "invitation has expired")
	}

	// Ensure the invited human exists in the tenant's per-tenant org, then
	// project both halves of membership. Zitadel-first (idempotent) then FGA,
	// matching SetTenantRole's fail-closed-on-authority ordering.
	orgID, err := s.resolveTenantOrgID(ctx, rec.TenantID)
	if err != nil {
		return nil, err
	}
	userID, err := s.idpClient.EnsureHumanUser(ctx, idp.EnsureHumanUserRequest{OrgID: orgID, Email: rec.Email})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ensure invited user: %v", err)
	}
	if err := s.addZitadelMember(ctx, rec.TenantID, userID, rec.Role); err != nil {
		return nil, err
	}
	tuple := authz.Tuple{User: "user:" + userID, Relation: rec.Role, Object: "tenant:" + rec.TenantID}
	present, err := s.authorizer.Check(ctx, tuple.User, tuple.Relation, tuple.Object)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "fga Check %s: %v", rec.Role, err)
	}
	if !present {
		if err := s.authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
			return nil, status.Errorf(codes.Internal, "fga Write %s: %v", rec.Role, err)
		}
	}

	if err := s.invitations.SetStatus(ctx, rec.ID, "accepted"); err != nil {
		// Membership is already projected (authoritative); a stale "pending"
		// status is self-healing on a retry. Log-and-succeed rather than fail
		// the now-completed accept.
		s.logger.WarnContext(ctx, "AcceptInvitation: membership projected but status update failed",
			slog.String("invitation_id", rec.ID), slog.String("error", err.Error()))
	}
	return &tenantv1.AcceptInvitationResponse{TenantId: rec.TenantID, UserId: userID}, nil
}

// lookupPendingInvitation resolves the target invitation for resend/cancel from
// (tenant, email). invitation_id-based lookup can layer on later.
func (s *TenantAdminServer) lookupPendingInvitation(ctx context.Context, req interface {
	GetTenantId() string
	GetEmail() string
}) (string, *InvitationRecord, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return "", nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	if s.invitations == nil {
		return "", nil, status.Error(codes.Unavailable, "invitation store not configured")
	}
	if req.GetEmail() == "" {
		return "", nil, status.Error(codes.InvalidArgument, "email required")
	}
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = tenant.String()
	}
	rec, err := s.invitations.FindPendingByEmail(ctx, tenantID, req.GetEmail())
	if errors.Is(err, ErrInvitationNotFound) {
		return "", nil, status.Error(codes.NotFound, "no pending invitation for that email")
	}
	if err != nil {
		return "", nil, status.Errorf(codes.Internal, "look up invitation: %v", err)
	}
	return tenantID, rec, nil
}

// ResendInvitation refreshes a pending invitation's token + TTL (re-issue).
// Emailing the refreshed link lands in gibson#632.
func (s *TenantAdminServer) ResendInvitation(ctx context.Context, req *tenantv1.ResendInvitationRequest) (*tenantv1.ResendInvitationResponse, error) {
	tenantID, rec, err := s.lookupPendingInvitation(ctx, req)
	if err != nil {
		return nil, err
	}
	token, hash, gerr := GenerateInvitationToken()
	if gerr != nil {
		return nil, status.Errorf(codes.Internal, "generate invitation token: %v", gerr)
	}
	var invitedBy string
	if id, ierr := auth.IdentityFromContext(ctx); ierr == nil {
		invitedBy = id.Subject
	}
	_, expiresAt, ierr := s.invitations.Issue(ctx, tenantID, rec.Email, rec.Role, hash, invitedBy)
	if ierr != nil {
		return nil, status.Errorf(codes.Internal, "reissue invitation: %v", ierr)
	}
	if err := s.sendInvitationEmail(ctx, tenantID, rec.Email, rec.Role, token, expiresAt); err != nil {
		return nil, status.Errorf(codes.Internal, "send invitation email: %v", err)
	}
	return &tenantv1.ResendInvitationResponse{}, nil
}

// CancelInvitation marks a pending invitation cancelled so it can no longer be
// accepted.
func (s *TenantAdminServer) CancelInvitation(ctx context.Context, req *tenantv1.CancelInvitationRequest) (*tenantv1.CancelInvitationResponse, error) {
	_, rec, err := s.lookupPendingInvitation(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.invitations.SetStatus(ctx, rec.ID, "cancelled"); err != nil {
		return nil, status.Errorf(codes.Internal, "cancel invitation: %v", err)
	}
	return &tenantv1.CancelInvitationResponse{}, nil
}
