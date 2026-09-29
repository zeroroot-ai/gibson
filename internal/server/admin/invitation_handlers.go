// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/mailer"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// invitableRoles are the roles InviteMember accepts. owner is excluded —
// ownership transfers via TransferOwnership, not invitation.
var invitableRoles = map[string]struct{}{"admin": {}, "member": {}, "writer": {}}

// sendInvitationEmail builds the accept link and sends the invitation email.
// The raw token rides the link only; it is never stored or returned over the
// RPC.
//
// When the mailer or base URL is unconfigured this refuses the call with
// FailedPrecondition rather than returning nil. Returning nil reported a
// delivery that never happened: the admin saw InviteMember succeed, the invitee
// never got a link, and nothing surfaced the gap. The invitation row is already
// persisted and idempotent on (tenant, email), so ResendInvitation replays the
// send once mail is configured.
//
// The refusal is per-call by design. A mail misconfiguration must degrade the
// invitation RPCs only — never fail daemon startup and take every other RPC
// down with it.
func (s *TenantAdminServer) sendInvitationEmail(ctx context.Context, tenantID, to, role, rawToken string, expiresAt time.Time) error {
	if s.inviteMailer == nil || s.inviteBaseURL == "" {
		s.logger.WarnContext(ctx, "invitation email not sent: mailer or base URL unconfigured", "tenant", tenantID, "to", to)
		return status.Error(codes.FailedPrecondition,
			"transactional email is not configured; the invitation was recorded but no email was sent — configure the email provider and public URL, then resend")
	}
	acceptURL := strings.TrimRight(s.inviteBaseURL, "/") + "/invite/" + rawToken
	if err := s.inviteMailer.SendInvitation(ctx, mailer.InvitationEmail{
		To:        to,
		AcceptURL: acceptURL,
		TenantID:  tenantID,
		Role:      role,
		ExpiresAt: expiresAt,
	}); err != nil {
		return status.Errorf(codes.Internal, "send invitation email: %v", err)
	}
	return nil
}

// invitedAddressBelongsElsewhere reports whether email already belongs to a
// Zitadel user who is not a member of t — hosted#203, ADR-0093 decision 1.
// false, nil covers both "the address is unused" and "the lookup could not
// run"; in both cases the caller proceeds with a normal invitation.
func (s *TenantAdminServer) invitedAddressBelongsElsewhere(ctx context.Context, t tenantrole.Tenant, email string) (bool, error) {
	existingUserID, err := s.idpClient.FindUserIDByEmail(ctx, email)
	switch {
	case errors.Is(err, idp.ErrNotFound):
		return false, nil
	case err != nil:
		// A directory that cannot answer is not a reason to disclose
		// anything or to block the invite (same rationale as signup's
		// existingSignupUserID, signup_service.go): proceed as if the
		// address is unused.
		s.logger.WarnContext(ctx, "InviteMember: directory lookup failed; proceeding with a normal invitation",
			slog.String("error", err.Error()))
		return false, nil
	}
	if s.roles == nil {
		return false, errors.New("tenant role sync not configured")
	}
	member, merr := s.roles.IsMember(ctx, t, existingUserID)
	if merr != nil {
		return false, fmt.Errorf("check tenant membership: %w", merr)
	}
	return !member, nil
}

// fakeSentAfterConflictNotice sends the invitee-only conflict notice (best
// effort — a delivery failure here must not tell the inviter anything went
// wrong) and returns the SAME response shape a real invitation would: the
// inviter cannot distinguish this from success, by design.
func (s *TenantAdminServer) fakeSentAfterConflictNotice(ctx context.Context, email string) (*tenantv1.InviteMemberResponse, error) {
	if s.inviteMailer != nil {
		if err := s.inviteMailer.SendInvitationConflict(ctx, mailer.InvitationConflictEmail{To: email}); err != nil {
			s.logger.WarnContext(ctx, "InviteMember: conflict notice send failed",
				slog.String("error", err.Error()))
		}
	}
	return &tenantv1.InviteMemberResponse{
		InvitationId: uuid.NewString(),
		ExpiresAt:    timestamppb.New(time.Now().Add(InvitationTTL)),
	}, nil
}

// InviteProvisionedOwner issues the founding Owner's invitation for a tenant
// the Platform owner provisions through AdminProvisionTenant (hosted#205).
//
// It is the same mechanism InviteMember uses, and nothing else: the same
// store row (role "owner", invited by the Platform owner), the same mail with
// the same <app origin>/invite/<token> link, and the same AcceptInvitation
// that creates the Zitadel user in the tenant's org, assigns Owner with its
// FGA copy and hands the person their setup link. Until this existed the
// provision path created the Tenant CR only, so the named owner had no
// account, no role and no way in.
//
// The mail is checked BEFORE anything is written: an install with no mail
// transport cannot bring an owner in, and AdminProvisionTenant must refuse
// before it queues a tenant nobody can reach. Issue is an upsert on
// (tenant, email), so a retry after a failed send mints a fresh token and
// mails again; it never strands a row whose token was lost.
func (s *TenantAdminServer) InviteProvisionedOwner(ctx context.Context, tenantID, ownerEmail, invitedBy string) error {
	if tenantID == "" || ownerEmail == "" {
		return status.Error(codes.InvalidArgument, "tenant id and owner email required")
	}
	if s.invitations == nil {
		return status.Error(codes.Unavailable, "invitation store not configured")
	}
	if s.inviteMailer == nil || s.inviteBaseURL == "" {
		return status.Error(codes.Unavailable,
			"transactional email is not configured; a provisioned tenant's owner is brought in by an emailed invitation, so configure the email provider and public URL first")
	}
	token, hash, err := GenerateInvitationToken()
	if err != nil {
		return status.Errorf(codes.Internal, "generate invitation token: %v", err)
	}
	_, expiresAt, err := s.invitations.Issue(ctx, tenantID, ownerEmail, tenantrole.Owner.Relation(), hash, invitedBy)
	if err != nil {
		return status.Errorf(codes.Internal, "issue owner invitation: %v", err)
	}
	return s.sendInvitationEmail(ctx, tenantID, ownerEmail, tenantrole.Owner.Relation(), token, expiresAt)
}

// InviteMember creates (or refreshes) a pending invitation for an email address
// with a tenant role. It generates a random token, persists only its hash with
// a TTL, and surfaces the invitee in ListMembers as "invited". Emailing the
// accept link is gibson#632; redeeming is gibson#633.
func (s *TenantAdminServer) InviteMember(ctx context.Context, req *tenantv1.InviteMemberRequest) (*tenantv1.InviteMemberResponse, error) {
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
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

	// The invited address may already belong to a DIFFERENT tenant
	// (ADR-0093 decision 1: one tenant per person, emails unique
	// install-wide). The inviter must never learn this: this call still
	// reports "sent" below, and only the invitee is told, by email
	// (hosted#203). Skipped when the optional collaborators it needs
	// (idpClient, orgResolver) are not configured — the same graceful
	// degradation this file already uses elsewhere.
	if s.idpClient != nil && s.orgResolver != nil {
		if t, terr := s.tenantOf(ctx, tenantID); terr == nil {
			conflict, cerr := s.invitedAddressBelongsElsewhere(ctx, t, req.GetEmail())
			if cerr != nil {
				return nil, status.Errorf(codes.Internal, "check invited address: %v", cerr)
			}
			if conflict {
				return s.fakeSentAfterConflictNotice(ctx, req.GetEmail())
			}
		}
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
		return nil, err
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

	if s.roles == nil {
		return nil, status.Error(codes.Unavailable, "role sync not configured")
	}
	t, err := s.tenantOf(ctx, rec.TenantID)
	if err != nil {
		return nil, err
	}
	roleValue, ok := tenantrole.FromRelation(rec.Role)
	if !ok {
		return nil, status.Errorf(codes.Internal, "invitation role %q has no tenant-role mapping", rec.Role)
	}

	// Ensure the invited human exists in the tenant's per-tenant org, then
	// assign the role: Zitadel grant first, then Roles.Sync copies it into
	// FGA in the same call. The same no-password create as the Platform owner
	// and the first tenant Owner: an ACTIVE user with a verified email and no
	// credential. The caller already proved control of rec.Email by redeeming
	// this exact token, and the setup link below is the one way to set a
	// credential. A v1 Management create left the user INITIAL, which the
	// Login v2 app refuses with "User Initial State is not supported"
	// (hosted#208).
	userID, err := s.idpClient.EnsureHumanUserNoPassword(ctx, t.OrgID, rec.Email, "Invited", "User")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ensure invited user: %v", err)
	}
	if err := s.roles.Assign(tenantrole.WithCaller(ctx, "daemon"), t, userID, roleValue); err != nil {
		return nil, status.Errorf(codes.Internal, "assign tenant role: %v", err)
	}
	if err := s.seedSessionTuples(ctx, userID, rec.TenantID); err != nil {
		return nil, status.Errorf(codes.Internal, "seed session tuples: %v", err)
	}

	// Mint a one-time Zitadel setup link: it creates the user's credential
	// (a password + MFA enrollment), which this call has not set — the
	// invitee never had a password from us to leak, ADR-0093 decision 8's
	// rule for every human this install creates. Never emailed a second
	// time by the IdP itself (CreateSetupLink's returnCode contract): this
	// RPC's own caller already owns messaging for this invitee.
	//
	// s.inviteBaseURL is the product-surface origin (GIBSON_APP_URL) — the
	// SAME value sendInvitationEmail already built the accept-link email
	// from, above. Never an OIDC issuer or a Zitadel endpoint: gibson#254
	// found the Platform owner's setup link built from spec.zitadel.issuer
	// resolved to an in-cluster address on kind.
	//
	// Left of SetStatus deliberately: if this fails, the invitation stays
	// "pending" so a retry can redeem the same token again — the user create
	// and Roles.Assign above are both idempotent, so a retry costs nothing.
	setupURL, err := s.idpClient.CreateSetupLink(ctx, t.OrgID, userID, s.inviteBaseURL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create setup link: %v", err)
	}

	// rec.TenantID, not a caller-supplied tenant: AcceptInvitation is
	// unauthenticated, so the token lookup is the only authority for which
	// tenant this invitation belongs to.
	if err := s.invitations.SetStatus(ctx, rec.TenantID, rec.ID, "accepted"); err != nil {
		// Membership is already projected (authoritative); a stale "pending"
		// status is self-healing on a retry. Log-and-succeed rather than fail
		// the now-completed accept.
		s.logger.WarnContext(ctx, "AcceptInvitation: membership projected but status update failed",
			slog.String("invitation_id", rec.ID), slog.String("error", err.Error()))
	}
	return &tenantv1.AcceptInvitationResponse{TenantId: rec.TenantID, UserId: userID, SetupUrl: setupURL}, nil
}

// lookupPendingInvitation resolves the target invitation for resend/cancel from
// (tenant, email). invitation_id-based lookup can layer on later.
//
// The tenant is always resolved through requireCallerTenant, so both callers
// (ResendInvitation, CancelInvitation) operate only inside the caller's own
// tenant and a request naming another tenant is rejected outright.
func (s *TenantAdminServer) lookupPendingInvitation(ctx context.Context, req interface {
	tenantScopedRequest
	GetEmail() string
}) (string, *InvitationRecord, error) {
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return "", nil, err
	}
	if s.invitations == nil {
		return "", nil, status.Error(codes.Unavailable, "invitation store not configured")
	}
	if req.GetEmail() == "" {
		return "", nil, status.Error(codes.InvalidArgument, "email required")
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
		return nil, err
	}
	return &tenantv1.ResendInvitationResponse{}, nil
}

// CancelInvitation marks a pending invitation cancelled so it can no longer be
// accepted.
func (s *TenantAdminServer) CancelInvitation(ctx context.Context, req *tenantv1.CancelInvitationRequest) (*tenantv1.CancelInvitationResponse, error) {
	// The tenant comes from requireCallerTenant (via lookupPendingInvitation),
	// so the UPDATE is confined to the caller's own tenant even if the
	// invitation id were somehow attacker-influenced.
	tenantID, rec, err := s.lookupPendingInvitation(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.invitations.SetStatus(ctx, tenantID, rec.ID, "cancelled"); err != nil {
		if errors.Is(err, ErrInvitationNotFound) {
			return nil, status.Error(codes.NotFound, "no pending invitation for that email")
		}
		return nil, status.Errorf(codes.Internal, "cancel invitation: %v", err)
	}
	return &tenantv1.CancelInvitationResponse{}, nil
}

// seedSessionTuples writes the invitee's two active_session tuples, the
// user-scoped one and the one for tenantID, with revoked_at at the epoch.
// ext-authz's session gate fails closed on a missing per-tenant tuple, so a
// member without it is denied on every call, starting with the
// ListMyMemberships that resolves their tenant at sign-in (hosted#208). The
// TenantMember controller wrote these for the old invitation path; this
// path replaced it (ADR-0093) and has to write them itself.
//
// WriteConditional keys on (user, relation, object): an existing tuple is a
// no-op. So a re-invited member who was removed keeps the revoked_at stamp
// the removal wrote, and only tokens issued after it pass the gate.
//
// Unlike the removal stamp, a failure here fails the call: the invitation
// stays pending, and a retry repairs it. Every write above is idempotent.
func (s *TenantAdminServer) seedSessionTuples(ctx context.Context, userID, tenantID string) error {
	cw, ok := s.authorizer.(authz.ConditionalWriter)
	if !ok {
		return errors.New("the authorizer cannot write session tuples")
	}
	if err := cw.WriteConditional(ctx, authz.ActiveSessionUserTuple(userID)); err != nil {
		return fmt.Errorf("user-scoped active_session: %w", err)
	}
	if err := cw.WriteConditional(ctx, authz.ActiveSessionTuple(userID, tenantID)); err != nil {
		return fmt.Errorf("active_session for tenant %s: %w", tenantID, err)
	}
	return nil
}
