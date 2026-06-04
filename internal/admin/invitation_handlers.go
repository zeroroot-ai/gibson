// Package admin — invitation_handlers.go
//
// MembershipService invitation RPC handlers (gibson#626). This slice
// (gibson#631) implements InviteMember + the pending-invitation store; the
// emailing (gibson#632), AcceptInvitation (gibson#633), and Resend/Cancel
// (gibson#634) handlers land alongside in later slices.
package admin

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// invitableRoles are the roles InviteMember accepts. owner is excluded —
// ownership transfers via TransferOwnership, not invitation.
var invitableRoles = map[string]struct{}{"admin": {}, "member": {}, "writer": {}}

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

	// The raw token rides the accept email (gibson#632); only its hash is
	// persisted. In this slice the raw token is generated + hashed + stored so
	// the pending invitation exists; emailing the raw token lands in gibson#632.
	_, hash, err := GenerateInvitationToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate invitation token: %v", err)
	}

	id, expiresAt, err := s.invitations.Issue(ctx, tenantID, req.GetEmail(), role, hash, invitedBy)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "issue invitation: %v", err)
	}

	return &tenantv1.InviteMemberResponse{
		InvitationId: id,
		ExpiresAt:    timestamppb.New(expiresAt),
	}, nil
}
