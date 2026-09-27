// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package admin — tenant_admin_removal.go
//
// RemoveMember and LeaveTenant implement Removal (ADR-0093 §11, hosted#205):
// ending a tenant user's place in their tenant. Both share removeTenantUser,
// which:
//
//  1. Refuses the target when they hold the tenant's owner relation — the
//     Owner cannot be removed or leave; TransferOwnership is the only way
//     out (ADR-0093 §5, mirroring the Owner rule in SetTenantRole).
//  2. Revokes every one of the target's IdP sessions and stamps their
//     active_session FGA tuples with revoked_at = now, the same
//     instant-revocation gate RevokeUserSessions uses (gibson#622/#627), so
//     their very next request fails rather than waiting for a token to
//     expire.
//  3. Revokes the target's tenant role through the tenantrole.Syncer, the
//     one writer of tenant-role tuples (ADR-0093 decision 3).
//  4. Deletes the target's Zitadel account outright, which is what frees
//     their email for another tenant and what distinguishes Removal from a
//     role change.
//
// The target's missions and findings are untouched by any of this — nothing
// here reaches those resources — so they stay in the tenant, attributed by
// the name and email already recorded on them at the time.
package admin

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/idp"
	"github.com/zeroroot-ai/gibson/internal/platform/tenantrole"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// RemoveMember ends user_id's place in the caller's tenant (ADR-0093 §11).
// The caller must hold the "admin" relation on the tenant (Admin or Owner,
// enforced by the authz registry); user_id may be any other tenant user.
// Refused when user_id is the tenant's Owner.
func (s *TenantAdminServer) RemoveMember(ctx context.Context, req *tenantv1.RemoveMemberRequest) (*tenantv1.RemoveMemberResponse, error) {
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if err := s.removeTenantUser(ctx, tenantID, req.GetUserId()); err != nil {
		return nil, err
	}
	return &tenantv1.RemoveMemberResponse{}, nil
}

// LeaveTenant is the self-service half of Removal (ADR-0093 §11): the caller
// ends their own place in their tenant. Gated on "member" rather than
// "admin" — every tenant role implies it, and removing yourself needs no
// admin standing. Refused when the caller is the tenant's Owner.
func (s *TenantAdminServer) LeaveTenant(ctx context.Context, req *tenantv1.LeaveTenantRequest) (*tenantv1.LeaveTenantResponse, error) {
	identity, identityErr := auth.IdentityFromContext(ctx)
	if identityErr != nil {
		return nil, status.Error(codes.PermissionDenied, "no identity in context")
	}
	tenantID, err := requireCallerTenant(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := s.removeTenantUser(ctx, tenantID, identity.Subject); err != nil {
		return nil, err
	}
	return &tenantv1.LeaveTenantResponse{}, nil
}

// removeTenantUser is the shared core of RemoveMember and LeaveTenant. The
// four steps run in an order chosen so a failure part-way through never
// leaves the target with LESS cut off than before: sessions are revoked
// (the access-denying step) before the role is revoked, and the role is
// revoked before the irreversible account delete.
func (s *TenantAdminServer) removeTenantUser(ctx context.Context, tenantID, userID string) error {
	if s.authorizer == nil {
		return status.Error(codes.Unavailable, "authorizer not configured")
	}
	if s.roles == nil {
		return status.Error(codes.Unavailable, "role sync not configured")
	}
	if s.idpClient == nil {
		return status.Error(codes.Unavailable, "IdP admin client not configured")
	}

	tenantRef := "tenant:" + tenantID
	userRef := "user:" + userID

	// The Owner can be removed or leave only through TransferOwnership
	// (ADR-0093 §5/§11): refuse before touching sessions, roles, or the
	// account.
	isOwner, err := s.authorizer.Check(ctx, userRef, "owner", tenantRef)
	if err != nil {
		return status.Errorf(codes.Internal, "fga Check owner: %v", err)
	}
	if isOwner {
		return status.Error(codes.PermissionDenied,
			"the tenant's Owner cannot be removed or leave; transfer ownership first")
	}

	t, err := s.tenantOf(ctx, tenantID)
	if err != nil {
		return err
	}

	// Cut off access at once: terminate the IdP sessions, then stamp the
	// active_session FGA tuples so the same instant-revocation gate
	// RevokeUserSessions relies on takes effect for this user's very next
	// request, tenant-scoped or not (gibson#622/#627/#1244).
	if _, err := s.idpClient.RevokeUserSessions(ctx, userID); err != nil {
		return status.Errorf(codes.Internal, "revoke sessions: %v", err)
	}
	s.stampSessionRevocation(ctx, userID, tenantID)

	// Revoke the tenant role (the Zitadel grant, synced into FGA) before the
	// account disappears.
	if err := s.roles.Revoke(tenantrole.WithCaller(ctx, "daemon"), t, userID); err != nil {
		return status.Errorf(codes.Internal, "revoke tenant role: %v", err)
	}

	// Delete the Zitadel account outright: this is what frees the user's
	// email for another tenant and what "Removal" means (ADR-0093 §11), as
	// opposed to a role change. Idempotent: deleting an absent user is
	// success, so a retry after a partial failure above is safe.
	if err := s.idpClient.DeleteHumanUser(ctx, idp.HumanUserStateRequest{OrgID: t.OrgID, UserID: userID}); err != nil {
		return status.Errorf(codes.Internal, "delete zitadel account: %v", err)
	}
	return nil
}

// stampSessionRevocation advances the target's active_session FGA tuples to
// revoked_at = now, mirroring RevokeUserSessions (server_revoke_sessions.go)
// exactly: both the user-scoped tuple (gates a tenant-less request) and the
// per-tenant tuple. Best-effort — the IdP session revocation above already
// happened and must not be rolled back; a stamp failure is logged loudly but
// the session still ages out of the IdP within the access-token TTL.
func (s *TenantAdminServer) stampSessionRevocation(ctx context.Context, userID, tenantID string) {
	cw, ok := s.authorizer.(authz.ConditionalWriter)
	if !ok {
		return
	}
	revokedAt := s.now().UTC().Format(time.RFC3339)

	if err := cw.UpdateConditionalTuple(ctx, authz.RevokedSessionUserTuple(userID, revokedAt)); err != nil {
		s.logger.ErrorContext(ctx, "removeTenantUser: failed to stamp user-scoped active_session revoked_at in FGA (non-fatal)",
			slog.String("target_user_id", userID),
			slog.String("revoked_at", revokedAt),
			slog.String("error", err.Error()),
		)
	}
	if err := cw.UpdateConditionalTuple(ctx, authz.RevokedSessionTuple(userID, tenantID, revokedAt)); err != nil {
		s.logger.ErrorContext(ctx, "removeTenantUser: failed to stamp active_session revoked_at in FGA (non-fatal)",
			slog.String("target_user_id", userID),
			slog.String("tenant", tenantID),
			slog.String("revoked_at", revokedAt),
			slog.String("error", err.Error()),
		)
	}
}
