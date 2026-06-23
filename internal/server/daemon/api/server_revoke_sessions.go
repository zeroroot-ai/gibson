// Package api — server_revoke_sessions.go
//
// RevokeUserSessions (gibson#622): a principal revokes logged-in sessions /
// tokens, authorized by FGA relation over the target:
//   - self      — anyone may revoke their own sessions (the `gibson logout` path)
//   - team lead — an FGA admin on a team:<id> may revoke sessions of users who
//     are members of that team
//   - tenant admin — an FGA admin on tenant:<id> may revoke any member's sessions
//   - a peer with no admin relation over the target is denied.
//
// The coarse ext-authz gate (member on the caller's tenant, USER) is enforced
// before this handler runs; the fine-grained can_revoke_sessions(caller, target)
// decision is COMPOSED here from existing FGA relations rather than a single
// model relation, because FGA cannot express "admin over a user" without
// maintaining reverse-edge tuples on every user object. Mirrors the in-handler
// caller-access intersection MembershipService.GrantComponentPermissions does.
//
// v1 model (DECIDED): revoking blocks NEW tokens immediately; the target's
// current stateless access JWT ages out within the access-token TTL (bounded to
// 15m on the CLI app, provisioned by platform-operator#80).
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// RevokeUserSessions terminates the target user's IdP sessions and revokes their
// refresh-token grants, after enforcing can_revoke_sessions(caller, target).
func (s *DaemonServer) RevokeUserSessions(ctx context.Context, req *tenantv1.RevokeUserSessionsRequest) (*tenantv1.RevokeUserSessionsResponse, error) {
	caller, err := auth.IdentityFromContext(ctx)
	if err != nil || caller.Subject == "" {
		return nil, status.Error(codes.Unauthenticated, "no identity in context")
	}
	target := req.GetTargetUserId()
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "target_user_id required")
	}

	allowed, err := s.canRevokeSessions(ctx, caller.Subject, auth.TenantStringFromContext(ctx), target)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, status.Error(codes.PermissionDenied,
			"caller may not revoke this user's sessions (need self, team admin over the target, or tenant admin)")
	}

	if s.idpAdminClient == nil {
		return nil, status.Error(codes.Unavailable, "IdP admin client not configured")
	}
	res, err := s.idpAdminClient.RevokeUserSessions(ctx, target)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "revoke sessions: %v", err)
	}
	return &tenantv1.RevokeUserSessionsResponse{
		SessionsTerminated: int32(res.SessionsTerminated),
		GrantsRevoked:      int32(res.GrantsRevoked),
	}, nil
}

// canRevokeSessions composes the can_revoke_sessions decision: self OR tenant
// admin over a target who is a tenant member OR admin of a team the target
// belongs to. Returns a gRPC status error only on an FGA failure; a clean
// "denied" is (false, nil).
func (s *DaemonServer) canRevokeSessions(ctx context.Context, callerSubject, callerTenant, targetUserID string) (bool, error) {
	// Self — always allowed, no FGA round-trip (this is `gibson logout`).
	if callerSubject == targetUserID {
		return true, nil
	}
	if s.authorizer == nil {
		// No FGA wired → only self is permitted (fail-closed).
		return false, nil
	}
	if callerTenant == "" {
		return false, status.Error(codes.PermissionDenied, "no tenant in context")
	}

	callerRef := "user:" + callerSubject
	targetRef := "user:" + targetUserID
	tenantRef := "tenant:" + callerTenant

	// Tenant admin over a target who is a member of the same tenant.
	callerIsTenantAdmin, err := s.authorizer.Check(ctx, callerRef, "admin", tenantRef)
	if err != nil {
		return false, status.Errorf(codes.Internal, "fga Check tenant admin: %v", err)
	}
	if callerIsTenantAdmin {
		targetInTenant, err := s.authorizer.Check(ctx, targetRef, "member", tenantRef)
		if err != nil {
			return false, status.Errorf(codes.Internal, "fga Check target member: %v", err)
		}
		if targetInTenant {
			return true, nil
		}
		// Caller is tenant admin but target is not in this tenant — fall
		// through to the team check (which will also be empty) → deny.
	}

	// Team admin over a target who is a member of that team. Enumerate the
	// teams the caller administers, then check the target's membership of
	// each in one batch.
	adminTeams, err := s.authorizer.ListObjects(ctx, callerRef, "admin", "team")
	if err != nil {
		return false, status.Errorf(codes.Internal, "fga ListObjects admin teams: %v", err)
	}
	if len(adminTeams) == 0 {
		return false, nil
	}
	checks := make([]authz.CheckRequest, 0, len(adminTeams))
	for _, team := range adminTeams {
		checks = append(checks, authz.CheckRequest{User: targetRef, Relation: "member", Object: team})
	}
	results, err := s.authorizer.BatchCheck(ctx, checks)
	if err != nil {
		return false, status.Errorf(codes.Internal, "fga BatchCheck team membership: %v", err)
	}
	for _, ok := range results {
		if ok {
			return true, nil
		}
	}
	return false, nil
}
