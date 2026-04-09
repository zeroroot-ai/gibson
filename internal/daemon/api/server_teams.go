// Package api — server_teams.go
//
// This file implements the team and component-grant gRPC handlers introduced in
// authz-04-dashboard-fga-migration:
//
//   - CreateTeam, ListTeams, DeleteTeam
//   - AddUserToTeam, RemoveUserFromTeam
//   - SetTeamCrosstalk
//   - ListUserComponentGrants, GrantComponentAccess, RevokeComponentAccess
//
// Each handler follows the thin-wrapper pattern: validate required fields,
// delegate to teamHandler or grantHandler in provisioner/, map the result back
// to the proto response, return.  No business logic lives here.
//
// Error mapping convention (same as server_admin.go):
//
//	provisioner.ErrInvalidSignupInput  → codes.InvalidArgument
//	provisioner.ErrTeamNotFound        → codes.NotFound
//	provisioner.ErrUserNotTenantMember → codes.FailedPrecondition
//	provisioner.ErrInvalidAction       → codes.InvalidArgument
//	provisioner.ErrGrantFailed         → codes.Internal
//	everything else                    → codes.Internal
package api

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
)

// ---------------------------------------------------------------------------
// Task 8a: Team management handlers
// ---------------------------------------------------------------------------

// CreateTeam creates a new team within a tenant.
func (s *DaemonServer) CreateTeam(ctx context.Context, req *CreateTeamRequest) (*CreateTeamResponse, error) {
	if s.teamHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "team handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if req.GetName() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "name is required")
	}

	// Determine the creator from the auth context.
	createdBy := ""
	if id, ok := auth.GibsonIdentityFromContext(ctx); ok {
		createdBy = id.Subject
	}

	rec, err := s.teamHandler.Create(ctx, tenantID, req.GetName(), req.GetDescription(), createdBy)
	if err != nil {
		return nil, mapProvisionerError(err)
	}

	return &CreateTeamResponse{
		Team: &Team{
			TeamId:      rec.TeamID,
			TenantId:    rec.TenantID,
			Name:        rec.Name,
			Description: rec.Description,
			CreatedAt:   rec.CreatedAt.Format(time.RFC3339),
			CreatedBy:   rec.CreatedBy,
		},
	}, nil
}

// ListTeams returns all teams within a tenant.
func (s *DaemonServer) ListTeams(ctx context.Context, req *ListTeamsRequest) (*ListTeamsResponse, error) {
	if s.teamHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "team handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	records, err := s.teamHandler.List(ctx, tenantID)
	if err != nil {
		return nil, mapProvisionerError(err)
	}

	teams := make([]*Team, 0, len(records))
	for _, r := range records {
		teams = append(teams, &Team{
			TeamId:      r.TeamID,
			TenantId:    r.TenantID,
			Name:        r.Name,
			Description: r.Description,
			CreatedAt:   r.CreatedAt.Format(time.RFC3339),
			CreatedBy:   r.CreatedBy,
		})
	}

	return &ListTeamsResponse{Teams: teams}, nil
}

// DeleteTeam permanently removes a team and its FGA relationships.
func (s *DaemonServer) DeleteTeam(ctx context.Context, req *DeleteTeamRequest) (*DeleteTeamResponse, error) {
	if s.teamHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "team handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetTeamId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id and team_id are required")
	}

	if err := s.teamHandler.Delete(ctx, tenantID, req.GetTeamId()); err != nil {
		return nil, mapProvisionerError(err)
	}

	s.logger.InfoContext(ctx, "team deleted via RPC",
		slog.String("tenant_id", tenantID),
		slog.String("team_id", req.GetTeamId()),
		slog.String("event_type", "rpc_team_deleted"),
	)

	return &DeleteTeamResponse{}, nil
}

// AddUserToTeam adds a user to a team within a tenant.
// The user must already be a member of the parent tenant (enforced by TeamHandler).
func (s *DaemonServer) AddUserToTeam(ctx context.Context, req *AddUserToTeamRequest) (*AddUserToTeamResponse, error) {
	if s.teamHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "team handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetTeamId() == "" || req.GetUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id, team_id, and user_id are required")
	}

	if err := s.teamHandler.AddMember(ctx, tenantID, req.GetTeamId(), req.GetUserId()); err != nil {
		return nil, mapProvisionerError(err)
	}

	return &AddUserToTeamResponse{}, nil
}

// RemoveUserFromTeam removes a user from a team.
func (s *DaemonServer) RemoveUserFromTeam(ctx context.Context, req *RemoveUserFromTeamRequest) (*RemoveUserFromTeamResponse, error) {
	if s.teamHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "team handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetTeamId() == "" || req.GetUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id, team_id, and user_id are required")
	}

	if err := s.teamHandler.RemoveMember(ctx, tenantID, req.GetTeamId(), req.GetUserId()); err != nil {
		return nil, mapProvisionerError(err)
	}

	return &RemoveUserFromTeamResponse{}, nil
}

// SetTeamCrosstalk grants or revokes team A's visibility into team B's data.
func (s *DaemonServer) SetTeamCrosstalk(ctx context.Context, req *SetTeamCrosstalkRequest) (*SetTeamCrosstalkResponse, error) {
	if s.teamHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "team handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetFromTeamId() == "" || req.GetToTeamId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id, from_team_id, and to_team_id are required")
	}

	if err := s.teamHandler.SetCrosstalk(ctx, tenantID, req.GetFromTeamId(), req.GetToTeamId(), req.GetEnabled()); err != nil {
		return nil, mapProvisionerError(err)
	}

	return &SetTeamCrosstalkResponse{}, nil
}

// ---------------------------------------------------------------------------
// Task 8b: Component grant handlers
// ---------------------------------------------------------------------------

// ListUserComponentGrants returns the component grants for a user within a tenant.
func (s *DaemonServer) ListUserComponentGrants(ctx context.Context, req *ListUserComponentGrantsRequest) (*ListUserComponentGrantsResponse, error) {
	if s.grantHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "grant handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetUserId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id and user_id are required")
	}

	domainGrants, err := s.grantHandler.List(ctx, tenantID, req.GetUserId())
	if err != nil {
		return nil, mapProvisionerError(err)
	}

	// Aggregate by component_ref: each ref can have multiple actions.
	byRef := make(map[string]*ComponentGrant)
	for _, g := range domainGrants {
		if existing, ok := byRef[g.ComponentRef]; ok {
			existing.Actions = append(existing.Actions, g.Action)
		} else {
			byRef[g.ComponentRef] = &ComponentGrant{
				ComponentRef: g.ComponentRef,
				Actions:      []string{g.Action},
			}
		}
	}

	grants := make([]*ComponentGrant, 0, len(byRef))
	for _, g := range byRef {
		grants = append(grants, g)
	}

	return &ListUserComponentGrantsResponse{Grants: grants}, nil
}

// GrantComponentAccess writes an FGA can_<action> tuple for the user on the component.
func (s *DaemonServer) GrantComponentAccess(ctx context.Context, req *GrantComponentAccessRequest) (*GrantComponentAccessResponse, error) {
	if s.grantHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "grant handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetUserId() == "" || req.GetComponentRef() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id, user_id, and component_ref are required")
	}

	action := componentActionToString(req.GetAction())
	if action == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "action must be one of EXECUTE, CONFIGURE, READ")
	}

	if err := s.grantHandler.Grant(ctx, tenantID, req.GetUserId(), req.GetComponentRef(), action); err != nil {
		return nil, mapProvisionerError(err)
	}

	s.logger.InfoContext(ctx, "component access granted",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", req.GetUserId()),
		slog.String("component_ref", req.GetComponentRef()),
		slog.String("action", action),
		slog.String("event_type", "component_grant_created"),
	)

	return &GrantComponentAccessResponse{}, nil
}

// RevokeComponentAccess deletes the FGA can_<action> tuple for the user on the component.
func (s *DaemonServer) RevokeComponentAccess(ctx context.Context, req *RevokeComponentAccessRequest) (*RevokeComponentAccessResponse, error) {
	if s.grantHandler == nil {
		return nil, status_grpc.Error(codes.Unavailable, "grant handler not configured")
	}

	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" || req.GetUserId() == "" || req.GetComponentRef() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id, user_id, and component_ref are required")
	}

	action := componentActionToString(req.GetAction())
	if action == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "action must be one of EXECUTE, CONFIGURE, READ")
	}

	if err := s.grantHandler.Revoke(ctx, tenantID, req.GetUserId(), req.GetComponentRef(), action); err != nil {
		return nil, mapProvisionerError(err)
	}

	s.logger.InfoContext(ctx, "component access revoked",
		slog.String("tenant_id", tenantID),
		slog.String("user_id", req.GetUserId()),
		slog.String("component_ref", req.GetComponentRef()),
		slog.String("action", action),
		slog.String("event_type", "component_grant_revoked"),
	)

	return &RevokeComponentAccessResponse{}, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// componentActionToString maps the proto ComponentAction enum to the provisioner
// action string expected by GrantHandler.
func componentActionToString(action ComponentAction) string {
	switch action {
	case ComponentAction_COMPONENT_ACTION_EXECUTE:
		return "execute"
	case ComponentAction_COMPONENT_ACTION_CONFIGURE:
		return "configure"
	case ComponentAction_COMPONENT_ACTION_READ:
		return "read"
	default:
		return ""
	}
}
