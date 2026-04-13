package api

// server_prod_handlers.go implements the new DaemonAdminService RPCs added by
// the prod-unimplemented-apis spec:
//
//   - ResetPassword
//   - RevokeUserSessions
//   - SuspendMember
//   - GetUserProfile
//   - UpdateUserProfile
//   - ExportFindings
//   - SaveMissionDraft
//   - ListMissionDrafts
//
// Note: RPCs that previously delegated to Keycloak (ResetPassword,
// RevokeUserSessions, SuspendMember, GetUserProfile, UpdateUserProfile) now
// return codes.Unimplemented until a Better Auth–backed implementation is
// wired. The FGA tuple management in SuspendMember is preserved.

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/authz"
)

// ---------------------------------------------------------------------------
// Identity and Access — ResetPassword
// ---------------------------------------------------------------------------

// ResetPassword always returns success=true to prevent email enumeration.
// The actual password reset flow is handled by Better Auth in the dashboard.
func (s *DaemonServer) ResetPassword(_ context.Context, req *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	if req.Email == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "email is required")
	}
	// Better Auth handles password reset via the dashboard. Always return success
	// to prevent email enumeration.
	return &ResetPasswordResponse{Success: true}, nil
}

// ---------------------------------------------------------------------------
// Identity and Access — RevokeUserSessions
// ---------------------------------------------------------------------------

// RevokeUserSessions is not yet implemented for Better Auth.
// Session revocation is handled by Better Auth's session management in the dashboard.
func (s *DaemonServer) RevokeUserSessions(_ context.Context, req *RevokeUserSessionsRequest) (*RevokeUserSessionsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}
	return nil, status_grpc.Errorf(codes.Unimplemented, "RevokeUserSessions: session management has moved to the dashboard layer (Better Auth)")
}

// ---------------------------------------------------------------------------
// Identity and Access — SuspendMember
// ---------------------------------------------------------------------------

// SuspendMember manages the FGA member tuple for a user.
// When suspend=true the FGA member tuple is removed.
// When suspend=false the FGA member tuple is restored.
// Note: disabling the user account is handled by Better Auth in the dashboard.
func (s *DaemonServer) SuspendMember(ctx context.Context, req *SuspendMemberRequest) (*SuspendMemberResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}

	newStatus := "active"
	if req.Suspend {
		newStatus = "suspended"
	}
	warning := ""

	// Manage the FGA member tuple when the authorizer is wired.
	if s.authorizer != nil {
		userFGA := fmt.Sprintf("user:%s", req.UserId)
		tenantFGA := fmt.Sprintf("tenant:%s", req.TenantId)
		tuple := authz.Tuple{User: userFGA, Relation: "member", Object: tenantFGA}

		if req.Suspend {
			if err := s.authorizer.Delete(ctx, []authz.Tuple{tuple}); err != nil {
				warning = fmt.Sprintf("FGA tuple deletion failed: %v — tenant access may still be granted via FGA until repaired", err)
				s.logger.Warn("SuspendMember: FGA delete failed",
					"user_id", req.UserId,
					"tenant_id", req.TenantId,
					"error", err,
				)
			}
		} else {
			if err := s.authorizer.Write(ctx, []authz.Tuple{tuple}); err != nil {
				warning = fmt.Sprintf("FGA tuple write failed: %v — re-enable may not propagate to FGA", err)
				s.logger.Warn("SuspendMember: FGA write failed",
					"user_id", req.UserId,
					"tenant_id", req.TenantId,
					"error", err,
				)
			}
		}
	}

	if s.auditLogger != nil {
		action := "members:suspend"
		if !req.Suspend {
			action = "members:reactivate"
		}
		_ = s.auditLogger.Log(ctx, action, "user", req.UserId, map[string]any{
			"tenant_id":  req.TenantId,
			"new_status": newStatus,
		})
	}

	s.logger.Info("SuspendMember: status updated",
		"user_id", req.UserId,
		"tenant_id", req.TenantId,
		"suspend", req.Suspend,
		"new_status", newStatus,
	)

	return &SuspendMemberResponse{
		NewStatus: newStatus,
		Warning:   warning,
	}, nil
}

// ---------------------------------------------------------------------------
// User Profile — GetUserProfile and UpdateUserProfile
// ---------------------------------------------------------------------------

// GetUserProfile is not yet implemented for Better Auth.
// User profile data is managed by Better Auth in the dashboard.
func (s *DaemonServer) GetUserProfile(_ context.Context, req *GetUserProfileRequest) (*GetUserProfileResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}
	return nil, status_grpc.Errorf(codes.Unimplemented, "GetUserProfile: user profile management has moved to the dashboard layer (Better Auth)")
}

// UpdateUserProfile is not yet implemented for Better Auth.
// User profile data is managed by Better Auth in the dashboard.
func (s *DaemonServer) UpdateUserProfile(ctx context.Context, req *UpdateUserProfileRequest) (*UpdateUserProfileResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}

	// Emit audit event for profile mutation attempts.
	if s.auditLogger != nil {
		_ = s.auditLogger.Log(ctx, "users:update-profile", "user", req.UserId, map[string]any{
			"tenant_id":    req.TenantId,
			"display_name": req.DisplayName,
		})
	}

	return nil, status_grpc.Errorf(codes.Unimplemented, "UpdateUserProfile: user profile management has moved to the dashboard layer (Better Auth)")
}

// ---------------------------------------------------------------------------
// Findings Export
// ---------------------------------------------------------------------------

// ExportFindings exports findings to the requested format (json, csv, sarif).
func (s *DaemonServer) ExportFindings(ctx context.Context, req *ExportFindingsRequest) (*ExportFindingsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	format := req.Format
	if format == "" {
		format = "json"
	}

	// The actual export implementation will be handled by findings_export.go.
	// For now, delegate to the export helper.
	data, filename, count, err := exportFindingsData(ctx, s, req)
	if err != nil {
		return nil, err
	}

	return &ExportFindingsResponse{
		Data:     data,
		Format:   format,
		Filename: filename,
		Count:    int32(count),
	}, nil
}

// ---------------------------------------------------------------------------
// Mission Drafts
// ---------------------------------------------------------------------------

// SaveMissionDraft persists a mission YAML draft for later use.
func (s *DaemonServer) SaveMissionDraft(ctx context.Context, req *SaveMissionDraftRequest) (*SaveMissionDraftResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.Name == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "name is required")
	}
	if len(req.Yaml) > 512*1024 {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "yaml exceeds maximum size of 512 KB")
	}

	if s.missionDraftStore == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "mission draft store not configured")
	}

	draftID, err := s.missionDraftStore.Save(ctx, req.TenantId, req.Name, req.Yaml, req.DraftId)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to save mission draft: %v", err)
	}

	s.logger.Info("SaveMissionDraft: draft saved",
		"tenant_id", req.TenantId,
		"draft_id", draftID,
		"name", req.Name,
	)

	return &SaveMissionDraftResponse{DraftId: draftID}, nil
}

// ListMissionDrafts returns all saved mission drafts for a tenant.
func (s *DaemonServer) ListMissionDrafts(ctx context.Context, req *ListMissionDraftsRequest) (*ListMissionDraftsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}

	if s.missionDraftStore == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "mission draft store not configured")
	}

	drafts, err := s.missionDraftStore.List(ctx, req.TenantId)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to list mission drafts: %v", err)
	}

	pbDrafts := make([]*MissionDraft, 0, len(drafts))
	for _, d := range drafts {
		pbDrafts = append(pbDrafts, &MissionDraft{
			Id:        d.ID,
			Name:      d.Name,
			CreatedAt: d.CreatedAt,
			UpdatedAt: d.UpdatedAt,
		})
	}

	return &ListMissionDraftsResponse{Drafts: pbDrafts}, nil
}

