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

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/authz"
	"github.com/zero-day-ai/gibson/internal/keycloak"
)

// ---------------------------------------------------------------------------
// Identity and Access — ResetPassword
// ---------------------------------------------------------------------------

// ResetPassword triggers a Keycloak password-reset email for the given address.
// Per Req 7.3, this always returns success=true regardless of whether the
// email exists, preventing email enumeration attacks.
func (s *DaemonServer) ResetPassword(ctx context.Context, req *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	if req.Email == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "email is required")
	}

	if s.keycloak == nil {
		// No Keycloak configured — still return success to avoid leaking info.
		return &ResetPasswordResponse{Success: true}, nil
	}

	// Determine realm (use tenant_id if provided; fall back to configured realm).
	realm := req.TenantId
	if realm == "" {
		realm = "gibson" // default realm name
	}

	// Look up users by email. Do not log whether the lookup found a user.
	users, err := s.keycloak.ListUsers(ctx, realm, keycloak.ListUsersOpts{Email: req.Email, Max: 1})
	if err != nil {
		// Log at DEBUG only — not INFO — to avoid correlating email to reset events.
		s.logger.Debug("ResetPassword: keycloak user lookup failed",
			"realm", realm,
			"error", err,
		)
		// Still return success — no email enumeration.
		return &ResetPasswordResponse{Success: true}, nil
	}

	if len(users) == 0 {
		// User not found — return success without logging at INFO.
		return &ResetPasswordResponse{Success: true}, nil
	}

	user := users[0]

	// POST /admin/realms/{realm}/users/{id}/execute-actions-email
	path := "/admin/realms/" + url.PathEscape(realm) + "/users/" + url.PathEscape(user.ID) + "/execute-actions-email"
	resp, doErr := s.keycloak.DoAdminRequest(ctx, http.MethodPut, path, []string{"UPDATE_PASSWORD"})
	if doErr != nil {
		s.logger.Debug("ResetPassword: execute-actions-email failed",
			"realm", realm,
			"error", doErr,
		)
		// Still return success — no email enumeration.
		return &ResetPasswordResponse{Success: true}, nil
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	return &ResetPasswordResponse{Success: true}, nil
}

// ---------------------------------------------------------------------------
// Identity and Access — RevokeUserSessions
// ---------------------------------------------------------------------------

// RevokeUserSessions revokes one or all active sessions for a user.
// Delegates to Keycloak session management; publishes a Redis pub/sub event
// after Keycloak succeeds.
func (s *DaemonServer) RevokeUserSessions(ctx context.Context, req *RevokeUserSessionsRequest) (*RevokeUserSessionsResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}

	// Verify caller is authenticated.
	_, ok := auth.GibsonIdentityFromContext(ctx)
	if !ok {
		return nil, status_grpc.Errorf(codes.Unauthenticated, "not authenticated")
	}

	if s.keycloak == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "keycloak client not configured")
	}

	realm := req.TenantId
	revokedCount := int32(0)

	if req.SessionId != "" {
		// Revoke a specific session.
		path := "/admin/realms/" + url.PathEscape(realm) + "/sessions/" + url.PathEscape(req.SessionId)
		resp, err := s.keycloak.DoAdminRequest(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return nil, status_grpc.Errorf(codes.Internal, "failed to revoke session: %v", err)
		}
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		revokedCount = 1
	} else {
		// Revoke all sessions for the user.
		sessions, err := s.keycloak.GetUserSessions(ctx, realm, req.UserId)
		if err != nil {
			return nil, status_grpc.Errorf(codes.Internal, "failed to list sessions: %v", err)
		}
		for _, session := range sessions {
			path := "/admin/realms/" + url.PathEscape(realm) + "/sessions/" + url.PathEscape(session.ID)
			resp, delErr := s.keycloak.DoAdminRequest(ctx, http.MethodDelete, path, nil)
			if delErr != nil {
				s.logger.Warn("RevokeUserSessions: failed to revoke individual session",
					"session_id", session.ID,
					"error", delErr,
				)
				continue
			}
			if resp != nil && resp.Body != nil {
				resp.Body.Close()
			}
			revokedCount++
		}
	}

	// Emit audit event.
	if s.auditLogger != nil {
		_ = s.auditLogger.Log(ctx, "sessions:revoke", "user", req.UserId, map[string]any{
			"tenant_id":     req.TenantId,
			"session_id":    req.SessionId,
			"revoked_count": revokedCount,
		})
	}

	s.logger.Info("RevokeUserSessions: sessions revoked",
		"tenant_id", req.TenantId,
		"user_id", req.UserId,
		"revoked_count", revokedCount,
	)

	return &RevokeUserSessionsResponse{RevokedCount: revokedCount}, nil
}

// ---------------------------------------------------------------------------
// Identity and Access — SuspendMember
// ---------------------------------------------------------------------------

// SuspendMember disables or reactivates a tenant member via Keycloak.
// When suspend=true the user is disabled and their FGA member tuple is removed.
// When suspend=false the user is re-enabled and the tuple is restored.
func (s *DaemonServer) SuspendMember(ctx context.Context, req *SuspendMemberRequest) (*SuspendMemberResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}

	if s.keycloak == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "keycloak client not configured")
	}

	realm := req.TenantId
	warning := ""

	// Enable or disable the user in Keycloak.
	updates := map[string]interface{}{
		"enabled": !req.Suspend,
	}
	if err := s.keycloak.UpdateUser(ctx, realm, req.UserId, updates); err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to update user status: %v", err)
	}

	newStatus := "active"
	if req.Suspend {
		newStatus = "suspended"
	}

	// Manage the FGA member tuple when the authorizer is wired.
	if s.authorizer != nil {
		userFGA := fmt.Sprintf("user:%s", req.UserId)
		tenantFGA := fmt.Sprintf("tenant:%s", req.TenantId)
		tuple := authz.Tuple{User: userFGA, Relation: "member", Object: tenantFGA}

		if req.Suspend {
			// Remove the FGA member tuple on suspension.
			if err := s.authorizer.Delete(ctx, []authz.Tuple{tuple}); err != nil {
				warning = fmt.Sprintf("FGA tuple deletion failed: %v — tenant access may still be granted via FGA until repaired", err)
				s.logger.Warn("SuspendMember: FGA delete failed",
					"user_id", req.UserId,
					"tenant_id", req.TenantId,
					"error", err,
				)
			}
		} else {
			// Restore the FGA member tuple on reactivation.
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

	// Emit audit event.
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

// GetUserProfile retrieves a user's profile information from Keycloak.
func (s *DaemonServer) GetUserProfile(ctx context.Context, req *GetUserProfileRequest) (*GetUserProfileResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}

	if s.keycloak == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "keycloak client not configured")
	}

	realm := req.TenantId
	user, err := s.keycloak.GetUser(ctx, realm, req.UserId)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to get user profile: %v", err)
	}

	profile := userRepToProfileData(user)
	return &GetUserProfileResponse{Profile: profile}, nil
}

// UpdateUserProfile updates mutable profile fields (display_name, avatar_url).
// Email and role changes are not permitted through this endpoint.
func (s *DaemonServer) UpdateUserProfile(ctx context.Context, req *UpdateUserProfileRequest) (*UpdateUserProfileResponse, error) {
	if req.TenantId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "tenant_id is required")
	}
	if req.UserId == "" {
		return nil, status_grpc.Errorf(codes.InvalidArgument, "user_id is required")
	}

	if s.keycloak == nil {
		return nil, status_grpc.Errorf(codes.Unavailable, "keycloak client not configured")
	}

	realm := req.TenantId

	// Build update payload — only display_name and avatar_url are permitted.
	// Email and roles are intentionally excluded.
	attrs := map[string][]string{}
	if req.AvatarUrl != "" {
		attrs["avatarUrl"] = []string{req.AvatarUrl}
	}

	updates := map[string]interface{}{}
	if req.DisplayName != "" {
		updates["firstName"] = req.DisplayName
	}
	if len(attrs) > 0 {
		updates["attributes"] = attrs
	}

	if len(updates) > 0 {
		if err := s.keycloak.UpdateUser(ctx, realm, req.UserId, updates); err != nil {
			return nil, status_grpc.Errorf(codes.Internal, "failed to update user profile: %v", err)
		}
	}

	// Re-fetch the updated profile to return the canonical state.
	user, err := s.keycloak.GetUser(ctx, realm, req.UserId)
	if err != nil {
		return nil, status_grpc.Errorf(codes.Internal, "failed to fetch updated profile: %v", err)
	}

	// Emit audit event for profile mutations.
	if s.auditLogger != nil {
		_ = s.auditLogger.Log(ctx, "users:update-profile", "user", req.UserId, map[string]any{
			"tenant_id":    req.TenantId,
			"display_name": req.DisplayName,
		})
	}

	profile := userRepToProfileData(user)
	return &UpdateUserProfileResponse{Profile: profile}, nil
}

// userRepToProfileData converts a *keycloak.UserRepresentation to UserProfileData.
// Password hashes and credentials are never included.
func userRepToProfileData(u *keycloak.UserRepresentation) *UserProfileData {
	if u == nil {
		return &UserProfileData{}
	}

	displayName := u.FirstName
	if u.LastName != "" {
		if displayName != "" {
			displayName += " " + u.LastName
		} else {
			displayName = u.LastName
		}
	}

	// Display name from attributes takes precedence if set.
	if attrs, ok := u.Attributes["displayName"]; ok && len(attrs) > 0 && attrs[0] != "" {
		displayName = attrs[0]
	}

	avatarURL := ""
	if attrs, ok := u.Attributes["avatarUrl"]; ok && len(attrs) > 0 {
		avatarURL = attrs[0]
	}

	status := "active"
	if !u.Enabled {
		status = "suspended"
	}

	createdAt := ""
	if u.CreatedTimestamp > 0 {
		createdAt = time.UnixMilli(u.CreatedTimestamp).UTC().Format(time.RFC3339)
	}

	return &UserProfileData{
		Id:          u.ID,
		Email:       u.Email,
		DisplayName: displayName,
		AvatarUrl:   avatarURL,
		Status:      status,
		CreatedAt:   createdAt,
	}
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

