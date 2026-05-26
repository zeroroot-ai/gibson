// Package api — user_profile_update.go implements UserService.UpdateUserProfile.
//
// IMPLEMENT-NOW per admin-services-completion spec disposition table.
// Editable fields: display_name, preferred_locale only.
// Email is immutable; attempts to change it are rejected with InvalidArgument.
// Self-check: subject == req.UserId; cross-user denial.
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	userv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/user/v1"
	"github.com/zeroroot-ai/gibson/internal/idp"
	"github.com/zeroroot-ai/sdk/auth"
)

// UpdateUserProfile updates mutable profile fields for a user.
//
// Editable fields: display_name, preferred_locale.
// Email is immutable (Zitadel-managed); returning InvalidArgument if attempted
// through a different field is handled by the IdP.
//
// Authorization: the caller may only update their own profile (subject == req.user_id).
func (s *DaemonServer) UpdateUserProfile(ctx context.Context, req *userv1.UpdateUserProfileRequest) (*userv1.UpdateUserProfileResponse, error) {
	if req.UserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	// Self-check: callers may only update their own profile.
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if callerID.Subject != req.UserId {
		return nil, status_grpc.Error(codes.PermissionDenied, "may only update own profile")
	}

	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable, "identity provider not configured")
	}

	updated, err := s.idpAdminClient.UpdateUserProfile(ctx, req.UserId, idp.UpdateUserProfileRequest{
		DisplayName:     req.DisplayName,
		PreferredLocale: req.PreferredLocale,
	})
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "user not found: %s", req.UserId)
		}
		s.logger.ErrorContext(ctx, "UpdateUserProfile: idp error",
			"user_id", req.UserId,
			"error", err.Error(),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to update user profile")
	}

	return &userv1.UpdateUserProfileResponse{
		Profile: &userv1.UserProfileData{
			Id:              updated.AccountID,
			Email:           updated.Email,
			DisplayName:     updated.DisplayName,
			AvatarUrl:       updated.AvatarURL,
			Status:          updated.Status,
			CreatedAt:       updated.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			PreferredLocale: updated.PreferredLocale,
		},
	}, nil
}
