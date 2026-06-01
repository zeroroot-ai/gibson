// Package api — user_profile_get.go implements UserService.GetUserProfile.
//
// IMPLEMENT-NOW per admin-services-completion spec disposition table.
// GetUserProfile maps the caller's IdP userinfo to the response shape.
// Self-check: subject == req.UserId; cross-user denial.
package api

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zeroroot-ai/gibson/internal/idp"
	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// GetUserProfile retrieves a user's profile information from the identity provider.
//
// Authorization: the caller may only access their own profile (subject == req.user_id).
func (s *DaemonServer) GetUserProfile(ctx context.Context, req *tenantv1.GetUserProfileRequest) (*tenantv1.GetUserProfileResponse, error) {
	if req.UserId == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	// Self-check: callers may only access their own profile.
	callerID, err := auth.IdentityFromContext(ctx)
	if err != nil {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if callerID.Subject != req.UserId {
		return nil, status_grpc.Error(codes.PermissionDenied, "may only access own profile")
	}

	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable, "identity provider not configured")
	}

	profile, err := s.idpAdminClient.GetUserProfile(ctx, req.UserId)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, status_grpc.Errorf(codes.NotFound, "user not found: %s", req.UserId)
		}
		s.logger.ErrorContext(ctx, "GetUserProfile: idp error",
			"user_id", req.UserId,
			"error", err.Error(),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to retrieve user profile")
	}

	return &tenantv1.GetUserProfileResponse{
		Profile: &tenantv1.UserProfileData{
			Id:              profile.AccountID,
			Email:           profile.Email,
			DisplayName:     profile.DisplayName,
			AvatarUrl:       profile.AvatarURL,
			Status:          profile.Status,
			CreatedAt:       profile.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			PreferredLocale: profile.PreferredLocale,
		},
	}, nil
}
