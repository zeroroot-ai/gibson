// Package api — server_user.go
//
// Implements the GetUserSessions RPC handler introduced by the
// prod-feature-wiring spec.  GetUserProfile and UpdateUserProfile are
// implemented in server_prod_handlers.go (added by prod-unimplemented-apis).
//
// GetUserSessions returns the active Keycloak sessions for a user.
// Accessible by the user themselves or by a tenant admin.
//
// Authorization: self-access (sub match) or FGA admin relation on the tenant.
package api

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
)

// GetUserSessions returns the active Keycloak sessions for a user.
func (s *DaemonServer) GetUserSessions(ctx context.Context, req *GetUserSessionsRequest) (*GetUserSessionsResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}

	userID := req.GetUserId()
	if userID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "user_id is required")
	}

	// Authorization: the caller may access their own sessions or must be admin.
	id, hasIdentity := auth.GibsonIdentityFromContext(ctx)
	isSelf := hasIdentity && id.Subject == userID

	if !isSelf {
		if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
			return nil, err
		}
	}

	if s.keycloak == nil {
		return nil, status_grpc.Error(codes.Unavailable, "keycloak client not configured")
	}

	// tenantID doubles as the Keycloak realm name.
	keycloakSessions, err := s.keycloak.GetUserSessions(ctx, tenantID, userID)
	if err != nil {
		s.logger.ErrorContext(ctx, "GetUserSessions: keycloak query failed",
			slog.String("tenant_id", tenantID),
			slog.String("user_id", userID),
			slog.String("error", err.Error()),
		)
		return nil, status_grpc.Error(codes.Internal, "failed to retrieve sessions")
	}

	sessions := make([]*UserSession, 0, len(keycloakSessions))
	for _, ks := range keycloakSessions {
		sessions = append(sessions, &UserSession{
			Id:              ks.ID,
			IpAddress:       ks.IPAddress,
			StartedAtUnix:   ks.Start / 1000, // Keycloak returns milliseconds
			LastActiveAtUnix: ks.LastAccess / 1000,
			Client:          ks.Username, // closest available field; client name not returned
		})
	}

	return &GetUserSessionsResponse{Sessions: sessions}, nil
}
