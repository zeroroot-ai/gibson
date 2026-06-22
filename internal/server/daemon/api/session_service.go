// Package api — session_service.go implements gibson.session.v1.SessionService:
// the self-service, dashboard-facing view of a user's own login sessions
// (PRD dashboard#738).
//
// STRICTLY self: both RPCs act on the authenticated caller's own sessions only.
// There is no user-id parameter and no admin path — seeing or revoking another
// user's sessions is not expressible here. The blunt "log me out everywhere"
// operation lives on gibson.tenant.v1.UserService.RevokeUserSessions (the
// `gibson logout` path); this service is the per-session complement.
//
// RevokeMySession enforces self-ownership in-handler: it lists the caller's own
// sessions and confirms the requested id is among them before deleting it, so a
// caller can never terminate a session that is not theirs (NOT_FOUND otherwise).
package api

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	sessionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/session/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ListMySessions returns the authenticated caller's own active login sessions.
func (s *DaemonServer) ListMySessions(ctx context.Context, _ *sessionv1.ListMySessionsRequest) (*sessionv1.ListMySessionsResponse, error) {
	caller, err := auth.IdentityFromContext(ctx)
	if err != nil || caller.Subject == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable, "identity provider not configured")
	}

	sessions, err := s.idpAdminClient.ListUserSessions(ctx, caller.Subject)
	if err != nil {
		s.logger.ErrorContext(ctx, "ListMySessions: idp error", "error", err.Error())
		return nil, status_grpc.Error(codes.Internal, "failed to list sessions")
	}

	out := make([]*sessionv1.UserSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, &sessionv1.UserSession{
			Id:           sess.ID,
			Ip:           sess.IP,
			Browser:      sess.Browser,
			CreatedAt:    timeOrNil(sess.CreatedAt),
			LastActiveAt: timeOrNil(sess.LastActiveAt),
		})
	}
	return &sessionv1.ListMySessionsResponse{Sessions: out}, nil
}

// RevokeMySession terminates one of the caller's own sessions by id. The
// session must belong to the caller; an unknown or non-owned id is NOT_FOUND.
func (s *DaemonServer) RevokeMySession(ctx context.Context, req *sessionv1.RevokeMySessionRequest) (*sessionv1.RevokeMySessionResponse, error) {
	caller, err := auth.IdentityFromContext(ctx)
	if err != nil || caller.Subject == "" {
		return nil, status_grpc.Error(codes.Unauthenticated, "not authenticated")
	}
	if req.GetSessionId() == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "session_id is required")
	}
	if s.idpAdminClient == nil {
		return nil, status_grpc.Error(codes.Unavailable, "identity provider not configured")
	}

	// Self-ownership: the caller may only revoke a session that is their own.
	// We enumerate the caller's sessions and confirm the id belongs to them
	// before deleting — the IdP delete is by session id alone, so the
	// ownership gate must live here.
	sessions, err := s.idpAdminClient.ListUserSessions(ctx, caller.Subject)
	if err != nil {
		s.logger.ErrorContext(ctx, "RevokeMySession: list error", "error", err.Error())
		return nil, status_grpc.Error(codes.Internal, "failed to verify session ownership")
	}
	owned := false
	for _, sess := range sessions {
		if sess.ID == req.GetSessionId() {
			owned = true
			break
		}
	}
	if !owned {
		return nil, status_grpc.Error(codes.NotFound, "session not found")
	}

	// RevokeSession already treats an already-gone session as success, so any
	// error here is a genuine failure.
	if err := s.idpAdminClient.RevokeSession(ctx, req.GetSessionId()); err != nil {
		s.logger.ErrorContext(ctx, "RevokeMySession: revoke error", "error", err.Error())
		return nil, status_grpc.Error(codes.Internal, "failed to revoke session")
	}
	return &sessionv1.RevokeMySessionResponse{}, nil
}

// timeOrNil maps a zero time.Time to a nil timestamp so unset IdP fields stay
// unset on the wire rather than serialising as the Unix epoch.
func timeOrNil(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
