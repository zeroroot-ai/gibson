// Package api — server_user.go
//
// GetUserSessions returns Unimplemented; session management lives in the
// dashboard layer (Better Auth).
package api

import (
	"context"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"
)

// GetUserSessions returns an Unimplemented error. Session management has
// moved to the dashboard layer (Better Auth). This RPC is kept in the proto
// for protocol compatibility but the daemon no longer serves it.
func (s *DaemonServer) GetUserSessions(_ context.Context, _ *GetUserSessionsRequest) (*GetUserSessionsResponse, error) {
	return nil, status_grpc.Error(codes.Unimplemented, "session management has moved to the dashboard layer (Better Auth)")
}
