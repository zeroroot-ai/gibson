package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
)

// ---------------------------------------------------------------------------
// GetUserSessions tests
//
// GetUserSessions returns codes.Unimplemented unconditionally — session
// management moved to the dashboard layer (Better Auth). The RPC is retained
// in the proto for protocol compatibility only.
// ---------------------------------------------------------------------------

func TestGetUserSessions_Unimplemented(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetUserSessions(context.Background(), &GetUserSessionsRequest{
		TenantId: "acme",
		UserId:   "user-1",
	})
	assert.Equal(t, codes.Unimplemented, grpcCode(err))
}

// GetUserProfile and UpdateUserProfile tests are covered in server_prod_handlers_test.go.
