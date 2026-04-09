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
// The handler uses s.keycloak *keycloak.Client (concrete type), so only the
// validation and nil-dependency branches can be tested without a real server.
// ---------------------------------------------------------------------------

func TestGetUserSessions_EmptyTenantIDUsesContext_NilKeycloak_Unavailable(t *testing.T) {
	// Empty TenantId falls back to auth.TenantFromContext (returns SystemTenant).
	// With nil keycloak → Unavailable (not InvalidArgument).
	srv := blankServer()
	_, err := srv.GetUserSessions(context.Background(), &GetUserSessionsRequest{
		TenantId: "",
		UserId:   "user-1",
	})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

func TestGetUserSessions_MissingUserID_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetUserSessions(context.Background(), &GetUserSessionsRequest{
		TenantId: "acme",
		UserId:   "",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}

func TestGetUserSessions_NilKeycloak_Unavailable(t *testing.T) {
	srv := blankServer()
	// keycloak is nil → handler must return Unavailable
	_, err := srv.GetUserSessions(context.Background(), &GetUserSessionsRequest{
		TenantId: "acme",
		UserId:   "user-1",
	})
	assert.Equal(t, codes.Unavailable, grpcCode(err))
}

// GetUserProfile and UpdateUserProfile tests are covered in server_prod_handlers_test.go.
