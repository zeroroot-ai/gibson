// Package api — tenant_admin_langfuse_test.go
//
// Unit tests for the Langfuse handler cross-tenant guard (Req 1.5).
// Verifies that the inline auth.TenantStringFromContext(ctx) != req.TenantId
// guard returns codes.PermissionDenied before any side effect.
package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"

	tenantv1 "github.com/zero-day-ai/sdk/api/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// tenantContext returns a context with the given tenant ID.
func tenantContext(tenantID string) context.Context {
	return auth.ContextWithTenantString(context.Background(), tenantID)
}

// ---------------------------------------------------------------------------
// GetTenantLangfuseCredentials cross-tenant guard
// ---------------------------------------------------------------------------

func TestGetTenantLangfuseCredentials_CrossTenantDenied(t *testing.T) {
	srv := blankServer()
	ctx := tenantContext("tenant-A")
	_, err := srv.GetTenantLangfuseCredentials(ctx, &tenantv1.GetTenantLangfuseCredentialsRequest{
		TenantId: "tenant-B",
	})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err),
		"cross-tenant Get must return PermissionDenied before reaching credential handler")
}

func TestGetTenantLangfuseCredentials_SameTenant_PassesGuard(t *testing.T) {
	srv := blankServer()
	ctx := tenantContext("acme")
	_, err := srv.GetTenantLangfuseCredentials(ctx, &tenantv1.GetTenantLangfuseCredentialsRequest{
		TenantId: "acme",
	})
	// Guard passes; no credential handler → Unavailable (not PermissionDenied)
	assert.NotEqual(t, codes.PermissionDenied, grpcCode(err))
}

// ---------------------------------------------------------------------------
// SetTenantLangfuseCredentials cross-tenant guard
// ---------------------------------------------------------------------------

func TestSetTenantLangfuseCredentials_CrossTenantDenied(t *testing.T) {
	srv := blankServer()
	ctx := tenantContext("tenant-A")
	_, err := srv.SetTenantLangfuseCredentials(ctx, &tenantv1.SetTenantLangfuseCredentialsRequest{
		TenantId: "tenant-B",
	})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err),
		"cross-tenant Set must return PermissionDenied before any side effect")
}

func TestSetTenantLangfuseCredentials_SameTenant_PassesGuard(t *testing.T) {
	srv := blankServer()
	ctx := tenantContext("acme")
	_, err := srv.SetTenantLangfuseCredentials(ctx, &tenantv1.SetTenantLangfuseCredentialsRequest{
		TenantId: "acme",
	})
	assert.NotEqual(t, codes.PermissionDenied, grpcCode(err))
}

// ---------------------------------------------------------------------------
// DeleteTenantLangfuseCredentials cross-tenant guard
// ---------------------------------------------------------------------------

func TestDeleteTenantLangfuseCredentials_CrossTenantDenied(t *testing.T) {
	srv := blankServer()
	ctx := tenantContext("tenant-A")
	_, err := srv.DeleteTenantLangfuseCredentials(ctx, &tenantv1.DeleteTenantLangfuseCredentialsRequest{
		TenantId: "tenant-B",
	})
	assert.Equal(t, codes.PermissionDenied, grpcCode(err),
		"cross-tenant Delete must return PermissionDenied before any side effect")
}

func TestDeleteTenantLangfuseCredentials_SameTenant_PassesGuard(t *testing.T) {
	srv := blankServer()
	ctx := tenantContext("acme")
	_, err := srv.DeleteTenantLangfuseCredentials(ctx, &tenantv1.DeleteTenantLangfuseCredentialsRequest{
		TenantId: "acme",
	})
	assert.NotEqual(t, codes.PermissionDenied, grpcCode(err))
}

// ---------------------------------------------------------------------------
// Tenant mismatch — empty tenant_id
// ---------------------------------------------------------------------------

func TestGetTenantLangfuseCredentials_EmptyTenantId_InvalidArgument(t *testing.T) {
	srv := blankServer()
	_, err := srv.GetTenantLangfuseCredentials(context.Background(), &tenantv1.GetTenantLangfuseCredentialsRequest{
		TenantId: "",
	})
	assert.Equal(t, codes.InvalidArgument, grpcCode(err))
}
