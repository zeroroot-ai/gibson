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

	tenantv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/tenant/v1"
	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	"github.com/zeroroot-ai/sdk/auth"
)

// TestGetTenantLangfuseCredentials_ErrorMapping pins the fix from gibson#596:
// a genuine missing secret maps to NotFound, but any other secrets-backend
// failure (e.g. a Vault PermissionDenied) maps to FailedPrecondition — it must
// NOT be masked as "not configured", which hid the real cause of the Traces
// outage (gibson#594). Regression guard for gibson#597.
func TestGetTenantLangfuseCredentials_ErrorMapping(t *testing.T) {
	cases := []struct {
		name      string
		brokerErr error
		wantCode  codes.Code
	}{
		{"secret absent → NotFound", sdksecrets.ErrNotFound, codes.NotFound},
		{"backend denied → FailedPrecondition (not masked as NotFound)", sdksecrets.ErrPermissionDenied, codes.FailedPrecondition},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := buildAPITestService(t, &apiTestBroker{getErr: tc.brokerErr})
			h, err := NewCredentialHandler(svc)
			if err != nil {
				t.Fatalf("NewCredentialHandler: %v", err)
			}
			srv := blankServer()
			srv.credentialHandler = h
			_, err = srv.GetTenantLangfuseCredentials(
				tenantContext("acme"),
				&tenantv1.GetTenantLangfuseCredentialsRequest{TenantId: "acme"},
			)
			assert.Equal(t, tc.wantCode, grpcCode(err),
				"broker err %v must map to %v", tc.brokerErr, tc.wantCode)
		})
	}
}

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

// TestLangfuseCredentialName_MatchesInfraWritePath pins the Langfuse credential
// name to the per-tenant Vault path the tenant-operator writes
// (pdataplane.VaultPathInfraLangfuse = "infra/langfuse") and that the per-tenant
// OpenBao policy grants read on (secret/data/infra/*). Regression guard for the
// legacy "langfuse_project:<id>" name, which resolved to a path the policy
// denied (403) — silently surfaced to the dashboard as "credentials not
// configured". The tenant is scoped by the per-tenant Vault namespace, so the
// name must NOT embed a tenant id.
func TestLangfuseCredentialName_MatchesInfraWritePath(t *testing.T) {
	const want = "infra/langfuse"
	if pdataplane.VaultPathInfraLangfuse != want {
		t.Fatalf("VaultPathInfraLangfuse = %q, want %q", pdataplane.VaultPathInfraLangfuse, want)
	}
	for _, tenant := range []string{"testoc", "acme", ""} {
		if got := langfuseCredentialName(tenant); got != want {
			t.Errorf("langfuseCredentialName(%q) = %q, want %q (must not embed tenant id)", tenant, got, want)
		}
	}
}
