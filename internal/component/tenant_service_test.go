package component

// tenant_service_test.go contains unit tests for RBAC enforcement in
// TenantService.  Each test builds a real auth context using the auth helpers
// (no mocking of the auth package) and a miniredis-backed TenantService, then
// asserts the expected gRPC status code for each identity type.

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestTenantService returns a TenantService backed by a fresh miniredis
// instance.  The client and server are cleaned up via t.Cleanup.
func newTestTenantService(t *testing.T) (*TenantService, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc := NewTenantService(client, logger, nil)
	return svc, mr
}

// adminCtx returns a context carrying an identity with the "admin" role,
// scoped to the given tenant.
func adminCtx(tenantID string) context.Context {
	return buildCtx(tenantID, "admin")
}

// platformOperatorCtx returns a context carrying an identity with the
// "platform-operator" role only.  No tenant scope is set because
// platform-operators operate across all tenants.
func platformOperatorCtx() context.Context {
	return buildCtx("", "platform-operator")
}

// regularUserCtx returns a context carrying an identity with the "user" role
// (a non-privileged role), scoped to the given tenant.
func regularUserCtx(tenantID string) context.Context {
	return buildCtx(tenantID, "user")
}

// noIdentityCtx returns a plain background context with no identity injected.
func noIdentityCtx() context.Context {
	return context.Background()
}

// buildCtx is the common builder for test contexts.  It creates a real
// auth.Identity with the supplied role(s), injects it via ContextWithIdentity,
// and optionally scopes to a tenant.
func buildCtx(tenantID string, roles ...string) context.Context {
	identity := &auth.Identity{
		Identity: sdkauth.Identity{
			Subject: "test-subject",
			Issuer:  "test-issuer",
			Groups:  roles,
			Claims:  map[string]any{},
		},
		Roles:       roles,
		Permissions: permissionsForRoles(roles),
	}

	ctx := auth.ContextWithIdentity(context.Background(), identity)
	if tenantID != "" {
		ctx = auth.ContextWithTenant(ctx, tenantID)
	}
	return ctx
}

// permissionsForRoles derives a minimal set of auth.Permission values from
// the supplied role names, matching the same logic used by the production
// RoleBinder so that interceptor-driven permission checks behave consistently.
func permissionsForRoles(roles []string) []auth.Permission {
	var perms []auth.Permission
	for _, role := range roles {
		if role == "admin" || role == "platform-operator" {
			perms = append(perms, auth.Permission{Action: "*", Resource: "*", Scope: "*"})
		}
	}
	return perms
}

// grpcCode extracts the gRPC status code from err.  If err is nil it returns
// codes.OK.
func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if st, ok := status.FromError(err); ok {
		return st.Code()
	}
	return codes.Unknown
}

// seedTenant writes a TenantRecord directly to miniredis so tests that focus
// on read/update/delete operations do not depend on CreateTenant's RBAC logic.
func seedTenant(t *testing.T, mr *miniredis.Miniredis, tenantID, displayName string) {
	t.Helper()

	record := TenantRecord{
		TenantID:    tenantID,
		DisplayName: displayName,
		Status:      "active",
		Config:      map[string]string{},
	}
	data, err := json.Marshal(record)
	require.NoError(t, err)

	require.NoError(t, mr.Set(tenantMetaKey(tenantID), string(data)))
	mr.SAdd(tenantIndexKey, tenantID)
}

// ---------------------------------------------------------------------------
// CreateTenant — RBAC
//
// CreateTenant is gated by the schema-driven RPCAuthzInterceptor on the
// tenants:provision permission, which permissions.yaml grants to the
// platform-operator role only.  The tenant-scoped "admin" role does NOT
// grant cross-tenant provisioning.
// ---------------------------------------------------------------------------

func TestTenantService_CreateTenant_RBAC(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		wantCode codes.Code
	}{
		{
			name:     "platform-operator succeeds",
			ctx:      platformOperatorCtx(),
			wantCode: codes.OK,
		},
		{
			name:     "admin gets PermissionDenied (tenant-scoped only)",
			ctx:      adminCtx("acme"),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "regular user gets PermissionDenied",
			ctx:      regularUserCtx("acme"),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "no identity gets Unauthenticated",
			ctx:      noIdentityCtx(),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestTenantService(t)

			_, err := svc.CreateTenant(tt.ctx, "new-tenant", "New Tenant", nil)
			assert.Equal(t, tt.wantCode, grpcCode(err), "unexpected gRPC status code")
		})
	}
}

// ---------------------------------------------------------------------------
// UpdateTenant — RBAC
//
// UpdateTenant is gated by the schema-driven RPCAuthzInterceptor on the
// tenants:update permission (granted to platform-operator only by
// permissions.yaml).
// ---------------------------------------------------------------------------

func TestTenantService_UpdateTenant_RBAC(t *testing.T) {
	const tenantID = "acme"

	tests := []struct {
		name     string
		ctx      context.Context
		wantCode codes.Code
	}{
		{
			name:     "platform-operator succeeds",
			ctx:      platformOperatorCtx(),
			wantCode: codes.OK,
		},
		{
			name:     "admin gets PermissionDenied (tenant-scoped only)",
			ctx:      adminCtx(tenantID),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "regular user gets PermissionDenied",
			ctx:      regularUserCtx(tenantID),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "no identity gets Unauthenticated",
			ctx:      noIdentityCtx(),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mr := newTestTenantService(t)
			seedTenant(t, mr, tenantID, "ACME Corp")

			_, err := svc.UpdateTenant(tt.ctx, tenantID, map[string]string{"display_name": "ACME Updated"})
			assert.Equal(t, tt.wantCode, grpcCode(err), "unexpected gRPC status code")
		})
	}
}

// ---------------------------------------------------------------------------
// DeleteTenant — RBAC
//
// DeleteTenant is gated by the schema-driven RPCAuthzInterceptor on the
// tenants:delete permission (granted to platform-operator only by
// permissions.yaml).
// ---------------------------------------------------------------------------

func TestTenantService_DeleteTenant_RBAC(t *testing.T) {
	const tenantID = "acme"

	tests := []struct {
		name     string
		ctx      context.Context
		wantCode codes.Code
	}{
		{
			name:     "platform-operator succeeds",
			ctx:      platformOperatorCtx(),
			wantCode: codes.OK,
		},
		{
			name:     "admin gets PermissionDenied (tenant-scoped only)",
			ctx:      adminCtx(tenantID),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "regular user gets PermissionDenied",
			ctx:      regularUserCtx(tenantID),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "no identity gets Unauthenticated",
			ctx:      noIdentityCtx(),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mr := newTestTenantService(t)
			// Seed a fresh copy for each sub-test so the platform-operator
			// case actually finds a record to delete.
			seedTenant(t, mr, tenantID, "ACME Corp")

			err := svc.DeleteTenant(tt.ctx, tenantID)
			assert.Equal(t, tt.wantCode, grpcCode(err), "unexpected gRPC status code")
		})
	}
}

// ---------------------------------------------------------------------------
// GetTenant — RBAC and visibility
//
// GetTenant checks identity presence then applies scoped visibility:
//   - platform-operator can fetch any tenant
//   - all other authenticated callers may only fetch their own tenant
//     (the tenant in the auth context must match the requested tenantID)
// ---------------------------------------------------------------------------

func TestTenantService_GetTenant_RBAC(t *testing.T) {
	const tenantID = "acme"

	tests := []struct {
		name     string
		ctx      context.Context
		wantCode codes.Code
	}{
		{
			name:     "member of own tenant succeeds",
			ctx:      regularUserCtx(tenantID),
			wantCode: codes.OK,
		},
		{
			name:     "admin of own tenant succeeds",
			ctx:      adminCtx(tenantID),
			wantCode: codes.OK,
		},
		{
			name:     "platform-operator can fetch any tenant",
			ctx:      platformOperatorCtx(),
			wantCode: codes.OK,
		},
		{
			name:     "user from different tenant gets PermissionDenied",
			ctx:      regularUserCtx("other-tenant"),
			wantCode: codes.PermissionDenied,
		},
		{
			name:     "no identity gets Unauthenticated",
			ctx:      noIdentityCtx(),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mr := newTestTenantService(t)
			seedTenant(t, mr, tenantID, "ACME Corp")

			_, err := svc.GetTenant(tt.ctx, tenantID)
			assert.Equal(t, tt.wantCode, grpcCode(err), "unexpected gRPC status code")
		})
	}
}

// ---------------------------------------------------------------------------
// ListTenants — RBAC and scoped visibility
//
// ListTenants applies different visibility depending on the caller role:
//   - platform-operator: sees every tenant in the Redis index
//   - all other authenticated callers (including admin): see only their own
//     tenant (read from meta key by tenant ID; the index is not consulted)
//   - no identity or no tenant context: returns an error
// ---------------------------------------------------------------------------

func TestTenantService_ListTenants_RBAC(t *testing.T) {
	const (
		tenantA = "acme"
		tenantB = "globex"
	)

	tests := []struct {
		name        string
		ctx         context.Context
		wantCode    codes.Code
		wantTenants []string // IDs expected in the returned list (only checked on codes.OK)
	}{
		{
			name:        "platform-operator sees all tenants",
			ctx:         platformOperatorCtx(),
			wantCode:    codes.OK,
			wantTenants: []string{tenantA, tenantB},
		},
		{
			name:        "regular user sees only their own tenant",
			ctx:         regularUserCtx(tenantA),
			wantCode:    codes.OK,
			wantTenants: []string{tenantA},
		},
		{
			// admin is now tenant-scoped and does NOT see other tenants.
			name:        "admin sees only their own tenant (tenant-scoped)",
			ctx:         adminCtx(tenantA),
			wantCode:    codes.OK,
			wantTenants: []string{tenantA},
		},
		{
			name:     "no identity gets Unauthenticated",
			ctx:      noIdentityCtx(),
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mr := newTestTenantService(t)
			seedTenant(t, mr, tenantA, "ACME Corp")
			seedTenant(t, mr, tenantB, "Globex")

			records, err := svc.ListTenants(tt.ctx)
			require.Equal(t, tt.wantCode, grpcCode(err), "unexpected gRPC status code")

			if tt.wantCode != codes.OK {
				return
			}

			got := make([]string, 0, len(records))
			for _, r := range records {
				got = append(got, r.TenantID)
			}

			assert.ElementsMatch(t, tt.wantTenants, got, "visible tenant list mismatch")
		})
	}
}

// TestTenantService_ListTenants_NoTenantContext verifies that an authenticated
// non-platform-operator without a tenant in their context receives
// PermissionDenied rather than an empty list.
func TestTenantService_ListTenants_NoTenantContext(t *testing.T) {
	svc, _ := newTestTenantService(t)

	// Identity with "user" role but no tenant injected.
	ctx := buildCtx("" /* no tenant */, "user")

	_, err := svc.ListTenants(ctx)
	assert.Equal(t, codes.PermissionDenied, grpcCode(err))
}

// ---------------------------------------------------------------------------
// Functional correctness — not purely RBAC, but validates that authorised
// callers actually get meaningful data back.
// ---------------------------------------------------------------------------

// TestTenantService_CreateTenant_Roundtrip verifies that a record created by
// a platform-operator can be retrieved.
func TestTenantService_CreateTenant_Roundtrip(t *testing.T) {
	svc, _ := newTestTenantService(t)
	ctx := platformOperatorCtx()

	created, err := svc.CreateTenant(ctx, "acme", "ACME Corp", map[string]string{"plan": "enterprise"})
	require.NoError(t, err)
	require.NotNil(t, created)

	assert.Equal(t, "acme", created.TenantID)
	assert.Equal(t, "ACME Corp", created.DisplayName)
	assert.Equal(t, "active", created.Status)
	assert.Equal(t, "enterprise", created.Config["plan"])
}

// TestTenantService_DeleteTenant_SoftDelete verifies that after DeleteTenant
// the record is removed from the active index but the meta key is retained with
// status "deleted" (soft delete semantics).
//
// For a non-platform-operator, ListTenants reads the tenant's own meta key
// directly (not via the index), so the soft-deleted record is still returned
// with status "deleted".  The index-based path (platform-operator) will no
// longer include the tenant.
func TestTenantService_DeleteTenant_SoftDelete(t *testing.T) {
	svc, mr := newTestTenantService(t)
	const tenantID = "acme"
	seedTenant(t, mr, tenantID, "ACME Corp")

	poCtx := platformOperatorCtx()

	// Soft-delete the tenant.
	err := svc.DeleteTenant(poCtx, tenantID)
	require.NoError(t, err)

	// A platform-operator listing all tenants should no longer see the deleted
	// tenant because it was removed from the active index SET.
	records, err := svc.ListTenants(poCtx)
	require.NoError(t, err)
	assert.Empty(t, records, "soft-deleted tenant must not appear in platform-operator list")

	// A direct GetTenant by a tenant member still finds the meta record
	// (soft-delete keeps the key for audit history).
	memberCtx := adminCtx(tenantID)
	record, err := svc.GetTenant(memberCtx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "deleted", record.Status, "soft-deleted record must have status 'deleted'")
}

// TestTenantService_UpdateTenant_PermissionDeniedDoesNotMutate confirms that a
// rejected UpdateTenant call leaves the record unchanged.
func TestTenantService_UpdateTenant_PermissionDeniedDoesNotMutate(t *testing.T) {
	svc, mr := newTestTenantService(t)
	const tenantID = "acme"
	seedTenant(t, mr, tenantID, "ACME Corp")

	// A regular user attempts to rename the tenant — this must be rejected.
	userCtx := regularUserCtx(tenantID)
	_, err := svc.UpdateTenant(userCtx, tenantID, map[string]string{"display_name": "Hacked"})
	require.Equal(t, codes.PermissionDenied, grpcCode(err))

	// Confirm the record is still intact via an authorised read.
	record, err := svc.GetTenant(adminCtx(tenantID), tenantID)
	require.NoError(t, err)
	assert.Equal(t, "ACME Corp", record.DisplayName, "display name must be unchanged after rejected update")
}
