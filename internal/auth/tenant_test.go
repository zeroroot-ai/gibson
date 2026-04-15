package auth

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	sdkauth "github.com/zero-day-ai/sdk/auth"
	"google.golang.org/grpc/metadata"
)

func TestTenantContextRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
		want   string
	}{
		{
			name:   "simple tenant",
			tenant: "acme",
			want:   "acme",
		},
		{
			name:   "tenant with hyphen",
			tenant: "acme-corp",
			want:   "acme-corp",
		},
		{
			name:   "tenant with underscore",
			tenant: "widgets_inc",
			want:   "widgets_inc",
		},
		{
			// Storing an empty tenant string is treated as "not set" and
			// falls through to SystemTenant (no identity in context).
			// Production code never sets an empty tenant explicitly.
			name:   "empty tenant",
			tenant: "",
			want:   SystemTenant,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = ContextWithTenant(ctx, tt.tenant)
			got := TenantFromContext(ctx)

			if got != tt.want {
				t.Errorf("TenantFromContext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTenantFromContext_Missing(t *testing.T) {
	// No tenant in context, no identity → falls through to SystemTenant.
	ctx := context.Background()
	got := TenantFromContext(ctx)

	if got != SystemTenant {
		t.Errorf("TenantFromContext() with no tenant = %q, want SystemTenant", got)
	}
}

func TestTenantFromContext_Nil(t *testing.T) {
	got := TenantFromContext(nil)

	if got != "" {
		t.Errorf("TenantFromContext(nil) = %q, want empty string", got)
	}
}

func TestExtractTenantFromIdentity_SimpleClaim(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"tenant_id": "acme-corp",
				"sub":       "user123",
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	got := ExtractTenantFromIdentity(identity, "tenant_id")
	want := "acme-corp"

	if got != want {
		t.Errorf("ExtractTenantFromIdentity() = %q, want %q", got, want)
	}
}

func TestExtractTenantFromIdentity_NestedClaim(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"org": map[string]any{
					"id":   "widgets-inc",
					"name": "Widgets Inc",
				},
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	got := ExtractTenantFromIdentity(identity, "org.id")
	want := "widgets-inc"

	if got != want {
		t.Errorf("ExtractTenantFromIdentity() = %q, want %q", got, want)
	}
}

func TestExtractTenantFromIdentity_DeeplyNestedClaim(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"organization": map[string]any{
					"tenant": map[string]any{
						"id":   "deep-tenant",
						"name": "Deep Tenant Co",
					},
				},
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	got := ExtractTenantFromIdentity(identity, "organization.tenant.id")
	want := "deep-tenant"

	if got != want {
		t.Errorf("ExtractTenantFromIdentity() = %q, want %q", got, want)
	}
}

func TestExtractTenantFromIdentity_MissingClaim(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"sub": "user123",
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	got := ExtractTenantFromIdentity(identity, "tenant_id")

	if got != "" {
		t.Errorf("ExtractTenantFromIdentity() with missing claim = %q, want empty string", got)
	}
}

func TestExtractTenantFromIdentity_MissingNestedPath(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"org": map[string]any{
					"name": "Widgets Inc",
				},
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	// org.id doesn't exist
	got := ExtractTenantFromIdentity(identity, "org.id")

	if got != "" {
		t.Errorf("ExtractTenantFromIdentity() with missing nested path = %q, want empty string", got)
	}
}

func TestExtractTenantFromIdentity_InvalidNestedType(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"org": "not-a-map",
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	// org is a string, not a map
	got := ExtractTenantFromIdentity(identity, "org.id")

	if got != "" {
		t.Errorf("ExtractTenantFromIdentity() with invalid nested type = %q, want empty string", got)
	}
}

func TestExtractTenantFromIdentity_NonStringValue(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject: "user123",
			Claims: map[string]any{
				"tenant_id": 12345, // number instead of string
			},
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	got := ExtractTenantFromIdentity(identity, "tenant_id")

	if got != "" {
		t.Errorf("ExtractTenantFromIdentity() with non-string value = %q, want empty string", got)
	}
}

func TestExtractTenantFromIdentity_NilIdentity(t *testing.T) {
	got := ExtractTenantFromIdentity(nil, "tenant_id")

	if got != "" {
		t.Errorf("ExtractTenantFromIdentity(nil) = %q, want empty string", got)
	}
}

func TestExtractTenantFromIdentity_NilClaims(t *testing.T) {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:         "user123",
			Claims:          nil,
			ExpiresAt:       time.Now().Add(time.Hour),
			AuthenticatedAt: time.Now(),
		},
	}

	got := ExtractTenantFromIdentity(identity, "tenant_id")

	if got != "" {
		t.Errorf("ExtractTenantFromIdentity() with nil claims = %q, want empty string", got)
	}
}

func TestTenantScopedRedisKey(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
		key    string
		want   string
	}{
		{
			name:   "mission key",
			tenant: "acme",
			key:    "mission:123",
			want:   "tenant:acme:mission:123",
		},
		{
			name:   "finding key",
			tenant: "widgets-inc",
			key:    "finding:abc-def",
			want:   "tenant:widgets-inc:finding:abc-def",
		},
		{
			name:   "simple key",
			tenant: "test-org",
			key:    "data",
			want:   "tenant:test-org:data",
		},
		{
			name:   "nested key with colons",
			tenant: "company",
			key:    "cache:user:profile:123",
			want:   "tenant:company:cache:user:profile:123",
		},
		{
			name:   "empty tenant",
			tenant: "",
			key:    "mission:123",
			want:   "tenant::mission:123",
		},
		{
			name:   "empty key",
			tenant: "acme",
			key:    "",
			want:   "tenant:acme:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TenantScopedRedisKey(tt.tenant, tt.key)

			if got != tt.want {
				t.Errorf("TenantScopedRedisKey(%q, %q) = %q, want %q", tt.tenant, tt.key, got, tt.want)
			}
		})
	}
}

func TestTenantNeo4jFilter(t *testing.T) {
	tests := []struct {
		name      string
		paramName string
		want      string
	}{
		{
			name:      "standard param name",
			paramName: "tenant",
			want:      "n.tenant_id = $tenant",
		},
		{
			name:      "custom param name",
			paramName: "tenantId",
			want:      "n.tenant_id = $tenantId",
		},
		{
			name:      "underscore param name",
			paramName: "tenant_id",
			want:      "n.tenant_id = $tenant_id",
		},
		{
			name:      "camelCase param name",
			paramName: "currentTenant",
			want:      "n.tenant_id = $currentTenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TenantNeo4jFilter(tt.paramName)

			if got != tt.want {
				t.Errorf("TenantNeo4jFilter(%q) = %q, want %q", tt.paramName, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TenantFromContext resolution tests
//
// These tests cover all seven decision branches:
//
//  1. ctx already has an explicit tenant set → use it
//  2. Valid X-Gibson-Tenant header + user is a member → use the header value
//  3. Invalid X-Gibson-Tenant header (user is not a member) → PermissionDenied
//     via TenantFromContextWithCheck; TenantFromContext falls back to SystemTenant
//  4. Single-tenant user, no header → use their only tenant
//  5. Multi-tenant user, no header → alphabetically first (WARN log)
//  6. Cross-tenant role with empty tenants → SystemTenant
//  7. Empty identity with no tenants → SystemTenant
// ---------------------------------------------------------------------------

// contextWithIdentityAndTenants is a test helper that builds a context with a
// Gibson Identity carrying the given tenants list.
func contextWithIdentityAndTenants(ctx context.Context, tenants []string) context.Context {
	identity := &Identity{
		Identity: sdkauth.Identity{
			Subject:         "test-user",
			Email:           "test@example.com",
			AuthenticatedAt: time.Now(),
			ExpiresAt:       time.Now().Add(time.Hour),
		},
		Tenants: tenants,
	}
	return ContextWithIdentity(ctx, identity)
}

// contextWithXGibsonTenantHeader attaches the X-Gibson-Tenant gRPC metadata
// header to the context.
func contextWithXGibsonTenantHeader(ctx context.Context, tenant string) context.Context {
	md := metadata.New(map[string]string{GibsonTenantHeader: tenant})
	return metadata.NewIncomingContext(ctx, md)
}

func TestTenantFromContext_ExplicitTenantInContext(t *testing.T) {
	// Branch 1: an explicit tenant already in context takes priority over everything.
	base := context.Background()
	base = contextWithIdentityAndTenants(base, []string{"tenant-b", "tenant-a"})
	base = contextWithXGibsonTenantHeader(base, "tenant-b") // header would select b
	ctx := ContextWithTenant(base, "explicit-tenant")       // explicit beats all

	got := TenantFromContext(ctx)
	if got != "explicit-tenant" {
		t.Errorf("expected explicit-tenant, got %q", got)
	}
}

func TestTenantFromContext_ValidXGibsonTenantHeader(t *testing.T) {
	// Branch 2: X-Gibson-Tenant header present and user is a member → use it.
	ctx := context.Background()
	ctx = contextWithIdentityAndTenants(ctx, []string{"tenant-a", "tenant-b"})
	ctx = contextWithXGibsonTenantHeader(ctx, "tenant-b")

	got := TenantFromContext(ctx)
	if got != "tenant-b" {
		t.Errorf("expected tenant-b, got %q", got)
	}
}

func TestTenantFromContextWithCheck_InvalidXGibsonTenantHeader_PermissionDenied(t *testing.T) {
	// Branch 3: X-Gibson-Tenant header requests a tenant the user does NOT belong to.
	// TenantFromContextWithCheck must return an error; TenantFromContext silently
	// falls back to SystemTenant.
	ctx := context.Background()
	ctx = contextWithIdentityAndTenants(ctx, []string{"tenant-a"})
	ctx = contextWithXGibsonTenantHeader(ctx, "tenant-evil") // not in user's list

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	tenant, err := TenantFromContextWithCheck(ctx, logger)
	if err == nil {
		t.Error("expected error for unauthorized tenant header, got nil")
	}
	if tenant != SystemTenant {
		t.Errorf("expected SystemTenant on denied header, got %q", tenant)
	}
	if !strings.Contains(logBuf.String(), "tenant_access_denied") {
		t.Errorf("expected WARN log about tenant_access_denied, got: %s", logBuf.String())
	}
}

func TestTenantFromContext_SingleTenantUser_NoHeader(t *testing.T) {
	// Branch 4: exactly one tenant, no X-Gibson-Tenant header → use the only tenant.
	ctx := context.Background()
	ctx = contextWithIdentityAndTenants(ctx, []string{"only-tenant"})

	got := TenantFromContext(ctx)
	if got != "only-tenant" {
		t.Errorf("expected only-tenant, got %q", got)
	}
}

func TestTenantFromContext_MultiTenantUser_NoHeader_AlphabeticallyFirst(t *testing.T) {
	// Branch 5: multiple tenants, no header → alphabetically first, with WARN log.
	ctx := context.Background()
	ctx = contextWithIdentityAndTenants(ctx, []string{"zebra-corp", "acme-corp", "mid-tenant"})

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	tenant, err := TenantFromContextWithCheck(ctx, logger)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	// "acme-corp" is alphabetically first.
	if tenant != "acme-corp" {
		t.Errorf("expected acme-corp (alphabetically first), got %q", tenant)
	}
	if !strings.Contains(logBuf.String(), "tenant_ambiguous") {
		t.Errorf("expected WARN log about tenant_ambiguous, got: %s", logBuf.String())
	}
}

func TestTenantFromContext_CrossTenantRole_EmptyTenants_SystemTenant(t *testing.T) {
	// Branch 6: identity present with nil Tenants slice → SystemTenant.
	// Platform operators / cross-tenant role holders have no Tenants list; they
	// reach SystemTenant via the empty-Tenants fallback at the bottom of the
	// resolution chain.
	ctx := context.Background()
	ctx = contextWithIdentityAndTenants(ctx, nil) // nil tenants → SystemTenant

	got := TenantFromContext(ctx)
	if got != SystemTenant {
		t.Errorf("expected SystemTenant for cross-tenant role with empty tenants, got %q", got)
	}
}

func TestTenantFromContext_EmptyIdentity_SystemTenant(t *testing.T) {
	// Branch 7: identity present but Tenants is nil/empty and not cross-tenant.
	ctx := context.Background()
	ctx = contextWithIdentityAndTenants(ctx, nil)

	got := TenantFromContext(ctx)
	if got != SystemTenant {
		t.Errorf("expected SystemTenant for empty-tenants non-cross-tenant user, got %q", got)
	}
}
