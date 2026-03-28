package auth

import (
	"context"
	"testing"
	"time"

	sdkauth "github.com/zero-day-ai/sdk/auth"
)

func TestTenantContextRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		tenant string
	}{
		{
			name:   "simple tenant",
			tenant: "acme",
		},
		{
			name:   "tenant with hyphen",
			tenant: "acme-corp",
		},
		{
			name:   "tenant with underscore",
			tenant: "widgets_inc",
		},
		{
			name:   "empty tenant",
			tenant: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = ContextWithTenant(ctx, tt.tenant)
			got := TenantFromContext(ctx)

			if got != tt.tenant {
				t.Errorf("TenantFromContext() = %q, want %q", got, tt.tenant)
			}
		})
	}
}

func TestTenantFromContext_Missing(t *testing.T) {
	ctx := context.Background()
	got := TenantFromContext(ctx)

	if got != "" {
		t.Errorf("TenantFromContext() with no tenant = %q, want empty string", got)
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
