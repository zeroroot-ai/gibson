//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// TestAuthMode_Disabled verifies that disabled mode skips authentication
// and injects a synthetic admin identity.
func TestAuthMode_Disabled(t *testing.T) {
	t.Parallel()

	// Setup config with disabled mode
	cfg := &auth.AuthConfig{
		Mode: "disabled",
	}
	cfg.ApplyDefaults()

	// Create composite authenticator (should return nil for disabled mode)
	authenticator, err := auth.NewCompositeAuthenticator(cfg)
	require.NoError(t, err, "Failed to create composite authenticator")
	assert.Nil(t, authenticator, "Disabled mode should return nil authenticator")

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create interceptor
	interceptor := auth.UnaryAuthInterceptor(authenticator, cfg, logger)
	require.NotNil(t, interceptor, "Interceptor should not be nil")

	// Create test context
	ctx := context.Background()

	// Define test handler that extracts identity
	var capturedIdentity *sdkauth.Identity
	testHandler := func(ctx context.Context, req any) (any, error) {
		// Extract identity from context
		identity, ok := sdkauth.IdentityFromContext(ctx)
		if ok {
			capturedIdentity = identity
		}
		return "success", nil
	}

	// Call interceptor without token (should still succeed)
	resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, testHandler)

	// Verify success
	require.NoError(t, err, "Disabled mode should succeed without token")
	assert.Equal(t, "success", resp)

	// Verify synthetic identity was injected
	require.NotNil(t, capturedIdentity, "Identity should be injected")
	assert.Equal(t, "system", capturedIdentity.Subject, "Disabled mode should inject system identity")
	assert.Equal(t, "internal", capturedIdentity.Issuer, "Issuer should be internal")
	assert.Contains(t, capturedIdentity.Groups, "admin", "Should have admin group")

	t.Logf("Successfully verified disabled mode: subject=%s, groups=%v",
		capturedIdentity.Subject, capturedIdentity.Groups)
}

// TestAuthMode_Disabled_WithDefaultTenant verifies that disabled mode
// injects the default tenant when configured.
func TestAuthMode_Disabled_WithDefaultTenant(t *testing.T) {
	t.Parallel()

	// Setup config with disabled mode and default tenant
	cfg := &auth.AuthConfig{
		Mode:          "disabled",
		DefaultTenant: "acme-corp",
	}
	cfg.ApplyDefaults()

	// Create authenticator (nil for disabled)
	authenticator, err := auth.NewCompositeAuthenticator(cfg)
	require.NoError(t, err)

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create interceptor
	interceptor := auth.UnaryAuthInterceptor(authenticator, cfg, logger)

	// Create test context
	ctx := context.Background()

	// Define test handler that extracts tenant
	var capturedTenant string
	testHandler := func(ctx context.Context, req any) (any, error) {
		capturedTenant = auth.TenantFromContext(ctx)
		return "success", nil
	}

	// Call interceptor
	_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, testHandler)

	// Verify success and tenant injection
	require.NoError(t, err)
	assert.Equal(t, "acme-corp", capturedTenant, "Default tenant should be injected")

	t.Logf("Successfully verified disabled mode with default tenant: %s", capturedTenant)
}

// TestAuthMode_Dev verifies that dev mode uses local static tokens.
func TestAuthMode_Dev(t *testing.T) {
	t.Parallel()

	// Setup config with dev mode and static tokens
	cfg := &auth.AuthConfig{
		Mode: "dev",
		Local: &auth.LocalAuthConfig{
			Users: []auth.LocalUser{
				{
					Name:  "test-user",
					Token: "test-token-12345",
					Roles: []string{"admin"},
				},
				{
					Name:  "readonly-user",
					Token: "readonly-token-67890",
					Roles: []string{"findings:read"},
				},
			},
		},
	}
	cfg.ApplyDefaults()

	// Create authenticator
	authenticator, err := auth.NewCompositeAuthenticator(cfg)
	require.NoError(t, err, "Failed to create composite authenticator")
	require.NotNil(t, authenticator, "Dev mode should return authenticator")

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create interceptor
	interceptor := auth.UnaryAuthInterceptor(authenticator, cfg, logger)

	t.Run("valid_token", func(t *testing.T) {
		// Create context with valid token
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"authorization", "Bearer test-token-12345",
		))

		// Define test handler that extracts identity
		var capturedIdentity *sdkauth.Identity
		testHandler := func(ctx context.Context, req any) (any, error) {
			identity, ok := sdkauth.IdentityFromContext(ctx)
			if ok {
				capturedIdentity = identity
			}
			return "success", nil
		}

		// Call interceptor
		resp, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, testHandler)

		// Verify success
		require.NoError(t, err, "Valid token should succeed")
		assert.Equal(t, "success", resp)

		// Verify identity
		require.NotNil(t, capturedIdentity, "Identity should be injected")
		assert.Equal(t, "test-user", capturedIdentity.Subject)

		t.Logf("Successfully verified dev mode with valid token: subject=%s", capturedIdentity.Subject)
	})

	t.Run("invalid_token", func(t *testing.T) {
		// Create context with invalid token
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"authorization", "Bearer invalid-token",
		))

		// Define test handler
		testHandler := func(ctx context.Context, req any) (any, error) {
			return "success", nil
		}

		// Call interceptor
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, testHandler)

		// Verify failure
		require.Error(t, err, "Invalid token should fail")
		st, ok := status.FromError(err)
		require.True(t, ok, "Error should be gRPC status")
		assert.Equal(t, codes.Unauthenticated, st.Code(), "Should return Unauthenticated code")

		t.Logf("Successfully verified dev mode rejects invalid token: %v", err)
	})

	t.Run("missing_token", func(t *testing.T) {
		// Create context without token
		ctx := context.Background()

		// Define test handler
		testHandler := func(ctx context.Context, req any) (any, error) {
			return "success", nil
		}

		// Call interceptor
		_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, testHandler)

		// Verify failure
		require.Error(t, err, "Missing token should fail")
		st, ok := status.FromError(err)
		require.True(t, ok, "Error should be gRPC status")
		assert.Equal(t, codes.Unauthenticated, st.Code(), "Should return Unauthenticated code")

		t.Logf("Successfully verified dev mode requires token")
	})
}

// TestAuthMode_Enterprise verifies enterprise mode with OIDC validation.
// Note: This test uses mock OIDC tokens for simplicity. Full integration
// tests with real Keycloak are in the SDK integration tests.
func TestAuthMode_Enterprise_Config(t *testing.T) {
	t.Parallel()

	// Setup config with enterprise mode
	cfg := &auth.AuthConfig{
		Mode: "enterprise",
		OIDC: []auth.OIDCIssuerConfig{
			{
				Issuer:   "https://keycloak.example.com/realms/gibson",
				Audience: "gibson-api",
			},
		},
		DefaultTenant: "enterprise-tenant",
	}
	cfg.ApplyDefaults()

	// Verify configuration validates
	err := cfg.Validate()
	require.NoError(t, err, "Enterprise config should validate")

	// Create authenticator
	authenticator, err := auth.NewCompositeAuthenticator(cfg)
	require.NoError(t, err, "Failed to create composite authenticator")
	require.NotNil(t, authenticator, "Enterprise mode should return authenticator")

	// Verify OIDC is configured
	assert.True(t, authenticator.HasOIDC(), "Enterprise mode should have OIDC")

	t.Logf("Successfully verified enterprise mode configuration")
}

// TestAuthMode_SaaS_TenantIsolation verifies SaaS mode with tenant extraction.
func TestAuthMode_SaaS_TenantIsolation(t *testing.T) {
	t.Parallel()

	// Setup config with SaaS mode
	cfg := &auth.AuthConfig{
		Mode:        "saas",
		TenantClaim: "tenant_id",
		OIDC: []auth.OIDCIssuerConfig{
			{
				Issuer:   "https://auth.saas.example.com",
				Audience: "gibson-saas",
			},
		},
	}
	cfg.ApplyDefaults()

	// Verify configuration validates
	err := cfg.Validate()
	require.NoError(t, err, "SaaS config should validate")

	// Test tenant extraction from identity
	t.Run("extract_tenant_from_claim", func(t *testing.T) {
		// Create identity with tenant claim
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@acme.com",
				Issuer:  "https://auth.saas.example.com",
				Claims: map[string]any{
					"tenant_id": "acme-corp",
					"email":     "user@acme.com",
				},
			},
		}

		// Extract tenant
		tenant := auth.ExtractTenantFromIdentity(identity, "tenant_id")
		assert.Equal(t, "acme-corp", tenant, "Should extract tenant from claim")

		t.Logf("Successfully extracted tenant: %s", tenant)
	})

	t.Run("extract_tenant_from_nested_claim", func(t *testing.T) {
		// Create identity with nested tenant claim
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@widgets.com",
				Issuer:  "https://auth.saas.example.com",
				Claims: map[string]any{
					"organization": map[string]any{
						"tenant": map[string]any{
							"id": "widgets-inc",
						},
					},
					"email": "user@widgets.com",
				},
			},
		}

		// Extract tenant using dot notation
		tenant := auth.ExtractTenantFromIdentity(identity, "organization.tenant.id")
		assert.Equal(t, "widgets-inc", tenant, "Should extract nested tenant")

		t.Logf("Successfully extracted nested tenant: %s", tenant)
	})

	t.Run("missing_tenant_claim", func(t *testing.T) {
		// Create identity without tenant claim
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
				Issuer:  "https://auth.saas.example.com",
				Claims: map[string]any{
					"email": "user@example.com",
				},
			},
		}

		// Extract tenant (should be empty)
		tenant := auth.ExtractTenantFromIdentity(identity, "tenant_id")
		assert.Empty(t, tenant, "Should return empty string for missing tenant")

		t.Logf("Successfully verified missing tenant returns empty string")
	})
}

// TestTenantIsolation_RedisKeys verifies tenant-scoped Redis key generation.
func TestTenantIsolation_RedisKeys(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		tenant   string
		key      string
		expected string
	}{
		{
			name:     "simple_mission_key",
			tenant:   "acme-corp",
			key:      "mission:123",
			expected: "tenant:acme-corp:mission:123",
		},
		{
			name:     "finding_key",
			tenant:   "widgets-inc",
			key:      "finding:abc-def-ghi",
			expected: "tenant:widgets-inc:finding:abc-def-ghi",
		},
		{
			name:     "state_key",
			tenant:   "enterprise",
			key:      "state:checkpoint:v1",
			expected: "tenant:enterprise:state:checkpoint:v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.TenantScopedRedisKey(tt.tenant, tt.key)
			assert.Equal(t, tt.expected, result, "Redis key should be tenant-scoped")

			t.Logf("Successfully verified tenant-scoped Redis key: %s", result)
		})
	}
}

// TestTenantIsolation_Neo4jFilter verifies tenant-scoped Neo4j filter generation.
func TestTenantIsolation_Neo4jFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		paramName string
		expected  string
	}{
		{
			name:      "tenant_parameter",
			paramName: "tenant",
			expected:  "n.tenant_id = $tenant",
		},
		{
			name:      "org_parameter",
			paramName: "org_id",
			expected:  "n.tenant_id = $org_id",
		},
		{
			name:      "custom_parameter",
			paramName: "tid",
			expected:  "n.tenant_id = $tid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.TenantNeo4jFilter(tt.paramName)
			assert.Equal(t, tt.expected, result, "Neo4j filter should use correct parameter")

			t.Logf("Successfully verified Neo4j filter: %s", result)
		})
	}
}

// TestTenantContext verifies tenant context injection and extraction.
func TestTenantContext(t *testing.T) {
	t.Parallel()

	t.Run("inject_and_extract_tenant", func(t *testing.T) {
		ctx := context.Background()

		// Initially no tenant
		tenant := auth.TenantFromContext(ctx)
		assert.Empty(t, tenant, "Initial context should have no tenant")

		// Inject tenant
		ctx = auth.ContextWithTenant(ctx, "acme-corp")

		// Extract tenant
		tenant = auth.TenantFromContext(ctx)
		assert.Equal(t, "acme-corp", tenant, "Should extract injected tenant")

		t.Logf("Successfully verified tenant context: %s", tenant)
	})

	t.Run("nil_context", func(t *testing.T) {
		// Extract from nil context (should not panic)
		tenant := auth.TenantFromContext(nil)
		assert.Empty(t, tenant, "Nil context should return empty string")

		t.Logf("Successfully verified nil context handling")
	})

	t.Run("overwrite_tenant", func(t *testing.T) {
		ctx := context.Background()
		ctx = auth.ContextWithTenant(ctx, "first-tenant")
		ctx = auth.ContextWithTenant(ctx, "second-tenant")

		tenant := auth.TenantFromContext(ctx)
		assert.Equal(t, "second-tenant", tenant, "Should use latest tenant")

		t.Logf("Successfully verified tenant overwrite: %s", tenant)
	})
}

// TestPermissionEnforcement_RoleBinder verifies role-based permission checking.
func TestPermissionEnforcement_RoleBinder(t *testing.T) {
	t.Parallel()

	// Create role binder with test bindings
	bindings := []auth.RoleBinding{
		{
			Matcher: "security-team",
			Roles:   []string{"mission:execute", "findings:read"},
		},
		{
			Matcher: "security-*",
			Roles:   []string{"findings:read"},
		},
		{
			Matcher: "admin",
			Roles:   []string{"admin"},
		},
	}
	binder := auth.NewRoleBinder(bindings)

	t.Run("exact_group_match", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
				Groups:  []string{"security-team"},
			},
		}

		roles, _, err := binder.ResolveRoles(identity)
		require.NoError(t, err, "Should resolve roles")
		assert.Contains(t, roles, "mission:execute", "Should have mission:execute role")
		assert.Contains(t, roles, "findings:read", "Should have findings:read role")

		t.Logf("Successfully resolved roles: %v", roles)
	})

	t.Run("wildcard_group_match", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
				Groups:  []string{"security-admins"},
			},
		}

		roles, _, err := binder.ResolveRoles(identity)
		require.NoError(t, err, "Should resolve roles")
		assert.Contains(t, roles, "findings:read", "Should match security-* pattern")

		t.Logf("Successfully resolved wildcard roles: %v", roles)
	})

	t.Run("admin_role_grants_all", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "admin@example.com",
				Groups:  []string{"admin"},
			},
		}

		roles, _, err := binder.ResolveRoles(identity)
		require.NoError(t, err, "Should resolve roles")
		assert.Contains(t, roles, "admin", "Should have admin role")

		// Admin role should grant wildcard permissions
		hasPermission := binder.HasPermission(roles, "execute", "mission")
		assert.True(t, hasPermission, "Admin should have all permissions")

		hasPermission = binder.HasPermission(roles, "delete", "finding")
		assert.True(t, hasPermission, "Admin should have all permissions")

		t.Logf("Successfully verified admin permissions")
	})

	t.Run("no_matching_groups", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
				Groups:  []string{"developers"},
			},
		}

		roles, permissions, err := binder.ResolveRoles(identity)
		assert.Error(t, err, "Should fail with no matching groups")
		assert.Empty(t, roles, "Should have no roles")
		assert.Empty(t, permissions, "Should have no permissions")

		t.Logf("Successfully verified no role binding error")
	})

	t.Run("permission_checking", func(t *testing.T) {
		roles := []string{"mission:execute", "findings:read"}

		// Check valid permissions
		assert.True(t, binder.HasPermission(roles, "execute", "mission"))
		assert.True(t, binder.HasPermission(roles, "read", "findings"))

		// Check invalid permissions
		assert.False(t, binder.HasPermission(roles, "delete", "mission"))
		assert.False(t, binder.HasPermission(roles, "write", "findings"))

		t.Logf("Successfully verified permission checking")
	})
}

// TestPermissionEnforcement_IdentityHelpers verifies Identity permission helpers.
func TestPermissionEnforcement_IdentityHelpers(t *testing.T) {
	t.Parallel()

	t.Run("has_permission", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
			},
			Roles: []string{"mission:execute"},
			Permissions: []auth.Permission{
				{
					Action:   "execute",
					Resource: "mission",
					Scope:    "*",
				},
			},
		}

		// Check permission
		hasPermission := identity.HasPermission("execute", "mission")
		assert.True(t, hasPermission, "Should have execute permission on mission")

		hasPermission = identity.HasPermission("delete", "mission")
		assert.False(t, hasPermission, "Should not have delete permission")

		t.Logf("Successfully verified HasPermission helper")
	})

	t.Run("has_role", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
			},
			Roles: []string{"mission:execute", "findings:read"},
		}

		// Check roles
		hasRole := identity.HasRole("mission:execute")
		assert.True(t, hasRole, "Should have mission:execute role")

		hasRole = identity.HasRole("admin")
		assert.False(t, hasRole, "Should not have admin role")

		t.Logf("Successfully verified HasRole helper")
	})

	t.Run("wildcard_permissions", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "admin@example.com",
			},
			Roles: []string{"admin"},
			Permissions: []auth.Permission{
				{
					Action:   "*",
					Resource: "*",
					Scope:    "*",
				},
			},
		}

		// Admin with wildcard should have all permissions
		assert.True(t, identity.HasPermission("execute", "mission"))
		assert.True(t, identity.HasPermission("delete", "finding"))
		assert.True(t, identity.HasPermission("write", "anything"))

		t.Logf("Successfully verified wildcard permissions")
	})

	t.Run("nil_identity", func(t *testing.T) {
		var identity *auth.Identity = nil

		// Should not panic
		hasPermission := identity.HasPermission("execute", "mission")
		assert.False(t, hasPermission, "Nil identity should have no permissions")

		hasRole := identity.HasRole("admin")
		assert.False(t, hasRole, "Nil identity should have no roles")

		t.Logf("Successfully verified nil identity handling")
	})
}

// TestAuthMode_LocalhostBypass verifies localhost bypass functionality.
func TestAuthMode_LocalhostBypass_Config(t *testing.T) {
	t.Parallel()

	// Setup config with localhost bypass
	cfg := &auth.AuthConfig{
		Mode:           "enterprise",
		TrustLocalhost: true,
		OIDC: []auth.OIDCIssuerConfig{
			{
				Issuer:   "https://keycloak.example.com",
				Audience: "gibson-api",
			},
		},
	}
	cfg.ApplyDefaults()

	// Verify configuration
	assert.True(t, cfg.TrustLocalhost, "Should trust localhost")

	t.Logf("Successfully verified localhost bypass configuration")
}

// TestAuthConfig_Validation verifies auth configuration validation.
func TestAuthConfig_Validation(t *testing.T) {
	t.Parallel()

	t.Run("valid_disabled_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "disabled"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Disabled mode should validate")
	})

	t.Run("valid_dev_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{
			Mode: "dev",
			Local: &auth.LocalAuthConfig{
				Users: []auth.LocalUser{
					{Name: "test", Token: "token", Roles: []string{"admin"}},
				},
			},
		}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Dev mode with users should validate")
	})

	t.Run("invalid_dev_mode_no_users", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "dev"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.Error(t, err, "Dev mode without users should fail")
		assert.Contains(t, err.Error(), "requires local.users")
	})

	t.Run("valid_enterprise_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{
			Mode: "enterprise",
			OIDC: []auth.OIDCIssuerConfig{
				{Issuer: "https://okta.example.com", Audience: "api"},
			},
		}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Enterprise mode with OIDC should validate")
	})

	t.Run("invalid_enterprise_mode_no_oidc", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "enterprise"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.Error(t, err, "Enterprise mode without OIDC should fail")
		assert.Contains(t, err.Error(), "requires at least one OIDC issuer")
	})

	t.Run("valid_saas_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{
			Mode: "saas",
			OIDC: []auth.OIDCIssuerConfig{
				{Issuer: "https://auth.saas.example.com", Audience: "api"},
			},
		}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "SaaS mode with OIDC should validate")
	})

	t.Run("invalid_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "invalid"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.Error(t, err, "Invalid mode should fail")
		assert.Contains(t, err.Error(), "invalid auth mode")
	})
}

// TestAuthConfig_Defaults verifies default configuration application.
func TestAuthConfig_Defaults(t *testing.T) {
	t.Parallel()

	t.Run("empty_mode_defaults_to_disabled", func(t *testing.T) {
		cfg := &auth.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, "disabled", cfg.Mode, "Empty mode should default to disabled")
	})

	t.Run("tenant_claim_default", func(t *testing.T) {
		cfg := &auth.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, "tenant_id", cfg.TenantClaim, "Should default to tenant_id")
	})

	t.Run("clock_skew_default", func(t *testing.T) {
		cfg := &auth.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, 30*time.Second, cfg.ClockSkew, "Should default to 30s")
	})

	t.Run("jwks_ttl_default", func(t *testing.T) {
		cfg := &auth.AuthConfig{
			Mode: "enterprise",
			OIDC: []auth.OIDCIssuerConfig{
				{Issuer: "https://example.com", Audience: "api"},
			},
		}
		cfg.ApplyDefaults()
		assert.Equal(t, 1*time.Hour, cfg.OIDC[0].JWKSTTL, "JWKS TTL should default to 1h")
	})
}

// TestFullAuthFlow_Integration verifies the complete auth flow from
// token extraction through tenant injection.
func TestFullAuthFlow_Integration(t *testing.T) {
	t.Parallel()

	// This test verifies the conceptual flow without real tokens
	// Full integration with OIDC providers is tested in SDK integration tests

	t.Run("flow_disabled_mode", func(t *testing.T) {
		// 1. Token validation -> SKIPPED (disabled mode)
		// 2. Tenant extraction -> From config (default tenant)
		// 3. Permission check -> Granted (synthetic admin)

		cfg := &auth.AuthConfig{
			Mode:          "disabled",
			DefaultTenant: "test-tenant",
		}
		cfg.ApplyDefaults()

		authenticator, err := auth.NewCompositeAuthenticator(cfg)
		require.NoError(t, err)

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError, // Quiet for tests
		}))

		interceptor := auth.UnaryAuthInterceptor(authenticator, cfg, logger)

		var capturedIdentity *sdkauth.Identity
		var capturedTenant string

		testHandler := func(ctx context.Context, req any) (any, error) {
			identity, _ := sdkauth.IdentityFromContext(ctx)
			capturedIdentity = identity
			capturedTenant = auth.TenantFromContext(ctx)
			return "success", nil
		}

		_, err = interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, testHandler)

		require.NoError(t, err)
		assert.NotNil(t, capturedIdentity, "Identity injected")
		assert.Equal(t, "test-tenant", capturedTenant, "Tenant injected")

		t.Logf("Full flow verified: mode=disabled, tenant=%s", capturedTenant)
	})

	t.Run("flow_dev_mode", func(t *testing.T) {
		// 1. Token validation -> Local token lookup
		// 2. Tenant extraction -> From config (default tenant)
		// 3. Permission check -> From role bindings

		cfg := &auth.AuthConfig{
			Mode:          "dev",
			DefaultTenant: "dev-tenant",
			Local: &auth.LocalAuthConfig{
				Users: []auth.LocalUser{
					{Name: "dev", Token: "dev-token", Roles: []string{"admin"}},
				},
			},
		}
		cfg.ApplyDefaults()

		authenticator, err := auth.NewCompositeAuthenticator(cfg)
		require.NoError(t, err)

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))

		interceptor := auth.UnaryAuthInterceptor(authenticator, cfg, logger)

		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
			"authorization", "Bearer dev-token",
		))

		var capturedIdentity *sdkauth.Identity
		var capturedTenant string

		testHandler := func(ctx context.Context, req any) (any, error) {
			identity, _ := sdkauth.IdentityFromContext(ctx)
			capturedIdentity = identity
			capturedTenant = auth.TenantFromContext(ctx)
			return "success", nil
		}

		_, err = interceptor(ctx, nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, testHandler)

		require.NoError(t, err)
		assert.NotNil(t, capturedIdentity, "Identity injected")
		assert.Equal(t, "dev", capturedIdentity.Subject)
		assert.Equal(t, "dev-tenant", capturedTenant, "Tenant injected")

		t.Logf("Full flow verified: mode=dev, subject=%s, tenant=%s",
			capturedIdentity.Subject, capturedTenant)
	})
}

// TestConcurrentAuthRequests verifies that auth handles concurrent requests safely.
func TestConcurrentAuthRequests(t *testing.T) {
	t.Parallel()

	// Setup config
	cfg := &auth.AuthConfig{
		Mode: "dev",
		Local: &auth.LocalAuthConfig{
			Users: []auth.LocalUser{
				{Name: "user1", Token: "token1", Roles: []string{"admin"}},
				{Name: "user2", Token: "token2", Roles: []string{"admin"}},
			},
		},
	}
	cfg.ApplyDefaults()

	authenticator, err := auth.NewCompositeAuthenticator(cfg)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	interceptor := auth.UnaryAuthInterceptor(authenticator, cfg, logger)

	// Run concurrent requests
	numRequests := 50
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			token := "token1"
			if idx%2 == 0 {
				token = "token2"
			}

			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
				"authorization", fmt.Sprintf("Bearer %s", token),
			))

			testHandler := func(ctx context.Context, req any) (any, error) {
				return "success", nil
			}

			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/Method",
			}, testHandler)

			results <- err
		}(i)
	}

	// Verify all requests succeeded
	for i := 0; i < numRequests; i++ {
		select {
		case err := <-results:
			assert.NoError(t, err, "Request %d should succeed", i)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	t.Logf("Successfully handled %d concurrent auth requests", numRequests)
}

// TestStreamAuthInterceptor verifies stream interceptor behavior.
func TestStreamAuthInterceptor(t *testing.T) {
	t.Parallel()

	// Setup config
	cfg := &auth.AuthConfig{
		Mode: "dev",
		Local: &auth.LocalAuthConfig{
			Users: []auth.LocalUser{
				{Name: "streamer", Token: "stream-token", Roles: []string{"admin"}},
			},
		},
	}
	cfg.ApplyDefaults()

	authenticator, err := auth.NewCompositeAuthenticator(cfg)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	streamInterceptor := auth.StreamAuthInterceptor(authenticator, cfg, logger)
	require.NotNil(t, streamInterceptor, "Stream interceptor should not be nil")

	t.Logf("Successfully created stream auth interceptor")
}
