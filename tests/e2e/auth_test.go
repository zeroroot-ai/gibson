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

// TestAuthMode_Disabled_Rejects verifies that disabled mode is rejected
// and returns Unauthenticated error.
func TestAuthMode_Disabled_Rejects(t *testing.T) {
	t.Parallel()

	// Setup config with disabled mode (no longer valid)
	cfg := &auth.AuthConfig{
		Mode: "disabled",
	}

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create interceptor with nil authenticator
	interceptor := auth.UnaryAuthInterceptor(nil, cfg, logger)
	require.NotNil(t, interceptor, "Interceptor should not be nil")

	// Create test context
	ctx := context.Background()

	// Define test handler that should not be called
	testHandler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called for disabled mode")
		return "success", nil
	}

	// Call interceptor without token (should be rejected)
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, testHandler)

	// Verify rejection
	require.Error(t, err, "Disabled mode should be rejected")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "authentication required")

	t.Logf("Successfully verified disabled mode is rejected")
}

// TestAuthMode_Disabled_WithDefaultTenant_Rejects verifies that disabled mode
// is rejected even when default tenant is configured.
func TestAuthMode_Disabled_WithDefaultTenant_Rejects(t *testing.T) {
	t.Parallel()

	// Setup config with disabled mode and default tenant (disabled is no longer valid)
	cfg := &auth.AuthConfig{
		Mode:          "disabled",
		DefaultTenant: "acme-corp",
	}

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create interceptor with nil authenticator
	interceptor := auth.UnaryAuthInterceptor(nil, cfg, logger)

	// Create test context
	ctx := context.Background()

	// Define test handler that should not be called
	testHandler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called for disabled mode")
		return "success", nil
	}

	// Call interceptor - should be rejected
	_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, testHandler)

	// Verify rejection
	require.Error(t, err, "Disabled mode should be rejected")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	t.Logf("Successfully verified disabled mode with default tenant is rejected")
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
	authenticator, err := auth.NewCompositeAuthenticator(cfg, nil)
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
// Note: This test uses mock OIDC tokens for simplicity. The example issuer
// URLs below are illustrative — any OIDC-compliant IdP works.
func TestAuthMode_Enterprise_Config(t *testing.T) {
	t.Parallel()

	// Setup config with enterprise mode
	cfg := &auth.AuthConfig{
		Mode: "enterprise",
		OIDC: []auth.OIDCIssuerConfig{
			{
				Issuer:   "https://oidc.example.com/realms/gibson",
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
	authenticator, err := auth.NewCompositeAuthenticator(cfg, nil)
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

// TestPermissionEnforcement_RoleBinder and TestPermissionEnforcement_IdentityHelpers
// were removed by the declarative-rbac-framework spec. They tested the legacy
// permission-as-role model (e.g. roles like "mission:execute") and the deleted
// Identity.HasRole / Identity.HasPermission methods. Permission enforcement now
// flows through the schema-driven RPCAuthzInterceptor, which is covered by:
//   - internal/auth/rpc_authz_interceptor_test.go
//   - internal/auth/permissions_loader_test.go
//   - internal/auth/roles_test.go (RoleBinder unit tests)

// TestAuthMode_LocalhostBypass verifies localhost bypass functionality.
func TestAuthMode_LocalhostBypass_Config(t *testing.T) {
	t.Parallel()

	// Setup config with localhost bypass
	cfg := &auth.AuthConfig{
		Mode:           "enterprise",
		TrustLocalhost: true,
		OIDC: []auth.OIDCIssuerConfig{
			{
				Issuer:   "https://oidc.example.com",
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

	t.Run("disabled_mode_is_invalid", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "disabled"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.Error(t, err, "Disabled mode should not validate")
		assert.Contains(t, err.Error(), "invalid auth mode")
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

	t.Run("empty_mode_stays_empty", func(t *testing.T) {
		cfg := &auth.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, "", cfg.Mode, "Empty mode should NOT be defaulted")
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

	t.Run("flow_disabled_mode_rejected", func(t *testing.T) {
		// Disabled mode is no longer valid - requests should be rejected

		cfg := &auth.AuthConfig{
			Mode:          "disabled",
			DefaultTenant: "test-tenant",
		}

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError, // Quiet for tests
		}))

		interceptor := auth.UnaryAuthInterceptor(nil, cfg, logger)

		testHandler := func(ctx context.Context, req any) (any, error) {
			t.Fatal("handler should not be called for disabled mode")
			return "success", nil
		}

		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, testHandler)

		require.Error(t, err, "Disabled mode should be rejected")
		assert.Equal(t, codes.Unauthenticated, status.Code(err))

		t.Logf("Full flow verified: mode=disabled is rejected")
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

		authenticator, err := auth.NewCompositeAuthenticator(cfg, nil)
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

	authenticator, err := auth.NewCompositeAuthenticator(cfg, nil)
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

	authenticator, err := auth.NewCompositeAuthenticator(cfg, nil)
	require.NoError(t, err)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	streamInterceptor := auth.StreamAuthInterceptor(authenticator, cfg, logger)
	require.NotNil(t, streamInterceptor, "Stream interceptor should not be nil")

	t.Logf("Successfully created stream auth interceptor")
}
