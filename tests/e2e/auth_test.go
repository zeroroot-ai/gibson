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
//
// The auth refactor removed the concept of "local users" (LocalAuthConfig /
// NewCompositeAuthenticator). Authentication now flows through four explicit
// validator paths: API key (gsk_), Agent Auth JWT, Better Auth session token,
// or SPIFFE peer cert. The interceptor signature changed from (authenticator,
// cfg, logger) to (apiKeys, agentJWT, betterAuth, cfg, logger).
func TestAuthMode_Disabled_Rejects(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{
		Mode: "disabled",
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Nil for all three validators — disabled mode is rejected before routing.
	interceptor := auth.UnaryAuthInterceptor(nil, nil, nil, cfg, logger)
	require.NotNil(t, interceptor, "Interceptor should not be nil")

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called for disabled mode")
		return "success", nil
	})

	require.Error(t, err, "Disabled mode should be rejected")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "authentication required")

	t.Logf("Successfully verified disabled mode is rejected")
}

// TestAuthMode_Disabled_WithDefaultTenant_Rejects verifies that disabled mode
// is rejected even when default tenant is configured.
func TestAuthMode_Disabled_WithDefaultTenant_Rejects(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{
		Mode:          "disabled",
		DefaultTenant: "acme-corp",
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	interceptor := auth.UnaryAuthInterceptor(nil, nil, nil, cfg, logger)

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called for disabled mode")
		return "success", nil
	})

	require.Error(t, err, "Disabled mode should be rejected")
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	t.Logf("Successfully verified disabled mode with default tenant is rejected")
}

// TestAuthMode_EmptyMode_Rejects verifies that an empty mode is rejected.
func TestAuthMode_EmptyMode_Rejects(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{Mode: ""}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	interceptor := auth.UnaryAuthInterceptor(nil, nil, nil, cfg, logger)

	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called for empty mode")
		return nil, nil
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	t.Logf("Successfully verified empty mode is rejected")
}

// TestAuthMode_MissingToken_Rejects verifies that a valid mode without a bearer
// token is rejected with Unauthenticated.
func TestAuthMode_MissingToken_Rejects(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{Mode: "enterprise"}
	cfg.ApplyDefaults()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	interceptor := auth.UnaryAuthInterceptor(nil, nil, nil, cfg, logger)

	// No authorization metadata — missing bearer token.
	_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
		FullMethod: "/test.Service/Method",
	}, func(ctx context.Context, req any) (any, error) {
		return "success", nil
	})

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	t.Logf("Successfully verified missing-token rejection")
}

// TestAuthMode_Enterprise_Config verifies enterprise mode config validates.
// Note: Full OIDC token validation requires a live IdP; this test only
// verifies that config validation succeeds.
func TestAuthMode_Enterprise_Config(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{
		Mode:          "enterprise",
		DefaultTenant: "enterprise-tenant",
	}
	cfg.ApplyDefaults()

	err := cfg.Validate()
	require.NoError(t, err, "Enterprise config should validate")

	t.Logf("Successfully verified enterprise mode configuration")
}

// TestAuthMode_SaaS_TenantIsolation verifies SaaS mode with tenant extraction.
func TestAuthMode_SaaS_TenantIsolation(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{
		Mode:        "saas",
		TenantClaim: "tenant_id",
	}
	cfg.ApplyDefaults()

	err := cfg.Validate()
	require.NoError(t, err, "SaaS config should validate")

	t.Run("extract_tenant_from_claim", func(t *testing.T) {
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

		tenant := auth.ExtractTenantFromIdentity(identity, "tenant_id")
		assert.Equal(t, "acme-corp", tenant, "Should extract tenant from claim")

		t.Logf("Successfully extracted tenant: %s", tenant)
	})

	t.Run("extract_tenant_from_nested_claim", func(t *testing.T) {
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

		tenant := auth.ExtractTenantFromIdentity(identity, "organization.tenant.id")
		assert.Equal(t, "widgets-inc", tenant, "Should extract nested tenant")

		t.Logf("Successfully extracted nested tenant: %s", tenant)
	})

	t.Run("missing_tenant_claim", func(t *testing.T) {
		identity := &auth.Identity{
			Identity: sdkauth.Identity{
				Subject: "user@example.com",
				Issuer:  "https://auth.saas.example.com",
				Claims: map[string]any{
					"email": "user@example.com",
				},
			},
		}

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
		ctx := auth.ContextWithTenant(context.Background(), "acme-corp")
		tenant := auth.TenantFromContext(ctx)
		assert.Equal(t, "acme-corp", tenant, "Should extract injected tenant")
		t.Logf("Successfully verified tenant context: %s", tenant)
	})

	t.Run("nil_context", func(t *testing.T) {
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
// permission-as-role model and deleted Identity.HasRole / Identity.HasPermission
// methods. Permission enforcement now flows through the schema-driven
// RPCAuthzInterceptor, covered by internal/auth/rpc_authz_interceptor_test.go.

// TestAuthMode_LocalhostBypass_Config verifies localhost bypass configuration.
func TestAuthMode_LocalhostBypass_Config(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{
		Mode:           "enterprise",
		TrustLocalhost: true,
	}
	cfg.ApplyDefaults()

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
		cfg := &auth.AuthConfig{Mode: "dev"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Dev mode should validate")
	})

	t.Run("valid_enterprise_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "enterprise"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Enterprise mode should validate")
	})

	t.Run("valid_saas_mode", func(t *testing.T) {
		cfg := &auth.AuthConfig{Mode: "saas"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "SaaS mode should validate")
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
}

// TestFullAuthFlow_Integration verifies the complete auth flow from
// token extraction through tenant injection.
func TestFullAuthFlow_Integration(t *testing.T) {
	t.Parallel()

	// This test verifies the conceptual flow without real tokens.
	// Full integration with OIDC providers is tested in SDK integration tests.

	t.Run("flow_disabled_mode_rejected", func(t *testing.T) {
		cfg := &auth.AuthConfig{
			Mode:          "disabled",
			DefaultTenant: "test-tenant",
		}

		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelError,
		}))

		interceptor := auth.UnaryAuthInterceptor(nil, nil, nil, cfg, logger)

		_, err := interceptor(context.Background(), nil, &grpc.UnaryServerInfo{
			FullMethod: "/test.Service/Method",
		}, func(ctx context.Context, req any) (any, error) {
			t.Fatal("handler should not be called for disabled mode")
			return "success", nil
		})

		require.Error(t, err, "Disabled mode should be rejected")
		assert.Equal(t, codes.Unauthenticated, status.Code(err))

		t.Logf("Full flow verified: mode=disabled is rejected")
	})
}

// TestConcurrentAuthRequests verifies that auth handles concurrent requests safely.
// The test uses nil validators so all token-bearing requests are rejected, but
// verifies no panics or data races occur under concurrent load.
func TestConcurrentAuthRequests(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{Mode: "enterprise"}
	cfg.ApplyDefaults()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Nil validators — all token-path requests will be rejected.
	interceptor := auth.UnaryAuthInterceptor(nil, nil, nil, cfg, logger)

	numRequests := 50
	results := make(chan error, numRequests)

	for i := 0; i < numRequests; i++ {
		go func(idx int) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
				"authorization", fmt.Sprintf("Bearer test-token-%d", idx),
			))

			_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{
				FullMethod: "/test.Service/Method",
			}, func(ctx context.Context, req any) (any, error) {
				return "success", nil
			})

			results <- err
		}(i)
	}

	// All requests should return errors (no validators configured) without panic.
	for i := 0; i < numRequests; i++ {
		select {
		case err := <-results:
			assert.Error(t, err, "Request %d should return error (no validators configured)", i)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent requests")
		}
	}

	t.Logf("Successfully handled %d concurrent auth requests without panic", numRequests)
}

// TestStreamAuthInterceptor verifies stream interceptor creation with the
// new 5-arg signature (apiKeys, agentJWT, betterAuth, cfg, logger).
func TestStreamAuthInterceptor(t *testing.T) {
	t.Parallel()

	cfg := &auth.AuthConfig{Mode: "enterprise"}
	cfg.ApplyDefaults()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	streamInterceptor := auth.StreamAuthInterceptor(nil, nil, nil, cfg, logger)
	require.NotNil(t, streamInterceptor, "Stream interceptor should not be nil")

	t.Logf("Successfully created stream auth interceptor")
}
