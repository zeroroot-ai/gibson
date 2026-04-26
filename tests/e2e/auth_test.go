//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/sdk/auth"
)

// Note: The auth interceptor tests that previously lived here tested the
// auth.UnaryAuthInterceptor / auth.StreamAuthInterceptor API, which has been
// removed as part of the Zitadel/Envoy-gateway migration.
//
// Authentication is now performed by the Envoy ext_authz sidecar. The daemon
// trusts the signed x-gibson-identity-* headers that Envoy injects after
// authenticating the request. The auth.UnaryServerInterceptor / StreamInterceptor
// verifies the HMAC signature on those headers.
//
// Integration tests for the identity interceptor live in:
//   internal/identity/interceptor_test.go

// TestAuthConfig_Validation verifies auth configuration validation.
func TestAuthConfig_Validation(t *testing.T) {
	t.Parallel()

	t.Run("empty_mode_is_invalid", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: ""}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.Error(t, err, "Empty mode should not validate")
		assert.Contains(t, err.Error(), "auth mode is required")
	})

	t.Run("invalid_mode", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: "disabled"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.Error(t, err, "Invalid mode should fail")
		assert.Contains(t, err.Error(), "invalid auth mode")
	})

	t.Run("valid_dev_mode", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: "dev"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Dev mode should validate")
	})

	t.Run("valid_enterprise_mode", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: "enterprise"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "Enterprise mode should validate")
	})

	t.Run("valid_saas_mode", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: "saas"}
		cfg.ApplyDefaults()
		err := cfg.Validate()
		assert.NoError(t, err, "SaaS mode should validate")
	})
}

// TestAuthConfig_Defaults verifies default configuration application.
func TestAuthConfig_Defaults(t *testing.T) {
	t.Parallel()

	t.Run("empty_mode_stays_empty", func(t *testing.T) {
		cfg := &config.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, "", cfg.Mode, "Empty mode should NOT be defaulted")
	})

	t.Run("tenant_claim_default", func(t *testing.T) {
		cfg := &config.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, "tenant_id", cfg.TenantClaim, "Should default to tenant_id")
	})

	t.Run("clock_skew_default", func(t *testing.T) {
		cfg := &config.AuthConfig{}
		cfg.ApplyDefaults()
		assert.Equal(t, 30*time.Second, cfg.ClockSkew, "Should default to 30s")
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
		})
	}
}

// TestTenantContext verifies tenant context injection and extraction.
func TestTenantContext(t *testing.T) {
	t.Parallel()

	t.Run("inject_and_extract_tenant", func(t *testing.T) {
		ctx := auth.ContextWithTenantString(context.Background(), "acme-corp")
		tenant := auth.TenantStringFromContext(ctx)
		assert.Equal(t, "acme-corp", tenant, "Should extract injected tenant")
	})

	t.Run("nil_context", func(t *testing.T) {
		tenant := auth.TenantStringFromContext(nil)
		assert.Equal(t, auth.SystemTenantString, tenant, "Nil context should return SystemTenant")
	})

	t.Run("overwrite_tenant", func(t *testing.T) {
		ctx := context.Background()
		ctx = auth.ContextWithTenantString(ctx, "first-tenant")
		ctx = auth.ContextWithTenantString(ctx, "second-tenant")
		tenant := auth.TenantStringFromContext(ctx)
		assert.Equal(t, "second-tenant", tenant, "Should use latest tenant")
	})
}

// TestAuthConfig_AutoProvision verifies auto-provisioning defaults per mode.
func TestAuthConfig_AutoProvision(t *testing.T) {
	t.Parallel()

	t.Run("enterprise_defaults_true", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: "enterprise"}
		assert.True(t, cfg.ShouldAutoProvision(), "enterprise should default to auto-provision")
	})

	t.Run("saas_defaults_false", func(t *testing.T) {
		cfg := &config.AuthConfig{Mode: "saas"}
		assert.False(t, cfg.ShouldAutoProvision(), "saas should not default to auto-provision")
	})

	t.Run("explicit_override", func(t *testing.T) {
		v := false
		cfg := &config.AuthConfig{Mode: "enterprise", AutoProvisionTenants: &v}
		assert.False(t, cfg.ShouldAutoProvision(), "explicit override should win")
	})
}

// TestIdentity_IsCrossTenantCaller verifies cross-tenant caller detection by issuer.
func TestIdentity_IsCrossTenantCaller(t *testing.T) {
	t.Parallel()

	require.True(t, auth.IsCrossTenantCaller(auth.Identity{Issuer: "spire"}),
		"spire issuer should be cross-tenant")
	require.False(t, auth.IsCrossTenantCaller(auth.Identity{Issuer: "zitadel"}),
		"zitadel issuer should NOT be cross-tenant")
	require.False(t, auth.IsCrossTenantCaller(auth.Identity{Issuer: "apikey"}),
		"apikey issuer should NOT be cross-tenant")
}
