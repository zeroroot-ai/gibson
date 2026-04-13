package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthConfig_Validate_ValidModes tests that valid auth modes pass validation.
func TestAuthConfig_Validate_ValidModes(t *testing.T) {
	tests := []struct {
		name string
		mode string
		cfg  AuthConfig
	}{
		{
			name: "dev mode",
			mode: "dev",
			cfg:  AuthConfig{Mode: "dev"},
		},
		{
			name: "enterprise mode",
			mode: "enterprise",
			cfg:  AuthConfig{Mode: "enterprise"},
		},
		{
			name: "saas mode",
			mode: "saas",
			cfg:  AuthConfig{Mode: "saas"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			require.NoError(t, err)
		})
	}
}

// TestAuthConfig_Validate_EmptyModeRequired tests that empty mode returns a validation error.
func TestAuthConfig_Validate_EmptyModeRequired(t *testing.T) {
	cfg := &AuthConfig{Mode: ""}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth mode is required")
}

// TestAuthConfig_Validate_DisabledNotValid tests that "disabled" is no longer a valid mode.
func TestAuthConfig_Validate_DisabledNotValid(t *testing.T) {
	cfg := &AuthConfig{Mode: "disabled"}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid auth mode")
}

// TestAuthConfig_Validate_InvalidModes tests that invalid modes are rejected.
func TestAuthConfig_Validate_InvalidModes(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "disabled", mode: "disabled"},
		{name: "empty string", mode: ""},
		{name: "invalid string", mode: "invalid"},
		{name: "ENTERPRISE uppercase", mode: "ENTERPRISE"},
		{name: "development (not dev)", mode: "development"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &AuthConfig{Mode: tt.mode}
			err := cfg.Validate()
			require.Error(t, err)
		})
	}
}

// TestAuthConfig_ApplyDefaults_DoesNotDefaultToDisabled tests that ApplyDefaults
// does not set the mode to "disabled" when it is empty.
func TestAuthConfig_ApplyDefaults_DoesNotDefaultToDisabled(t *testing.T) {
	cfg := &AuthConfig{}
	cfg.ApplyDefaults()
	assert.Equal(t, "", cfg.Mode, "empty mode should NOT be defaulted to 'disabled'")
	// Other defaults should still be applied
	assert.Equal(t, "tenant_id", cfg.TenantClaim)
}

// TestAuthConfig_IsAuthEnabled tests the IsAuthEnabled method.
func TestAuthConfig_IsAuthEnabled(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AuthConfig
		enabled bool
	}{
		{
			name:    "dev mode is enabled",
			cfg:     AuthConfig{Mode: "dev"},
			enabled: true,
		},
		{
			name:    "enterprise mode is enabled",
			cfg:     AuthConfig{Mode: "enterprise"},
			enabled: true,
		},
		{
			name:    "saas mode is enabled",
			cfg:     AuthConfig{Mode: "saas"},
			enabled: true,
		},
		{
			name:    "empty mode with Enabled=false",
			cfg:     AuthConfig{Mode: "", Enabled: false},
			enabled: false,
		},
		{
			name:    "empty mode with Enabled=true (deprecated field)",
			cfg:     AuthConfig{Mode: "", Enabled: true},
			enabled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.enabled, tt.cfg.IsAuthEnabled())
		})
	}
}
