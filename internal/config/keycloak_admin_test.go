package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestValidateKeycloakAdminConfig covers the fail-closed validation used at
// daemon startup when authz.enabled=true. It is the unit-level gate that
// prevents the daemon from operating without provisioner credentials.
func TestValidateKeycloakAdminConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     KeycloakAdminConfig
		wantErr bool
		errMsg  string // substring that must appear in error
	}{
		{
			name: "client_credentials_complete",
			cfg: KeycloakAdminConfig{
				Endpoint:     "http://keycloak:8080",
				Realm:        "gibson",
				ClientID:     "gibson-system-ops",
				ClientSecret: "super-secret",
			},
			wantErr: false,
		},
		{
			name: "password_grant_complete",
			cfg: KeycloakAdminConfig{
				Endpoint: "http://keycloak:8080",
				Realm:    "gibson",
				Username: "admin",
				Password: "admin-pass",
			},
			wantErr: false,
		},
		{
			name: "both_modes_configured_is_valid",
			cfg: KeycloakAdminConfig{
				Endpoint:     "http://keycloak:8080",
				Realm:        "gibson",
				ClientID:     "gibson-system-ops",
				ClientSecret: "super-secret",
				Username:     "admin",
				Password:     "admin-pass",
			},
			wantErr: false,
		},
		{
			name:    "empty_config_all_missing",
			cfg:     KeycloakAdminConfig{},
			wantErr: true,
			errMsg:  "endpoint",
		},
		{
			name: "missing_endpoint",
			cfg: KeycloakAdminConfig{
				Realm:        "gibson",
				ClientID:     "gibson-system-ops",
				ClientSecret: "super-secret",
			},
			wantErr: true,
			errMsg:  "endpoint",
		},
		{
			name: "missing_realm",
			cfg: KeycloakAdminConfig{
				Endpoint:     "http://keycloak:8080",
				ClientID:     "gibson-system-ops",
				ClientSecret: "super-secret",
			},
			wantErr: true,
			errMsg:  "realm",
		},
		{
			name: "client_id_without_secret",
			cfg: KeycloakAdminConfig{
				Endpoint: "http://keycloak:8080",
				Realm:    "gibson",
				ClientID: "gibson-system-ops",
				// ClientSecret missing
			},
			wantErr: true,
			errMsg:  "client_secret",
		},
		{
			name: "client_secret_without_id",
			cfg: KeycloakAdminConfig{
				Endpoint:     "http://keycloak:8080",
				Realm:        "gibson",
				ClientSecret: "super-secret",
				// ClientID missing
			},
			wantErr: true,
			errMsg:  "client_id",
		},
		{
			name: "username_without_password",
			cfg: KeycloakAdminConfig{
				Endpoint: "http://keycloak:8080",
				Realm:    "gibson",
				Username: "admin",
				// Password missing
			},
			wantErr: true,
			errMsg:  "password",
		},
		{
			name: "password_without_username",
			cfg: KeycloakAdminConfig{
				Endpoint: "http://keycloak:8080",
				Realm:    "gibson",
				Password: "admin-pass",
				// Username missing
			},
			wantErr: true,
			errMsg:  "username",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKeycloakAdminConfig(tc.cfg)
			if tc.wantErr {
				require.Error(t, err, "expected validation error")
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg,
						"error message should mention the missing field")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestKeycloakAdminConfig_EnvVarInterpolation verifies that the config loader
// substitutes GIBSON_KEYCLOAK_ADMIN_* environment variables when loading a
// YAML file that uses ${VAR} syntax. This exercises the applyInterpolation
// code path added in authz-02.
func TestKeycloakAdminConfig_EnvVarInterpolation(t *testing.T) {
	// Set env vars for the test.
	t.Setenv("GIBSON_KEYCLOAK_ADMIN_ENDPOINT", "http://test-kc:8080")
	t.Setenv("GIBSON_KEYCLOAK_ADMIN_REALM", "test-realm")
	t.Setenv("GIBSON_KEYCLOAK_ADMIN_CLIENT_ID", "test-client")
	t.Setenv("GIBSON_KEYCLOAK_ADMIN_CLIENT_SECRET", "test-secret")

	// Write a minimal config YAML using ${VAR} syntax in a temp file.
	yamlContent := `
core:
  home_dir: /tmp/.gibson-test
  parallel_limit: 1
  timeout: 5m
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: false
  audit_logging: false
redis:
  url: redis://localhost:6379
activity_logging:
  enabled: false
  level: normal
  max_content_length: 100
  output: stdout
  buffer_size: 100
keycloak:
  admin:
    endpoint: "${GIBSON_KEYCLOAK_ADMIN_ENDPOINT:-}"
    realm: "${GIBSON_KEYCLOAK_ADMIN_REALM:-}"
    client_id: "${GIBSON_KEYCLOAK_ADMIN_CLIENT_ID:-}"
    client_secret: "${GIBSON_KEYCLOAK_ADMIN_CLIENT_SECRET:-}"
`

	tmpFile, err := os.CreateTemp(t.TempDir(), "gibson-test-*.yaml")
	require.NoError(t, err)
	_, err = tmpFile.WriteString(yamlContent)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.LoadWithDefaults(tmpFile.Name())
	require.NoError(t, err, "config should load without error")

	assert.Equal(t, "http://test-kc:8080", cfg.Keycloak.Admin.Endpoint)
	assert.Equal(t, "test-realm", cfg.Keycloak.Admin.Realm)
	assert.Equal(t, "test-client", cfg.Keycloak.Admin.ClientID)
	assert.Equal(t, "test-secret", cfg.Keycloak.Admin.ClientSecret)

	// Verify the validation passes with these values.
	assert.NoError(t, ValidateKeycloakAdminConfig(cfg.Keycloak.Admin))
}
