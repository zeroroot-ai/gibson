package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minimalConfigYAML is the minimal YAML required by the loader validator.
// Tests append tenant_postgres blocks to this base.
const minimalConfigYAML = `
core:
  home_dir: /tmp/gibson-tenant-pg-test
  data_dir: /tmp/gibson-tenant-pg-test/data
  cache_dir: /tmp/gibson-tenant-pg-test/cache
  parallel_limit: 10
  timeout: 5m
  debug: false

redis:
  url: redis://localhost:6379
  password: ""
  database: 0
  pool_size: 10
  connect_timeout: 5s
  read_timeout: 3s
  write_timeout: 3s

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true

logging:
  level: info
  format: json

activity_logging:
  enabled: false
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

func loadConfigWithTenantPostgres(t *testing.T, tenantPostgresYAML string) *Config {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := minimalConfigYAML + tenantPostgresYAML
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0644))
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	return cfg
}

// TestTenantPostgresInterpolation_Host verifies that a ${PG_HOST} placeholder
// in the tenant_postgres.host field is expanded to the env var value.
func TestTenantPostgresInterpolation_Host(t *testing.T) {
	os.Setenv("PG_HOST", "tenant-pg.gibson.svc.cluster.local")
	defer os.Unsetenv("PG_HOST")

	cfg := loadConfigWithTenantPostgres(t, `
tenant_postgres:
  host: ${PG_HOST}
  port: 5432
  admin_database: postgres
  admin_username: gibson_admin
  admin_password: static-pass
  ssl_mode: disable
`)

	assert.Equal(t, "tenant-pg.gibson.svc.cluster.local", cfg.TenantPostgres.Host)
}

// TestTenantPostgresInterpolation_AdminPassword verifies the security-sensitive
// admin_password field expands from ${PG_ADMIN_PASSWORD}. This is the primary
// reason for the interpolation block — the chart injects the password via a
// Kubernetes Secret rather than rendering it in plaintext into the ConfigMap.
func TestTenantPostgresInterpolation_AdminPassword(t *testing.T) {
	os.Setenv("PG_ADMIN_PASSWORD", "s3cr3t-admin-pw")
	defer os.Unsetenv("PG_ADMIN_PASSWORD")

	cfg := loadConfigWithTenantPostgres(t, `
tenant_postgres:
  host: tenant-postgresql
  port: 5432
  admin_database: postgres
  admin_username: gibson_admin
  admin_password: ${PG_ADMIN_PASSWORD}
  ssl_mode: disable
`)

	assert.Equal(t, "s3cr3t-admin-pw", cfg.TenantPostgres.AdminPassword)
}

// TestTenantPostgresInterpolation_LiteralPassthrough verifies that a literal
// host value (no ${…} placeholder) passes through without modification.
func TestTenantPostgresInterpolation_LiteralPassthrough(t *testing.T) {
	cfg := loadConfigWithTenantPostgres(t, `
tenant_postgres:
  host: localhost
  port: 5432
  admin_database: gibson_admin
  admin_username: gibson_admin
  admin_password: literal-password
  ssl_mode: disable
`)

	assert.Equal(t, "localhost", cfg.TenantPostgres.Host)
	assert.Equal(t, "gibson_admin", cfg.TenantPostgres.AdminDatabase)
	assert.Equal(t, "literal-password", cfg.TenantPostgres.AdminPassword)
}

// TestTenantPostgresInterpolation_MissingEnvVar verifies that a missing env var
// resolves to empty string (the interpolateString behavior for undefined vars).
// The daemon will fail to connect at runtime when the password is empty, which
// is the intended fail-closed behavior (operator misconfiguration).
func TestTenantPostgresInterpolation_MissingEnvVar(t *testing.T) {
	// Ensure the var is definitely not set.
	os.Unsetenv("NONEXISTENT_TENANT_PG_PASS")

	cfg := loadConfigWithTenantPostgres(t, `
tenant_postgres:
  host: tenant-postgresql
  port: 5432
  admin_database: postgres
  admin_username: gibson_admin
  admin_password: ${NONEXISTENT_TENANT_PG_PASS}
  ssl_mode: disable
`)

	// Missing env var → interpolateString preserves the original placeholder.
	// The daemon will refuse to connect at runtime when the placeholder is
	// not a valid password.
	assert.Equal(t, "${NONEXISTENT_TENANT_PG_PASS}", cfg.TenantPostgres.AdminPassword)
}

// TestTenantPostgresInterpolation_AbsentSection verifies that omitting the
// tenant_postgres section entirely produces zero-value fields and no error.
func TestTenantPostgresInterpolation_AbsentSection(t *testing.T) {
	cfg := loadConfigWithTenantPostgres(t, "") // no tenant_postgres block
	assert.Empty(t, cfg.TenantPostgres.Host)
	assert.Empty(t, cfg.TenantPostgres.AdminPassword)
}

// TestTenantPostgresInterpolation_AdminUsername verifies admin_username resolves.
func TestTenantPostgresInterpolation_AdminUsername(t *testing.T) {
	os.Setenv("PG_ADMIN_USER", "super_admin")
	defer os.Unsetenv("PG_ADMIN_USER")

	cfg := loadConfigWithTenantPostgres(t, `
tenant_postgres:
  host: tenant-postgresql
  port: 5432
  admin_database: postgres
  admin_username: ${PG_ADMIN_USER}
  admin_password: pw
  ssl_mode: disable
`)

	assert.Equal(t, "super_admin", cfg.TenantPostgres.AdminUsername)
}
