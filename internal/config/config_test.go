package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Test Core defaults
	assert.NotEmpty(t, cfg.Core.HomeDir, "HomeDir should not be empty")
	assert.Contains(t, cfg.Core.HomeDir, ".gibson", "HomeDir should contain .gibson")
	assert.Equal(t, filepath.Join(cfg.Core.HomeDir, "data"), cfg.Core.DataDir)
	assert.Equal(t, filepath.Join(cfg.Core.HomeDir, "cache"), cfg.Core.CacheDir)
	assert.Equal(t, 10, cfg.Core.ParallelLimit)
	assert.Equal(t, 5*time.Minute, cfg.Core.Timeout)
	assert.False(t, cfg.Core.Debug)

	// Test Database defaults
	assert.Equal(t, filepath.Join(cfg.Core.HomeDir, "gibson.db"), cfg.Database.Path)
	assert.Equal(t, 10, cfg.Database.MaxConnections)
	assert.Equal(t, 30*time.Second, cfg.Database.Timeout)
	assert.True(t, cfg.Database.WALMode)
	assert.True(t, cfg.Database.AutoVacuum)

	// Test Security defaults
	assert.Equal(t, "aes-256-gcm", cfg.Security.EncryptionAlgorithm)
	assert.Equal(t, "scrypt", cfg.Security.KeyDerivation)
	assert.True(t, cfg.Security.SSLValidation)
	assert.True(t, cfg.Security.AuditLogging)

	// Test LLM defaults
	assert.Empty(t, cfg.LLM.DefaultProvider)

	// Test Logging defaults
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)

	// Test Tracing defaults
	assert.False(t, cfg.Tracing.Enabled)
	assert.Empty(t, cfg.Tracing.Endpoint)

	// Test Metrics defaults
	assert.False(t, cfg.Metrics.Enabled)
	assert.Equal(t, 9090, cfg.Metrics.Port)
}

func TestLoadValidConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/gibson-test
  data_dir: /tmp/gibson-test/data
  cache_dir: /tmp/gibson-test/cache
  parallel_limit: 20
  timeout: 10m
  debug: true

database:
  path: /tmp/gibson-test/gibson.db
  max_connections: 20
  timeout: 1m
  wal_mode: true
  auto_vacuum: false

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: false

llm:
  default_provider: openai

logging:
  level: debug
  format: text

tracing:
  enabled: true
  endpoint: http://localhost:4318

metrics:
  enabled: true
  port: 8080

activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify loaded values
	assert.Equal(t, "/tmp/gibson-test", cfg.Core.HomeDir)
	assert.Equal(t, "/tmp/gibson-test/data", cfg.Core.DataDir)
	assert.Equal(t, "/tmp/gibson-test/cache", cfg.Core.CacheDir)
	assert.Equal(t, 20, cfg.Core.ParallelLimit)
	assert.Equal(t, 10*time.Minute, cfg.Core.Timeout)
	assert.True(t, cfg.Core.Debug)

	assert.Equal(t, "/tmp/gibson-test/gibson.db", cfg.Database.Path)
	assert.Equal(t, 20, cfg.Database.MaxConnections)
	assert.Equal(t, 1*time.Minute, cfg.Database.Timeout)
	assert.True(t, cfg.Database.WALMode)
	assert.False(t, cfg.Database.AutoVacuum)

	assert.Equal(t, "aes-256-gcm", cfg.Security.EncryptionAlgorithm)
	assert.Equal(t, "scrypt", cfg.Security.KeyDerivation)
	assert.True(t, cfg.Security.SSLValidation)
	assert.False(t, cfg.Security.AuditLogging)

	assert.Equal(t, "openai", cfg.LLM.DefaultProvider)

	assert.Equal(t, "debug", cfg.Logging.Level)
	assert.Equal(t, "text", cfg.Logging.Format)

	assert.True(t, cfg.Tracing.Enabled)
	assert.Equal(t, "http://localhost:4318", cfg.Tracing.Endpoint)

	assert.True(t, cfg.Metrics.Enabled)
	assert.Equal(t, 8080, cfg.Metrics.Port)
}

func TestLoadWithEnvironmentVariableInterpolation(t *testing.T) {
	// Set test environment variables
	os.Setenv("GIBSON_HOME", "/custom/gibson")
	os.Setenv("GIBSON_DB_PATH", "/custom/gibson/db.sqlite")
	os.Setenv("GIBSON_PROVIDER", "anthropic")
	defer func() {
		os.Unsetenv("GIBSON_HOME")
		os.Unsetenv("GIBSON_DB_PATH")
		os.Unsetenv("GIBSON_PROVIDER")
	}()

	// Create a temporary config file with environment variables
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: ${GIBSON_HOME}
  data_dir: ${GIBSON_HOME}/data
  cache_dir: ${GIBSON_HOME}/cache
  parallel_limit: 10
  timeout: 5m
  debug: false

database:
  path: ${GIBSON_DB_PATH}
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true

llm:
  default_provider: ${GIBSON_PROVIDER}

logging:
  level: info
  format: json

activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify environment variable interpolation
	assert.Equal(t, "/custom/gibson", cfg.Core.HomeDir)
	assert.Equal(t, "/custom/gibson/data", cfg.Core.DataDir)
	assert.Equal(t, "/custom/gibson/cache", cfg.Core.CacheDir)
	assert.Equal(t, "/custom/gibson/db.sqlite", cfg.Database.Path)
	assert.Equal(t, "anthropic", cfg.LLM.DefaultProvider)
}

func TestLoadWithMissingEnvironmentVariables(t *testing.T) {
	// Create a temporary config file with non-existent environment variables
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: ${NONEXISTENT_VAR}
  data_dir: /tmp/data
  cache_dir: /tmp/cache
  parallel_limit: 10
  timeout: 5m
  debug: false

database:
  path: /tmp/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true

activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify that missing environment variables are left as-is
	assert.Equal(t, "${NONEXISTENT_VAR}", cfg.Core.HomeDir)
}

func TestLoadWithDefaults_FileNotFound(t *testing.T) {
	validator := NewValidator()
	loader := NewConfigLoader(validator)

	// Try to load a non-existent file
	cfg, err := loader.LoadWithDefaults("/nonexistent/config.yaml")
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Should return default configuration
	defaultCfg := DefaultConfig()
	assert.Equal(t, defaultCfg.Core.ParallelLimit, cfg.Core.ParallelLimit)
	assert.Equal(t, defaultCfg.Database.MaxConnections, cfg.Database.MaxConnections)
	assert.Equal(t, defaultCfg.Security.EncryptionAlgorithm, cfg.Security.EncryptionAlgorithm)
}

func TestLoadWithDefaults_FileExists(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/gibson-custom
  data_dir: /tmp/gibson-custom/data
  cache_dir: /tmp/gibson-custom/cache
  parallel_limit: 50
  timeout: 15m
  debug: true

database:
  path: /tmp/gibson-custom/gibson.db
  max_connections: 50
  timeout: 2m
  wal_mode: false
  auto_vacuum: false

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: false
  audit_logging: false
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.LoadWithDefaults(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Should load from file, not defaults
	assert.Equal(t, 50, cfg.Core.ParallelLimit)
	assert.Equal(t, 50, cfg.Database.MaxConnections)
	assert.True(t, cfg.Core.Debug)
}

func TestValidation_Success(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()

	err := validator.Validate(cfg)
	assert.NoError(t, err)
}

func TestValidation_NilConfig(t *testing.T) {
	validator := NewValidator()

	err := validator.Validate(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is nil")
}

func TestValidation_ParallelLimitTooLow(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Core.ParallelLimit = 0

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parallel_limit")
	assert.Contains(t, err.Error(), "must be at least 1")
}

func TestValidation_ParallelLimitTooHigh(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Core.ParallelLimit = 101

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parallel_limit")
	assert.Contains(t, err.Error(), "must be at most 100")
}

func TestValidation_MaxConnectionsTooLow(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Database.MaxConnections = 0

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_connections")
	assert.Contains(t, err.Error(), "must be at least 1")
}

func TestValidation_MaxConnectionsTooHigh(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Database.MaxConnections = 101

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max_connections")
	assert.Contains(t, err.Error(), "must be at most 100")
}

func TestValidation_CoreTimeoutTooLow(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Core.Timeout = 500 * time.Millisecond

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	assert.Contains(t, err.Error(), "must be at least 1s")
}

func TestValidation_DatabaseTimeoutTooLow(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Database.Timeout = 500 * time.Millisecond

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	assert.Contains(t, err.Error(), "must be at least 1s")
}

func TestValidation_MultipleErrors(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()
	cfg.Core.ParallelLimit = 0
	cfg.Database.MaxConnections = 0
	cfg.Core.Timeout = 0

	err := validator.Validate(cfg)
	require.Error(t, err)

	// Should contain all validation errors
	assert.Contains(t, err.Error(), "parallel_limit")
	assert.Contains(t, err.Error(), "max_connections")
	assert.Contains(t, err.Error(), "timeout")
}

func TestLoadInvalidYAML(t *testing.T) {
	// Create a temporary config file with invalid YAML
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/gibson
  invalid yaml syntax here [[[
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	_, err = loader.Load(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestLoadInvalidFilePath(t *testing.T) {
	validator := NewValidator()
	loader := NewConfigLoader(validator)

	_, err := loader.Load("/nonexistent/directory/config.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestInterpolateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		envVars  map[string]string
		expected string
	}{
		{
			name:     "single variable",
			input:    "${HOME}",
			envVars:  map[string]string{"HOME": "/home/user"},
			expected: "/home/user",
		},
		{
			name:     "multiple variables",
			input:    "${HOME}/${USER}/data",
			envVars:  map[string]string{"HOME": "/home", "USER": "testuser"},
			expected: "/home/testuser/data",
		},
		{
			name:     "missing variable",
			input:    "${MISSING_VAR}",
			envVars:  map[string]string{},
			expected: "${MISSING_VAR}",
		},
		{
			name:     "no variables",
			input:    "/static/path",
			envVars:  map[string]string{},
			expected: "/static/path",
		},
		{
			name:     "mixed content",
			input:    "prefix_${VAR}_suffix",
			envVars:  map[string]string{"VAR": "value"},
			expected: "prefix_value_suffix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}

			result := interpolateString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCamelToSnake(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ParallelLimit", "parallel_limit"},
		{"MaxConnections", "max_connections"},
		{"HomeDir", "home_dir"},
		{"SSLValidation", "s_s_l_validation"},
		{"simple", "simple"},
		{"HTTPServer", "h_t_t_p_server"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := camelToSnake(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatFieldPath(t *testing.T) {
	tests := []struct {
		namespace string
		expected  string
	}{
		{"Config.Core.ParallelLimit", "core.parallel_limit"},
		{"Config.Database.MaxConnections", "database.max_connections"},
		{"Config.Security.EncryptionAlgorithm", "security.encryption_algorithm"},
		{"Config", "Config"},
	}

	for _, tt := range tests {
		t.Run(tt.namespace, func(t *testing.T) {
			result := formatFieldPath(tt.namespace)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFormatValidationError(t *testing.T) {
	validator := NewValidator()
	cfg := DefaultConfig()

	// Test URL validation error
	cfg.Core.ParallelLimit = -1

	err := validator.Validate(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parallel_limit")
}

func TestInterpolateEnvVars(t *testing.T) {
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
	}{
		{
			name:     "map with string interpolation",
			input:    map[string]interface{}{"key": "${TEST_VAR}"},
			expected: map[string]interface{}{"key": "test_value"},
		},
		{
			name:     "nested map",
			input:    map[string]interface{}{"outer": map[string]interface{}{"inner": "${TEST_VAR}"}},
			expected: map[string]interface{}{"outer": map[string]interface{}{"inner": "test_value"}},
		},
		{
			name:     "array of strings",
			input:    []interface{}{"${TEST_VAR}", "static"},
			expected: []interface{}{"test_value", "static"},
		},
		{
			name:     "non-string value",
			input:    123,
			expected: 123,
		},
		{
			name:     "boolean value",
			input:    true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := interpolateEnvVars(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefaultHomeDir(t *testing.T) {
	homeDir := DefaultHomeDir()
	assert.NotEmpty(t, homeDir)
	assert.Contains(t, homeDir, ".gibson")
}

func TestGetDefaultHomeDir(t *testing.T) {
	homeDir := getDefaultHomeDir()
	assert.NotEmpty(t, homeDir)
	assert.Contains(t, homeDir, ".gibson")
}

func TestApplyInterpolation_EdgeCases(t *testing.T) {
	cfg := DefaultConfig()

	// Test with empty map
	err := applyInterpolation(cfg, map[string]interface{}{})
	assert.NoError(t, err)

	// Test with map containing non-map values for sections
	interpolated := map[string]interface{}{
		"core":     "not a map",
		"database": 123,
		"security": true,
		"llm":      []string{"test"},
		"logging":  nil,
		"tracing":  3.14,
	}
	err = applyInterpolation(cfg, interpolated)
	assert.NoError(t, err)
}

func TestLoadWithDefaults_IOError(t *testing.T) {
	// Create a directory that will cause ReadInConfig to fail
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "subdir", "config.yaml")

	// Create the parent directory but make it read-only to cause an error
	os.Mkdir(filepath.Join(tmpDir, "subdir"), 0755)

	// Write a valid config file
	configContent := `
core:
  home_dir: /tmp/test
  data_dir: /tmp/test/data
  cache_dir: /tmp/test/cache
  parallel_limit: 10
  timeout: 5m
  debug: false

database:
  path: /tmp/test/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Should load the file successfully
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.LoadWithDefaults(configPath)
	require.NoError(t, err)
	assert.Equal(t, 10, cfg.Core.ParallelLimit)
}

func TestLoad_UnmarshalError(t *testing.T) {
	// Create a config file with invalid types that will cause unmarshal errors
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/test
  data_dir: /tmp/test/data
  cache_dir: /tmp/test/cache
  parallel_limit: "not a number"
  timeout: 5m
  debug: false

database:
  path: /tmp/test/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	validator := NewValidator()
	loader := NewConfigLoader(validator)
	_, err = loader.Load(configPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal config")
}

func TestLoadWithDefaults_UnmarshalError(t *testing.T) {
	// Create a config file with invalid types
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/test
  data_dir: /tmp/test/data
  cache_dir: /tmp/test/cache
  parallel_limit: "invalid"
  timeout: 5m
  debug: false

database:
  path: /tmp/test/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true

security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	validator := NewValidator()
	loader := NewConfigLoader(validator)
	_, err = loader.LoadWithDefaults(configPath)
	require.Error(t, err)
}
