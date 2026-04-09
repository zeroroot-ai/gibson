package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfigWithPromptSection(t *testing.T) {
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


security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: false

prompt:
  prompts_dir: /tmp/gibson-test/prompts
  load_builtins: true
  default_persona: assistant

logging:
  level: info
  format: json

tracing:
  enabled: false
  endpoint: ""

metrics:
  enabled: false
  port: 9090

activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify prompt configuration was loaded
	assert.Equal(t, "/tmp/gibson-test/prompts", cfg.Prompt.PromptsDir)
	assert.True(t, cfg.Prompt.LoadBuiltins)
	assert.Equal(t, "assistant", cfg.Prompt.DefaultPersona)
}

func TestLoadConfigWithoutPromptSection(t *testing.T) {
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


security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: false

logging:
  level: info
  format: json

tracing:
  enabled: false
  endpoint: ""

metrics:
  enabled: false
  port: 9090

activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Verify config loads successfully without prompt section
	// Default values should be applied
	assert.Equal(t, "", cfg.Prompt.PromptsDir)
	assert.False(t, cfg.Prompt.LoadBuiltins) // false is zero value for bool
	assert.Equal(t, "", cfg.Prompt.DefaultPersona)
}
