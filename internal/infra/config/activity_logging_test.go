package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActivityLoggingConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.True(t, cfg.ActivityLogging.Enabled, "Activity logging should be enabled by default")
	assert.Equal(t, "normal", cfg.ActivityLogging.Level, "Default level should be normal")
	assert.Equal(t, 500, cfg.ActivityLogging.MaxContentLength, "Default max content length should be 500")
	assert.Equal(t, "stdout", cfg.ActivityLogging.Output, "Default output should be stdout")
	assert.Equal(t, "", cfg.ActivityLogging.FilePath, "Default file path should be empty")
	assert.Equal(t, 10000, cfg.ActivityLogging.BufferSize, "Default buffer size should be 10000")
}

func TestActivityLoggingConfig_EnvironmentOverrides(t *testing.T) {
	// Save original env vars
	origEnabled := os.Getenv("GIBSON_ACTIVITY_LOG_ENABLED")
	origLevel := os.Getenv("GIBSON_ACTIVITY_LOG_LEVEL")
	origMaxContent := os.Getenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT")
	origOutput := os.Getenv("GIBSON_ACTIVITY_LOG_OUTPUT")
	origFile := os.Getenv("GIBSON_ACTIVITY_LOG_FILE")
	defer func() {
		os.Setenv("GIBSON_ACTIVITY_LOG_ENABLED", origEnabled)
		os.Setenv("GIBSON_ACTIVITY_LOG_LEVEL", origLevel)
		os.Setenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT", origMaxContent)
		os.Setenv("GIBSON_ACTIVITY_LOG_OUTPUT", origOutput)
		os.Setenv("GIBSON_ACTIVITY_LOG_FILE", origFile)
	}()

	// Test with environment variables set
	os.Setenv("GIBSON_ACTIVITY_LOG_ENABLED", "false")
	os.Setenv("GIBSON_ACTIVITY_LOG_LEVEL", "debug")
	os.Setenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT", "1000")
	os.Setenv("GIBSON_ACTIVITY_LOG_OUTPUT", "file")
	os.Setenv("GIBSON_ACTIVITY_LOG_FILE", "/tmp/activity.log")

	cfg := ActivityLoggingConfig{
		Enabled:          true,
		Level:            "normal",
		MaxContentLength: 500,
		Output:           "stdout",
		FilePath:         "",
		BufferSize:       10000,
	}

	cfg.ApplyEnvironmentOverrides()

	assert.False(t, cfg.Enabled, "Enabled should be overridden by env var")
	assert.Equal(t, "debug", cfg.Level, "Level should be overridden by env var")
	assert.Equal(t, 1000, cfg.MaxContentLength, "MaxContentLength should be overridden by env var")
	assert.Equal(t, "file", cfg.Output, "Output should be overridden by env var")
	assert.Equal(t, "/tmp/activity.log", cfg.FilePath, "FilePath should be overridden by env var")
}

func TestActivityLoggingConfig_EnvironmentOverrides_EmptyEnv(t *testing.T) {
	// Save original env vars
	origEnabled := os.Getenv("GIBSON_ACTIVITY_LOG_ENABLED")
	origLevel := os.Getenv("GIBSON_ACTIVITY_LOG_LEVEL")
	origMaxContent := os.Getenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT")
	origOutput := os.Getenv("GIBSON_ACTIVITY_LOG_OUTPUT")
	origFile := os.Getenv("GIBSON_ACTIVITY_LOG_FILE")
	defer func() {
		os.Setenv("GIBSON_ACTIVITY_LOG_ENABLED", origEnabled)
		os.Setenv("GIBSON_ACTIVITY_LOG_LEVEL", origLevel)
		os.Setenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT", origMaxContent)
		os.Setenv("GIBSON_ACTIVITY_LOG_OUTPUT", origOutput)
		os.Setenv("GIBSON_ACTIVITY_LOG_FILE", origFile)
	}()

	// Clear environment variables
	os.Unsetenv("GIBSON_ACTIVITY_LOG_ENABLED")
	os.Unsetenv("GIBSON_ACTIVITY_LOG_LEVEL")
	os.Unsetenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT")
	os.Unsetenv("GIBSON_ACTIVITY_LOG_OUTPUT")
	os.Unsetenv("GIBSON_ACTIVITY_LOG_FILE")

	cfg := ActivityLoggingConfig{
		Enabled:          true,
		Level:            "normal",
		MaxContentLength: 500,
		Output:           "stdout",
		FilePath:         "",
		BufferSize:       10000,
	}

	cfg.ApplyEnvironmentOverrides()

	assert.True(t, cfg.Enabled, "Enabled should not change when env var is empty")
	assert.Equal(t, "normal", cfg.Level, "Level should not change when env var is empty")
	assert.Equal(t, 500, cfg.MaxContentLength, "MaxContentLength should not change when env var is empty")
	assert.Equal(t, "stdout", cfg.Output, "Output should not change when env var is empty")
	assert.Equal(t, "", cfg.FilePath, "FilePath should not change when env var is empty")
}

func TestActivityLoggingConfig_EnvironmentOverrides_InvalidValues(t *testing.T) {
	// Save original env vars
	origEnabled := os.Getenv("GIBSON_ACTIVITY_LOG_ENABLED")
	origMaxContent := os.Getenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT")
	defer func() {
		os.Setenv("GIBSON_ACTIVITY_LOG_ENABLED", origEnabled)
		os.Setenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT", origMaxContent)
	}()

	// Test with invalid environment variables
	os.Setenv("GIBSON_ACTIVITY_LOG_ENABLED", "invalid")
	os.Setenv("GIBSON_ACTIVITY_LOG_MAX_CONTENT", "notanumber")

	cfg := ActivityLoggingConfig{
		Enabled:          true,
		Level:            "normal",
		MaxContentLength: 500,
		Output:           "stdout",
	}

	cfg.ApplyEnvironmentOverrides()

	// Invalid values should be ignored, original values should remain
	assert.True(t, cfg.Enabled, "Enabled should not change with invalid env var")
	assert.Equal(t, 500, cfg.MaxContentLength, "MaxContentLength should not change with invalid env var")
}

func TestActivityLoggingConfig_Validation_ValidLevels(t *testing.T) {
	validator := NewValidator()

	validLevels := []string{"quiet", "normal", "verbose", "debug"}

	for _, level := range validLevels {
		t.Run(level, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ActivityLogging.Level = level

			err := validator.Validate(cfg)
			assert.NoError(t, err, "Level %s should be valid", level)
		})
	}
}

func TestActivityLoggingConfig_Validation_InvalidLevel(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.Level = "invalid"

	err := validator.Validate(cfg)
	assert.Error(t, err, "Invalid level should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.level must be one of [quiet, normal, verbose, debug]")
}

func TestActivityLoggingConfig_Validation_MaxContentLengthZero(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.MaxContentLength = 0

	err := validator.Validate(cfg)
	assert.Error(t, err, "MaxContentLength of 0 should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.max_content_length must be positive")
}

func TestActivityLoggingConfig_Validation_MaxContentLengthNegative(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.MaxContentLength = -100

	err := validator.Validate(cfg)
	assert.Error(t, err, "Negative MaxContentLength should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.max_content_length must be positive")
}

func TestActivityLoggingConfig_Validation_ValidOutputs(t *testing.T) {
	validator := NewValidator()

	validOutputs := []string{"stdout", "file", "both"}

	for _, output := range validOutputs {
		t.Run(output, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.ActivityLogging.Output = output

			// Set file path for file and both modes
			if output == "file" || output == "both" {
				cfg.ActivityLogging.FilePath = "/tmp/test.log"
			}

			err := validator.Validate(cfg)
			assert.NoError(t, err, "Output %s should be valid", output)
		})
	}
}

func TestActivityLoggingConfig_Validation_InvalidOutput(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.Output = "invalid"

	err := validator.Validate(cfg)
	assert.Error(t, err, "Invalid output should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.output must be one of [stdout, file, both]")
}

func TestActivityLoggingConfig_Validation_FilePathRequiredForFile(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.Output = "file"
	cfg.ActivityLogging.FilePath = ""

	err := validator.Validate(cfg)
	assert.Error(t, err, "Missing file path for 'file' output should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.file_path must be set when output is 'file' or 'both'")
}

func TestActivityLoggingConfig_Validation_FilePathRequiredForBoth(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.Output = "both"
	cfg.ActivityLogging.FilePath = ""

	err := validator.Validate(cfg)
	assert.Error(t, err, "Missing file path for 'both' output should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.file_path must be set when output is 'file' or 'both'")
}

func TestActivityLoggingConfig_Validation_FilePathNotRequiredForStdout(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.Output = "stdout"
	cfg.ActivityLogging.FilePath = ""

	err := validator.Validate(cfg)
	assert.NoError(t, err, "File path should not be required for 'stdout' output")
}

func TestActivityLoggingConfig_Validation_BufferSizeZero(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.BufferSize = 0

	err := validator.Validate(cfg)
	assert.Error(t, err, "BufferSize of 0 should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.buffer_size must be positive")
}

func TestActivityLoggingConfig_Validation_BufferSizeNegative(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.BufferSize = -100

	err := validator.Validate(cfg)
	assert.Error(t, err, "Negative BufferSize should cause validation error")
	assert.Contains(t, err.Error(), "activity_logging.buffer_size must be positive")
}

func TestActivityLoggingConfig_Validation_MultipleErrors(t *testing.T) {
	validator := NewValidator()

	cfg := DefaultConfig()
	cfg.ActivityLogging.Level = "invalid"
	cfg.ActivityLogging.MaxContentLength = -1
	cfg.ActivityLogging.Output = "file"
	cfg.ActivityLogging.FilePath = ""
	cfg.ActivityLogging.BufferSize = 0

	err := validator.Validate(cfg)
	assert.Error(t, err, "Multiple validation errors should be reported")
	assert.Contains(t, err.Error(), "activity_logging.level")
	assert.Contains(t, err.Error(), "activity_logging.max_content_length")
	assert.Contains(t, err.Error(), "activity_logging.file_path")
	assert.Contains(t, err.Error(), "activity_logging.buffer_size")
}

func TestLoadActivityLoggingFromYAML(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/gibson-test
  data_dir: /tmp/gibson-test/data
  cache_dir: /tmp/gibson-test/cache
  parallel_limit: 10
  timeout: 5m


security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true

activity_logging:
  enabled: true
  level: verbose
  max_content_length: 1000
  output: both
  file_path: /var/log/gibson/activity.log
  buffer_size: 20000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)

	// Verify activity logging config was loaded correctly
	assert.True(t, cfg.ActivityLogging.Enabled)
	assert.Equal(t, "verbose", cfg.ActivityLogging.Level)
	assert.Equal(t, 1000, cfg.ActivityLogging.MaxContentLength)
	assert.Equal(t, "both", cfg.ActivityLogging.Output)
	assert.Equal(t, "/var/log/gibson/activity.log", cfg.ActivityLogging.FilePath)
	assert.Equal(t, 20000, cfg.ActivityLogging.BufferSize)
}

func TestLoadActivityLoggingWithDefaults(t *testing.T) {
	// Create a temporary config file with minimal content (no activity_logging section)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/gibson-test
  data_dir: /tmp/gibson-test/data
  cache_dir: /tmp/gibson-test/cache
  parallel_limit: 10
  timeout: 5m


security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config with defaults
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.LoadWithDefaults(configPath)
	require.NoError(t, err)

	// Verify activity logging config has defaults
	assert.True(t, cfg.ActivityLogging.Enabled)
	assert.Equal(t, "normal", cfg.ActivityLogging.Level)
	assert.Equal(t, 500, cfg.ActivityLogging.MaxContentLength)
	assert.Equal(t, "stdout", cfg.ActivityLogging.Output)
	assert.Equal(t, "", cfg.ActivityLogging.FilePath)
	assert.Equal(t, 10000, cfg.ActivityLogging.BufferSize)
}

func TestActivityLoggingConfig_EnvVarInterpolation(t *testing.T) {
	// Set environment variables for interpolation
	os.Setenv("TEST_ACTIVITY_LOG_PATH", "/test/activity.log")
	defer os.Unsetenv("TEST_ACTIVITY_LOG_PATH")

	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `
core:
  home_dir: /tmp/gibson-test
  data_dir: /tmp/gibson-test/data
  cache_dir: /tmp/gibson-test/cache
  parallel_limit: 10
  timeout: 5m


security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true

activity_logging:
  enabled: true
  level: verbose
  max_content_length: 500
  output: file
  file_path: ${TEST_ACTIVITY_LOG_PATH}
  buffer_size: 10000
`

	err := os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Load the config
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.Load(configPath)
	require.NoError(t, err)

	// Verify environment variable was interpolated
	assert.Equal(t, "/test/activity.log", cfg.ActivityLogging.FilePath)
}
