package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestCallbackConfig_YAMLMarshaling(t *testing.T) {
	// Create a config with callback settings
	cfg := &Config{
		Callback: CallbackConfig{
			Enabled:          true,
			ListenAddress:    "127.0.0.1:50002",
			AdvertiseAddress: "localhost:50002",
		},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	require.NoError(t, err, "Should marshal config to YAML")

	// Unmarshal back
	var cfg2 Config
	err = yaml.Unmarshal(data, &cfg2)
	require.NoError(t, err, "Should unmarshal YAML to config")

	// Verify callback config was preserved
	assert.Equal(t, cfg.Callback.Enabled, cfg2.Callback.Enabled, "Enabled should be preserved")
	assert.Equal(t, cfg.Callback.ListenAddress, cfg2.Callback.ListenAddress, "ListenAddress should be preserved")
	assert.Equal(t, cfg.Callback.AdvertiseAddress, cfg2.Callback.AdvertiseAddress, "AdvertiseAddress should be preserved")
}

func TestCallbackConfig_YAMLUnmarshalingWithoutCallback(t *testing.T) {
	// YAML without callback section (backward compatibility)
	yamlData := `
core:
  home_dir: /tmp/.gibson
  parallel_limit: 10
  timeout: 5m
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
`

	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err, "Should unmarshal YAML without callback section")

	// Callback should have zero values (which is fine, defaults are applied elsewhere)
	assert.False(t, cfg.Callback.Enabled, "Enabled should be false when not specified")
	assert.Equal(t, "", cfg.Callback.ListenAddress, "ListenAddress should be empty when not specified")
	assert.Equal(t, "", cfg.Callback.AdvertiseAddress, "AdvertiseAddress should be empty when not specified")
}

func TestCallbackConfig_YAMLUnmarshalingWithCallback(t *testing.T) {
	// YAML with callback section
	yamlData := `
callback:
  enabled: true
  listen_address: "0.0.0.0:50001"
  advertise_address: "gibson:50001"
`

	var cfg Config
	err := yaml.Unmarshal([]byte(yamlData), &cfg)
	require.NoError(t, err, "Should unmarshal YAML with callback section")

	// Verify callback config
	assert.True(t, cfg.Callback.Enabled, "Enabled should be true")
	assert.Equal(t, "0.0.0.0:50001", cfg.Callback.ListenAddress, "ListenAddress should match YAML")
	assert.Equal(t, "gibson:50001", cfg.Callback.AdvertiseAddress, "AdvertiseAddress should match YAML")
}

func TestCallbackConfig_YAMLFile(t *testing.T) {
	// Create a temporary YAML file
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	require.NoError(t, err, "Should create temp file")
	defer os.Remove(tmpfile.Name())

	yamlContent := `
callback:
  enabled: false
  listen_address: "127.0.0.1:9999"
  advertise_address: ""
`
	_, err = tmpfile.Write([]byte(yamlContent))
	require.NoError(t, err, "Should write to temp file")
	tmpfile.Close()

	// Read and unmarshal
	data, err := os.ReadFile(tmpfile.Name())
	require.NoError(t, err, "Should read temp file")

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	require.NoError(t, err, "Should unmarshal from file")

	// Verify
	assert.False(t, cfg.Callback.Enabled, "Enabled should be false")
	assert.Equal(t, "127.0.0.1:9999", cfg.Callback.ListenAddress, "ListenAddress should match file")
	assert.Equal(t, "", cfg.Callback.AdvertiseAddress, "AdvertiseAddress should be empty")
}
