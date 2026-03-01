package config

import (
	"os"
	"testing"
)

func TestDaemonConfig_Default(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Daemon.GRPCAddress != "localhost:50002" {
		t.Errorf("expected default GRPCAddress to be 'localhost:50002', got %q", cfg.Daemon.GRPCAddress)
	}
}

func TestDaemonConfig_EnvironmentVariable(t *testing.T) {
	// Set environment variable
	testAddr := "${GIBSON_DAEMON_GRPC_ADDR}"
	os.Setenv("GIBSON_DAEMON_GRPC_ADDR", "localhost:9999")
	defer os.Unsetenv("GIBSON_DAEMON_GRPC_ADDR")

	// Test interpolation
	result := interpolateString(testAddr)
	if result != "localhost:9999" {
		t.Errorf("expected interpolated address to be 'localhost:9999', got %q", result)
	}
}

func TestDaemonConfig_ConfigFileValue(t *testing.T) {
	// Create a temporary config file
	tmpfile, err := os.CreateTemp("", "gibson-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configContent := `
core:
  home_dir: /tmp/gibson
  data_dir: /tmp/gibson/data
  cache_dir: /tmp/gibson/cache
  parallel_limit: 10
  timeout: 5m
  debug: false
database:
  path: /tmp/gibson/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
daemon:
  grpc_address: localhost:7777
activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Daemon.GRPCAddress != "localhost:7777" {
		t.Errorf("expected GRPCAddress to be 'localhost:7777', got %q", cfg.Daemon.GRPCAddress)
	}
}

func TestDaemonConfig_EnvVarInterpolation(t *testing.T) {
	// Set environment variable
	os.Setenv("DAEMON_PORT", "8888")
	defer os.Unsetenv("DAEMON_PORT")

	// Create a temporary config file with env var
	tmpfile, err := os.CreateTemp("", "gibson-config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	configContent := `
core:
  home_dir: /tmp/gibson
  data_dir: /tmp/gibson/data
  cache_dir: /tmp/gibson/cache
  parallel_limit: 10
  timeout: 5m
  debug: false
database:
  path: /tmp/gibson/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
daemon:
  grpc_address: localhost:${DAEMON_PORT}
activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Load config
	validator := NewValidator()
	loader := NewConfigLoader(validator)
	cfg, err := loader.Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.Daemon.GRPCAddress != "localhost:8888" {
		t.Errorf("expected GRPCAddress to be 'localhost:8888', got %q", cfg.Daemon.GRPCAddress)
	}
}
