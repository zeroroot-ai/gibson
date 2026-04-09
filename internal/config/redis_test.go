package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisConfig_Defaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "redis://localhost:6379", cfg.Redis.URL)
	assert.Equal(t, "", cfg.Redis.Password)
	assert.Equal(t, 0, cfg.Redis.Database)
	assert.Equal(t, 10, cfg.Redis.PoolSize)
	assert.Equal(t, 5*time.Second, cfg.Redis.ConnectTimeout)
	assert.Equal(t, 3*time.Second, cfg.Redis.ReadTimeout)
	assert.Equal(t, 3*time.Second, cfg.Redis.WriteTimeout)
	assert.Equal(t, 3, cfg.Redis.MaxRetries)
	assert.False(t, cfg.Redis.ClusterMode)
	assert.Empty(t, cfg.Redis.ClusterAddrs)
	assert.Equal(t, "", cfg.Redis.SentinelMaster)
	assert.Empty(t, cfg.Redis.SentinelAddrs)
	assert.False(t, cfg.Redis.TLSEnabled)
	assert.Equal(t, "", cfg.Redis.TLSCertFile)
	assert.Equal(t, "", cfg.Redis.TLSKeyFile)
	assert.Equal(t, "", cfg.Redis.TLSCAFile)
}

func TestRedisConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		config   RedisConfig
		expected RedisConfig
	}{
		{
			name:   "empty config gets all defaults",
			config: RedisConfig{},
			expected: RedisConfig{
				URL:            "redis://localhost:6379",
				Database:       0,
				PoolSize:       10,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
				MaxRetries:     3,
			},
		},
		{
			name: "partial config preserves custom values",
			config: RedisConfig{
				URL:      "redis://custom:6380",
				PoolSize: 20,
			},
			expected: RedisConfig{
				URL:            "redis://custom:6380",
				Database:       0,
				PoolSize:       20,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
				MaxRetries:     3,
			},
		},
		{
			name: "cluster mode doesn't set URL",
			config: RedisConfig{
				ClusterMode:  true,
				ClusterAddrs: []string{"node1:6379", "node2:6379"},
			},
			expected: RedisConfig{
				ClusterMode:    true,
				ClusterAddrs:   []string{"node1:6379", "node2:6379"},
				Database:       0,
				PoolSize:       10,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
				MaxRetries:     3,
			},
		},
		{
			name: "sentinel mode doesn't set URL",
			config: RedisConfig{
				SentinelMaster: "mymaster",
				SentinelAddrs:  []string{"sentinel1:26379"},
			},
			expected: RedisConfig{
				SentinelMaster: "mymaster",
				SentinelAddrs:  []string{"sentinel1:26379"},
				Database:       0,
				PoolSize:       10,
				ConnectTimeout: 5 * time.Second,
				ReadTimeout:    3 * time.Second,
				WriteTimeout:   3 * time.Second,
				MaxRetries:     3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config
			cfg.ApplyDefaults()
			assert.Equal(t, tt.expected, cfg)
		})
	}
}

func TestRedisConfig_EnvVarInterpolation(t *testing.T) {
	// Set environment variables
	os.Setenv("TEST_REDIS_PASSWORD", "secret123")
	os.Setenv("TEST_REDIS_URL", "redis://prod:6379")
	os.Setenv("TEST_TLS_CERT", "/path/to/cert.pem")
	defer func() {
		os.Unsetenv("TEST_REDIS_PASSWORD")
		os.Unsetenv("TEST_REDIS_URL")
		os.Unsetenv("TEST_TLS_CERT")
	}()

	// Create a test config file
	configContent := `
core:
  home_dir: ~/.gibson
  parallel_limit: 10
  timeout: 5m
database:
  path: ~/.gibson/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
logging:
  level: info
  format: json
tracing:
  enabled: false
metrics:
  enabled: false
  port: 9090
registry:
  type: embedded
  namespace: gibson
  ttl: 30s
daemon:
  grpc_address: localhost:50002
redis:
  url: "${TEST_REDIS_URL}"
  password: "${TEST_REDIS_PASSWORD}"
  database: 1
  pool_size: 20
  connect_timeout: 10s
  read_timeout: 5s
  write_timeout: 5s
  max_retries: 5
  tls_enabled: true
  tls_cert_file: "${TEST_TLS_CERT}"
  tls_key_file: "/path/to/key.pem"
  tls_ca_file: "/path/to/ca.pem"
activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	tmpFile, err := os.CreateTemp("", "redis-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(configContent))
	require.NoError(t, err)
	tmpFile.Close()

	// Load config
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.Load(tmpFile.Name())
	require.NoError(t, err)

	// Verify environment variable interpolation
	assert.Equal(t, "redis://prod:6379", cfg.Redis.URL, "URL should be interpolated")
	assert.Equal(t, "secret123", cfg.Redis.Password, "Password should be interpolated")
	assert.Equal(t, "/path/to/cert.pem", cfg.Redis.TLSCertFile, "TLS cert file should be interpolated")
	assert.Equal(t, "/path/to/key.pem", cfg.Redis.TLSKeyFile)
	assert.Equal(t, "/path/to/ca.pem", cfg.Redis.TLSCAFile)

	// Verify other fields
	assert.Equal(t, 1, cfg.Redis.Database)
	assert.Equal(t, 20, cfg.Redis.PoolSize)
	assert.Equal(t, 10*time.Second, cfg.Redis.ConnectTimeout)
	assert.Equal(t, 5*time.Second, cfg.Redis.ReadTimeout)
	assert.Equal(t, 5*time.Second, cfg.Redis.WriteTimeout)
	assert.Equal(t, 5, cfg.Redis.MaxRetries)
	assert.True(t, cfg.Redis.TLSEnabled)
}

func TestRedisConfig_ClusterModeInterpolation(t *testing.T) {
	// Set environment variables
	os.Setenv("TEST_NODE1", "node1.example.com:6379")
	os.Setenv("TEST_NODE2", "node2.example.com:6379")
	defer func() {
		os.Unsetenv("TEST_NODE1")
		os.Unsetenv("TEST_NODE2")
	}()

	configContent := `
core:
  home_dir: ~/.gibson
  parallel_limit: 10
  timeout: 5m
database:
  path: ~/.gibson/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
logging:
  level: info
  format: json
tracing:
  enabled: false
metrics:
  enabled: false
  port: 9090
registry:
  type: embedded
  namespace: gibson
  ttl: 30s
daemon:
  grpc_address: localhost:50002
redis:
  cluster_mode: true
  cluster_addrs:
    - "${TEST_NODE1}"
    - "${TEST_NODE2}"
    - "node3.example.com:6379"
  password: "clusterpass"
  pool_size: 30
activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	tmpFile, err := os.CreateTemp("", "redis-cluster-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(configContent))
	require.NoError(t, err)
	tmpFile.Close()

	// Load config
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.Load(tmpFile.Name())
	require.NoError(t, err)

	// Verify cluster configuration
	assert.True(t, cfg.Redis.ClusterMode)
	assert.Len(t, cfg.Redis.ClusterAddrs, 3)
	assert.Equal(t, "node1.example.com:6379", cfg.Redis.ClusterAddrs[0], "First cluster address should be interpolated")
	assert.Equal(t, "node2.example.com:6379", cfg.Redis.ClusterAddrs[1], "Second cluster address should be interpolated")
	assert.Equal(t, "node3.example.com:6379", cfg.Redis.ClusterAddrs[2])
	assert.Equal(t, "clusterpass", cfg.Redis.Password)
	assert.Equal(t, 30, cfg.Redis.PoolSize)
}

func TestRedisConfig_SentinelModeInterpolation(t *testing.T) {
	// Set environment variables
	os.Setenv("TEST_SENTINEL_MASTER", "mymaster")
	os.Setenv("TEST_SENTINEL1", "sentinel1.example.com:26379")
	defer func() {
		os.Unsetenv("TEST_SENTINEL_MASTER")
		os.Unsetenv("TEST_SENTINEL1")
	}()

	configContent := `
core:
  home_dir: ~/.gibson
  parallel_limit: 10
  timeout: 5m
database:
  path: ~/.gibson/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
logging:
  level: info
  format: json
tracing:
  enabled: false
metrics:
  enabled: false
  port: 9090
registry:
  type: embedded
  namespace: gibson
  ttl: 30s
daemon:
  grpc_address: localhost:50002
redis:
  sentinel_master: "${TEST_SENTINEL_MASTER}"
  sentinel_addrs:
    - "${TEST_SENTINEL1}"
    - "sentinel2.example.com:26379"
  password: "sentinelpass"
activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	tmpFile, err := os.CreateTemp("", "redis-sentinel-config-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(configContent))
	require.NoError(t, err)
	tmpFile.Close()

	// Load config
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.Load(tmpFile.Name())
	require.NoError(t, err)

	// Verify sentinel configuration
	assert.Equal(t, "mymaster", cfg.Redis.SentinelMaster, "Sentinel master should be interpolated")
	assert.Len(t, cfg.Redis.SentinelAddrs, 2)
	assert.Equal(t, "sentinel1.example.com:26379", cfg.Redis.SentinelAddrs[0], "First sentinel address should be interpolated")
	assert.Equal(t, "sentinel2.example.com:26379", cfg.Redis.SentinelAddrs[1])
	assert.Equal(t, "sentinelpass", cfg.Redis.Password)
}

func TestRedisConfig_DeprecationWarning(t *testing.T) {
	configContent := `
core:
  home_dir: ~/.gibson
  parallel_limit: 10
  timeout: 5m
database:
  path: ~/.gibson/gibson.db
  max_connections: 10
  timeout: 30s
  wal_mode: true
  auto_vacuum: true
security:
  encryption_algorithm: aes-256-gcm
  key_derivation: scrypt
  ssl_validation: true
  audit_logging: true
logging:
  level: info
  format: json
tracing:
  enabled: false
metrics:
  enabled: false
  port: 9090
registry:
  type: embedded
  namespace: gibson
  ttl: 30s
daemon:
  grpc_address: localhost:50002
redis:
  url: redis://localhost:6379
  database: 0
activity_logging:
  enabled: true
  level: normal
  max_content_length: 500
  output: stdout
  buffer_size: 10000
`

	tmpFile, err := os.CreateTemp("", "redis-deprecation-*.yaml")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write([]byte(configContent))
	require.NoError(t, err)
	tmpFile.Close()

	// Load config - should succeed and log a warning about deprecated database section
	loader := NewConfigLoader(NewValidator())
	cfg, err := loader.Load(tmpFile.Name())
	require.NoError(t, err, "Config should load successfully and just warn about deprecated database section")
	assert.NotNil(t, cfg)

	// Verify Redis config is loaded (database section is ignored)
	assert.NotEmpty(t, cfg.Redis.URL)
	assert.Equal(t, "redis://localhost:6379", cfg.Redis.URL)
}
