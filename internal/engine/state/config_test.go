package state

import (
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.NotNil(t, cfg)
	assert.Equal(t, "redis://localhost:6379/0", cfg.URL)
	assert.Equal(t, 0, cfg.Database)
	assert.Equal(t, 10, cfg.PoolSize)
	assert.Equal(t, 5*time.Second, cfg.DialTimeout)
	assert.Equal(t, 3*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 3*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 2, cfg.MinIdleConns)
	assert.Equal(t, time.Duration(0), cfg.MaxConnAge)
	assert.Equal(t, 4*time.Second, cfg.PoolTimeout)
	assert.Equal(t, 5*time.Minute, cfg.IdleTimeout)
	assert.Equal(t, 1*time.Minute, cfg.IdleCheckFrequency)
	assert.False(t, cfg.ClusterMode)
	assert.False(t, cfg.TLSEnabled)
}

func TestConfigApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    *Config
		validate func(t *testing.T, cfg *Config)
	}{
		{
			name:  "empty config",
			input: &Config{},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "redis://localhost:6379/0", cfg.URL)
				assert.Equal(t, 10, cfg.PoolSize)
				assert.Equal(t, 5*time.Second, cfg.DialTimeout)
				assert.Equal(t, 3*time.Second, cfg.ReadTimeout)
				assert.Equal(t, 3*time.Second, cfg.WriteTimeout)
				assert.Equal(t, 3, cfg.MaxRetries)
				assert.Equal(t, 2, cfg.MinIdleConns)
				assert.Equal(t, 4*time.Second, cfg.PoolTimeout)
				assert.Equal(t, 5*time.Minute, cfg.IdleTimeout)
				assert.Equal(t, 1*time.Minute, cfg.IdleCheckFrequency)
			},
		},
		{
			name: "partial config",
			input: &Config{
				URL:      "redis://custom:6379",
				PoolSize: 20,
			},
			validate: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "redis://custom:6379", cfg.URL)
				assert.Equal(t, 20, cfg.PoolSize)
				assert.Equal(t, 5*time.Second, cfg.DialTimeout)
				assert.Equal(t, 3*time.Second, cfg.ReadTimeout)
			},
		},
		{
			name: "cluster mode - no default URL",
			input: &Config{
				ClusterMode:  true,
				ClusterAddrs: []string{"node1:6379"},
			},
			validate: func(t *testing.T, cfg *Config) {
				// URL should not be set for cluster mode
				assert.Empty(t, cfg.URL)
				assert.Equal(t, 10, cfg.PoolSize)
			},
		},
		{
			name: "sentinel mode - no default URL",
			input: &Config{
				SentinelMaster: "mymaster",
				SentinelAddrs:  []string{"sentinel:26379"},
			},
			validate: func(t *testing.T, cfg *Config) {
				// URL should not be set for sentinel mode
				assert.Empty(t, cfg.URL)
				assert.Equal(t, 10, cfg.PoolSize)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.ApplyDefaults()
			tt.validate(t, tt.input)
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
		errorType   error
	}{
		{
			name: "valid standalone config",
			config: &Config{
				URL: "redis://localhost:6379",
			},
			expectError: false,
		},
		{
			name: "valid cluster config",
			config: &Config{
				ClusterMode: true,
				ClusterAddrs: []string{
					"node1:6379",
					"node2:6379",
				},
			},
			expectError: false,
		},
		{
			name: "valid sentinel config",
			config: &Config{
				SentinelMaster: "mymaster",
				SentinelAddrs: []string{
					"sentinel1:26379",
					"sentinel2:26379",
				},
			},
			expectError: false,
		},
		{
			name:        "no connection method specified",
			config:      &Config{},
			expectError: true,
		},
		{
			name: "cluster mode without addresses",
			config: &Config{
				ClusterMode: true,
			},
			expectError: true,
		},
		{
			name: "sentinel mode without addresses",
			config: &Config{
				SentinelMaster: "mymaster",
			},
			expectError: true,
		},
		{
			name: "invalid database number - negative",
			config: &Config{
				URL:      "redis://localhost:6379",
				Database: -1,
			},
			expectError: true,
		},
		{
			name: "invalid database number - too high",
			config: &Config{
				URL:      "redis://localhost:6379",
				Database: 16,
			},
			expectError: true,
		},
		{
			name: "valid database number",
			config: &Config{
				URL:      "redis://localhost:6379",
				Database: 5,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConfigTLS(t *testing.T) {
	cfg := &Config{
		URL:        "redis://localhost:6379",
		TLSEnabled: true,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	assert.True(t, cfg.TLSEnabled)
	assert.NotNil(t, cfg.TLSConfig)
	assert.True(t, cfg.TLSConfig.InsecureSkipVerify)
}

func TestConfigTimeouts(t *testing.T) {
	cfg := &Config{
		URL:          "redis://localhost:6379",
		DialTimeout:  10 * time.Second,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	cfg.ApplyDefaults()

	assert.Equal(t, 10*time.Second, cfg.DialTimeout)
	assert.Equal(t, 5*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 5*time.Second, cfg.WriteTimeout)
	// PoolTimeout should default to ReadTimeout + 1s
	assert.Equal(t, 6*time.Second, cfg.PoolTimeout)
}

func TestConfigPoolSettings(t *testing.T) {
	cfg := &Config{
		URL:          "redis://localhost:6379",
		PoolSize:     50,
		MinIdleConns: 10,
		MaxConnAge:   1 * time.Hour,
	}

	assert.Equal(t, 50, cfg.PoolSize)
	assert.Equal(t, 10, cfg.MinIdleConns)
	assert.Equal(t, 1*time.Hour, cfg.MaxConnAge)
}

func TestConfigPassword(t *testing.T) {
	cfg := &Config{
		URL:      "redis://localhost:6379",
		Password: "secretpassword",
	}

	assert.Equal(t, "secretpassword", cfg.Password)
}

func TestConfigSentinelPassword(t *testing.T) {
	cfg := &Config{
		SentinelMaster:   "mymaster",
		SentinelAddrs:    []string{"sentinel:26379"},
		SentinelPassword: "sentinelpass",
		Password:         "redispass",
	}

	err := cfg.Validate()
	require.NoError(t, err)

	assert.Equal(t, "sentinelpass", cfg.SentinelPassword)
	assert.Equal(t, "redispass", cfg.Password)
}
