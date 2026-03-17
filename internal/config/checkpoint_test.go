package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultCheckpointConfig(t *testing.T) {
	cfg := DefaultCheckpointConfig()
	require.NotNil(t, cfg)

	assert.True(t, cfg.Enabled)
	assert.True(t, cfg.AutoCheckpoint)
	assert.Equal(t, "gibson:checkpoint", cfg.KeyPrefix)
	assert.Equal(t, "msgpack", cfg.Format)
	assert.True(t, cfg.Compression.Enabled)
	assert.Equal(t, int64(10485760), cfg.Compression.Threshold)
	assert.False(t, cfg.Encryption.Enabled)
	assert.Equal(t, "kubernetes", cfg.Encryption.KeyProvider)
	assert.Equal(t, "final_only", cfg.Retention.DefaultMode)
	assert.Equal(t, 168*time.Hour, cfg.Retention.DefaultTTL)
	assert.Equal(t, 100, cfg.Retention.MaxCheckpoints)
	assert.Equal(t, int64(104857600), cfg.MaxCheckpointSize)
	assert.Equal(t, int64(1048576), cfg.LargeObjectThreshold)
	assert.False(t, cfg.RequireCheckpoints)
	assert.Equal(t, 24*time.Hour, cfg.ApprovalTimeout)
}

func TestCheckpointConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *CheckpointConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid default config",
			config:  DefaultCheckpointConfig(),
			wantErr: false,
		},
		{
			name: "invalid format",
			config: &CheckpointConfig{
				Format: "invalid",
			},
			wantErr: true,
			errMsg:  "invalid checkpoint format",
		},
		{
			name: "negative compression threshold",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   true,
					Threshold: -1,
				},
			},
			wantErr: true,
			errMsg:  "compression threshold must be non-negative",
		},
		{
			name: "invalid encryption provider",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled:     true,
					KeyProvider: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid encryption key provider",
		},
		{
			name: "invalid retention mode",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode: "invalid",
				},
			},
			wantErr: true,
			errMsg:  "invalid retention mode",
		},
		{
			name: "negative TTL",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode: "all",
					DefaultTTL:  -1 * time.Hour,
				},
			},
			wantErr: true,
			errMsg:  "retention TTL must be non-negative",
		},
		{
			name: "negative max checkpoints",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode:    "all",
					DefaultTTL:     24 * time.Hour,
					MaxCheckpoints: -1,
				},
			},
			wantErr: true,
			errMsg:  "max checkpoints must be non-negative",
		},
		{
			name: "negative max checkpoint size",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode:    "all",
					DefaultTTL:     24 * time.Hour,
					MaxCheckpoints: 100,
				},
				MaxCheckpointSize: -1,
			},
			wantErr: true,
			errMsg:  "max checkpoint size must be non-negative",
		},
		{
			name: "negative large object threshold",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode:    "all",
					DefaultTTL:     24 * time.Hour,
					MaxCheckpoints: 100,
				},
				MaxCheckpointSize:    1000,
				LargeObjectThreshold: -1,
			},
			wantErr: true,
			errMsg:  "large object threshold must be non-negative",
		},
		{
			name: "large object threshold exceeds max size",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode:    "all",
					DefaultTTL:     24 * time.Hour,
					MaxCheckpoints: 100,
				},
				MaxCheckpointSize:    1000,
				LargeObjectThreshold: 2000,
			},
			wantErr: true,
			errMsg:  "large object threshold",
		},
		{
			name: "negative approval timeout",
			config: &CheckpointConfig{
				Format: "msgpack",
				Compression: CompressionConfig{
					Enabled:   false,
					Threshold: 0,
				},
				Encryption: EncryptionConfig{
					Enabled: false,
				},
				Retention: RetentionConfigYAML{
					DefaultMode:    "all",
					DefaultTTL:     24 * time.Hour,
					MaxCheckpoints: 100,
				},
				MaxCheckpointSize:    1000,
				LargeObjectThreshold: 500,
				ApprovalTimeout:      -1 * time.Hour,
			},
			wantErr: true,
			errMsg:  "approval timeout must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestCheckpointConfigApplyDefaults(t *testing.T) {
	cfg := &CheckpointConfig{}
	cfg.ApplyDefaults()

	assert.Equal(t, "gibson:checkpoint", cfg.KeyPrefix)
	assert.Equal(t, "msgpack", cfg.Format)
	assert.Equal(t, int64(10485760), cfg.Compression.Threshold)
	assert.Equal(t, "kubernetes", cfg.Encryption.KeyProvider)
	assert.Equal(t, "final_only", cfg.Retention.DefaultMode)
	assert.Equal(t, 168*time.Hour, cfg.Retention.DefaultTTL)
	assert.Equal(t, 100, cfg.Retention.MaxCheckpoints)
	assert.Equal(t, int64(104857600), cfg.MaxCheckpointSize)
	assert.Equal(t, int64(1048576), cfg.LargeObjectThreshold)
	assert.Equal(t, 24*time.Hour, cfg.ApprovalTimeout)
}

func TestCheckpointConfigValidRetentionModes(t *testing.T) {
	modes := []string{"final_only", "all", "error_only", "none", "labeled"}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			cfg := DefaultCheckpointConfig()
			cfg.Retention.DefaultMode = mode
			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}

func TestCheckpointConfigValidFormats(t *testing.T) {
	formats := []string{"msgpack", "json"}

	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			cfg := DefaultCheckpointConfig()
			cfg.Format = format
			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}

func TestCheckpointConfigValidKeyProviders(t *testing.T) {
	providers := []string{"kubernetes", "vault", "aws_kms", "azure", "gcp"}

	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
			cfg := DefaultCheckpointConfig()
			cfg.Encryption.Enabled = true
			cfg.Encryption.KeyProvider = provider
			err := cfg.Validate()
			require.NoError(t, err)
		})
	}
}
