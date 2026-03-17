package config

import (
	"fmt"
	"time"
)

// CheckpointConfig contains configuration for the checkpointing system.
// This controls checkpoint creation, serialization, compression, encryption,
// retention, and human-in-the-loop approval workflows.
type CheckpointConfig struct {
	// Core settings
	Enabled        bool   `mapstructure:"enabled" yaml:"enabled"`
	AutoCheckpoint bool   `mapstructure:"auto_checkpoint" yaml:"auto_checkpoint"`
	KeyPrefix      string `mapstructure:"key_prefix" yaml:"key_prefix"`

	// Serialization
	Format      string            `mapstructure:"format" yaml:"format"` // msgpack or json
	Compression CompressionConfig `mapstructure:"compression" yaml:"compression"`

	// Encryption
	Encryption EncryptionConfig `mapstructure:"encryption" yaml:"encryption"`

	// Retention
	Retention RetentionConfigYAML `mapstructure:"retention" yaml:"retention"`

	// Limits
	MaxCheckpointSize    int64 `mapstructure:"max_checkpoint_size" yaml:"max_checkpoint_size"`
	LargeObjectThreshold int64 `mapstructure:"large_object_threshold" yaml:"large_object_threshold"`

	// Performance
	RequireCheckpoints bool `mapstructure:"require_checkpoints" yaml:"require_checkpoints"`

	// Human-in-the-loop
	ApprovalTimeout time.Duration `mapstructure:"approval_timeout" yaml:"approval_timeout"`
}

// CompressionConfig contains configuration for checkpoint compression.
type CompressionConfig struct {
	Enabled   bool  `mapstructure:"enabled" yaml:"enabled"`
	Threshold int64 `mapstructure:"threshold" yaml:"threshold"` // bytes
}

// EncryptionConfig contains configuration for checkpoint encryption.
type EncryptionConfig struct {
	Enabled       bool   `mapstructure:"enabled" yaml:"enabled"`
	KeyProvider   string `mapstructure:"key_provider" yaml:"key_provider"` // kubernetes, vault, aws_kms, etc.
	KeySecretName string `mapstructure:"key_secret_name" yaml:"key_secret_name"`
}

// RetentionConfigYAML contains configuration for checkpoint retention policies
// as specified in YAML configuration files. This is separate from the internal
// checkpoint.RetentionConfig to handle YAML-specific fields and conversions.
type RetentionConfigYAML struct {
	DefaultMode    string        `mapstructure:"default_mode" yaml:"default_mode"` // final_only, all, error_only
	DefaultTTL     time.Duration `mapstructure:"default_ttl" yaml:"default_ttl"`
	MaxCheckpoints int           `mapstructure:"max_checkpoints_per_thread" yaml:"max_checkpoints_per_thread"`
}

// DefaultCheckpointConfig returns a sensible default checkpoint configuration.
// These defaults balance storage costs with debugging needs and are production-ready.
func DefaultCheckpointConfig() *CheckpointConfig {
	return &CheckpointConfig{
		Enabled:        true,
		AutoCheckpoint: true,
		KeyPrefix:      "gibson:checkpoint",
		Format:         "msgpack",
		Compression: CompressionConfig{
			Enabled:   true,
			Threshold: 10485760, // 10MB
		},
		Encryption: EncryptionConfig{
			Enabled:     false,
			KeyProvider: "kubernetes",
		},
		Retention: RetentionConfigYAML{
			DefaultMode:    "final_only",
			DefaultTTL:     168 * time.Hour, // 7 days
			MaxCheckpoints: 100,
		},
		MaxCheckpointSize:    104857600, // 100MB
		LargeObjectThreshold: 1048576,   // 1MB
		RequireCheckpoints:   false,
		ApprovalTimeout:      24 * time.Hour,
	}
}

// Validate validates the checkpoint configuration.
// Returns an error if the configuration is invalid.
func (c *CheckpointConfig) Validate() error {
	// Validate format
	if c.Format != "msgpack" && c.Format != "json" {
		return fmt.Errorf("invalid checkpoint format: %s (must be msgpack or json)", c.Format)
	}

	// Validate compression threshold
	if c.Compression.Enabled && c.Compression.Threshold < 0 {
		return fmt.Errorf("compression threshold must be non-negative, got: %d", c.Compression.Threshold)
	}

	// Validate encryption key provider
	if c.Encryption.Enabled {
		validProviders := map[string]bool{
			"kubernetes": true,
			"vault":      true,
			"aws_kms":    true,
			"azure":      true,
			"gcp":        true,
		}
		if !validProviders[c.Encryption.KeyProvider] {
			return fmt.Errorf("invalid encryption key provider: %s (must be one of: kubernetes, vault, aws_kms, azure, gcp)", c.Encryption.KeyProvider)
		}
	}

	// Validate retention mode
	validModes := map[string]bool{
		"final_only": true,
		"all":        true,
		"error_only": true,
		"none":       true,
		"labeled":    true,
	}
	if !validModes[c.Retention.DefaultMode] {
		return fmt.Errorf("invalid retention mode: %s (must be one of: final_only, all, error_only, none, labeled)", c.Retention.DefaultMode)
	}

	// Validate TTL
	if c.Retention.DefaultTTL < 0 {
		return fmt.Errorf("retention TTL must be non-negative, got: %v", c.Retention.DefaultTTL)
	}

	// Validate max checkpoints
	if c.Retention.MaxCheckpoints < 0 {
		return fmt.Errorf("max checkpoints must be non-negative, got: %d", c.Retention.MaxCheckpoints)
	}

	// Validate checkpoint size limits
	if c.MaxCheckpointSize < 0 {
		return fmt.Errorf("max checkpoint size must be non-negative, got: %d", c.MaxCheckpointSize)
	}

	if c.LargeObjectThreshold < 0 {
		return fmt.Errorf("large object threshold must be non-negative, got: %d", c.LargeObjectThreshold)
	}

	if c.LargeObjectThreshold > c.MaxCheckpointSize {
		return fmt.Errorf("large object threshold (%d) cannot exceed max checkpoint size (%d)", c.LargeObjectThreshold, c.MaxCheckpointSize)
	}

	// Validate approval timeout
	if c.ApprovalTimeout < 0 {
		return fmt.Errorf("approval timeout must be non-negative, got: %v", c.ApprovalTimeout)
	}

	return nil
}

// TODO: Once the checkpoint package compilation errors are fixed, uncomment these conversion methods:
//
// ToCheckpointerConfig converts the YAML config to an internal CheckpointerConfig.
// This is used when initializing the checkpointing system.
//
// func (c *CheckpointConfig) ToCheckpointerConfig() checkpoint.CheckpointerConfig {
// 	config := checkpoint.DefaultCheckpointerConfig()
//
// 	// Configure serialization format
// 	if c.Format == "json" {
// 		config.Serialization.Format = checkpoint.FormatJSON
// 	} else {
// 		config.Serialization.Format = checkpoint.FormatMessagePack
// 	}
//
// 	// Configure compression
// 	config.Compression.Enabled = c.Compression.Enabled
// 	config.Compression.Threshold = c.Compression.Threshold
//
// 	// Configure encryption (KeyProvider is set separately during initialization)
// 	config.Encryption.Enabled = c.Encryption.Enabled
//
// 	// Configure blob threshold for large objects
// 	config.BlobThreshold = c.LargeObjectThreshold
//
// 	// Configure default TTL
// 	config.DefaultTTL = c.Retention.DefaultTTL
//
// 	return config
// }
//
// ToPolicyConfig converts the YAML config to an internal PolicyConfig.
// This is used when initializing the checkpoint retention policy.
//
// func (c *CheckpointConfig) ToPolicyConfig() checkpoint.PolicyConfig {
// 	config := checkpoint.DefaultPolicyConfig()
//
// 	// Configure auto-checkpoint behavior
// 	config.AutoCheckpoint = c.AutoCheckpoint
//
// 	// Convert retention mode string to internal type
// 	var defaultMode checkpoint.RetentionMode
// 	switch c.Retention.DefaultMode {
// 	case "final_only":
// 		defaultMode = checkpoint.RetentionFinalOnly
// 	case "all":
// 		defaultMode = checkpoint.RetentionAll
// 	case "error_only":
// 		defaultMode = checkpoint.RetentionErrorOnly
// 	case "none":
// 		defaultMode = checkpoint.RetentionNone
// 	case "labeled":
// 		defaultMode = checkpoint.RetentionLabeled
// 	default:
// 		defaultMode = checkpoint.RetentionFinalOnly
// 	}
//
// 	config.DefaultMode = defaultMode
// 	config.DefaultTTL = c.Retention.DefaultTTL
// 	config.MaxCheckpoints = c.Retention.MaxCheckpoints
//
// 	// Use the same retention mode for completed missions by default
// 	config.CompletedRetention = checkpoint.RetentionConfig{
// 		Mode:        defaultMode,
// 		TTL:         c.Retention.DefaultTTL,
// 		MaxCount:    c.Retention.MaxCheckpoints,
// 		MinInterval: 30 * time.Second,
// 	}
//
// 	// More generous retention for failed missions (for debugging)
// 	config.FailedRetention = checkpoint.RetentionConfig{
// 		Mode:        checkpoint.RetentionAll,
// 		TTL:         30 * 24 * time.Hour, // 30 days
// 		MaxCount:    0,                   // Unlimited
// 		MinInterval: 30 * time.Second,
// 	}
//
// 	// Shorter retention for cancelled missions
// 	config.CancelledRetention = checkpoint.RetentionConfig{
// 		Mode:        checkpoint.RetentionFinalOnly,
// 		TTL:         3 * 24 * time.Hour, // 3 days
// 		MaxCount:    5,
// 		MinInterval: 30 * time.Second,
// 	}
//
// 	// Keep all checkpoints while paused
// 	config.PausedRetention = checkpoint.RetentionConfig{
// 		Mode:        checkpoint.RetentionAll,
// 		TTL:         0, // No TTL while paused
// 		MaxCount:    0, // Unlimited
// 		MinInterval: 30 * time.Second,
// 	}
//
// 	return config
// }
//
// ToApprovalConfig converts the YAML config to an internal ApprovalConfig.
// This is used when initializing the approval management system.
//
// func (c *CheckpointConfig) ToApprovalConfig() checkpoint.ApprovalConfig {
// 	return checkpoint.ApprovalConfig{
// 		DefaultTimeout: c.ApprovalTimeout,
// 		MaxTimeout:     7 * 24 * time.Hour, // 7 days max
// 		EventEmitter:   nil,                // Set separately during initialization
// 		ResumeDelay:    500 * time.Millisecond,
// 	}
// }

// ApplyDefaults fills in zero-valued fields with sensible defaults.
// This is useful when loading partial configurations from files or environment.
func (c *CheckpointConfig) ApplyDefaults() {
	defaults := DefaultCheckpointConfig()

	if c.KeyPrefix == "" {
		c.KeyPrefix = defaults.KeyPrefix
	}

	if c.Format == "" {
		c.Format = defaults.Format
	}

	if c.Compression.Threshold == 0 {
		c.Compression.Threshold = defaults.Compression.Threshold
	}

	if c.Encryption.KeyProvider == "" {
		c.Encryption.KeyProvider = defaults.Encryption.KeyProvider
	}

	if c.Retention.DefaultMode == "" {
		c.Retention.DefaultMode = defaults.Retention.DefaultMode
	}

	if c.Retention.DefaultTTL == 0 {
		c.Retention.DefaultTTL = defaults.Retention.DefaultTTL
	}

	if c.Retention.MaxCheckpoints == 0 {
		c.Retention.MaxCheckpoints = defaults.Retention.MaxCheckpoints
	}

	if c.MaxCheckpointSize == 0 {
		c.MaxCheckpointSize = defaults.MaxCheckpointSize
	}

	if c.LargeObjectThreshold == 0 {
		c.LargeObjectThreshold = defaults.LargeObjectThreshold
	}

	if c.ApprovalTimeout == 0 {
		c.ApprovalTimeout = defaults.ApprovalTimeout
	}
}
