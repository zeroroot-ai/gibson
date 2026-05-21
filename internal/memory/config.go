package memory

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// MemoryConfig is the top-level memory configuration.
// It contains configuration for all three memory tiers: working, mission, and long-term.
type MemoryConfig struct {
	Working  WorkingMemoryConfig  `mapstructure:"working" yaml:"working" json:"working"`
	Mission  MissionMemoryConfig  `mapstructure:"mission" yaml:"mission" json:"mission"`
	LongTerm LongTermMemoryConfig `mapstructure:"long_term" yaml:"long_term" json:"long_term"`
}

// Validate performs validation on the MemoryConfig.
// It validates each sub-configuration and ensures all required fields are present.
func (c *MemoryConfig) Validate() error {
	if err := c.Working.Validate(); err != nil {
		return types.WrapError(types.CONFIG_VALIDATION_FAILED, "working memory config validation failed", err)
	}

	if err := c.Mission.Validate(); err != nil {
		return types.WrapError(types.CONFIG_VALIDATION_FAILED, "mission memory config validation failed", err)
	}

	if err := c.LongTerm.Validate(); err != nil {
		return types.WrapError(types.CONFIG_VALIDATION_FAILED, "long-term memory config validation failed", err)
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
func (c *MemoryConfig) ApplyDefaults() {
	c.Working.ApplyDefaults()
	c.Mission.ApplyDefaults()
	c.LongTerm.ApplyDefaults()
}

// WorkingMemoryConfig configures working memory behavior.
// Working memory is ephemeral key-value storage with token budget management.
type WorkingMemoryConfig struct {
	MaxTokens      int    `mapstructure:"max_tokens" yaml:"max_tokens" json:"max_tokens"`
	EvictionPolicy string `mapstructure:"eviction_policy" yaml:"eviction_policy" json:"eviction_policy"`
}

// Validate performs validation on the WorkingMemoryConfig.
func (c *WorkingMemoryConfig) Validate() error {
	if c.MaxTokens <= 0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("working memory max_tokens must be greater than 0, got %d", c.MaxTokens))
	}

	// Validate eviction policy
	validPolicies := map[string]bool{
		"lru": true, // Least Recently Used (default)
	}

	if !validPolicies[c.EvictionPolicy] {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid eviction_policy '%s', must be one of: lru", c.EvictionPolicy))
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
func (c *WorkingMemoryConfig) ApplyDefaults() {
	if c.MaxTokens == 0 {
		c.MaxTokens = 100000 // Default: 100K tokens
	}
	if c.EvictionPolicy == "" {
		c.EvictionPolicy = "lru" // Default: LRU eviction
	}
}

// MissionMemoryConfig configures mission memory behavior.
// Mission memory is persistent Redis storage with RediSearch for FTS and configurable TTLs.
type MissionMemoryConfig struct {
	CacheSize int  `mapstructure:"cache_size" yaml:"cache_size" json:"cache_size"`
	EnableFTS bool `mapstructure:"enable_fts" yaml:"enable_fts" json:"enable_fts"`

	// TTL is the default time-to-live for mission memory keys.
	// Keys are refreshed on every read/write access. After a mission completes
	// or becomes inactive for this duration, its memory keys expire automatically.
	// Set to 0 to disable TTL (keys persist indefinitely). Default: 24h.
	TTL time.Duration `mapstructure:"ttl" yaml:"ttl" json:"ttl"`

	// CompletedTTL is the TTL applied to mission memory keys after a mission completes.
	// This allows faster cleanup of finished missions while keeping active ones longer.
	// Set to 0 to use the default TTL for completed missions. Default: 2h.
	CompletedTTL time.Duration `mapstructure:"completed_ttl" yaml:"completed_ttl" json:"completed_ttl"`
}

// Validate performs validation on the MissionMemoryConfig.
func (c *MissionMemoryConfig) Validate() error {
	if c.CacheSize < 0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("mission memory cache_size cannot be negative, got %d", c.CacheSize))
	}

	if c.TTL < 0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("mission memory ttl cannot be negative, got %v", c.TTL))
	}

	if c.CompletedTTL < 0 {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("mission memory completed_ttl cannot be negative, got %v", c.CompletedTTL))
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
func (c *MissionMemoryConfig) ApplyDefaults() {
	if c.CacheSize == 0 {
		c.CacheSize = 1000 // Default: 1000 entries
	}
	if c.TTL == 0 {
		c.TTL = 24 * time.Hour // Default: 24 hours
	}
	if c.CompletedTTL == 0 {
		c.CompletedTTL = 2 * time.Hour // Default: 2 hours for completed missions
	}
	// EnableFTS defaults to true (zero value for bool is false, so we need special handling)
	// This will be set explicitly in code when config is loaded
}

// LongTermMemoryConfig configures long-term memory (vector store).
// Long-term memory provides semantic search over historical data using embeddings.
type LongTermMemoryConfig struct {
	Backend       string         `mapstructure:"backend" yaml:"backend" json:"backend"`
	ConnectionURL string         `mapstructure:"connection_url" yaml:"connection_url" json:"connection_url"`
	StoragePath   string         `mapstructure:"storage_path" yaml:"storage_path" json:"storage_path"`
	Embedder      EmbedderConfig `mapstructure:"embedder" yaml:"embedder" json:"embedder"`
}

// Validate performs validation on the LongTermMemoryConfig.
func (c *LongTermMemoryConfig) Validate() error {
	// Validate backend type
	validBackends := map[string]bool{
		"embedded": true, // In-memory vector store (non-persistent)
		"redis":    true, // Redis vector database
		"qdrant":   true, // Qdrant vector database
		"milvus":   true, // Milvus vector database
	}

	if c.Backend != "" && !validBackends[c.Backend] {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid backend '%s', must be one of: embedded, redis, qdrant, milvus", c.Backend))
	}

	// If using an external backend that requires a connection URL (not redis, not embedded),
	// ConnectionURL is required. Redis reuses the daemon's existing StateClient connection.
	connectionURLRequired := c.Backend != "" && c.Backend != "embedded" && c.Backend != "redis"
	if connectionURLRequired && c.ConnectionURL == "" {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("connection_url is required for backend '%s'", c.Backend))
	}

	// Validate embedder configuration
	if err := c.Embedder.Validate(); err != nil {
		return types.WrapError(types.CONFIG_VALIDATION_FAILED, "embedder config validation failed", err)
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
func (c *LongTermMemoryConfig) ApplyDefaults() {
	if c.Backend == "" {
		c.Backend = "embedded" // Default: embedded vector store
	}
	c.Embedder.ApplyDefaults()
}

// EmbedderConfig configures the embedding provider.
// Embeddings are used for semantic similarity search in long-term memory.
type EmbedderConfig struct {
	Provider string `mapstructure:"provider" yaml:"provider" json:"provider"`
}

// Validate performs validation on the EmbedderConfig.
func (c *EmbedderConfig) Validate() error {
	// Validate provider type
	validProviders := map[string]bool{
		"native": true, // Native ONNX embedder (all-MiniLM-L6-v2, runs offline)
	}

	if c.Provider != "" && !validProviders[c.Provider] {
		return types.NewError(types.CONFIG_VALIDATION_FAILED,
			fmt.Sprintf("invalid embedder provider '%s', must be: native", c.Provider))
	}

	return nil
}

// ApplyDefaults applies default values to unset fields.
func (c *EmbedderConfig) ApplyDefaults() {
	if c.Provider == "" {
		c.Provider = "native" // Default: native ONNX embedder (runs offline, no API key needed)
	}
}

// NewDefaultMemoryConfig creates a MemoryConfig with default values.
// This is useful for testing or when no configuration file is provided.
func NewDefaultMemoryConfig() *MemoryConfig {
	config := &MemoryConfig{}
	config.ApplyDefaults()
	return config
}
