package embedder

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Embedder generates embedding vectors from text content.
// Implementations must be thread-safe for concurrent access.
type Embedder interface {
	// Embed generates an embedding vector for a single text.
	Embed(ctx context.Context, text string) ([]float64, error)

	// EmbedBatch generates embeddings for multiple texts efficiently.
	EmbedBatch(ctx context.Context, texts []string) ([][]float64, error)

	// Dimensions returns the dimensionality of embedding vectors.
	Dimensions() int

	// Model returns the name of the embedding model being used.
	Model() string

	// Health returns the health status of the embedder.
	Health(ctx context.Context) types.HealthStatus
}

// EmbedderConfig holds configuration for the native embedding provider.
type EmbedderConfig struct {
	// Provider specifies which embedder implementation to use.
	// Only "native" is supported for offline embedding generation.
	Provider string `yaml:"provider" json:"provider" mapstructure:"provider"`

	// MaxRetries is the maximum number of retry attempts for transient failures.
	MaxRetries int `yaml:"max_retries" json:"max_retries" mapstructure:"max_retries"`

	// Timeout is the request timeout in seconds.
	Timeout int `yaml:"timeout" json:"timeout" mapstructure:"timeout"`
}

// Validate checks if the EmbedderConfig is valid.
func (c *EmbedderConfig) Validate() error {
	// Provider must be "native" or empty (defaults to native)
	if c.Provider != "" && c.Provider != "native" {
		return types.NewError(ErrCodeInvalidConfig, "only 'native' provider is supported")
	}

	if c.MaxRetries < 0 {
		return types.NewError(ErrCodeInvalidConfig, "max_retries must be non-negative")
	}

	if c.Timeout < 0 {
		return types.NewError(ErrCodeInvalidConfig, "timeout must be non-negative")
	}

	return nil
}

// DefaultEmbedderConfig returns a default configuration for the native embedder.
// The native embedder (all-MiniLM-L6-v2) runs offline without requiring API keys
// and provides predictable latency.
func DefaultEmbedderConfig() EmbedderConfig {
	return EmbedderConfig{
		Provider:   "native",
		MaxRetries: 3,
		Timeout:    30,
	}
}
