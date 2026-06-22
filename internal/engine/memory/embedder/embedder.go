package embedder

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
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

// EmbedderConfig holds transport-level configuration for the embedding
// provider. Per docs ADR-0059 embedding is a BYO provider: the concrete model
// and credentials are resolved from the tenant's configured embedding provider
// (mirroring the LLM ProviderService), not from this struct. gibson no longer
// bundles a local embedder.
type EmbedderConfig struct {
	// Provider names the embedding provider backend. Empty means "not
	// configured" — vector recall stays gated until a provider is set
	// (ADR-0059 §4). There is no bundled default.
	Provider string `yaml:"provider" json:"provider" mapstructure:"provider"`

	// MaxRetries is the maximum number of retry attempts for transient failures.
	MaxRetries int `yaml:"max_retries" json:"max_retries" mapstructure:"max_retries"`

	// Timeout is the request timeout in seconds.
	Timeout int `yaml:"timeout" json:"timeout" mapstructure:"timeout"`
}

// Validate checks if the EmbedderConfig is valid.
func (c *EmbedderConfig) Validate() error {
	if c.MaxRetries < 0 {
		return types.NewError(ErrCodeInvalidConfig, "max_retries must be non-negative")
	}

	if c.Timeout < 0 {
		return types.NewError(ErrCodeInvalidConfig, "timeout must be non-negative")
	}

	return nil
}

// DefaultEmbedderConfig returns the default embedder transport configuration.
// Provider is intentionally empty: there is no bundled embedder, so vector
// recall is gated until a BYO embedding provider is configured (ADR-0059).
func DefaultEmbedderConfig() EmbedderConfig {
	return EmbedderConfig{
		Provider:   "",
		MaxRetries: 3,
		Timeout:    30,
	}
}
