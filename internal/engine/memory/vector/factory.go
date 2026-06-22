package vector

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// VectorStoreConfig holds configuration for creating a vector store.
type VectorStoreConfig struct {
	Backend     string // "embedded" or "redis"
	StoragePath string // Deprecated: no longer used
	Dimensions  int    // Embedding dimensions (e.g., 384 for all-MiniLM-L6-v2)
}

// Note: For Redis backend, use NewRedisVectorStore(client, dims) directly
// as it requires a state.StateClient instance for connection management.

// NewVectorStore creates a vector store based on the configuration.
// Supported backends:
//   - "embedded": In-memory vector store (non-persistent, brute-force search)
//   - "redis": Redis-backed vector store (use NewRedisVectorStore directly - requires StateClient)
func NewVectorStore(cfg VectorStoreConfig) (VectorStore, error) {
	// Validate dimensions
	if cfg.Dimensions <= 0 {
		return nil, types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("dimensions must be positive, got %d", cfg.Dimensions))
	}

	switch cfg.Backend {
	case "embedded", "":
		// In-memory vector store (default for backward compatibility)
		return NewEmbeddedVectorStore(cfg.Dimensions), nil

	default:
		return nil, types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("unknown backend '%s', must be one of: embedded, redis",
				cfg.Backend))
	}
}
