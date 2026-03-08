package vector

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/types"
)

// QdrantConfig holds configuration for connecting to a Qdrant vector database.
type QdrantConfig struct {
	Host       string // Qdrant server host (e.g., "localhost", "qdrant.example.com")
	Port       int    // Qdrant gRPC port (default: 6334)
	Collection string // Collection name for storing vectors
	APIKey     string // Optional API key for authentication
	UseTLS     bool   // Whether to use TLS for connection
}

// DefaultQdrantConfig returns a QdrantConfig with sensible defaults for local development.
// Default configuration:
//   - Host: "localhost"
//   - Port: 6334 (Qdrant default gRPC port)
//   - Collection: "gibson_vectors"
//   - APIKey: "" (no authentication)
//   - UseTLS: false
func DefaultQdrantConfig() QdrantConfig {
	return QdrantConfig{
		Host:       "localhost",
		Port:       6334,
		Collection: "gibson_vectors",
		APIKey:     "",
		UseTLS:     false,
	}
}

// Validate checks if the configuration is valid and returns an error if not.
// Validation rules:
//   - Host must not be empty
//   - Port must be between 1 and 65535
//   - Collection name must not be empty
func (c *QdrantConfig) Validate() error {
	if c.Host == "" {
		return types.NewError(ErrCodeInvalidConfig, "qdrant host cannot be empty")
	}

	if c.Port < 1 || c.Port > 65535 {
		return types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("qdrant port must be between 1 and 65535, got %d", c.Port))
	}

	if c.Collection == "" {
		return types.NewError(ErrCodeInvalidConfig, "qdrant collection name cannot be empty")
	}

	return nil
}
