package vector

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/types"
)

// MilvusConfig holds configuration for connecting to a Milvus vector database.
type MilvusConfig struct {
	Host       string // Milvus server host (e.g., "localhost", "milvus.example.com")
	Port       int    // Milvus gRPC port (default: 19530)
	Collection string // Collection name for storing vectors
	Username   string // Optional username for authentication
	Password   string // Optional password for authentication
}

// DefaultMilvusConfig returns a MilvusConfig with sensible defaults for local development.
// Default configuration:
//   - Host: "localhost"
//   - Port: 19530 (Milvus default gRPC port)
//   - Collection: "gibson_vectors"
//   - Username: "" (no authentication)
//   - Password: "" (no authentication)
func DefaultMilvusConfig() MilvusConfig {
	return MilvusConfig{
		Host:       "localhost",
		Port:       19530,
		Collection: "gibson_vectors",
		Username:   "",
		Password:   "",
	}
}

// Validate checks if the configuration is valid and returns an error if not.
// Validation rules:
//   - Host must not be empty
//   - Port must be between 1 and 65535
//   - Collection name must not be empty
func (c *MilvusConfig) Validate() error {
	if c.Host == "" {
		return types.NewError(ErrCodeInvalidConfig, "milvus host cannot be empty")
	}

	if c.Port < 1 || c.Port > 65535 {
		return types.NewError(ErrCodeInvalidConfig,
			fmt.Sprintf("milvus port must be between 1 and 65535, got %d", c.Port))
	}

	if c.Collection == "" {
		return types.NewError(ErrCodeInvalidConfig, "milvus collection name cannot be empty")
	}

	return nil
}
