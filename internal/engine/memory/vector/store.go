package vector

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// VectorStore provides vector-based semantic search capabilities.
// Implementations must be thread-safe for concurrent access.
type VectorStore interface {
	// Store adds a single vector record to the store.
	Store(ctx context.Context, record VectorRecord) error

	// StoreBatch adds multiple vector records efficiently.
	StoreBatch(ctx context.Context, records []VectorRecord) error

	// Search finds similar records by embedding vector.
	Search(ctx context.Context, query VectorQuery) ([]VectorResult, error)

	// Get retrieves a specific record by ID.
	Get(ctx context.Context, id string) (*VectorRecord, error)

	// Delete removes a record from the store.
	Delete(ctx context.Context, id string) error

	// Health returns the health status of the vector store.
	Health(ctx context.Context) types.HealthStatus

	// Close releases all resources held by the vector store.
	Close() error
}
