package memory

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/memory/vector"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// LongTermMemory provides semantic search over historical data using vector embeddings.
// It combines a VectorStore for storage and an Embedder for generating embeddings.
type LongTermMemory interface {
	// Store adds content with automatic embedding generation.
	// The content is embedded using the configured Embedder, then stored in the VectorStore.
	Store(ctx context.Context, id string, content string, metadata map[string]any) error

	// Search finds similar content by semantic query.
	// The query text is embedded, then used to search the VectorStore for similar content.
	Search(ctx context.Context, query string, topK int, filters map[string]any) ([]MemoryResult, error)

	// SimilarFindings finds findings similar to the given content.
	// This is a convenience method that adds a type=finding filter.
	SimilarFindings(ctx context.Context, content string, topK int) ([]MemoryResult, error)

	// SimilarPatterns finds attack patterns similar to the query.
	// This is a convenience method that adds a type=pattern filter.
	SimilarPatterns(ctx context.Context, pattern string, topK int) ([]MemoryResult, error)

	// Delete removes content by ID from the vector store.
	Delete(ctx context.Context, id string) error

	// Health returns the combined health of the vector store and embedder.
	Health(ctx context.Context) types.HealthStatus
}

// DefaultLongTermMemory implements LongTermMemory by combining a VectorStore and Embedder.
type DefaultLongTermMemory struct {
	store    vector.VectorStore
	embedder embedder.Embedder
}

// NewLongTermMemory creates a new LongTermMemory instance.
func NewLongTermMemory(store vector.VectorStore, emb embedder.Embedder) LongTermMemory {
	return &DefaultLongTermMemory{
		store:    store,
		embedder: emb,
	}
}

// Store adds content with automatic embedding generation.
func (l *DefaultLongTermMemory) Store(ctx context.Context, id string, content string, metadata map[string]any) error {
	// Generate embedding for the content
	embedding, err := l.embedder.Embed(ctx, content)
	if err != nil {
		return NewEmbeddingError("failed to generate embedding for content", err)
	}

	// Create vector record
	record := vector.NewVectorRecord(id, content, embedding, metadata)

	// Store in vector store
	if err := l.store.Store(ctx, *record); err != nil {
		return NewVectorStoreError("failed to store vector record", err)
	}

	return nil
}

// Search finds similar content by semantic query.
func (l *DefaultLongTermMemory) Search(ctx context.Context, query string, topK int, filters map[string]any) ([]MemoryResult, error) {
	// Generate embedding for the query
	queryEmbedding, err := l.embedder.Embed(ctx, query)
	if err != nil {
		return nil, NewEmbeddingError("failed to generate embedding for query", err)
	}

	// Create vector query with embedding
	vectorQuery := vector.NewVectorQueryFromEmbedding(queryEmbedding, topK)
	if filters != nil {
		vectorQuery.WithFilters(filters)
	}

	// Search vector store
	vectorResults, err := l.store.Search(ctx, *vectorQuery)
	if err != nil {
		return nil, NewVectorSearchError("failed to search vector store", err)
	}

	// Convert VectorResult to MemoryResult
	results := make([]MemoryResult, len(vectorResults))
	for i, vr := range vectorResults {
		item := MemoryItem{
			Key:       vr.Record.ID,
			Value:     vr.Record.Content,
			Metadata:  vr.Record.Metadata,
			CreatedAt: vr.Record.CreatedAt,
			UpdatedAt: vr.Record.CreatedAt, // Vector records don't track updates
		}
		results[i] = MemoryResult{
			Item:  item,
			Score: vr.Score,
		}
	}

	return results, nil
}

// SimilarFindings finds findings similar to the given content.
// Automatically adds a type=finding filter to the search.
func (l *DefaultLongTermMemory) SimilarFindings(ctx context.Context, content string, topK int) ([]MemoryResult, error) {
	filters := map[string]any{
		"type": "finding",
	}
	return l.Search(ctx, content, topK, filters)
}

// SimilarPatterns finds attack patterns similar to the query.
// Automatically adds a type=pattern filter to the search.
func (l *DefaultLongTermMemory) SimilarPatterns(ctx context.Context, pattern string, topK int) ([]MemoryResult, error) {
	filters := map[string]any{
		"type": "pattern",
	}
	return l.Search(ctx, pattern, topK, filters)
}

// Delete removes content by ID from the vector store.
func (l *DefaultLongTermMemory) Delete(ctx context.Context, id string) error {
	if err := l.store.Delete(ctx, id); err != nil {
		return NewVectorStoreError("failed to delete vector record", err)
	}
	return nil
}

// Health returns the combined health of the vector store and embedder.
// If either component is unhealthy, the overall status is degraded/unhealthy.
func (l *DefaultLongTermMemory) Health(ctx context.Context) types.HealthStatus {
	storeHealth := l.store.Health(ctx)
	embedderHealth := l.embedder.Health(ctx)

	// If both are healthy, return healthy
	if storeHealth.IsHealthy() && embedderHealth.IsHealthy() {
		return types.Healthy("long-term memory healthy")
	}

	// If either is unhealthy, return unhealthy
	if storeHealth.IsUnhealthy() || embedderHealth.IsUnhealthy() {
		message := "long-term memory unhealthy"
		if storeHealth.IsUnhealthy() {
			message += "; vector store: " + storeHealth.Message
		}
		if embedderHealth.IsUnhealthy() {
			message += "; embedder: " + embedderHealth.Message
		}
		return types.Unhealthy(message)
	}

	// Otherwise, return degraded
	message := "long-term memory degraded"
	if storeHealth.IsDegraded() {
		message += "; vector store: " + storeHealth.Message
	}
	if embedderHealth.IsDegraded() {
		message += "; embedder: " + embedderHealth.Message
	}
	return types.Degraded(message)
}
