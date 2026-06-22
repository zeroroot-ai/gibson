package vector

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// EmbeddedVectorStore is an in-memory vector store implementation.
// It uses brute-force search with cosine similarity, suitable for
// development and small-to-medium datasets (up to ~100K vectors).
// For production workloads with larger datasets, use external vector
// stores like Redis or Milvus.
type EmbeddedVectorStore struct {
	mu      sync.RWMutex
	records map[string]VectorRecord
	dims    int
}

// NewEmbeddedVectorStore creates a new in-memory vector store.
// dims specifies the expected dimensionality of embedding vectors.
func NewEmbeddedVectorStore(dims int) *EmbeddedVectorStore {
	return &EmbeddedVectorStore{
		records: make(map[string]VectorRecord),
		dims:    dims,
	}
}

// Store adds a single vector record to the store.
func (s *EmbeddedVectorStore) Store(ctx context.Context, record VectorRecord) error {
	// Validate the record
	if err := record.Validate(); err != nil {
		return err
	}

	// Check dimensionality matches
	if len(record.Embedding) != s.dims {
		return types.NewError(ErrCodeVectorStoreFailed,
			fmt.Sprintf("embedding dimensions mismatch: expected %d, got %d", s.dims, len(record.Embedding)))
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.records[record.ID] = record
	return nil
}

// StoreBatch adds multiple vector records to the store efficiently.
func (s *EmbeddedVectorStore) StoreBatch(ctx context.Context, records []VectorRecord) error {
	if len(records) == 0 {
		return nil
	}

	// Validate all records first
	for i, record := range records {
		if err := record.Validate(); err != nil {
			return types.WrapError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("invalid record at index %d", i), err)
		}
		if len(record.Embedding) != s.dims {
			return types.NewError(ErrCodeVectorStoreFailed,
				fmt.Sprintf("record %d: embedding dimensions mismatch: expected %d, got %d",
					i, s.dims, len(record.Embedding)))
		}
	}

	// Store all records atomically
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, record := range records {
		s.records[record.ID] = record
	}

	return nil
}

// Search finds similar records by embedding vector using brute-force search.
// Uses cosine similarity for scoring and returns results sorted by descending score.
func (s *EmbeddedVectorStore) Search(ctx context.Context, query VectorQuery) ([]VectorResult, error) {
	// Validate the query
	if err := query.Validate(); err != nil {
		return nil, err
	}

	// Must have an embedding to search (text queries should be embedded first)
	if len(query.Embedding) == 0 {
		return nil, types.NewError(ErrCodeVectorSearchFailed,
			"query must have embedding for search (embed text first)")
	}

	// Check dimensionality matches
	if len(query.Embedding) != s.dims {
		return nil, types.NewError(ErrCodeVectorSearchFailed,
			fmt.Sprintf("query embedding dimensions mismatch: expected %d, got %d",
				s.dims, len(query.Embedding)))
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Pre-allocate result slice with capacity
	results := make([]VectorResult, 0, len(s.records))

	// Compute similarity for all records
	for _, record := range s.records {
		// Apply metadata filters if specified
		if !matchesFilters(record, query.Filters) {
			continue
		}

		// Compute cosine similarity
		score := cosineSimilarity(query.Embedding, record.Embedding)

		// Apply minimum score threshold
		if score >= query.MinScore {
			results = append(results, *NewVectorResult(record, score))
		}
	}

	// Sort by score descending (highest similarity first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	// Return top-k results
	if len(results) > query.TopK {
		results = results[:query.TopK]
	}

	return results, nil
}

// Get retrieves a specific record by ID.
func (s *EmbeddedVectorStore) Get(ctx context.Context, id string) (*VectorRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[id]
	if !exists {
		return nil, nil
	}

	return &record, nil
}

// Delete removes a record from the store.
func (s *EmbeddedVectorStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.records, id)
	return nil
}

// Health returns the current health status of the vector store.
func (s *EmbeddedVectorStore) Health(ctx context.Context) types.HealthStatus {
	s.mu.RLock()
	count := len(s.records)
	s.mu.RUnlock()

	return types.NewHealthStatus(
		types.HealthStateHealthy,
		fmt.Sprintf("embedded vector store operational with %d records (dims: %d)", count, s.dims),
	)
}

// Close releases all resources held by the vector store.
func (s *EmbeddedVectorStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clear the records map
	s.records = nil
	return nil
}

// cosineSimilarity computes the cosine similarity between two embedding vectors.
// Returns a score between 0 and 1, where 1 means identical direction.
//
// Formula: similarity = (a · b) / (||a|| * ||b||)
// where · is dot product and ||x|| is the L2 norm (Euclidean length).
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0
	}

	var dotProduct, normA, normB float64

	for i := range a {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	// Handle zero vectors
	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

// matchesFilters checks if a vector record matches the specified metadata filters.
// All filters must match for the function to return true (AND semantics).
func matchesFilters(record VectorRecord, filters map[string]any) bool {
	if len(filters) == 0 {
		return true
	}

	if record.Metadata == nil {
		return false
	}

	for key, expectedValue := range filters {
		actualValue, exists := record.Metadata[key]
		if !exists {
			return false
		}

		// Simple equality check (could be extended for range queries, etc.)
		if actualValue != expectedValue {
			return false
		}
	}

	return true
}
