package vector

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestRedisVectorStore_Store verifies that vector records can be stored successfully.
func TestRedisVectorStore_Store(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	// Create vector store
	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Create test record
	record := VectorRecord{
		ID:        "test-vector-1",
		Content:   "This is a test document about machine learning",
		Embedding: makeTestEmbedding(384),
		Metadata: map[string]any{
			"category": "test",
			"priority": 1,
		},
		CreatedAt: time.Now(),
	}

	// Store record
	err := store.Store(ctx, record)
	require.NoError(t, err, "Store should succeed")

	// Verify record was stored
	retrieved, err := store.Get(ctx, "test-vector-1")
	require.NoError(t, err, "Get should succeed")
	assert.Equal(t, record.ID, retrieved.ID)
	assert.Equal(t, record.Content, retrieved.Content)
	assert.Equal(t, 384, len(retrieved.Embedding))

	// Cleanup
	_ = store.Delete(ctx, "test-vector-1")
}

// TestRedisVectorStore_Store_ValidationErrors tests validation error cases.
func TestRedisVectorStore_Store_ValidationErrors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	tests := []struct {
		name        string
		record      VectorRecord
		expectedErr string
	}{
		{
			name: "empty ID",
			record: VectorRecord{
				ID:        "",
				Content:   "test",
				Embedding: makeTestEmbedding(384),
				CreatedAt: time.Now(),
			},
			expectedErr: "ID cannot be empty",
		},
		{
			name: "empty content",
			record: VectorRecord{
				ID:        "test-1",
				Content:   "",
				Embedding: makeTestEmbedding(384),
				CreatedAt: time.Now(),
			},
			expectedErr: "content cannot be empty",
		},
		{
			name: "empty embedding",
			record: VectorRecord{
				ID:        "test-1",
				Content:   "test",
				Embedding: []float64{},
				CreatedAt: time.Now(),
			},
			expectedErr: "embedding cannot be empty",
		},
		{
			name: "wrong dimensions",
			record: VectorRecord{
				ID:        "test-1",
				Content:   "test",
				Embedding: makeTestEmbedding(256), // Wrong dimensions
				CreatedAt: time.Now(),
			},
			expectedErr: "dimensions mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Store(ctx, tt.record)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

// TestRedisVectorStore_StoreBatch tests batch storage operations.
func TestRedisVectorStore_StoreBatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Create batch of records
	records := []VectorRecord{
		{
			ID:        "batch-1",
			Content:   "First document about AI",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"batch": 1},
			CreatedAt: time.Now(),
		},
		{
			ID:        "batch-2",
			Content:   "Second document about ML",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"batch": 1},
			CreatedAt: time.Now(),
		},
		{
			ID:        "batch-3",
			Content:   "Third document about data",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"batch": 1},
			CreatedAt: time.Now(),
		},
	}

	// Store batch
	err := store.StoreBatch(ctx, records)
	require.NoError(t, err, "StoreBatch should succeed")

	// Verify all records were stored
	for _, record := range records {
		retrieved, err := store.Get(ctx, record.ID)
		require.NoError(t, err, "Get should succeed for %s", record.ID)
		assert.Equal(t, record.ID, retrieved.ID)
		assert.Equal(t, record.Content, retrieved.Content)
	}

	// Cleanup
	for _, record := range records {
		_ = store.Delete(ctx, record.ID)
	}
}

// TestRedisVectorStore_StoreBatch_EmptySlice tests that empty batches are handled gracefully.
func TestRedisVectorStore_StoreBatch_EmptySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Empty batch should succeed without error
	err := store.StoreBatch(ctx, []VectorRecord{})
	require.NoError(t, err)
}

// TestRedisVectorStore_Get tests retrieval of vector records.
func TestRedisVectorStore_Get(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Store a record
	record := VectorRecord{
		ID:        "get-test-1",
		Content:   "Test content for retrieval",
		Embedding: makeTestEmbedding(384),
		Metadata: map[string]any{
			"key": "value",
		},
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.Store(ctx, record))

	// Get the record
	retrieved, err := store.Get(ctx, "get-test-1")
	require.NoError(t, err)
	assert.Equal(t, record.ID, retrieved.ID)
	assert.Equal(t, record.Content, retrieved.Content)
	assert.NotNil(t, retrieved.Metadata)
	assert.Equal(t, "value", retrieved.Metadata["key"])

	// Cleanup
	_ = store.Delete(ctx, "get-test-1")
}

// TestRedisVectorStore_Get_NotFound tests that Get returns proper error for missing records.
func TestRedisVectorStore_Get_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	_, err := store.Get(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRedisVectorStore_Delete tests deletion of vector records.
func TestRedisVectorStore_Delete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Store a record
	record := VectorRecord{
		ID:        "delete-test-1",
		Content:   "Test content for deletion",
		Embedding: makeTestEmbedding(384),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.Store(ctx, record))

	// Verify it exists
	_, err := store.Get(ctx, "delete-test-1")
	require.NoError(t, err)

	// Delete the record
	err = store.Delete(ctx, "delete-test-1")
	require.NoError(t, err)

	// Verify it's gone
	_, err = store.Get(ctx, "delete-test-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestRedisVectorStore_Search_KNN tests KNN vector similarity search.
func TestRedisVectorStore_Search_KNN(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	// Ensure indexes are created
	require.NoError(t, client.EnsureIndexes(ctx), "Failed to create indexes")

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Store multiple test vectors
	testVectors := []VectorRecord{
		{
			ID:        "search-1",
			Content:   "Machine learning algorithms",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"category": "ml"},
			CreatedAt: time.Now(),
		},
		{
			ID:        "search-2",
			Content:   "Deep neural networks",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"category": "dl"},
			CreatedAt: time.Now(),
		},
		{
			ID:        "search-3",
			Content:   "Natural language processing",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"category": "nlp"},
			CreatedAt: time.Now(),
		},
	}

	for _, vec := range testVectors {
		require.NoError(t, store.Store(ctx, vec))
	}

	// Allow time for indexing
	time.Sleep(100 * time.Millisecond)

	// Perform KNN search
	query := NewVectorQueryFromEmbedding(makeTestEmbedding(384), 2)
	results, err := store.Search(ctx, *query)
	require.NoError(t, err)

	// Should return up to 2 results (TopK=2)
	assert.LessOrEqual(t, len(results), 2)

	// Results should have scores
	for _, result := range results {
		assert.GreaterOrEqual(t, result.Score, 0.0)
		assert.LessOrEqual(t, result.Score, 1.0)
		assert.NotEmpty(t, result.Record.Content)
	}

	// Cleanup
	for _, vec := range testVectors {
		_ = store.Delete(ctx, vec.ID)
	}
}

// TestRedisVectorStore_Search_WithFilters tests vector search with metadata filters.
func TestRedisVectorStore_Search_WithFilters(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Store vectors with different categories
	testVectors := []VectorRecord{
		{
			ID:        "filter-1",
			Content:   "ML document",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"category": "ml", "priority": 1},
			CreatedAt: time.Now(),
		},
		{
			ID:        "filter-2",
			Content:   "AI document",
			Embedding: makeTestEmbedding(384),
			Metadata:  map[string]any{"category": "ai", "priority": 2},
			CreatedAt: time.Now(),
		},
	}

	for _, vec := range testVectors {
		require.NoError(t, store.Store(ctx, vec))
	}

	time.Sleep(100 * time.Millisecond)

	// Search with filter
	query := NewVectorQueryFromEmbedding(makeTestEmbedding(384), 5).
		WithFilters(map[string]any{"category": "ml"})

	results, err := store.Search(ctx, *query)
	require.NoError(t, err)

	// Should only return filtered results
	for _, result := range results {
		assert.Equal(t, "ml", result.Record.Metadata["category"])
	}

	// Cleanup
	for _, vec := range testVectors {
		_ = store.Delete(ctx, vec.ID)
	}
}

// TestRedisVectorStore_Search_HybridSearch tests combining text and vector search.
func TestRedisVectorStore_Search_HybridSearch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Store test vectors
	testVectors := []VectorRecord{
		{
			ID:        "hybrid-1",
			Content:   "Security vulnerability in authentication",
			Embedding: makeTestEmbedding(384),
			CreatedAt: time.Now(),
		},
		{
			ID:        "hybrid-2",
			Content:   "Performance optimization techniques",
			Embedding: makeTestEmbedding(384),
			CreatedAt: time.Now(),
		},
	}

	for _, vec := range testVectors {
		require.NoError(t, store.Store(ctx, vec))
	}

	time.Sleep(100 * time.Millisecond)

	// Hybrid search with text query
	query := VectorQuery{
		Text:      "security",             // Text component
		Embedding: makeTestEmbedding(384), // Vector component
		TopK:      5,
		MinScore:  0.0,
	}

	results, err := store.Search(ctx, query)
	require.NoError(t, err)

	// Results should prioritize documents matching both text and vector
	assert.NotEmpty(t, results)

	// Cleanup
	for _, vec := range testVectors {
		_ = store.Delete(ctx, vec.ID)
	}
}

// TestRedisVectorStore_Search_MinScore tests minimum score threshold filtering.
func TestRedisVectorStore_Search_MinScore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	require.NoError(t, client.EnsureIndexes(ctx))

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Store test vector
	testVector := VectorRecord{
		ID:        "minscore-1",
		Content:   "Test document",
		Embedding: makeTestEmbedding(384),
		CreatedAt: time.Now(),
	}
	require.NoError(t, store.Store(ctx, testVector))

	time.Sleep(100 * time.Millisecond)

	// Search with high minimum score
	query := NewVectorQueryFromEmbedding(makeTestEmbedding(384), 5).
		WithMinScore(0.95) // Very high threshold

	results, err := store.Search(ctx, *query)
	require.NoError(t, err)

	// Only high-similarity results should be returned
	for _, result := range results {
		assert.GreaterOrEqual(t, result.Score, 0.95)
	}

	// Cleanup
	_ = store.Delete(ctx, "minscore-1")
}

// TestRedisVectorStore_Health tests health check functionality.
func TestRedisVectorStore_Health(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Health check should succeed
	health := store.Health(ctx)
	assert.Equal(t, types.HealthStateHealthy, health.State)
	assert.Contains(t, health.Message, "operational")
	assert.Contains(t, health.Message, "dims: 384")
}

// TestRedisVectorStore_Health_Closed tests health check on closed store.
func TestRedisVectorStore_Health_Closed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	store.Close()

	// Health check should indicate unhealthy
	health := store.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, health.State)
	assert.Contains(t, health.Message, "closed")
}

// TestRedisVectorStore_Close tests proper cleanup.
func TestRedisVectorStore_Close(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := setupRedisTestClient(t)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)

	// Close should succeed
	err := store.Close()
	require.NoError(t, err)

	// Subsequent operations should fail
	ctx := context.Background()
	record := VectorRecord{
		ID:        "test",
		Content:   "test",
		Embedding: makeTestEmbedding(384),
		CreatedAt: time.Now(),
	}

	err = store.Store(ctx, record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

// TestEmbeddingToFloat32Bytes tests the binary encoding of embeddings.
func TestEmbeddingToFloat32Bytes(t *testing.T) {
	tests := []struct {
		name      string
		embedding []float64
		wantLen   int
	}{
		{
			name:      "small embedding",
			embedding: []float64{0.1, 0.2, 0.3},
			wantLen:   12, // 3 floats * 4 bytes
		},
		{
			name:      "384 dimensions",
			embedding: makeTestEmbedding(384),
			wantLen:   1536, // 384 floats * 4 bytes
		},
		{
			name:      "single value",
			embedding: []float64{1.0},
			wantLen:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bytes := embeddingToFloat32Bytes(tt.embedding)
			assert.Equal(t, tt.wantLen, len(bytes))

			// Verify all bytes are written (not all zeros unless embedding is zeros)
			hasNonZero := false
			for _, b := range bytes {
				if b != 0 {
					hasNonZero = true
					break
				}
			}
			assert.True(t, hasNonZero || len(tt.embedding) == 0)
		})
	}
}

// Benchmark tests

// BenchmarkRedisVectorStore_Store benchmarks single vector storage.
func BenchmarkRedisVectorStore_Store(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(b)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	record := VectorRecord{
		ID:        "bench-1",
		Content:   "Benchmark test document",
		Embedding: makeTestEmbedding(384),
		CreatedAt: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		record.ID = fmt.Sprintf("bench-%d", i)
		_ = store.Store(ctx, record)
	}
}

// BenchmarkRedisVectorStore_StoreBatch benchmarks batch storage.
func BenchmarkRedisVectorStore_StoreBatch(b *testing.B) {
	if testing.Short() {
		b.Skip("skipping benchmark in short mode")
	}

	ctx := context.Background()
	client := setupRedisTestClient(b)
	defer client.Close()

	store := NewRedisVectorStore(client, 384)
	defer store.Close()

	// Create batch of 10 records
	batchSize := 10
	records := make([]VectorRecord, batchSize)
	for i := 0; i < batchSize; i++ {
		records[i] = VectorRecord{
			ID:        fmt.Sprintf("batch-bench-%d", i),
			Content:   "Batch benchmark document",
			Embedding: makeTestEmbedding(384),
			CreatedAt: time.Now(),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.StoreBatch(ctx, records)
	}
}

// Helper functions

// setupRedisTestClient creates a test Redis client.
// Set GIBSON_REDIS_URL environment variable to override default.
func setupRedisTestClient(t testing.TB) *state.StateClient {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		if isRedisUnavailableErr(err) {
			t.Skip("Redis not available for testing: " + err.Error())
		}
		require.NoError(t, err, "Failed to create Redis client")
	}

	return client
}

// isRedisUnavailableErr returns true when the error indicates Redis is not reachable.
func isRedisUnavailableErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection failed") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "i/o timeout")
}

// makeTestEmbedding creates a test embedding vector with the specified dimensions.
// Values are deterministic for consistent testing.
func makeTestEmbedding(dims int) []float64 {
	embedding := make([]float64, dims)
	for i := range embedding {
		// Create deterministic but varied values
		embedding[i] = float64(i%100) / 100.0
	}
	return embedding
}
