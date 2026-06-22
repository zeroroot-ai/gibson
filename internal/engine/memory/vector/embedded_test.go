package vector

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestEmbeddedVectorStore_StoreAndGet(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	record := NewVectorRecord("test-1", "test content", []float64{1.0, 0.0, 0.0}, nil)

	// Store the record
	err := store.Store(ctx, *record)
	require.NoError(t, err)

	// Retrieve the record
	retrieved, err := store.Get(ctx, "test-1")
	require.NoError(t, err)
	assert.Equal(t, record.ID, retrieved.ID)
	assert.Equal(t, record.Content, retrieved.Content)
	assert.Equal(t, record.Embedding, retrieved.Embedding)
}

func TestEmbeddedVectorStore_GetNotFound(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	result, err := store.Get(ctx, "nonexistent")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestEmbeddedVectorStore_StoreBatch(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	records := []VectorRecord{
		*NewVectorRecord("test-1", "content 1", []float64{1.0, 0.0, 0.0}, nil),
		*NewVectorRecord("test-2", "content 2", []float64{0.0, 1.0, 0.0}, nil),
		*NewVectorRecord("test-3", "content 3", []float64{0.0, 0.0, 1.0}, nil),
	}

	err := store.StoreBatch(ctx, records)
	require.NoError(t, err)

	// Verify all records were stored
	for _, record := range records {
		retrieved, err := store.Get(ctx, record.ID)
		require.NoError(t, err)
		assert.Equal(t, record.ID, retrieved.ID)
	}
}

func TestEmbeddedVectorStore_Delete(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	record := NewVectorRecord("test-1", "test content", []float64{1.0, 0.0, 0.0}, nil)
	err := store.Store(ctx, *record)
	require.NoError(t, err)

	// Verify it exists
	_, err = store.Get(ctx, "test-1")
	require.NoError(t, err)

	// Delete it
	err = store.Delete(ctx, "test-1")
	require.NoError(t, err)

	// Verify it's gone
	result, err := store.Get(ctx, "test-1")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestEmbeddedVectorStore_Search_TopK(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	// Store test records with known embeddings
	records := []VectorRecord{
		*NewVectorRecord("test-1", "content 1", []float64{1.0, 0.0, 0.0}, nil),
		*NewVectorRecord("test-2", "content 2", []float64{0.9, 0.1, 0.0}, nil),
		*NewVectorRecord("test-3", "content 3", []float64{0.0, 1.0, 0.0}, nil),
	}
	err := store.StoreBatch(ctx, records)
	require.NoError(t, err)

	// Search with query vector close to test-1
	query := NewVectorQueryFromEmbedding([]float64{1.0, 0.0, 0.0}, 2)
	results, err := store.Search(ctx, *query)
	require.NoError(t, err)

	// Should return top 2 results
	assert.Len(t, results, 2)
	// First result should be test-1 (perfect match)
	assert.Equal(t, "test-1", results[0].Record.ID)
	assert.InDelta(t, 1.0, results[0].Score, 0.001)
	// Second result should be test-2 (close match)
	assert.Equal(t, "test-2", results[1].Record.ID)
}

func TestEmbeddedVectorStore_Search_MinScore(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	// Store test records
	records := []VectorRecord{
		*NewVectorRecord("test-1", "content 1", []float64{1.0, 0.0, 0.0}, nil),
		*NewVectorRecord("test-2", "content 2", []float64{0.5, 0.5, 0.0}, nil),
		*NewVectorRecord("test-3", "content 3", []float64{0.0, 1.0, 0.0}, nil),
	}
	err := store.StoreBatch(ctx, records)
	require.NoError(t, err)

	// Search with minimum score threshold
	query := NewVectorQueryFromEmbedding([]float64{1.0, 0.0, 0.0}, 10).WithMinScore(0.8)
	results, err := store.Search(ctx, *query)
	require.NoError(t, err)

	// Should only return results with score >= 0.8
	for _, result := range results {
		assert.GreaterOrEqual(t, result.Score, 0.8)
	}
}

func TestEmbeddedVectorStore_Search_Filters(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	// Store records with metadata
	records := []VectorRecord{
		*NewVectorRecord("test-1", "finding 1", []float64{1.0, 0.0, 0.0},
			map[string]any{"type": "finding", "severity": "high"}),
		*NewVectorRecord("test-2", "finding 2", []float64{0.9, 0.1, 0.0},
			map[string]any{"type": "finding", "severity": "low"}),
		*NewVectorRecord("test-3", "pattern 1", []float64{0.8, 0.2, 0.0},
			map[string]any{"type": "pattern"}),
	}
	err := store.StoreBatch(ctx, records)
	require.NoError(t, err)

	// Search with type filter
	query := NewVectorQueryFromEmbedding([]float64{1.0, 0.0, 0.0}, 10).
		WithFilters(map[string]any{"type": "finding"})
	results, err := store.Search(ctx, *query)
	require.NoError(t, err)

	// Should only return finding records
	assert.Len(t, results, 2)
	for _, result := range results {
		assert.Equal(t, "finding", result.Record.Metadata["type"])
	}
}

func TestCosineSimilarity(t *testing.T) {
	tests := []struct {
		name     string
		a        []float64
		b        []float64
		expected float64
	}{
		{
			name:     "identical vectors",
			a:        []float64{1.0, 0.0, 0.0},
			b:        []float64{1.0, 0.0, 0.0},
			expected: 1.0,
		},
		{
			name:     "orthogonal vectors",
			a:        []float64{1.0, 0.0, 0.0},
			b:        []float64{0.0, 1.0, 0.0},
			expected: 0.0,
		},
		{
			name:     "opposite vectors",
			a:        []float64{1.0, 0.0, 0.0},
			b:        []float64{-1.0, 0.0, 0.0},
			expected: -1.0,
		},
		{
			name:     "45 degree angle",
			a:        []float64{1.0, 0.0},
			b:        []float64{1.0, 1.0},
			expected: 1.0 / math.Sqrt(2), // cos(45°) = 1/√2 ≈ 0.707
		},
		{
			name:     "zero vector",
			a:        []float64{0.0, 0.0, 0.0},
			b:        []float64{1.0, 0.0, 0.0},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cosineSimilarity(tt.a, tt.b)
			assert.InDelta(t, tt.expected, result, 0.001)
		})
	}
}

func TestCosineSimilarity_DifferentDimensions(t *testing.T) {
	a := []float64{1.0, 0.0}
	b := []float64{1.0, 0.0, 0.0}

	result := cosineSimilarity(a, b)
	assert.Equal(t, 0.0, result)
}

func TestEmbeddedVectorStore_DimensionValidation(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	// Try to store record with wrong dimensions
	record := NewVectorRecord("test-1", "test", []float64{1.0, 0.0}, nil)
	err := store.Store(ctx, *record)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dimensions mismatch")
}

func TestEmbeddedVectorStore_Health(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	// Initial health check
	health := store.Health(ctx)
	assert.Equal(t, types.HealthStateHealthy, health.State)
	assert.Contains(t, health.Message, "0 records")

	// Add some records
	record := NewVectorRecord("test-1", "test", []float64{1.0, 0.0, 0.0}, nil)
	err := store.Store(ctx, *record)
	require.NoError(t, err)

	// Health check should reflect the record count
	health = store.Health(ctx)
	assert.Equal(t, types.HealthStateHealthy, health.State)
	assert.Contains(t, health.Message, "1 record")
}

func TestEmbeddedVectorStore_Close(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	record := NewVectorRecord("test-1", "test", []float64{1.0, 0.0, 0.0}, nil)
	err := store.Store(ctx, *record)
	require.NoError(t, err)

	// Close the store
	err = store.Close()
	require.NoError(t, err)

	// Store should be empty after close
	store.mu.RLock()
	assert.Nil(t, store.records)
	store.mu.RUnlock()
}

func TestEmbeddedVectorStore_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	store := NewEmbeddedVectorStore(3)

	// Run concurrent stores and searches
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			record := NewVectorRecord(
				time.Now().String(),
				"test content",
				[]float64{1.0, 0.0, 0.0},
				nil,
			)
			_ = store.Store(ctx, *record)
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			query := NewVectorQueryFromEmbedding([]float64{1.0, 0.0, 0.0}, 5)
			_, _ = store.Search(ctx, *query)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done

	// Store should still be functional
	health := store.Health(ctx)
	assert.Equal(t, types.HealthStateHealthy, health.State)
}
