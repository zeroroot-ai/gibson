package memory

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestLongTermMemory_Store tests that Store generates embeddings and stores them in the vector store.
func TestLongTermMemory_Store(t *testing.T) {
	ctx := context.Background()

	// Create mock dependencies
	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()

	// Create long-term memory
	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Store some content
	metadata := map[string]any{"type": "finding"}
	err := ltm.Store(ctx, "test-id", "test content", metadata)
	require.NoError(t, err)

	// Verify the vector was stored
	record, err := mockStore.Get(ctx, "test-id")
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, "test-id", record.ID)
	assert.Equal(t, "test content", record.Content)
	assert.Equal(t, metadata, record.Metadata)
	assert.NotEmpty(t, record.Embedding)
	assert.Len(t, record.Embedding, mockEmbedder.Dimensions())
}

// TestLongTermMemory_Store_MultipleItems tests storing multiple items.
func TestLongTermMemory_Store_MultipleItems(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()
	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Store multiple items
	items := []struct {
		id      string
		content string
	}{
		{"id1", "first content"},
		{"id2", "second content"},
		{"id3", "third content"},
	}

	for _, item := range items {
		err := ltm.Store(ctx, item.id, item.content, nil)
		require.NoError(t, err)
	}

	// Verify all items were stored
	for _, item := range items {
		record, err := mockStore.Get(ctx, item.id)
		require.NoError(t, err)
		require.NotNil(t, record)
		assert.Equal(t, item.content, record.Content)
	}
}

// TestLongTermMemory_Search tests semantic search functionality.
func TestLongTermMemory_Search(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()

	// Configure mock search results
	expectedResults := []vector.VectorResult{
		{
			Record: *vector.NewVectorRecord("result1", "matching content", make([]float64, 1536), nil),
			Score:  0.95,
		},
		{
			Record: *vector.NewVectorRecord("result2", "similar content", make([]float64, 1536), nil),
			Score:  0.85,
		},
	}
	mockStore.SetSearchResults(expectedResults)

	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Perform search
	results, err := ltm.Search(ctx, "test query", 10, nil)
	require.NoError(t, err)
	require.Len(t, results, 2)

	// Verify results are converted correctly from VectorResult to MemoryResult
	assert.Equal(t, "result1", results[0].Item.Key)
	assert.Equal(t, "matching content", results[0].Item.Value)
	assert.Equal(t, 0.95, results[0].Score)

	assert.Equal(t, "result2", results[1].Item.Key)
	assert.Equal(t, "similar content", results[1].Item.Value)
	assert.Equal(t, 0.85, results[1].Score)
}

// TestLongTermMemory_Search_WithFilters tests search with metadata filters.
func TestLongTermMemory_Search_WithFilters(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()

	mockStore.SetSearchResults([]vector.VectorResult{})

	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Search with filters
	filters := map[string]any{
		"type":     "finding",
		"severity": "high",
	}
	results, err := ltm.Search(ctx, "test query", 5, filters)
	require.NoError(t, err)
	assert.NotNil(t, results)
}

// TestLongTermMemory_SimilarFindings tests the SimilarFindings convenience method.
func TestLongTermMemory_SimilarFindings(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()

	// Configure mock results
	expectedResults := []vector.VectorResult{
		{
			Record: *vector.NewVectorRecord("finding1", "SQL injection found", make([]float64, 1536), map[string]any{"type": "finding"}),
			Score:  0.92,
		},
	}
	mockStore.SetSearchResults(expectedResults)

	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Call SimilarFindings - should automatically add type=finding filter
	results, err := ltm.SimilarFindings(ctx, "SQL injection vulnerability", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "finding1", results[0].Item.Key)
	assert.Equal(t, "SQL injection found", results[0].Item.Value)
	assert.Equal(t, 0.92, results[0].Score)
}

// TestLongTermMemory_SimilarPatterns tests the SimilarPatterns convenience method.
func TestLongTermMemory_SimilarPatterns(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()

	// Configure mock results
	expectedResults := []vector.VectorResult{
		{
			Record: *vector.NewVectorRecord("pattern1", "OWASP A1 injection pattern", make([]float64, 1536), map[string]any{"type": "pattern"}),
			Score:  0.88,
		},
	}
	mockStore.SetSearchResults(expectedResults)

	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Call SimilarPatterns - should automatically add type=pattern filter
	results, err := ltm.SimilarPatterns(ctx, "injection attack pattern", 10)
	require.NoError(t, err)
	require.Len(t, results, 1)

	assert.Equal(t, "pattern1", results[0].Item.Key)
	assert.Equal(t, "OWASP A1 injection pattern", results[0].Item.Value)
	assert.Equal(t, 0.88, results[0].Score)
}

// TestLongTermMemory_Delete tests deleting content from the vector store.
func TestLongTermMemory_Delete(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()
	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Store an item first
	err := ltm.Store(ctx, "test-id", "test content", nil)
	require.NoError(t, err)

	// Verify it exists
	record, err := mockStore.Get(ctx, "test-id")
	require.NoError(t, err)
	require.NotNil(t, record)

	// Delete the item
	err = ltm.Delete(ctx, "test-id")
	require.NoError(t, err)

	// Verify it's deleted
	gone, err := mockStore.Get(ctx, "test-id")
	assert.NoError(t, err)
	assert.Nil(t, gone)
}

// TestLongTermMemory_Delete_NonExistent tests deleting non-existent content.
func TestLongTermMemory_Delete_NonExistent(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()
	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	// Delete non-existent item - should not error
	err := ltm.Delete(ctx, "non-existent-id")
	require.NoError(t, err)
}

// TestLongTermMemory_Health tests health status aggregation.
func TestLongTermMemory_Health(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		storeHealth    types.HealthStatus
		embedderHealth types.HealthStatus
		expectedState  types.HealthState
	}{
		{
			name:           "both healthy",
			storeHealth:    types.Healthy("store ok"),
			embedderHealth: types.Healthy("embedder ok"),
			expectedState:  types.HealthStateHealthy,
		},
		{
			name:           "store degraded",
			storeHealth:    types.Degraded("store slow"),
			embedderHealth: types.Healthy("embedder ok"),
			expectedState:  types.HealthStateDegraded,
		},
		{
			name:           "embedder degraded",
			storeHealth:    types.Healthy("store ok"),
			embedderHealth: types.Degraded("embedder slow"),
			expectedState:  types.HealthStateDegraded,
		},
		{
			name:           "both degraded",
			storeHealth:    types.Degraded("store slow"),
			embedderHealth: types.Degraded("embedder slow"),
			expectedState:  types.HealthStateDegraded,
		},
		{
			name:           "store unhealthy",
			storeHealth:    types.Unhealthy("store down"),
			embedderHealth: types.Healthy("embedder ok"),
			expectedState:  types.HealthStateUnhealthy,
		},
		{
			name:           "embedder unhealthy",
			storeHealth:    types.Healthy("store ok"),
			embedderHealth: types.Unhealthy("embedder down"),
			expectedState:  types.HealthStateUnhealthy,
		},
		{
			name:           "both unhealthy",
			storeHealth:    types.Unhealthy("store down"),
			embedderHealth: types.Unhealthy("embedder down"),
			expectedState:  types.HealthStateUnhealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStore := vector.NewMockVectorStore()
			mockEmbedder := embedder.NewMockEmbedder()

			mockStore.SetHealthStatus(tt.storeHealth)
			mockEmbedder.SetHealthStatus(tt.embedderHealth)

			ltm := NewLongTermMemory(mockStore, mockEmbedder)

			health := ltm.Health(ctx)
			assert.Equal(t, tt.expectedState, health.State)
		})
	}
}

// TestLongTermMemory_Health_Messages tests that health messages include component details.
func TestLongTermMemory_Health_Messages(t *testing.T) {
	ctx := context.Background()

	mockStore := vector.NewMockVectorStore()
	mockEmbedder := embedder.NewMockEmbedder()

	// Set store as unhealthy with specific message
	mockStore.SetHealthStatus(types.Unhealthy("connection timeout"))
	mockEmbedder.SetHealthStatus(types.Healthy("ok"))

	ltm := NewLongTermMemory(mockStore, mockEmbedder)

	health := ltm.Health(ctx)
	assert.Equal(t, types.HealthStateUnhealthy, health.State)
	assert.Contains(t, health.Message, "vector store")
	assert.Contains(t, health.Message, "connection timeout")
}
