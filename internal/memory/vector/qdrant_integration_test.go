//go:build integration
// +build integration

package vector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/qdrant/go-client/qdrant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/zero-day-ai/gibson/internal/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// setupQdrantContainer starts a Qdrant container and returns its host and port.
func setupQdrantContainer(t *testing.T) (testcontainers.Container, string, int) {
	t.Helper()

	ctx := context.Background()

	// Define the Qdrant container request
	req := testcontainers.ContainerRequest{
		Image:        "qdrant/qdrant:latest",
		ExposedPorts: []string{"6334/tcp", "6333/tcp"},
		WaitingFor: wait.ForHTTP("/").
			WithPort("6333/tcp").
			WithStartupTimeout(60 * time.Second),
	}

	// Start the container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Docker not available or failed to start Qdrant container: %v", err)
		return nil, "", 0
	}

	// Get the gRPC port (6334)
	grpcPort, err := container.MappedPort(ctx, "6334")
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to get mapped gRPC port: %v", err)
	}

	// Get the container host
	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Fatalf("Failed to get container host: %v", err)
	}

	return container, host, grpcPort.Int()
}

// createQdrantStore creates a QdrantVectorStore connected to the test container.
// It directly creates the store using the raw constructor approach since we need
// to specify custom host/port for the container.
func createQdrantStore(t *testing.T, host string, port int) *QdrantVectorStore {
	t.Helper()

	ctx := context.Background()
	dims := 384

	// Build gRPC connection string
	addr := fmt.Sprintf("%s:%d", host, port)

	// Connect to Qdrant with insecure credentials for testing
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "Failed to connect to Qdrant")

	client := qdrant.NewPointsClient(conn)
	collectionName := fmt.Sprintf("test_collection_%s", uuid.New().String()[:8])

	store := &QdrantVectorStore{
		client:     client,
		collection: collectionName,
		dims:       dims,
		grpcConn:   conn,
		closed:     false,
	}

	// Ensure collection exists
	err = store.ensureCollection(ctx)
	require.NoError(t, err, "Failed to ensure collection exists")

	return store
}

// TestQdrantIntegration_Health tests the Health method with a real Qdrant instance.
func TestQdrantIntegration_Health(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)
	defer store.Close()

	ctx := context.Background()
	status := store.Health(ctx)

	assert.True(t, status.IsHealthy(), "Qdrant store should be healthy")
	assert.NotEmpty(t, status.Message, "Health message should not be empty")
	t.Logf("Health status: %+v", status)
}

// TestQdrantIntegration_StoreAndGet tests storing and retrieving a single vector.
func TestQdrantIntegration_StoreAndGet(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create a test vector record
	recordID := uuid.New().String()
	record := VectorRecord{
		ID:        recordID,
		Content:   "This is a test document for integration testing",
		Embedding: generateTestEmbedding(384),
		Metadata: map[string]any{
			"category": "test",
			"source":   "integration_test",
		},
		CreatedAt: time.Now(),
	}

	// Store the record
	err := store.Store(ctx, record)
	require.NoError(t, err, "Failed to store vector record")

	// Give Qdrant a moment to index
	time.Sleep(500 * time.Millisecond)

	// Retrieve the record
	retrieved, err := store.Get(ctx, recordID)
	require.NoError(t, err, "Failed to retrieve vector record")
	require.NotNil(t, retrieved, "Retrieved record should not be nil")

	// Verify the retrieved record
	assert.Equal(t, record.ID, retrieved.ID)
	assert.Equal(t, record.Content, retrieved.Content)
	// Note: Qdrant may return embeddings differently, so we just check if present
	if len(retrieved.Embedding) > 0 {
		assert.Equal(t, len(record.Embedding), len(retrieved.Embedding),
			"Embedding dimensions should match if returned")
	}
	assert.Equal(t, record.Metadata["category"], retrieved.Metadata["category"])
	assert.Equal(t, record.Metadata["source"], retrieved.Metadata["source"])

	t.Logf("Successfully stored and retrieved record: %s", recordID)
}

// TestQdrantIntegration_StoreBatch tests batch storage of multiple vectors.
func TestQdrantIntegration_StoreBatch(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create multiple test records
	numRecords := 10
	records := make([]VectorRecord, numRecords)
	for i := 0; i < numRecords; i++ {
		records[i] = VectorRecord{
			ID:        uuid.New().String(),
			Content:   fmt.Sprintf("Test document %d for batch storage", i),
			Embedding: generateTestEmbedding(384),
			Metadata: map[string]any{
				"batch":  "test_batch",
				"index":  i,
				"source": "integration_test",
			},
			CreatedAt: time.Now(),
		}
	}

	// Store the batch
	err := store.StoreBatch(ctx, records)
	require.NoError(t, err, "Failed to store batch of vector records")

	// Give Qdrant time to index
	time.Sleep(1 * time.Second)

	// Verify each record can be retrieved
	for i, record := range records {
		retrieved, err := store.Get(ctx, record.ID)
		require.NoError(t, err, "Failed to retrieve record %d from batch", i)
		require.NotNil(t, retrieved, "Retrieved record %d should not be nil", i)
		assert.Equal(t, record.ID, retrieved.ID)
		assert.Equal(t, record.Content, retrieved.Content)
	}

	t.Logf("Successfully stored and verified %d records in batch", numRecords)
}

// TestQdrantIntegration_Search tests vector similarity search.
func TestQdrantIntegration_Search(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create and store test vectors with similar embeddings
	queryEmbedding := generateTestEmbedding(384)

	records := []VectorRecord{
		{
			ID:        uuid.New().String(),
			Content:   "The quick brown fox jumps over the lazy dog",
			Embedding: queryEmbedding, // Exact match
			Metadata:  map[string]any{"relevance": "high"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "A fast brown fox leaps over a sleeping dog",
			Embedding: generateSimilarEmbedding(queryEmbedding, 0.9), // Very similar
			Metadata:  map[string]any{"relevance": "medium"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "Completely unrelated content about cats and trees",
			Embedding: generateTestEmbedding(384), // Random, dissimilar
			Metadata:  map[string]any{"relevance": "low"},
			CreatedAt: time.Now(),
		},
	}

	err := store.StoreBatch(ctx, records)
	require.NoError(t, err, "Failed to store test records")

	// Give Qdrant time to index
	time.Sleep(1 * time.Second)

	// Perform a search
	query := VectorQuery{
		Embedding: queryEmbedding,
		TopK:      3,
		MinScore:  0.0,
	}

	results, err := store.Search(ctx, query)
	require.NoError(t, err, "Failed to perform vector search")
	require.NotEmpty(t, results, "Search should return results")

	// Verify results are ordered by similarity (highest score first)
	assert.GreaterOrEqual(t, len(results), 2, "Should have at least 2 results")
	if len(results) >= 2 {
		assert.GreaterOrEqual(t, results[0].Score, results[1].Score,
			"Results should be ordered by score (highest first)")
	}

	// The exact match should be among the top results
	foundExactMatch := false
	for i, result := range results {
		if result.Record.ID == records[0].ID {
			foundExactMatch = true
			t.Logf("Exact match found at position %d with score %.4f", i, result.Score)
			assert.Greater(t, result.Score, 0.95, "Exact match should have high similarity score")
			break
		}
	}
	assert.True(t, foundExactMatch, "Exact match should be in the results")

	t.Logf("Search returned %d results, top score: %.4f", len(results), results[0].Score)
}

// TestQdrantIntegration_SearchWithFilters tests search with metadata filters.
func TestQdrantIntegration_SearchWithFilters(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create test records with different categories
	queryEmbedding := generateTestEmbedding(384)

	records := []VectorRecord{
		{
			ID:        uuid.New().String(),
			Content:   "Document about technology",
			Embedding: queryEmbedding,
			Metadata:  map[string]any{"category": "technology"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "Document about science",
			Embedding: generateSimilarEmbedding(queryEmbedding, 0.95),
			Metadata:  map[string]any{"category": "science"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "Another technology document",
			Embedding: generateSimilarEmbedding(queryEmbedding, 0.9),
			Metadata:  map[string]any{"category": "technology"},
			CreatedAt: time.Now(),
		},
	}

	err := store.StoreBatch(ctx, records)
	require.NoError(t, err, "Failed to store test records")

	// Give Qdrant time to index
	time.Sleep(1 * time.Second)

	// Search with category filter
	query := VectorQuery{
		Embedding: queryEmbedding,
		TopK:      5,
		Filters:   map[string]any{"category": "technology"},
	}

	results, err := store.Search(ctx, query)
	require.NoError(t, err, "Failed to perform filtered search")
	require.NotEmpty(t, results, "Filtered search should return results")

	// Verify all results match the filter
	for _, result := range results {
		category, ok := result.Record.Metadata["category"]
		assert.True(t, ok, "Result should have category metadata")
		assert.Equal(t, "technology", category, "All results should have category 'technology'")
	}

	t.Logf("Filtered search returned %d results (all with category=technology)", len(results))
}

// TestQdrantIntegration_Delete tests deleting a vector record.
func TestQdrantIntegration_Delete(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create and store a test record
	recordID := uuid.New().String()
	record := VectorRecord{
		ID:        recordID,
		Content:   "Document to be deleted",
		Embedding: generateTestEmbedding(384),
		Metadata:  map[string]any{"test": "delete"},
		CreatedAt: time.Now(),
	}

	err := store.Store(ctx, record)
	require.NoError(t, err, "Failed to store record")

	time.Sleep(500 * time.Millisecond)

	// Verify the record exists
	retrieved, err := store.Get(ctx, recordID)
	require.NoError(t, err, "Failed to retrieve record before deletion")
	require.NotNil(t, retrieved, "Record should exist before deletion")

	// Delete the record
	err = store.Delete(ctx, recordID)
	require.NoError(t, err, "Failed to delete record")

	time.Sleep(500 * time.Millisecond)

	// Verify the record no longer exists
	retrieved, err = store.Get(ctx, recordID)
	assert.Error(t, err, "Get should return error for deleted record")
	assert.Nil(t, retrieved, "Retrieved record should be nil after deletion")

	t.Logf("Successfully deleted record: %s", recordID)
}

// TestQdrantIntegration_Close tests proper cleanup of resources.
func TestQdrantIntegration_Close(t *testing.T) {
	container, host, port := setupQdrantContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createQdrantStore(t, host, port)

	// Close the store
	err := store.Close()
	require.NoError(t, err, "Failed to close store")

	// Verify that operations fail after close
	ctx := context.Background()
	record := VectorRecord{
		ID:        uuid.New().String(),
		Content:   "Test",
		Embedding: generateTestEmbedding(384),
		CreatedAt: time.Now(),
	}

	err = store.Store(ctx, record)
	assert.Error(t, err, "Store should fail after close")

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeVectorStoreUnavailable, gibsonErr.Code)

	t.Log("Store properly closed and rejects operations")
}

// generateTestEmbedding creates a random embedding vector for testing.
func generateTestEmbedding(dims int) []float64 {
	embedding := make([]float64, dims)
	for i := range embedding {
		// Generate random values between -1 and 1
		embedding[i] = (float64(i%100) / 100.0) - 0.5
	}
	return embedding
}

// generateSimilarEmbedding creates an embedding similar to the input with given similarity factor.
func generateSimilarEmbedding(base []float64, similarity float64) []float64 {
	result := make([]float64, len(base))
	for i := range base {
		// Mix base embedding with small random perturbation
		noise := (float64(i%50) / 100.0) - 0.25
		result[i] = base[i]*similarity + noise*(1-similarity)
	}
	return result
}
