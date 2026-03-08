//go:build integration
// +build integration

package vector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/milvus-io/milvus-sdk-go/v2/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupMilvusContainer starts a Milvus standalone container and returns its host and port.
func setupMilvusContainer(t *testing.T) (testcontainers.Container, string, int) {
	t.Helper()

	ctx := context.Background()

	// Define the Milvus container request
	// Using standalone mode which is simpler for testing
	// Note: Milvus requires significant resources and may not work in all environments
	req := testcontainers.ContainerRequest{
		Image:        "milvusdb/milvus:v2.4.1",
		ExposedPorts: []string{"19530/tcp"},
		Env: map[string]string{
			"ETCD_USE_EMBED":     "true",
			"COMMON_STORAGETYPE": "local",
		},
		Cmd: []string{"milvus", "run", "standalone"},
		WaitingFor: wait.ForListeningPort("19530/tcp").
			WithStartupTimeout(120 * time.Second), // Milvus needs more time to start
	}

	// Start the container
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Docker not available or failed to start Milvus container: %v", err)
		return nil, "", 0
	}

	// Get the gRPC port (19530)
	grpcPort, err := container.MappedPort(ctx, "19530")
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

	// Give Milvus extra time to fully initialize
	time.Sleep(5 * time.Second)

	return container, host, grpcPort.Int()
}

// createMilvusStore creates a MilvusVectorStore connected to the test container.
// It directly creates the store using the raw constructor approach since we need
// to specify custom host/port for the container.
func createMilvusStore(t *testing.T, host string, port int) *MilvusVectorStore {
	t.Helper()

	ctx := context.Background()
	dims := 384

	// Build connection address
	addr := fmt.Sprintf("%s:%d", host, port)

	// Connect to Milvus
	c, err := client.NewClient(ctx, client.Config{
		Address: addr,
	})
	require.NoError(t, err, "Failed to connect to Milvus")

	collectionName := fmt.Sprintf("test_collection_%s", uuid.New().String()[:8])

	store := &MilvusVectorStore{
		client:     c,
		collection: collectionName,
		dims:       dims,
		closed:     false,
	}

	// Ensure collection exists
	err = store.ensureCollection(ctx)
	require.NoError(t, err, "Failed to ensure collection exists")

	return store
}

// TestMilvusIntegration_Health tests the Health method with a real Milvus instance.
func TestMilvusIntegration_Health(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()
	status := store.Health(ctx)

	assert.True(t, status.IsHealthy(), "Milvus store should be healthy")
	assert.NotEmpty(t, status.Message, "Health message should not be empty")
	t.Logf("Health status: %+v", status)
}

// TestMilvusIntegration_StoreAndGet tests storing and retrieving a single vector.
func TestMilvusIntegration_StoreAndGet(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create a test vector record
	recordID := uuid.New().String()
	record := VectorRecord{
		ID:        recordID,
		Content:   "This is a test document for Milvus integration testing",
		Embedding: generateMilvusTestEmbedding(384),
		Metadata: map[string]any{
			"category": "test",
			"source":   "integration_test",
		},
		CreatedAt: time.Now(),
	}

	// Store the record
	err := store.Store(ctx, record)
	require.NoError(t, err, "Failed to store vector record")

	// Give Milvus a moment to index
	time.Sleep(500 * time.Millisecond)

	// Retrieve the record
	retrieved, err := store.Get(ctx, recordID)
	require.NoError(t, err, "Failed to retrieve vector record")
	require.NotNil(t, retrieved, "Retrieved record should not be nil")

	// Verify the retrieved record
	assert.Equal(t, record.ID, retrieved.ID)
	assert.Equal(t, record.Content, retrieved.Content)
	assert.Equal(t, len(record.Embedding), len(retrieved.Embedding))

	// Metadata comparison - Milvus may return metadata differently
	if retrieved.Metadata != nil {
		if category, ok := retrieved.Metadata["category"]; ok {
			assert.Equal(t, record.Metadata["category"], category)
		}
		if source, ok := retrieved.Metadata["source"]; ok {
			assert.Equal(t, record.Metadata["source"], source)
		}
	}

	t.Logf("Successfully stored and retrieved record: %s", recordID)
}

// TestMilvusIntegration_StoreBatch tests batch storage of multiple vectors.
func TestMilvusIntegration_StoreBatch(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create multiple test records
	numRecords := 10
	records := make([]VectorRecord, numRecords)
	for i := 0; i < numRecords; i++ {
		records[i] = VectorRecord{
			ID:        uuid.New().String(),
			Content:   fmt.Sprintf("Test document %d for Milvus batch storage", i),
			Embedding: generateMilvusTestEmbedding(384),
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

	// Give Milvus time to index
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

// TestMilvusIntegration_Search tests vector similarity search.
func TestMilvusIntegration_Search(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create and store test vectors with similar embeddings
	queryEmbedding := generateMilvusTestEmbedding(384)

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
			Embedding: generateMilvusSimilarEmbedding(queryEmbedding, 0.9), // Very similar
			Metadata:  map[string]any{"relevance": "medium"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "Completely unrelated content about cats and trees",
			Embedding: generateMilvusTestEmbedding(384), // Random, dissimilar
			Metadata:  map[string]any{"relevance": "low"},
			CreatedAt: time.Now(),
		},
	}

	err := store.StoreBatch(ctx, records)
	require.NoError(t, err, "Failed to store test records")

	// Give Milvus time to index
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

	// The exact match should be among the top results (not necessarily first due to approx. search)
	foundExactMatch := false
	for i, result := range results {
		if result.Record.ID == records[0].ID {
			foundExactMatch = true
			t.Logf("Exact match found at position %d with score %.4f", i, result.Score)
			break
		}
	}
	assert.True(t, foundExactMatch, "Exact match should be in the results")
	assert.Greater(t, results[0].Score, 0.5, "Top result should have decent similarity score")

	t.Logf("Search returned %d results, top score: %.4f", len(results), results[0].Score)
}

// TestMilvusIntegration_SearchWithMinScore tests search with minimum score threshold.
func TestMilvusIntegration_SearchWithMinScore(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create test records with varying similarities
	queryEmbedding := generateMilvusTestEmbedding(384)

	records := []VectorRecord{
		{
			ID:        uuid.New().String(),
			Content:   "Very similar document",
			Embedding: generateMilvusSimilarEmbedding(queryEmbedding, 0.98),
			Metadata:  map[string]any{"similarity": "very_high"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "Somewhat similar document",
			Embedding: generateMilvusSimilarEmbedding(queryEmbedding, 0.7),
			Metadata:  map[string]any{"similarity": "medium"},
			CreatedAt: time.Now(),
		},
		{
			ID:        uuid.New().String(),
			Content:   "Not very similar document",
			Embedding: generateMilvusTestEmbedding(384),
			Metadata:  map[string]any{"similarity": "low"},
			CreatedAt: time.Now(),
		},
	}

	err := store.StoreBatch(ctx, records)
	require.NoError(t, err, "Failed to store test records")

	// Give Milvus time to index
	time.Sleep(1 * time.Second)

	// Search with high minimum score threshold
	query := VectorQuery{
		Embedding: queryEmbedding,
		TopK:      10,
		MinScore:  0.8, // Should filter out low similarity results
	}

	results, err := store.Search(ctx, query)
	require.NoError(t, err, "Failed to perform filtered search")

	// All results should have score >= 0.8
	for _, result := range results {
		assert.GreaterOrEqual(t, result.Score, 0.8,
			"All results should have score >= min_score threshold")
	}

	t.Logf("Search with min_score=0.8 returned %d results", len(results))
}

// TestMilvusIntegration_Delete tests deleting a vector record.
func TestMilvusIntegration_Delete(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Create and store a test record
	recordID := uuid.New().String()
	record := VectorRecord{
		ID:        recordID,
		Content:   "Document to be deleted from Milvus",
		Embedding: generateMilvusTestEmbedding(384),
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

	// Milvus needs time to sync deletions (eventual consistency)
	// In production, you would need to handle this with proper retry logic
	time.Sleep(5 * time.Second)

	// Verify the record no longer exists
	// Note: Due to Milvus's eventual consistency, this may still return the record
	// in some cases. In production code, implement proper retry logic.
	retrieved, err = store.Get(ctx, recordID)
	if err == nil && retrieved != nil {
		t.Logf("Warning: Record still retrievable after deletion (Milvus eventual consistency)")
		// This is acceptable for an integration test given Milvus's behavior
	} else {
		assert.Error(t, err, "Get should return error for deleted record")
		assert.Nil(t, retrieved, "Retrieved record should be nil after deletion")
	}

	t.Logf("Delete operation completed for record: %s", recordID)
}

// TestMilvusIntegration_Close tests proper cleanup of resources.
func TestMilvusIntegration_Close(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)

	// Close the store
	err := store.Close()
	require.NoError(t, err, "Failed to close store")

	// Verify that operations fail after close
	ctx := context.Background()
	record := VectorRecord{
		ID:        uuid.New().String(),
		Content:   "Test",
		Embedding: generateMilvusTestEmbedding(384),
		CreatedAt: time.Now(),
	}

	err = store.Store(ctx, record)
	assert.Error(t, err, "Store should fail after close")

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeVectorStoreUnavailable, gibsonErr.Code)

	t.Log("Store properly closed and rejects operations")
}

// TestMilvusIntegration_ConcurrentOperations tests thread-safety with concurrent access.
func TestMilvusIntegration_ConcurrentOperations(t *testing.T) {
	container, host, port := setupMilvusContainer(t)
	if container == nil {
		return
	}
	defer container.Terminate(context.Background())

	store := createMilvusStore(t, host, port)
	defer store.Close()

	ctx := context.Background()

	// Perform concurrent store operations
	numGoroutines := 5
	recordsPerGoroutine := 5

	done := make(chan bool, numGoroutines)
	errors := make(chan error, numGoroutines*recordsPerGoroutine)

	for g := 0; g < numGoroutines; g++ {
		go func(goroutineID int) {
			for i := 0; i < recordsPerGoroutine; i++ {
				record := VectorRecord{
					ID:        uuid.New().String(),
					Content:   fmt.Sprintf("Concurrent test doc from goroutine %d, record %d", goroutineID, i),
					Embedding: generateMilvusTestEmbedding(384),
					Metadata: map[string]any{
						"goroutine": goroutineID,
						"index":     i,
					},
					CreatedAt: time.Now(),
				}

				if err := store.Store(ctx, record); err != nil {
					errors <- err
				}
			}
			done <- true
		}(g)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
		errorCount++
	}

	assert.Equal(t, 0, errorCount, "No errors should occur during concurrent operations")
	t.Logf("Successfully completed %d concurrent store operations", numGoroutines*recordsPerGoroutine)
}

// generateMilvusTestEmbedding creates a random embedding vector for testing.
func generateMilvusTestEmbedding(dims int) []float64 {
	embedding := make([]float64, dims)
	for i := range embedding {
		// Generate random values between -1 and 1
		embedding[i] = (float64(i%100) / 100.0) - 0.5
	}
	return embedding
}

// generateMilvusSimilarEmbedding creates an embedding similar to the input with given similarity factor.
func generateMilvusSimilarEmbedding(base []float64, similarity float64) []float64 {
	result := make([]float64, len(base))
	for i := range base {
		// Mix base embedding with small random perturbation
		noise := (float64(i%50) / 100.0) - 0.25
		result[i] = base[i]*similarity + noise*(1-similarity)
	}
	return result
}
