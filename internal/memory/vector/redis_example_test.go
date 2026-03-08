package vector_test

import (
	"context"
	"fmt"
	"log"

	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/state"
)

// Example_redisVectorStore demonstrates basic usage of RedisVectorStore
// for semantic search with vector embeddings.
func Example_redisVectorStore() {
	ctx := context.Background()

	// 1. Create Redis state client
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	// 2. Ensure vector index is created
	if err := client.EnsureIndexes(ctx); err != nil {
		log.Fatalf("failed to create indexes: %v", err)
	}

	// 3. Create vector store (384 dimensions for all-minilm-l6-v2)
	store := vector.NewRedisVectorStore(client, 384)
	defer store.Close()

	// 4. Store vector records
	record := vector.VectorRecord{
		ID:        "doc-1",
		Content:   "Machine learning is a subset of artificial intelligence",
		Embedding: make([]float64, 384), // In practice, use real embeddings
		Metadata: map[string]any{
			"category": "ml",
			"source":   "tutorial",
		},
	}

	if err := store.Store(ctx, record); err != nil {
		log.Fatalf("failed to store vector: %v", err)
	}

	// 5. Search by similarity
	queryEmbedding := make([]float64, 384) // In practice, embed your query text
	query := vector.NewVectorQueryFromEmbedding(queryEmbedding, 10)

	results, err := store.Search(ctx, *query)
	if err != nil {
		log.Fatalf("failed to search: %v", err)
	}

	fmt.Printf("Found %d results\n", len(results))
	for _, result := range results {
		fmt.Printf("- %s (score: %.3f)\n", result.Record.Content, result.Score)
	}
}

// Example_redisVectorStore_hybridSearch demonstrates combining
// full-text search with vector similarity search.
func Example_redisVectorStore_hybridSearch() {
	ctx := context.Background()

	// Setup client and store (omitted for brevity)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		log.Fatalf("failed to create client: %v", err)
	}
	defer client.Close()

	if err := client.EnsureIndexes(ctx); err != nil {
		log.Fatalf("failed to create indexes: %v", err)
	}

	store := vector.NewRedisVectorStore(client, 384)
	defer store.Close()

	// Hybrid search: text + vector
	query := vector.VectorQuery{
		Text:      "security vulnerability", // Full-text component
		Embedding: make([]float64, 384),     // Vector component (use real embeddings)
		TopK:      5,
		MinScore:  0.7, // Only return results with >70% similarity
	}

	results, err := store.Search(ctx, query)
	if err != nil {
		log.Fatalf("failed to search: %v", err)
	}

	fmt.Printf("Found %d results matching both text and vector\n", len(results))
	for _, result := range results {
		fmt.Printf("- %s\n", result.Record.Content)
	}
}

// Example_redisVectorStore_batchOperations demonstrates efficient
// batch storage of multiple vectors.
func Example_redisVectorStore_batchOperations() {
	ctx := context.Background()

	// Setup (omitted for brevity)
	cfg := state.DefaultConfig()
	client, _ := state.NewStateClient(cfg)
	defer client.Close()
	_ = client.EnsureIndexes(ctx)

	store := vector.NewRedisVectorStore(client, 384)
	defer store.Close()

	// Prepare batch of records
	records := []vector.VectorRecord{
		{
			ID:        "doc-1",
			Content:   "First document",
			Embedding: make([]float64, 384),
		},
		{
			ID:        "doc-2",
			Content:   "Second document",
			Embedding: make([]float64, 384),
		},
		{
			ID:        "doc-3",
			Content:   "Third document",
			Embedding: make([]float64, 384),
		},
	}

	// Store batch efficiently using Redis pipeline
	if err := store.StoreBatch(ctx, records); err != nil {
		log.Fatalf("failed to store batch: %v", err)
	}

	fmt.Printf("Successfully stored %d vectors\n", len(records))
}

// Example_redisVectorStore_metadataFiltering demonstrates filtering
// search results by metadata attributes.
func Example_redisVectorStore_metadataFiltering() {
	ctx := context.Background()

	// Setup (omitted for brevity)
	cfg := state.DefaultConfig()
	client, _ := state.NewStateClient(cfg)
	defer client.Close()
	_ = client.EnsureIndexes(ctx)

	store := vector.NewRedisVectorStore(client, 384)
	defer store.Close()

	// Search with metadata filters
	query := vector.NewVectorQueryFromEmbedding(make([]float64, 384), 10).
		WithFilters(map[string]any{
			"category": "security",
			"severity": "high",
		}).
		WithMinScore(0.8)

	results, err := store.Search(ctx, *query)
	if err != nil {
		log.Fatalf("failed to search: %v", err)
	}

	fmt.Printf("Found %d high-severity security documents\n", len(results))
}
