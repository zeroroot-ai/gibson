package knowledge

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupTestKnowledgeManager creates a test knowledge manager with in-memory vector store
// Note: This is a minimal test setup. For full testing, use Redis-based integration tests.
func setupTestKnowledgeManager(t *testing.T) (KnowledgeManager, func()) {
	t.Helper()

	// Create embedded vector store (in-memory)
	vecStore := vector.NewEmbeddedVectorStore(384)

	// Create embedder (mock for testing)
	emb := embedder.NewMockEmbedder()

	// Create long-term memory
	ltm := memory.NewLongTermMemory(vecStore, emb)

	// Create mock knowledge manager
	// Note: Since the default knowledge manager requires database.sql.DB which is SQLite-specific,
	// this test now uses a limited mock. For full testing, use integration tests with Redis.
	km := &mockKnowledgeManager{
		ltm:     ltm,
		sources: make(map[string]KnowledgeSource),
		chunks:  make(map[string]KnowledgeChunk),
	}

	cleanup := func() {
		vecStore.Close()
	}

	return km, cleanup
}

// mockKnowledgeManager is a simple in-memory implementation for unit testing
type mockKnowledgeManager struct {
	ltm     memory.LongTermMemory
	sources map[string]KnowledgeSource
	chunks  map[string]KnowledgeChunk
}

func (m *mockKnowledgeManager) StoreChunk(ctx context.Context, chunk KnowledgeChunk) error {
	if err := m.ltm.Store(ctx, memory.Document{
		ID:        chunk.ID,
		Content:   chunk.Text,
		Metadata:  map[string]any{"source": chunk.Source, "source_hash": chunk.SourceHash},
		Timestamp: chunk.CreatedAt,
	}); err != nil {
		return err
	}
	m.chunks[chunk.ID] = chunk
	return nil
}

func (m *mockKnowledgeManager) StoreBatch(ctx context.Context, chunks []KnowledgeChunk) error {
	for _, chunk := range chunks {
		if err := m.StoreChunk(ctx, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (m *mockKnowledgeManager) Search(ctx context.Context, query string, opts SearchOptions) ([]KnowledgeResult, error) {
	docs, err := m.ltm.Search(ctx, query, memory.SearchOptions{Limit: opts.Limit})
	if err != nil {
		return nil, err
	}
	results := make([]KnowledgeResult, len(docs))
	for i, doc := range docs {
		results[i] = KnowledgeResult{
			ChunkID:    doc.ID,
			Content:    doc.Content,
			Similarity: doc.Score,
		}
	}
	return results, nil
}

func (m *mockKnowledgeManager) ListSources(ctx context.Context) ([]KnowledgeSource, error) {
	sources := make([]KnowledgeSource, 0, len(m.sources))
	for _, s := range m.sources {
		sources = append(sources, s)
	}
	return sources, nil
}

func (m *mockKnowledgeManager) GetSourceByHash(ctx context.Context, hash string) (*KnowledgeSource, error) {
	for _, s := range m.sources {
		if s.SourceHash == hash {
			return &s, nil
		}
	}
	return nil, nil
}

func (m *mockKnowledgeManager) StoreSource(ctx context.Context, source KnowledgeSource) error {
	m.sources[source.Source] = source
	return nil
}

func (m *mockKnowledgeManager) GetStats(ctx context.Context) (KnowledgeStats, error) {
	return KnowledgeStats{
		TotalChunks:  len(m.chunks),
		TotalSources: len(m.sources),
	}, nil
}

func (m *mockKnowledgeManager) DeleteBySource(ctx context.Context, source string) error {
	for id, chunk := range m.chunks {
		if chunk.Source == source {
			delete(m.chunks, id)
			m.ltm.Delete(ctx, id)
		}
	}
	delete(m.sources, source)
	return nil
}

func (m *mockKnowledgeManager) DeleteAll(ctx context.Context) error {
	m.chunks = make(map[string]KnowledgeChunk)
	m.sources = make(map[string]KnowledgeSource)
	return nil
}

func (m *mockKnowledgeManager) Health(ctx context.Context) types.HealthStatus {
	return types.HealthStatusHealthy
}

func (m *mockKnowledgeManager) Close() error {
	return nil
}

func TestStoreChunk(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("store valid chunk", func(t *testing.T) {
		chunk := KnowledgeChunk{
			ID:         "chunk-1",
			Source:     "test.pdf",
			SourceHash: "hash123",
			Text:       "This is a test chunk of knowledge.",
			Metadata: ChunkMetadata{
				Section:    "Introduction",
				PageNumber: 1,
				StartChar:  0,
			},
			CreatedAt: time.Now(),
		}

		err := km.StoreChunk(ctx, chunk)
		assert.NoError(t, err)
	})

	t.Run("reject chunk without ID", func(t *testing.T) {
		chunk := KnowledgeChunk{
			Source: "test.pdf",
			Text:   "Content",
		}

		err := km.StoreChunk(ctx, chunk)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "ID cannot be empty")
	})

	t.Run("reject chunk without text", func(t *testing.T) {
		chunk := KnowledgeChunk{
			ID:     "chunk-2",
			Source: "test.pdf",
		}

		err := km.StoreChunk(ctx, chunk)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "text cannot be empty")
	})

	t.Run("reject chunk without source", func(t *testing.T) {
		chunk := KnowledgeChunk{
			ID:   "chunk-3",
			Text: "Content",
		}

		err := km.StoreChunk(ctx, chunk)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source cannot be empty")
	})

	t.Run("store chunk with code metadata", func(t *testing.T) {
		chunk := KnowledgeChunk{
			ID:         "chunk-code",
			Source:     "code.md",
			SourceHash: "hashcode",
			Text:       "```go\nfunc main() {}\n```",
			Metadata: ChunkMetadata{
				HasCode:  true,
				Language: "go",
			},
			CreatedAt: time.Now(),
		}

		err := km.StoreChunk(ctx, chunk)
		assert.NoError(t, err)
	})
}

func TestStoreBatch(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("store multiple chunks", func(t *testing.T) {
		chunks := []KnowledgeChunk{
			{
				ID:         "batch-1",
				Source:     "doc1.pdf",
				SourceHash: "hash1",
				Text:       "First chunk",
				CreatedAt:  time.Now(),
			},
			{
				ID:         "batch-2",
				Source:     "doc1.pdf",
				SourceHash: "hash1",
				Text:       "Second chunk",
				CreatedAt:  time.Now(),
			},
			{
				ID:         "batch-3",
				Source:     "doc2.pdf",
				SourceHash: "hash2",
				Text:       "Third chunk",
				CreatedAt:  time.Now(),
			},
		}

		err := km.StoreBatch(ctx, chunks)
		assert.NoError(t, err)
	})

	t.Run("reject batch with invalid chunk", func(t *testing.T) {
		chunks := []KnowledgeChunk{
			{
				ID:     "valid",
				Source: "test.pdf",
				Text:   "Valid",
			},
			{
				ID:   "invalid",
				Text: "No source",
			},
		}

		err := km.StoreBatch(ctx, chunks)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source cannot be empty")
	})

	t.Run("handle empty batch", func(t *testing.T) {
		err := km.StoreBatch(ctx, []KnowledgeChunk{})
		assert.NoError(t, err)
	})
}

func TestSearch(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	// Store test data
	chunks := []KnowledgeChunk{
		{
			ID:         "search-1",
			Source:     "security.pdf",
			SourceHash: "sec123",
			Text:       "SQL injection is a common web vulnerability",
			Metadata: ChunkMetadata{
				Section: "Web Security",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:         "search-2",
			Source:     "security.pdf",
			SourceHash: "sec123",
			Text:       "Cross-site scripting (XSS) attacks exploit user input",
			Metadata: ChunkMetadata{
				Section: "Web Security",
			},
			CreatedAt: time.Now(),
		},
		{
			ID:         "search-3",
			Source:     "network.pdf",
			SourceHash: "net456",
			Text:       "TCP three-way handshake establishes connections",
			Metadata: ChunkMetadata{
				Section: "Networking",
			},
			CreatedAt: time.Now(),
		},
	}

	for _, chunk := range chunks {
		err := km.StoreChunk(ctx, chunk)
		require.NoError(t, err)
	}

	t.Run("basic search", func(t *testing.T) {
		opts := SearchOptions{
			Limit:     10,
			Threshold: 0.0,
		}

		results, err := km.Search(ctx, "web security vulnerabilities", opts)
		assert.NoError(t, err)
		assert.NotEmpty(t, results)
	})

	t.Run("search with limit", func(t *testing.T) {
		opts := SearchOptions{
			Limit:     1,
			Threshold: 0.0,
		}

		results, err := km.Search(ctx, "security", opts)
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(results), 1)
	})

	t.Run("search with source filter", func(t *testing.T) {
		opts := SearchOptions{
			Limit:  10,
			Source: "network.pdf",
		}

		results, err := km.Search(ctx, "connection", opts)
		assert.NoError(t, err)
		for _, result := range results {
			assert.Equal(t, "network.pdf", result.Chunk.Source)
		}
	})

	t.Run("search with threshold", func(t *testing.T) {
		opts := SearchOptions{
			Limit:     10,
			Threshold: 0.5, // High threshold
		}

		_, err := km.Search(ctx, "unrelated query about quantum physics", opts)
		assert.NoError(t, err)
		// Should return fewer or no results due to high threshold
	})

	t.Run("search with custom filter", func(t *testing.T) {
		opts := SearchOptions{
			Limit:   10,
			Filters: map[string]any{"section": "Web Security"},
		}

		results, err := km.Search(ctx, "attacks", opts)
		assert.NoError(t, err)
		for _, result := range results {
			assert.Equal(t, "Web Security", result.Chunk.Metadata.Section)
		}
	})

	t.Run("search returns scores", func(t *testing.T) {
		opts := NewSearchOptions().WithLimit(5)

		results, err := km.Search(ctx, "security", *opts)
		assert.NoError(t, err)
		for _, result := range results {
			assert.GreaterOrEqual(t, result.Score, 0.0)
			assert.LessOrEqual(t, result.Score, 1.0)
		}
	})
}

func TestListSources(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty sources", func(t *testing.T) {
		sources, err := km.ListSources(ctx)
		assert.NoError(t, err)
		assert.Empty(t, sources)
	})

	t.Run("list multiple sources", func(t *testing.T) {
		// Insert test sources
		sources := []KnowledgeSource{
			{
				Source:     "doc1.pdf",
				SourceType: "pdf",
				SourceHash: "hash1",
				ChunkCount: 5,
				IngestedAt: time.Now(),
			},
			{
				Source:     "doc2.pdf",
				SourceType: "pdf",
				SourceHash: "hash2",
				ChunkCount: 3,
				IngestedAt: time.Now(),
			},
			{
				Source:     "https://example.com/article",
				SourceType: "url",
				SourceHash: "hash3",
				ChunkCount: 10,
				IngestedAt: time.Now(),
			},
		}

		for _, src := range sources {
			_, err := db.ExecContext(ctx, `
				INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count, ingested_at)
				VALUES (?, ?, ?, ?, ?)
			`, src.Source, src.SourceType, src.SourceHash, src.ChunkCount, src.IngestedAt)
			require.NoError(t, err)
		}

		// List sources
		listed, err := km.ListSources(ctx)
		assert.NoError(t, err)
		assert.Len(t, listed, 3)

		// Verify sources are ordered by ingested_at DESC
		for i := 0; i < len(listed)-1; i++ {
			assert.True(t, listed[i].IngestedAt.After(listed[i+1].IngestedAt) ||
				listed[i].IngestedAt.Equal(listed[i+1].IngestedAt))
		}
	})
}

func TestGetStats(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("empty stats", func(t *testing.T) {
		stats, err := km.GetStats(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 0, stats.TotalSources)
		assert.Equal(t, 0, stats.TotalChunks)
	})

	t.Run("stats with data", func(t *testing.T) {
		// Insert test sources - format time as RFC3339 for SQLite compatibility
		now := time.Now().Format(time.RFC3339)
		_, err := db.ExecContext(ctx, `
			INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count, ingested_at)
			VALUES (?, ?, ?, ?, ?)
		`, "doc1.pdf", "pdf", "hash1", 5, now)
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `
			INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count, ingested_at)
			VALUES (?, ?, ?, ?, ?)
		`, "doc2.pdf", "pdf", "hash2", 3, now)
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, `
			INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count, ingested_at)
			VALUES (?, ?, ?, ?, ?)
		`, "https://example.com", "url", "hash3", 10, now)
		require.NoError(t, err)

		// Store some chunks
		chunks := []KnowledgeChunk{
			{ID: "c1", Source: "doc1.pdf", SourceHash: "hash1", Text: "Chunk 1", CreatedAt: time.Now()},
			{ID: "c2", Source: "doc1.pdf", SourceHash: "hash1", Text: "Chunk 2", CreatedAt: time.Now()},
			{ID: "c3", Source: "doc2.pdf", SourceHash: "hash2", Text: "Chunk 3", CreatedAt: time.Now()},
		}
		err = km.StoreBatch(ctx, chunks)
		require.NoError(t, err)

		// Get stats
		stats, err := km.GetStats(ctx)
		assert.NoError(t, err)
		assert.Equal(t, 3, stats.TotalSources)
		assert.Equal(t, 3, stats.TotalChunks)
		assert.Greater(t, stats.StorageBytes, int64(0))
		assert.False(t, stats.LastIngestTime.IsZero())

		// Check sources by type
		assert.Equal(t, 2, stats.SourcesByType["pdf"])
		assert.Equal(t, 1, stats.SourcesByType["url"])
	})
}

func TestDeleteBySource(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	// Store test data
	chunks := []KnowledgeChunk{
		{ID: "del-1", Source: "delete-me.pdf", SourceHash: "hash1", Text: "Chunk 1", CreatedAt: time.Now()},
		{ID: "del-2", Source: "delete-me.pdf", SourceHash: "hash1", Text: "Chunk 2", CreatedAt: time.Now()},
		{ID: "keep-1", Source: "keep-me.pdf", SourceHash: "hash2", Text: "Keep this", CreatedAt: time.Now()},
	}

	for _, chunk := range chunks {
		err := km.StoreChunk(ctx, chunk)
		require.NoError(t, err)
	}

	// Insert source records
	_, err := db.ExecContext(ctx, `
		INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count)
		VALUES (?, ?, ?, ?)
	`, "delete-me.pdf", "pdf", "hash1", 2)
	require.NoError(t, err)

	_, err = db.ExecContext(ctx, `
		INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count)
		VALUES (?, ?, ?, ?)
	`, "keep-me.pdf", "pdf", "hash2", 1)
	require.NoError(t, err)

	t.Run("delete by source", func(t *testing.T) {
		err := km.DeleteBySource(ctx, "delete-me.pdf")
		assert.NoError(t, err)

		// Verify chunks are deleted
		var count int
		err = db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM knowledge_vectors 
			WHERE json_extract(metadata, '$.source') = ?
		`, "delete-me.pdf").Scan(&count)
		assert.NoError(t, err)
		assert.Equal(t, 0, count)

		// Verify source record is deleted
		err = db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM knowledge_sources WHERE source = ?
		`, "delete-me.pdf").Scan(&count)
		assert.NoError(t, err)
		assert.Equal(t, 0, count)

		// Verify other chunks remain
		err = db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM knowledge_vectors 
			WHERE json_extract(metadata, '$.source') = ?
		`, "keep-me.pdf").Scan(&count)
		assert.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("delete non-existent source", func(t *testing.T) {
		err := km.DeleteBySource(ctx, "non-existent.pdf")
		assert.NoError(t, err) // Should not error
	})
}

func TestDeleteAll(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	// Store test data
	chunks := []KnowledgeChunk{
		{ID: "all-1", Source: "doc1.pdf", SourceHash: "hash1", Text: "Chunk 1", CreatedAt: time.Now()},
		{ID: "all-2", Source: "doc2.pdf", SourceHash: "hash2", Text: "Chunk 2", CreatedAt: time.Now()},
	}

	for _, chunk := range chunks {
		err := km.StoreChunk(ctx, chunk)
		require.NoError(t, err)
	}

	// Insert source records
	_, err := db.ExecContext(ctx, `
		INSERT INTO knowledge_sources (source, source_type, source_hash, chunk_count)
		VALUES (?, ?, ?, ?)
	`, "doc1.pdf", "pdf", "hash1", 1)
	require.NoError(t, err)

	t.Run("delete all knowledge", func(t *testing.T) {
		err := km.DeleteAll(ctx)
		assert.NoError(t, err)

		// Verify all chunks deleted
		var chunkCount int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM knowledge_vectors").Scan(&chunkCount)
		assert.NoError(t, err)
		assert.Equal(t, 0, chunkCount)

		// Verify all sources deleted
		var sourceCount int
		err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM knowledge_sources").Scan(&sourceCount)
		assert.NoError(t, err)
		assert.Equal(t, 0, sourceCount)
	})
}

func TestHealth(t *testing.T) {
	km, cleanup := setupTestKnowledgeManager(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("healthy knowledge manager", func(t *testing.T) {
		health := km.Health(ctx)
		assert.True(t, health.IsHealthy())
		assert.Contains(t, health.Message, "operational")
	})

	t.Run("health reports chunk count", func(t *testing.T) {
		// Store a chunk
		chunk := KnowledgeChunk{
			ID:         "health-1",
			Source:     "test.pdf",
			SourceHash: "hash",
			Text:       "Test",
			CreatedAt:  time.Now(),
		}
		err := km.StoreChunk(ctx, chunk)
		require.NoError(t, err)

		health := km.Health(ctx)
		assert.True(t, health.IsHealthy())
		assert.Contains(t, health.Message, "1 chunk")
	})
}

func TestSearchOptions(t *testing.T) {
	t.Run("default options", func(t *testing.T) {
		opts := NewSearchOptions()
		assert.Equal(t, 10, opts.Limit)
		assert.Equal(t, 0.0, opts.Threshold)
		assert.NotNil(t, opts.Filters)
	})

	t.Run("fluent builder", func(t *testing.T) {
		opts := NewSearchOptions().
			WithLimit(20).
			WithThreshold(0.7).
			WithSource("test.pdf").
			WithSourceType("pdf").
			WithFilter("custom_key", "custom_value")

		assert.Equal(t, 20, opts.Limit)
		assert.Equal(t, 0.7, opts.Threshold)
		assert.Equal(t, "test.pdf", opts.Source)
		assert.Equal(t, "pdf", opts.SourceType)
		assert.Equal(t, "custom_value", opts.Filters["custom_key"])
	})
}
