package graphrag

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


func TestNewGraphRAGStoreWithProvider_Success(t *testing.T) {
	// Test that NewGraphRAGStoreWithProvider works with injected provider
	config := GraphRAGConfig{
		Provider: "neo4j",
		Neo4j: Neo4jConfig{
			URI:      "bolt://localhost:7687",
			Username: "neo4j",
			Password: "password",
			Database: "neo4j",
			PoolSize: 50,
		},
	}
	embedder := NewMockEmbedder()
	mockProvider := NewMockGraphRAGProvider()

	store, err := NewGraphRAGStoreWithProvider(config, embedder, mockProvider)

	// Should succeed
	require.NoError(t, err)
	require.NotNil(t, store)

	// Verify it's a DefaultGraphRAGStore
	defaultStore, ok := store.(*DefaultGraphRAGStore)
	require.True(t, ok, "Expected *DefaultGraphRAGStore")

	// Verify provider is the injected mock
	assert.Equal(t, mockProvider, defaultStore.provider)
}

func TestNewGraphRAGStoreWithProvider_NilProvider(t *testing.T) {
	// Test that NewGraphRAGStoreWithProvider rejects nil provider
	config := GraphRAGConfig{
		Provider: "neo4j",
		Neo4j: Neo4jConfig{
			URI:      "bolt://localhost:7687",
			Username: "neo4j",
			Password: "password",
		},
	}
	embedder := NewMockEmbedder()

	store, err := NewGraphRAGStoreWithProvider(config, embedder, nil)

	// Should fail
	require.Error(t, err)
	require.Nil(t, store)
	assert.Contains(t, err.Error(), "provider cannot be nil")
}

func TestNewGraphRAGStoreWithProvider_NilEmbedder(t *testing.T) {
	// Test that NewGraphRAGStoreWithProvider rejects nil embedder
	config := GraphRAGConfig{
		Provider: "neo4j",
		Neo4j: Neo4jConfig{
			URI:      "bolt://localhost:7687",
			Username: "neo4j",
			Password: "password",
		},
	}
	mockProvider := NewMockGraphRAGProvider()

	store, err := NewGraphRAGStoreWithProvider(config, nil, mockProvider)

	// Should fail
	require.Error(t, err)
	require.Nil(t, store)
	assert.Contains(t, err.Error(), "embedder cannot be nil")
}

func TestNewGraphRAGStoreWithProvider_InvalidConfig(t *testing.T) {
	// Test that NewGraphRAGStoreWithProvider validates config
	config := GraphRAGConfig{
		Provider: "", // Empty provider is invalid
	}
	embedder := NewMockEmbedder()
	mockProvider := NewMockGraphRAGProvider()

	store, err := NewGraphRAGStoreWithProvider(config, embedder, mockProvider)

	// Should fail due to invalid config
	require.Error(t, err)
	require.Nil(t, store)
}

func TestMockGraphRAGProvider_BasicOperations(t *testing.T) {
	// Test that the mock provider implements all operations correctly for testing
	provider := NewMockGraphRAGProvider()
	ctx := context.Background()

	// All operations should succeed with empty/nil results
	err := provider.Initialize(ctx)
	assert.NoError(t, err)

	nodes, err := provider.QueryNodes(ctx, *NewNodeQuery())
	assert.NoError(t, err)
	assert.Empty(t, nodes)

	rels, err := provider.QueryRelationships(ctx, *NewRelQuery())
	assert.NoError(t, err)
	assert.Empty(t, rels)

	traversed, err := provider.TraverseGraph(ctx, "test", 3, TraversalFilters{})
	assert.NoError(t, err)
	assert.Empty(t, traversed)

	vectorResults, err := provider.VectorSearch(ctx, []float64{0.1, 0.2}, 10, nil)
	assert.NoError(t, err)
	assert.Empty(t, vectorResults)

	health := provider.Health(ctx)
	assert.True(t, health.IsHealthy())

	err = provider.Close()
	assert.NoError(t, err)
}
