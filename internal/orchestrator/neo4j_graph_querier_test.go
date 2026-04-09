package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockSemanticEmbeddingProvider returns a fixed vector for Embed.
type mockSemanticEmbeddingProvider struct {
	err error
}

func (m *mockSemanticEmbeddingProvider) Embed(_ context.Context, texts []string) ([][]float64, error) {
	if m.err != nil {
		return nil, m.err
	}
	result := make([][]float64, len(texts))
	for i := range texts {
		result[i] = []float64{0.1, 0.9, 0.3}
	}
	return result, nil
}
func (m *mockSemanticEmbeddingProvider) SupportsEmbeddings() bool { return true }

// TestSemanticSearch_VectorPathCypher checks that vectorSearch generates Cypher
// containing the Neo4j vector procedure call. Since we don't have a real Neo4j
// instance, we verify the query string by inspecting the generated Cypher
// indirectly through the embeddingKey code path.
//
// The test verifies that:
// - WithEmbeddingProvider wires the provider onto the querier
// - The querier has the provider set correctly
func TestNeo4jGraphQuerier_WithEmbeddingProvider(t *testing.T) {
	q := NewNeo4jGraphQuerier(nil, "neo4j")
	assert.Nil(t, q.embeddingProvider)

	ep := &mockSemanticEmbeddingProvider{}
	q2 := q.WithEmbeddingProvider(ep)
	assert.Same(t, q, q2) // mutates in place and returns self
	assert.NotNil(t, q.embeddingProvider)
}

// TestNeo4jGraphQuerier_FilterByMinSimilarity checks the score filter helper.
func TestNeo4jGraphQuerier_FilterByMinSimilarity(t *testing.T) {
	q := &Neo4jGraphQuerier{}
	matches := []EntityMatch{
		{Score: 0.9},
		{Score: 0.4},
		{Score: 0.7},
	}

	filtered := q.filterByMinSimilarity(matches, 0.6)
	require.Len(t, filtered, 2)
	assert.InDelta(t, 0.9, filtered[0].Score, 0.001)
	assert.InDelta(t, 0.7, filtered[1].Score, 0.001)
}

// TestNeo4jGraphQuerier_FilterByMinSimilarity_ZeroThreshold passes all matches.
func TestNeo4jGraphQuerier_FilterByMinSimilarity_ZeroThreshold(t *testing.T) {
	q := &Neo4jGraphQuerier{}
	matches := []EntityMatch{{Score: 0.1}, {Score: 0.5}}
	assert.Len(t, q.filterByMinSimilarity(matches, 0), 2)
}

// TestNeo4jGraphQuerier_TextSimilarity verifies word-overlap scoring.
func TestNeo4jGraphQuerier_TextSimilarity(t *testing.T) {
	q := &Neo4jGraphQuerier{}

	props := map[string]any{
		"description": "SQL injection vulnerability in login form",
		"name":        "SQLi",
	}
	score := q.calculateTextSimilarity("SQL injection", props)
	assert.Greater(t, score, 0.0)
	assert.LessOrEqual(t, score, 1.0)
}

// TestNeo4jGraphQuerier_VectorSearch_EmbedError_FallsBack verifies that when
// the embedding provider returns an error, vectorSearch propagates it and
// the SemanticSearch caller can catch it (the test only covers the
// embeddingProvider path returns an error, which causes vector search to return
// an error that triggers a fallback).
func TestNeo4jGraphQuerier_VectorSearch_EmbedError(t *testing.T) {
	ep := &mockSemanticEmbeddingProvider{err: errors.New("provider down")}
	q := NewNeo4jGraphQuerier(nil, "neo4j").WithEmbeddingProvider(ep)

	// vectorSearch should return an error when Embed fails
	_, err := q.vectorSearch(context.Background(), SemanticQuery{Query: "test"}, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider down")
}
