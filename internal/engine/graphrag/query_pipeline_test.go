// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Helper to create test IDs with readable names for debugging
var testIDMap = make(map[string]types.ID)

func testID(name string) types.ID {
	if id, ok := testIDMap[name]; ok {
		return id
	}
	id := types.NewID()
	testIDMap[name] = id
	return id
}

// MockEmbedder is a mock implementation of the Embedder interface for testing.
type MockEmbedder struct {
	embeddings map[string][]float64 // text -> embedding
	embedError error
	dimensions int
	model      string
	health     types.HealthStatus
}

// NewMockEmbedder creates a new mock embedder with predefined embeddings.
func NewMockEmbedder() *MockEmbedder {
	return &MockEmbedder{
		embeddings: make(map[string][]float64),
		dimensions: 1536,
		model:      "mock-embedding-model",
		health:     types.Healthy("mock embedder ready"),
	}
}

// Embed generates an embedding for text (looks up from predefined map).
func (m *MockEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	if m.embedError != nil {
		return nil, m.embedError
	}
	if emb, ok := m.embeddings[text]; ok {
		return emb, nil
	}
	// Return a default embedding if not found
	return generateMockEmbedding(text, m.dimensions), nil
}

// EmbedBatch generates embeddings for multiple texts.
func (m *MockEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	if m.embedError != nil {
		return nil, m.embedError
	}
	embeddings := make([][]float64, len(texts))
	for i, text := range texts {
		embeddings[i], _ = m.Embed(ctx, text)
	}
	return embeddings, nil
}

// Dimensions returns the embedding dimensions.
func (m *MockEmbedder) Dimensions() int {
	return m.dimensions
}

// Model returns the model name.
func (m *MockEmbedder) Model() string {
	return m.model
}

// Health returns the health status.
func (m *MockEmbedder) Health(ctx context.Context) types.HealthStatus {
	return m.health
}

// SetEmbedding sets a predefined embedding for a text.
func (m *MockEmbedder) SetEmbedding(text string, embedding []float64) {
	m.embeddings[text] = embedding
}

// SetEmbedError configures Embed to return an error.
func (m *MockEmbedder) SetEmbedError(err error) {
	m.embedError = err
}

// SetHealth configures the health status.
func (m *MockEmbedder) SetHealth(health types.HealthStatus) {
	m.health = health
}

// generateMockEmbedding creates a simple mock embedding based on text length.
func generateMockEmbedding(text string, dimensions int) []float64 {
	embedding := make([]float64, dimensions)
	// Simple hash-like function based on text
	for i := range embedding {
		embedding[i] = float64((len(text)+i)%100) / 100.0
	}
	return embedding
}

// MockGraphRAGProvider is a mock implementation of GraphRAGProvider for testing.
type MockGraphRAGProvider struct {
	vectorResults     []VectorResult
	graphNodes        []GraphNode
	queriedNodes      []GraphNode
	relationships     []Relationship
	vectorSearchError error
	traverseError     error
	queryNodesError   error
	health            types.HealthStatus
}

// NewMockProvider creates a new mock GraphRAG provider.
func NewMockProvider() *MockGraphRAGProvider {
	return &MockGraphRAGProvider{
		vectorResults: []VectorResult{},
		graphNodes:    []GraphNode{},
		queriedNodes:  []GraphNode{},
		relationships: []Relationship{},
		health:        types.Healthy("mock provider ready"),
	}
}

// NewMockGraphRAGProvider creates a new mock GraphRAG provider (alias for NewMockProvider).
func NewMockGraphRAGProvider() *MockGraphRAGProvider {
	return NewMockProvider()
}

// Initialize is a no-op for the mock.
func (m *MockGraphRAGProvider) Initialize(ctx context.Context) error {
	return nil
}

// VectorSearch returns the configured mock vector results.
func (m *MockGraphRAGProvider) VectorSearch(ctx context.Context, embedding []float64, topK int, filters map[string]any) ([]VectorResult, error) {
	if m.vectorSearchError != nil {
		return nil, m.vectorSearchError
	}

	// Limit to topK
	results := m.vectorResults
	if topK > 0 && len(results) > topK {
		results = results[:topK]
	}

	return results, nil
}

// TraverseGraph returns the configured mock graph nodes.
func (m *MockGraphRAGProvider) TraverseGraph(ctx context.Context, startID string, maxHops int, filters TraversalFilters) ([]GraphNode, error) {
	if m.traverseError != nil {
		return nil, m.traverseError
	}
	return m.graphNodes, nil
}

// QueryNodes returns the configured mock nodes, honouring an "id" property
// predicate when the query carries one.
//
// The id filter is not decoration: FindSimilarFindings / GetRelatedFindings
// resolve each vector hit back to a node with exactly this query, so a mock
// that returned the whole set regardless would hand every hit the same node
// and make an ID assertion meaningless (gibson#1322).
func (m *MockGraphRAGProvider) QueryNodes(ctx context.Context, query NodeQuery) ([]GraphNode, error) {
	if m.queryNodesError != nil {
		return nil, m.queryNodesError
	}
	wantID, ok := query.Properties["id"].(string)
	if !ok || wantID == "" {
		return m.queriedNodes, nil
	}
	matched := make([]GraphNode, 0, 1)
	for _, n := range m.queriedNodes {
		if n.ID.String() == wantID {
			matched = append(matched, n)
		}
	}
	return matched, nil
}

// QueryRelationships returns the configured mock relationships.
func (m *MockGraphRAGProvider) QueryRelationships(ctx context.Context, query RelQuery) ([]Relationship, error) {
	return m.relationships, nil
}

// Health returns the configured health status.
func (m *MockGraphRAGProvider) Health(ctx context.Context) types.HealthStatus {
	return m.health
}

// Close is a no-op for the mock.
func (m *MockGraphRAGProvider) Close() error {
	return nil
}

// SetVectorResults configures the vector search results.
func (m *MockGraphRAGProvider) SetVectorResults(results []VectorResult) {
	m.vectorResults = results
}

// SetGraphNodes configures the graph traversal results.
func (m *MockGraphRAGProvider) SetGraphNodes(nodes []GraphNode) {
	m.graphNodes = nodes
}

// SetQueriedNodes configures the query nodes results.
func (m *MockGraphRAGProvider) SetQueriedNodes(nodes []GraphNode) {
	m.queriedNodes = nodes
}

// SetVectorSearchError configures VectorSearch to return an error.
func (m *MockGraphRAGProvider) SetVectorSearchError(err error) {
	m.vectorSearchError = err
}

// SetTraverseError configures TraverseGraph to return an error.
func (m *MockGraphRAGProvider) SetTraverseError(err error) {
	m.traverseError = err
}

// SetQueryNodesError configures QueryNodes to return an error.
func (m *MockGraphRAGProvider) SetQueryNodesError(err error) {
	m.queryNodesError = err
}

// SetHealth configures the health status.
func (m *MockGraphRAGProvider) SetHealth(health types.HealthStatus) {
	m.health = health
}

// TestDefaultMergeReranker_Merge tests the merge functionality.
func TestDefaultMergeReranker_Merge(t *testing.T) {
	tests := []struct {
		name          string
		vectorResults []VectorResult
		graphResults  []GraphNode
		wantCount     int
		wantInVector  int // Count of nodes that should have InVector=true
		wantInGraph   int // Count of nodes that should have InGraph=true
	}{
		{
			name: "merge with no overlap",
			vectorResults: []VectorResult{
				{NodeID: testID("node1"), Similarity: 0.9},
				{NodeID: testID("node2"), Similarity: 0.8},
			},
			graphResults: []GraphNode{
				{ID: testID("node3")},
				{ID: testID("node4")},
			},
			wantCount:    4, // All unique nodes
			wantInVector: 2,
			wantInGraph:  2,
		},
		{
			name: "merge with overlap",
			vectorResults: []VectorResult{
				{NodeID: testID("node1"), Similarity: 0.9},
				{NodeID: testID("node2"), Similarity: 0.8},
			},
			graphResults: []GraphNode{
				{ID: testID("node2")}, // Overlap with vector
				{ID: testID("node3")},
			},
			wantCount:    3, // Deduplicated
			wantInVector: 2,
			wantInGraph:  2,
		},
		{
			name:          "empty vector results",
			vectorResults: []VectorResult{},
			graphResults: []GraphNode{
				{ID: testID("node1")},
			},
			wantCount:    1,
			wantInVector: 0,
			wantInGraph:  1,
		},
		{
			name: "empty graph results",
			vectorResults: []VectorResult{
				{NodeID: testID("node1"), Similarity: 0.9},
			},
			graphResults: []GraphNode{},
			wantCount:    1,
			wantInVector: 1,
			wantInGraph:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reranker := NewDefaultMergeReranker(0.6, 0.4)
			merged := reranker.Merge(tt.vectorResults, tt.graphResults)

			assert.Equal(t, tt.wantCount, len(merged), "merged result count mismatch")

			inVectorCount := 0
			inGraphCount := 0
			for _, m := range merged {
				if m.InVector {
					inVectorCount++
				}
				if m.InGraph {
					inGraphCount++
				}
			}

			assert.Equal(t, tt.wantInVector, inVectorCount, "InVector count mismatch")
			assert.Equal(t, tt.wantInGraph, inGraphCount, "InGraph count mismatch")
		})
	}
}

// TestDefaultMergeReranker_Rerank tests the reranking functionality.
func TestDefaultMergeReranker_Rerank(t *testing.T) {
	tests := []struct {
		name      string
		merged    []MergedResult
		topK      int
		wantCount int
		wantFirst types.ID // Expected first result's ID (highest score)
	}{
		{
			name: "rerank with hybrid scores",
			merged: []MergedResult{
				{
					Node:        GraphNode{ID: testID("node1")},
					VectorScore: 0.9,
					GraphScore:  0.3,
				},
				{
					Node:        GraphNode{ID: testID("node2")},
					VectorScore: 0.5,
					GraphScore:  0.9,
				},
				{
					Node:        GraphNode{ID: testID("node3")},
					VectorScore: 0.7,
					GraphScore:  0.7,
				},
			},
			topK:      3,
			wantCount: 3,
			wantFirst: testID("node3"), // 0.6*0.7 + 0.4*0.7 = 0.7 (highest)
		},
		{
			name: "limit to topK",
			merged: []MergedResult{
				{Node: GraphNode{ID: testID("node1")}, VectorScore: 0.9, GraphScore: 0.9},
				{Node: GraphNode{ID: testID("node2")}, VectorScore: 0.8, GraphScore: 0.8},
				{Node: GraphNode{ID: testID("node3")}, VectorScore: 0.7, GraphScore: 0.7},
			},
			topK:      2,
			wantCount: 2,
			wantFirst: testID("node1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reranker := NewDefaultMergeReranker(0.6, 0.4)
			reranked := reranker.Rerank(tt.merged, "", tt.topK)

			assert.Equal(t, tt.wantCount, len(reranked), "reranked result count mismatch")
			if len(reranked) > 0 {
				assert.Equal(t, tt.wantFirst, reranked[0].Node.ID, "first result ID mismatch")

				// Verify results are sorted by score (descending)
				for i := 1; i < len(reranked); i++ {
					assert.GreaterOrEqual(t, reranked[i-1].Score, reranked[i].Score,
						"results not sorted by score")
				}
			}
		})
	}
}

// TestNewQueryPipelineFromConfig tests processor creation from config.
func TestNewQueryPipelineFromConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  GraphRAGConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: GraphRAGConfig{
				Query: QueryConfig{
					DefaultTopK:    10,
					DefaultMaxHops: 3,
					MinScore:       0.7,
					VectorWeight:   0.6,
					GraphWeight:    0.4,
				},
			},
			wantErr: false,
		},
		{
			name: "invalid weights (don't sum to 1)",
			config: GraphRAGConfig{
				Query: QueryConfig{
					DefaultTopK:    10,
					DefaultMaxHops: 3,
					MinScore:       0.7,
					VectorWeight:   0.5,
					GraphWeight:    0.6, // Sum > 1
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			embedder := NewMockEmbedder()
			processor, err := NewQueryPipelineFromConfig(tt.config, embedder, nil)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, processor)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, processor)
			}
		})
	}
}

// BenchmarkMergeReranker benchmarks the merge and rerank operations.
func BenchmarkMergeReranker(b *testing.B) {
	// Setup test data
	vectorResults := make([]VectorResult, 100)
	for i := 0; i < 100; i++ {
		vectorResults[i] = VectorResult{
			NodeID:     types.NewID(),
			Similarity: float64(100-i) / 100.0,
		}
	}

	graphResults := make([]GraphNode, 50)
	for i := 0; i < 50; i++ {
		graphResults[i] = GraphNode{
			ID: types.NewID(),
		}
	}

	reranker := NewDefaultMergeReranker(0.6, 0.4)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		merged := reranker.Merge(vectorResults, graphResults)
		_ = reranker.Rerank(merged, "test query", 10)
	}
}
