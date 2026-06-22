package graphrag

import (
	"context"
	"errors"
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

// StoreNode is a no-op for the mock.
func (m *MockGraphRAGProvider) StoreNode(ctx context.Context, node GraphNode) error {
	return nil
}

// StoreRelationship is a no-op for the mock.
func (m *MockGraphRAGProvider) StoreRelationship(ctx context.Context, rel Relationship) error {
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

// QueryNodes returns the configured mock nodes.
func (m *MockGraphRAGProvider) QueryNodes(ctx context.Context, query NodeQuery) ([]GraphNode, error) {
	if m.queryNodesError != nil {
		return nil, m.queryNodesError
	}
	return m.queriedNodes, nil
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

// TestDefaultQueryPipeline_ProcessQuery tests the full query pipeline.
func TestDefaultQueryPipeline_ProcessQuery(t *testing.T) {
	tests := []struct {
		name         string
		query        GraphRAGQuery
		setupMocks   func(*MockEmbedder, *MockGraphRAGProvider)
		wantErr      bool
		wantCount    int
		wantMinScore float64
	}{
		{
			name: "successful hybrid query with text",
			query: *NewGraphRAGQuery("test query").
				WithTopK(5).
				WithMaxHops(2).
				WithWeights(0.6, 0.4),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				// Setup embedding
				emb.SetEmbedding("test query", generateMockEmbedding("test query", 1536))

				// Setup vector results
				prov.SetVectorResults([]VectorResult{
					{NodeID: testID("node1"), Similarity: 0.9},
					{NodeID: testID("node2"), Similarity: 0.8},
				})

				// Setup graph results
				prov.SetGraphNodes([]GraphNode{
					{ID: testID("node3")},
				})

				// Setup queried nodes for vector-only fallback
				prov.SetQueriedNodes([]GraphNode{
					{ID: testID("node1")},
				})
			},
			wantErr:      false,
			wantCount:    3, // 2 vector + 1 graph
			wantMinScore: 0.0,
		},
		{
			name: "query with pre-computed embedding",
			query: *NewGraphRAGQueryFromEmbedding(generateMockEmbedding("test", 1536)).
				WithTopK(3).
				WithMaxHops(1),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				prov.SetVectorResults([]VectorResult{
					{NodeID: testID("node1"), Similarity: 0.95},
				})
				prov.SetGraphNodes([]GraphNode{})
				prov.SetQueriedNodes([]GraphNode{
					{ID: testID("node1")},
				})
			},
			wantErr:      false,
			wantCount:    1,
			wantMinScore: 0.0,
		},
		{
			name: "vector-only query (MaxHops=0)",
			query: *NewGraphRAGQuery("test query").
				WithTopK(3).
				WithMaxHops(0), // No graph traversal
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				emb.SetEmbedding("test query", generateMockEmbedding("test query", 1536))
				prov.SetVectorResults([]VectorResult{
					{NodeID: testID("node1"), Similarity: 0.9},
				})
				prov.SetQueriedNodes([]GraphNode{
					{ID: testID("node1")},
				})
			},
			wantErr:      false,
			wantCount:    1,
			wantMinScore: 0.0,
		},
		{
			name: "graceful degradation - graph fails",
			query: *NewGraphRAGQuery("test query").
				WithTopK(5).
				WithMaxHops(2),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				emb.SetEmbedding("test query", generateMockEmbedding("test query", 1536))
				prov.SetVectorResults([]VectorResult{
					{NodeID: testID("node1"), Similarity: 0.9},
				})
				prov.SetTraverseError(errors.New("graph unavailable"))
				prov.SetQueriedNodes([]GraphNode{
					{ID: testID("node1")},
				})
			},
			wantErr:      false,
			wantCount:    1, // Falls back to vector-only
			wantMinScore: 0.0,
		},
		{
			name: "filter by MinScore",
			query: *NewGraphRAGQuery("test query").
				WithTopK(5).
				WithMinScore(0.85). // High threshold
				WithMaxHops(1),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				emb.SetEmbedding("test query", generateMockEmbedding("test query", 1536))
				prov.SetVectorResults([]VectorResult{
					{NodeID: testID("node1"), Similarity: 0.9}, // Above threshold
					{NodeID: testID("node2"), Similarity: 0.8}, // Below threshold
				})
				prov.SetGraphNodes([]GraphNode{})
				prov.SetQueriedNodes([]GraphNode{
					{ID: testID("node1")},
				})
			},
			wantErr:      false,
			wantCount:    1, // Only 1 result above threshold
			wantMinScore: 0.0,
		},
		{
			name: "embedding generation fails",
			query: *NewGraphRAGQuery("test query").
				WithTopK(5),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				emb.SetEmbedError(errors.New("embedding service unavailable"))
			},
			wantErr:      true,
			wantCount:    0,
			wantMinScore: 0.0,
		},
		{
			name: "vector search fails",
			query: *NewGraphRAGQuery("test query").
				WithTopK(5),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				emb.SetEmbedding("test query", generateMockEmbedding("test query", 1536))
				prov.SetVectorSearchError(errors.New("vector store unavailable"))
			},
			wantErr:      true,
			wantCount:    0,
			wantMinScore: 0.0,
		},
		{
			name: "no vector results returns empty",
			query: *NewGraphRAGQuery("test query").
				WithTopK(5),
			setupMocks: func(emb *MockEmbedder, prov *MockGraphRAGProvider) {
				emb.SetEmbedding("test query", generateMockEmbedding("test query", 1536))
				prov.SetVectorResults([]VectorResult{}) // No results
			},
			wantErr:      false,
			wantCount:    0,
			wantMinScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			embedder := NewMockEmbedder()
			provider := NewMockProvider()
			tt.setupMocks(embedder, provider)

			// Create processor
			reranker := NewDefaultMergeReranker(0.6, 0.4)
			processor := NewDefaultQueryPipeline(embedder, reranker, nil)

			// Execute query
			ctx := context.Background()
			results, err := processor.ProcessQuery(ctx, tt.query, provider)

			// Verify error expectation
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify result count
			assert.Equal(t, tt.wantCount, len(results), "result count mismatch")

			// Verify all scores are within valid range
			for _, r := range results {
				assert.GreaterOrEqual(t, r.Score, 0.0, "score below 0")
				assert.LessOrEqual(t, r.Score, 1.0, "score above 1")
			}
		})
	}
}

// TestDefaultQueryPipeline_FilterByNodeType tests node type filtering.
func TestDefaultQueryPipeline_FilterByNodeType(t *testing.T) {
	embedder := NewMockEmbedder()
	provider := NewMockProvider()
	reranker := NewDefaultMergeReranker(0.6, 0.4)
	processor := NewDefaultQueryPipeline(embedder, reranker, nil)

	// Setup mocks
	embedder.SetEmbedding("test query", generateMockEmbedding("test query", 1536))
	provider.SetVectorResults([]VectorResult{
		{NodeID: testID("node1"), Similarity: 0.9},
		{NodeID: testID("node2"), Similarity: 0.8},
	})
	provider.SetGraphNodes([]GraphNode{
		{
			ID:     testID("node3"),
			Labels: []NodeType{NodeType("finding")},
		},
	})
	provider.SetQueriedNodes([]GraphNode{
		{
			ID:     testID("node1"),
			Labels: []NodeType{NodeType("finding")},
		},
		{
			ID:     testID("node2"),
			Labels: []NodeType{NodeType("attack_pattern")},
		},
	})

	// Query with node type filter
	query := NewGraphRAGQuery("test query").
		WithTopK(10).
		WithMaxHops(1).
		WithNodeTypes(NodeType("finding")) // Only findings

	ctx := context.Background()
	results, err := processor.ProcessQuery(ctx, *query, provider)

	require.NoError(t, err)

	// Verify all results are findings
	for _, r := range results {
		assert.True(t, r.Node.HasLabel(NodeType("finding")),
			"result should have Finding label")
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

// TestValidateProvider tests provider validation.
func TestValidateProvider(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		provider GraphRAGProvider
		wantErr  bool
	}{
		{
			name:     "nil provider",
			provider: nil,
			wantErr:  true,
		},
		{
			name: "healthy provider",
			provider: &MockGraphRAGProvider{
				health: types.Healthy("provider ready"),
			},
			wantErr: false,
		},
		{
			name: "unhealthy provider",
			provider: &MockGraphRAGProvider{
				health: types.Unhealthy("provider down"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProvider(ctx, tt.provider)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestProcessorEmbedderHealth tests embedder health checking.
func TestProcessorEmbedderHealth(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name     string
		embedder *MockEmbedder
		wantErr  bool
	}{
		{
			name: "healthy embedder",
			embedder: &MockEmbedder{
				health: types.Healthy("embedder ready"),
			},
			wantErr: false,
		},
		{
			name: "unhealthy embedder",
			embedder: &MockEmbedder{
				health: types.Unhealthy("embedder down"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reranker := NewDefaultMergeReranker(0.6, 0.4)
			processor := NewDefaultQueryPipeline(tt.embedder, reranker, nil)

			err := processor.EnsureEmbedderHealth(ctx)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestMergeOptions_Validate tests merge options validation.
func TestMergeOptions_Validate(t *testing.T) {
	tests := []struct {
		name    string
		options MergeOptions
		wantErr bool
	}{
		{
			name: "valid options",
			options: MergeOptions{
				VectorWeight:     0.6,
				GraphWeight:      0.4,
				TopK:             10,
				BoostBothSources: 1.2,
			},
			wantErr: false,
		},
		{
			name: "invalid vector weight",
			options: MergeOptions{
				VectorWeight: 1.5, // > 1.0
				GraphWeight:  0.4,
				TopK:         10,
			},
			wantErr: true,
		},
		{
			name: "invalid graph weight",
			options: MergeOptions{
				VectorWeight: 0.6,
				GraphWeight:  -0.1, // < 0.0
				TopK:         10,
			},
			wantErr: true,
		},
		{
			name: "invalid topK",
			options: MergeOptions{
				VectorWeight: 0.6,
				GraphWeight:  0.4,
				TopK:         0, // <= 0
			},
			wantErr: true,
		},
		{
			name: "invalid boost",
			options: MergeOptions{
				VectorWeight:     0.6,
				GraphWeight:      0.4,
				TopK:             10,
				BoostBothSources: 0.5, // < 1.0
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.options.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
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

// BenchmarkProcessQuery benchmarks the full query processing pipeline.
func BenchmarkProcessQuery(b *testing.B) {
	// Setup mocks
	embedder := NewMockEmbedder()
	embedder.SetEmbedding("test query", generateMockEmbedding("test query", 1536))

	provider := NewMockProvider()
	vectorResults := make([]VectorResult, 20)
	for i := 0; i < 20; i++ {
		vectorResults[i] = VectorResult{
			NodeID:     types.NewID(),
			Similarity: float64(20-i) / 20.0,
		}
	}
	provider.SetVectorResults(vectorResults)
	provider.SetGraphNodes([]GraphNode{{ID: types.NewID()}})
	provider.SetQueriedNodes([]GraphNode{{ID: vectorResults[0].NodeID}})

	reranker := NewDefaultMergeReranker(0.6, 0.4)
	processor := NewDefaultQueryPipeline(embedder, reranker, nil)

	query := NewGraphRAGQuery("test query").WithTopK(10).WithMaxHops(2)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = processor.ProcessQuery(ctx, *query, provider)
	}
}
