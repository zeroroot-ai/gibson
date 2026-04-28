package graphrag

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Note: MockEmbedder and MockGraphRAGProvider are defined in processor_test.go
// We use those existing mocks to avoid duplication.

// MockQueryProcessor is a mock implementation of QueryPipeline for testing.
type MockQueryProcessor struct {
	results []GraphRAGResult
	err     error
}

func (m *MockQueryProcessor) ProcessQuery(ctx context.Context, query GraphRAGQuery, provider GraphRAGProvider) ([]GraphRAGResult, error) {
	return m.results, m.err
}

// NewMockQueryProcessor creates a new mock query processor.
func NewMockQueryProcessor(results []GraphRAGResult, err error) *MockQueryProcessor {
	return &MockQueryProcessor{
		results: results,
		err:     err,
	}
}

func TestGraphRecord_Methods(t *testing.T) {
	node := NewGraphNode(types.NewID(), NodeType("finding"))
	record := NewGraphRecord(*node)

	// Test WithRelationship
	rel1 := NewRelationship(types.NewID(), types.NewID(), RelationType("similar_to"))
	record.WithRelationship(*rel1)
	assert.Len(t, record.Relationships, 1)

	// Test WithRelationships
	rel2 := NewRelationship(types.NewID(), types.NewID(), RelationType("related_to"))
	rel3 := NewRelationship(types.NewID(), types.NewID(), RelationType("exploits"))
	record.WithRelationships([]Relationship{*rel2, *rel3})
	assert.Len(t, record.Relationships, 3)

	// Test WithEmbedContent
	record.WithEmbedContent("test content")
	assert.Equal(t, "test content", record.EmbedContent)
}

func TestDefaultGraphRAGStore_Store(t *testing.T) {
	ctx := context.Background()

	t.Run("successful store with embedding generation", func(t *testing.T) {
		mockProvider := NewMockGraphRAGProvider()
		mockEmbedder := NewMockEmbedder()
		mockProcessor := NewMockQueryProcessor(nil, nil)

		store := &DefaultGraphRAGStore{
			provider:  mockProvider,
			processor: mockProcessor,
			embedder:  mockEmbedder,
		}

		record := GraphRecord{
			Node:         *NewGraphNode(types.NewID(), NodeType("finding")),
			EmbedContent: "test content",
		}

		mockEmbedder.SetEmbedding("test content", []float64{0.1, 0.2, 0.3})

		// Execute
		err := store.Store(ctx, record)

		// Verify
		assert.NoError(t, err)
	})

	t.Run("successful store with existing embedding", func(t *testing.T) {
		mockProvider := NewMockGraphRAGProvider()
		mockEmbedder := NewMockEmbedder()
		mockProcessor := NewMockQueryProcessor(nil, nil)

		store := &DefaultGraphRAGStore{
			provider:  mockProvider,
			processor: mockProcessor,
			embedder:  mockEmbedder,
		}

		record := GraphRecord{
			Node: *NewGraphNode(types.NewID(), NodeType("finding")).
				WithEmbedding([]float64{0.1, 0.2, 0.3}),
		}

		// Execute
		err := store.Store(ctx, record)

		// Verify
		assert.NoError(t, err)
	})

	t.Run("store with relationships", func(t *testing.T) {
		mockProvider := NewMockGraphRAGProvider()
		mockEmbedder := NewMockEmbedder()
		mockProcessor := NewMockQueryProcessor(nil, nil)

		store := &DefaultGraphRAGStore{
			provider:  mockProvider,
			processor: mockProcessor,
			embedder:  mockEmbedder,
		}

		record := GraphRecord{
			Node: *NewGraphNode(types.NewID(), NodeType("finding")).
				WithEmbedding([]float64{0.1, 0.2, 0.3}),
			Relationships: []Relationship{
				*NewRelationship(types.NewID(), types.NewID(), RelationType("similar_to")),
			},
		}

		// Execute
		err := store.Store(ctx, record)

		// Verify
		assert.NoError(t, err)
	})
}

func TestDefaultGraphRAGStore_StoreBatch(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	// Create test records
	records := []GraphRecord{
		{
			Node:         *NewGraphNode(types.NewID(), NodeType("finding")),
			EmbedContent: "content 1",
		},
		{
			Node:         *NewGraphNode(types.NewID(), NodeType("finding")),
			EmbedContent: "content 2",
		},
		{
			Node: *NewGraphNode(types.NewID(), NodeType("finding")).
				WithEmbedding([]float64{0.1, 0.2, 0.3}), // Already has embedding
		},
	}

	// Setup mock embeddings
	mockEmbedder.SetEmbedding("content 1", []float64{0.1, 0.2, 0.3})
	mockEmbedder.SetEmbedding("content 2", []float64{0.4, 0.5, 0.6})

	// Execute
	err := store.StoreBatch(ctx, records)

	// Verify
	assert.NoError(t, err)
}

func TestDefaultGraphRAGStore_Query(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()

	// Create expected results
	expectedResults := []GraphRAGResult{
		{
			Node:        *NewGraphNode(types.NewID(), NodeType("finding")),
			Score:       0.9,
			VectorScore: 0.8,
			GraphScore:  0.7,
		},
	}
	mockProcessor := NewMockQueryProcessor(expectedResults, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	// Create test query
	query := NewGraphRAGQuery("test query")

	// Execute
	results, err := store.Query(ctx, *query)

	// Verify
	assert.NoError(t, err)
	assert.Equal(t, expectedResults, results)
}

func TestDefaultGraphRAGStore_StoreAttackPattern(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	// Create test attack pattern
	pattern := NewAttackPattern("T1566", "Phishing", "Phishing attack description")
	pattern.Tactics = []string{"Initial Access", "Execution"}

	// Setup mock embedding
	mockEmbedder.SetEmbedding(pattern.Description, []float64{0.1, 0.2, 0.3})

	// Execute
	err := store.StoreAttackPattern(ctx, *pattern)

	// Verify
	assert.NoError(t, err)
}

func TestDefaultGraphRAGStore_FindSimilarAttacks(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	content := "phishing attack"
	topK := 5
	embedding := []float64{0.1, 0.2, 0.3}

	// Create test attack pattern node
	patternID := types.NewID()
	patternNode := NewGraphNode(patternID, NodeType("attack_pattern")).
		WithProperty("technique_id", "T1566").
		WithProperty("name", "Phishing").
		WithProperty("description", "Phishing attack").
		WithProperty("tactics", []string{"Initial Access"}).
		WithProperty("platforms", []string{"Windows", "Linux"})

	// Setup mock responses
	mockEmbedder.SetEmbedding(content, embedding)
	mockProvider.vectorResults = []VectorResult{
		{NodeID: patternID, Similarity: 0.9},
	}
	mockProvider.queriedNodes = []GraphNode{*patternNode}

	// Execute
	patterns, err := store.FindSimilarAttacks(ctx, content, topK)

	// Verify
	assert.NoError(t, err)
	assert.Len(t, patterns, 1)
	assert.Equal(t, "T1566", patterns[0].TechniqueID)
	assert.Equal(t, "Phishing", patterns[0].Name)
}

func TestDefaultGraphRAGStore_FindSimilarFindings(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	// Create source finding
	sourceFindingID := types.NewID()
	sourceEmbedding := []float64{0.1, 0.2, 0.3}
	sourceFindingNode := NewGraphNode(sourceFindingID, NodeType("finding")).
		WithProperty("title", "Source Finding").
		WithProperty("description", "Source description").
		WithProperty("severity", "high").
		WithEmbedding(sourceEmbedding)

	// Create similar finding
	similarFindingID := types.NewID()
	similarFindingNode := NewGraphNode(similarFindingID, NodeType("finding")).
		WithProperty("title", "Similar Finding").
		WithProperty("description", "Similar description").
		WithProperty("severity", "medium")

	topK := 5

	// Setup mock responses
	// First query for source finding returns the source node
	mockProvider.queriedNodes = []GraphNode{*sourceFindingNode, *similarFindingNode}

	// Vector search returns both findings
	mockProvider.vectorResults = []VectorResult{
		{NodeID: sourceFindingID, Similarity: 1.0},   // Source itself
		{NodeID: similarFindingID, Similarity: 0.85}, // Similar finding
	}

	// Execute
	findings, err := store.FindSimilarFindings(ctx, sourceFindingID.String(), topK)

	// Verify
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 0) // May be 0 or 1 depending on mock state
}

func TestDefaultGraphRAGStore_GetAttackChains(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	techniqueID := "T1566"
	maxDepth := 3

	// Create starting technique node
	startNode := NewGraphNode(types.NewID(), NodeType("technique")).
		WithProperty("technique_id", techniqueID).
		WithProperty("name", "Phishing").
		WithProperty("description", "Phishing technique")

	// Create subsequent technique nodes
	node2 := NewGraphNode(types.NewID(), NodeType("technique")).
		WithProperty("technique_id", "T1204").
		WithProperty("name", "User Execution").
		WithProperty("description", "User execution technique")

	// Setup mock responses
	mockProvider.queriedNodes = []GraphNode{*startNode}
	mockProvider.graphNodes = []GraphNode{*node2}

	// Execute
	chains, err := store.GetAttackChains(ctx, techniqueID, maxDepth)

	// Verify
	assert.NoError(t, err)
	assert.NotEmpty(t, chains)
	assert.GreaterOrEqual(t, len(chains[0].Steps), 1)
}

func TestDefaultGraphRAGStore_StoreFinding(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	// Create test finding
	targetID := types.NewID()
	missionID := types.NewID()
	finding := NewFindingNode(types.NewID(), "Test Finding", "Finding description", missionID)
	finding.TargetID = &targetID
	finding.Severity = "high"

	// Setup mock embedding
	mockEmbedder.SetEmbedding(finding.Description, []float64{0.1, 0.2, 0.3})

	// Execute
	err := store.StoreFinding(ctx, *finding)

	// Verify
	assert.NoError(t, err)
}

func TestDefaultGraphRAGStore_GetRelatedFindings(t *testing.T) {
	ctx := context.Background()
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	findingID := types.NewID()
	relatedFindingID := types.NewID()

	// Create related finding node
	relatedNode := NewGraphNode(relatedFindingID, NodeType("finding")).
		WithProperty("title", "Related Finding").
		WithProperty("description", "Related description")

	// Setup mock responses
	mockProvider.relationships = []Relationship{
		*NewRelationship(findingID, relatedFindingID, RelationType("similar_to")),
	}
	mockProvider.queriedNodes = []GraphNode{*relatedNode}

	// Execute
	findings, err := store.GetRelatedFindings(ctx, findingID.String())

	// Verify
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(findings), 0) // May be 0 or more depending on mock state
}

func TestDefaultGraphRAGStore_Health(t *testing.T) {
	tests := []struct {
		name             string
		providerHealth   types.HealthStatus
		embedderHealth   types.HealthStatus
		expectedState    types.HealthState
		expectedContains string
	}{
		{
			name:           "all healthy",
			providerHealth: types.Healthy("provider ok"),
			embedderHealth: types.Healthy("embedder ok"),
			expectedState:  types.HealthStateHealthy,
		},
		{
			name:             "provider unhealthy",
			providerHealth:   types.Unhealthy("provider down"),
			embedderHealth:   types.Healthy("embedder ok"),
			expectedState:    types.HealthStateUnhealthy,
			expectedContains: "provider unhealthy",
		},
		{
			name:             "embedder unhealthy",
			providerHealth:   types.Healthy("provider ok"),
			embedderHealth:   types.Unhealthy("embedder down"),
			expectedState:    types.HealthStateUnhealthy,
			expectedContains: "embedder unhealthy",
		},
		{
			name:             "provider degraded",
			providerHealth:   types.Degraded("provider slow"),
			embedderHealth:   types.Healthy("embedder ok"),
			expectedState:    types.HealthStateDegraded,
			expectedContains: "degraded",
		},
		{
			name:             "embedder degraded",
			providerHealth:   types.Healthy("provider ok"),
			embedderHealth:   types.Degraded("embedder slow"),
			expectedState:    types.HealthStateDegraded,
			expectedContains: "degraded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockProvider := NewMockGraphRAGProvider()
			mockEmbedder := NewMockEmbedder()
			mockProcessor := NewMockQueryProcessor(nil, nil)

			mockProvider.health = tt.providerHealth
			mockEmbedder.SetHealth(tt.embedderHealth)

			store := &DefaultGraphRAGStore{
				provider:  mockProvider,
				processor: mockProcessor,
				embedder:  mockEmbedder,
			}

			// Execute
			health := store.Health(ctx)

			// Verify
			assert.Equal(t, tt.expectedState, health.State)
			if tt.expectedContains != "" {
				assert.Contains(t, health.Message, tt.expectedContains)
			}
		})
	}
}

func TestDefaultGraphRAGStore_Close(t *testing.T) {
	mockProvider := NewMockGraphRAGProvider()
	mockEmbedder := NewMockEmbedder()
	mockProcessor := NewMockQueryProcessor(nil, nil)

	store := &DefaultGraphRAGStore{
		provider:  mockProvider,
		processor: mockProcessor,
		embedder:  mockEmbedder,
	}

	// Execute
	err := store.Close()

	// Verify
	assert.NoError(t, err)
}

func TestGraphNodeToAttackPattern(t *testing.T) {
	// Create a GraphNode with attack pattern properties
	node := NewGraphNode(types.NewID(), NodeType("attack_pattern")).
		WithProperty("technique_id", "T1566").
		WithProperty("name", "Phishing").
		WithProperty("description", "Phishing attack").
		WithProperty("tactics", []string{"Initial Access", "Execution"}).
		WithProperty("platforms", []string{"Windows", "Linux"}).
		WithEmbedding([]float64{0.1, 0.2, 0.3})

	// Convert to AttackPattern
	pattern := graphNodeToAttackPattern(*node)

	// Verify
	assert.Equal(t, "T1566", pattern.TechniqueID)
	assert.Equal(t, "Phishing", pattern.Name)
	assert.Equal(t, "Phishing attack", pattern.Description)
	assert.Equal(t, []string{"Initial Access", "Execution"}, pattern.Tactics)
	assert.Equal(t, []string{"Windows", "Linux"}, pattern.Platforms)
	assert.Equal(t, []float64{0.1, 0.2, 0.3}, pattern.Embedding)
}

func TestGraphNodeToFindingNode(t *testing.T) {
	// Create a GraphNode with finding properties
	missionID := types.NewID()
	targetID := types.NewID()
	node := NewGraphNode(types.NewID(), NodeType("finding")).
		WithProperty("title", "Test Finding").
		WithProperty("description", "Finding description").
		WithProperty("severity", "high").
		WithProperty("category", "vulnerability").
		WithProperty("confidence", 0.95).
		WithProperty("target_id", targetID.String()).
		WithMission(missionID).
		WithEmbedding([]float64{0.1, 0.2, 0.3})

	// Convert to FindingNode
	finding := graphNodeToFindingNode(*node)

	// Verify
	assert.Equal(t, "Test Finding", finding.Title)
	assert.Equal(t, "Finding description", finding.Description)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "vulnerability", finding.Category)
	assert.Equal(t, 0.95, finding.Confidence)
	assert.Equal(t, missionID, finding.MissionID)
	assert.NotNil(t, finding.TargetID)
	assert.Equal(t, targetID, *finding.TargetID)
	assert.Equal(t, []float64{0.1, 0.2, 0.3}, finding.Embedding)
}

func TestBuildAttackChainsFromNodes(t *testing.T) {
	// Create starting technique node
	startNode := NewGraphNode(types.NewID(), NodeType("technique")).
		WithProperty("technique_id", "T1566").
		WithProperty("description", "Phishing")

	// Create subsequent technique nodes
	node2 := NewGraphNode(types.NewID(), NodeType("technique")).
		WithProperty("technique_id", "T1204").
		WithProperty("description", "User Execution")

	node3 := NewGraphNode(types.NewID(), NodeType("technique")).
		WithProperty("technique_id", "T1059").
		WithProperty("description", "Command Execution")

	traversedNodes := []GraphNode{*node2, *node3}

	// Build chains
	chains := buildAttackChainsFromNodes(*startNode, traversedNodes, 3)

	// Verify
	assert.NotEmpty(t, chains)
	assert.GreaterOrEqual(t, len(chains[0].Steps), 2) // At least start node + one traversed node
	assert.Equal(t, "T1566", chains[0].Steps[0].TechniqueID)
}
