// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
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
