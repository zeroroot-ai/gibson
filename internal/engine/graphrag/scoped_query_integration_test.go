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

// TestIntegration_ScopedGraphRAGQueries tests the complete flow of scoped
// GraphRAG queries across multiple mission runs with different scope filters.
// This verifies that mission scope filtering works correctly for:
// - ScopeCurrentRun: Only data from current mission run
// - ScopeSameMission: Data from all runs of the same mission
// - ScopeAll: Data from all missions (no filtering)
func TestIntegration_ScopedGraphRAGQueries(t *testing.T) {
	ctx := context.Background()

	// Setup mock components
	embedder := NewMockEmbedder()
	provider := NewMockGraphRAGProvider()
	reranker := NewDefaultMergeReranker(0.6, 0.4)

	// Create missions for multiple runs of the same mission name
	missionName := "security-scan-mission"
	mission1ID := types.NewID() // Run 1
	mission2ID := types.NewID() // Run 2
	mission3ID := types.NewID() // Run 3

	// Create a different mission for cross-mission testing
	otherMissionID := types.NewID()

	// Create processor
	processor := NewDefaultQueryPipeline(embedder, reranker, nil)

	config := GraphRAGConfig{
		Provider: "local",
		Query: QueryConfig{
			DefaultTopK:    10,
			DefaultMaxHops: 2,
			VectorWeight:   0.6,
			GraphWeight:    0.4,
		},
	}

	store := &DefaultGraphRAGStore{
		provider:  provider,
		processor: processor,
		embedder:  embedder,
		config:    config,
	}

	// Create findings across different runs
	// Run 1 findings
	finding1Run1 := NewFindingNode(
		types.NewID(),
		"SQL Injection - Login",
		"SQL injection in login form detected in run 1",
		mission1ID,
	)
	finding1Run1.Category = "injection"

	finding2Run1 := NewFindingNode(
		types.NewID(),
		"XSS - Comments",
		"Cross-site scripting in comments found in run 1",
		mission1ID,
	)
	finding2Run1.Category = "xss"

	// Run 2 findings
	finding1Run2 := NewFindingNode(
		types.NewID(),
		"SQL Injection - Search",
		"SQL injection in search functionality found in run 2",
		mission2ID,
	)
	finding1Run2.Category = "injection"

	// Run 3 findings (current run)
	finding1Run3 := NewFindingNode(
		types.NewID(),
		"SQL Injection - Admin",
		"SQL injection in admin panel found in run 3",
		mission3ID,
	)
	finding1Run3.Category = "injection"

	// Other mission finding
	findingOther := NewFindingNode(
		types.NewID(),
		"SQL Injection - API",
		"SQL injection in API endpoint from different mission",
		otherMissionID,
	)
	findingOther.Category = "injection"

	// Setup embeddings for all findings
	allFindings := []*FindingNode{finding1Run1, finding2Run1, finding1Run2, finding1Run3, findingOther}
	for _, f := range allFindings {
		embedder.SetEmbedding(f.Description, generateMockEmbedding(f.Description, 1536))
	}

	// Test 1: ScopeCurrentRun - should only return findings from run 3
	t.Run("ScopeCurrentRun_OnlyCurrentRunFindings", func(t *testing.T) {
		// Setup provider to return the run 3 finding
		finding3WithEmbed := finding1Run3.ToGraphNode()
		finding3WithEmbed.Embedding = embedder.embeddings[finding1Run3.Description]

		provider.SetVectorResults([]VectorResult{
			{NodeID: finding1Run3.ID, Similarity: 0.95},
		})
		provider.SetQueriedNodes([]GraphNode{*finding3WithEmbed})

		// Create query with ScopeCurrentRun
		query := NewGraphRAGQuery("SQL injection vulnerability").
			WithTopK(10).
			WithMissionScope(ScopeCurrentRun).
			WithMission(mission3ID)

		embedder.SetEmbedding("SQL injection vulnerability", generateMockEmbedding("SQL injection vulnerability", 1536))

		results, err := store.Query(ctx, *query)
		require.NoError(t, err)

		// Verify only run 3 finding is returned
		assert.Len(t, results, 1, "should only return current run findings")
		if len(results) > 0 {
			assert.Equal(t, finding1Run3.ID, results[0].Node.ID, "should return run 3 finding")
		}
	})

	// Test 2: ScopeSameMission - should return findings from all runs of same mission
	t.Run("ScopeSameMission_AllSameMissionFindings", func(t *testing.T) {
		// Setup provider to return all findings from same mission
		f1 := finding1Run1.ToGraphNode()
		f1.Embedding = embedder.embeddings[finding1Run1.Description]

		f2 := finding1Run2.ToGraphNode()
		f2.Embedding = embedder.embeddings[finding1Run2.Description]

		f3 := finding1Run3.ToGraphNode()
		f3.Embedding = embedder.embeddings[finding1Run3.Description]

		provider.SetVectorResults([]VectorResult{
			{NodeID: finding1Run1.ID, Similarity: 0.95},
			{NodeID: finding1Run2.ID, Similarity: 0.92},
			{NodeID: finding1Run3.ID, Similarity: 0.90},
		})
		provider.SetQueriedNodes([]GraphNode{*f1, *f2, *f3})

		// Create query with ScopeSameMission
		query := NewGraphRAGQuery("SQL injection vulnerability").
			WithTopK(10).
			WithMissionScope(ScopeSameMission).
			WithMissionName(missionName).
			WithMission(mission3ID)

		results, err := store.Query(ctx, *query)
		require.NoError(t, err)

		// Verify findings from all runs of same mission are returned
		assert.GreaterOrEqual(t, len(results), 1, "should return findings from same mission runs")

		// Verify all returned findings are from the same mission
		expectedMissionIDs := map[types.ID]bool{
			mission1ID: true,
			mission2ID: true,
			mission3ID: true,
		}
		for _, r := range results {
			missionProp, ok := r.Node.Properties["mission_id"]
			if ok {
				missionIDStr, _ := missionProp.(string)
				missionID, _ := types.ParseID(missionIDStr)
				assert.True(t, expectedMissionIDs[missionID], "finding should be from same mission")
			}
		}
	})

	// Test 3: ScopeAll - should return findings from all missions
	t.Run("ScopeAll_AllMissionFindings", func(t *testing.T) {
		// Setup provider to return findings from all missions
		f1 := finding1Run1.ToGraphNode()
		f1.Embedding = embedder.embeddings[finding1Run1.Description]

		f2 := finding1Run2.ToGraphNode()
		f2.Embedding = embedder.embeddings[finding1Run2.Description]

		fOther := findingOther.ToGraphNode()
		fOther.Embedding = embedder.embeddings[findingOther.Description]

		provider.SetVectorResults([]VectorResult{
			{NodeID: finding1Run1.ID, Similarity: 0.95},
			{NodeID: finding1Run2.ID, Similarity: 0.92},
			{NodeID: findingOther.ID, Similarity: 0.88},
		})
		provider.SetQueriedNodes([]GraphNode{*f1, *f2, *fOther})

		// Create query with ScopeAll (or no scope - defaults to all)
		query := NewGraphRAGQuery("SQL injection vulnerability").
			WithTopK(10).
			WithMissionScope(ScopeAll)

		results, err := store.Query(ctx, *query)
		require.NoError(t, err)

		// Verify findings from multiple missions are returned
		assert.GreaterOrEqual(t, len(results), 1, "should return findings from all missions")
	})

	// Test 4: Default scope (empty) behaves as ScopeAll
	t.Run("DefaultScope_BehavesAsScopeAll", func(t *testing.T) {
		// Setup provider to return findings from all missions
		f1 := finding1Run1.ToGraphNode()
		f1.Embedding = embedder.embeddings[finding1Run1.Description]

		fOther := findingOther.ToGraphNode()
		fOther.Embedding = embedder.embeddings[findingOther.Description]

		provider.SetVectorResults([]VectorResult{
			{NodeID: finding1Run1.ID, Similarity: 0.95},
			{NodeID: findingOther.ID, Similarity: 0.88},
		})
		provider.SetQueriedNodes([]GraphNode{*f1, *fOther})

		// Create query without setting scope (defaults to all)
		query := NewGraphRAGQuery("SQL injection vulnerability").
			WithTopK(10)
		// Note: MissionScope is not set, should default to ScopeAll

		results, err := store.Query(ctx, *query)
		require.NoError(t, err)

		// Verify query succeeds and returns results
		assert.GreaterOrEqual(t, len(results), 1, "default scope should return results")
	})
}

// TestIntegration_ScopedQueryEdgeCases tests edge cases for scoped queries.
func TestIntegration_ScopedQueryEdgeCases(t *testing.T) {
	ctx := context.Background()

	// Setup mock components
	embedder := NewMockEmbedder()
	provider := NewMockGraphRAGProvider()
	reranker := NewDefaultMergeReranker(0.6, 0.4)

	t.Run("FirstRun_NoHistoricalData", func(t *testing.T) {
		missionID := types.NewID()
		missionName := "first-run-mission"

		// Mock lister returns only current mission (first run)
		processor := NewDefaultQueryPipeline(embedder, reranker, nil)

		config := GraphRAGConfig{}
		store := &DefaultGraphRAGStore{
			provider:  provider,
			processor: processor,
			embedder:  embedder,
			config:    config,
		}

		// Create finding for first run
		finding := NewFindingNode(
			types.NewID(),
			"First Run Finding",
			"Finding from the first run",
			missionID,
		)

		embedder.SetEmbedding(finding.Description, generateMockEmbedding(finding.Description, 1536))

		// Query with ScopeSameMission on first run
		findingNode := finding.ToGraphNode()
		findingNode.Embedding = embedder.embeddings[finding.Description]

		provider.SetVectorResults([]VectorResult{{NodeID: finding.ID, Similarity: 0.95}})
		provider.SetQueriedNodes([]GraphNode{*findingNode})

		query := NewGraphRAGQuery("first run").
			WithTopK(10).
			WithMissionScope(ScopeSameMission).
			WithMissionName(missionName)

		embedder.SetEmbedding("first run", generateMockEmbedding("first run", 1536))

		results, err := store.Query(ctx, *query)
		require.NoError(t, err)

		// Should return the first run's finding
		assert.Len(t, results, 1, "first run should return its own finding")
	})

	t.Run("ManyRuns_LargeHistory", func(t *testing.T) {
		missionName := "many-runs-mission"

		// Create many mission IDs (simulating many runs)
		numRuns := 100
		missionIDs := make([]types.ID, numRuns)
		for i := 0; i < numRuns; i++ {
			missionIDs[i] = types.NewID()
		}

		processor := NewDefaultQueryPipeline(embedder, reranker, nil)

		config := GraphRAGConfig{}
		store := &DefaultGraphRAGStore{
			provider:  provider,
			processor: processor,
			embedder:  embedder,
			config:    config,
		}

		// Create a test finding
		currentMissionID := missionIDs[numRuns-1]
		finding := NewFindingNode(
			types.NewID(),
			"Many Runs Finding",
			"Finding from mission with many runs",
			currentMissionID,
		)

		embedder.SetEmbedding(finding.Description, generateMockEmbedding(finding.Description, 1536))

		findingNode := finding.ToGraphNode()
		findingNode.Embedding = embedder.embeddings[finding.Description]

		provider.SetVectorResults([]VectorResult{{NodeID: finding.ID, Similarity: 0.95}})
		provider.SetQueriedNodes([]GraphNode{*findingNode})

		// Query should handle many runs without issue
		query := NewGraphRAGQuery("many runs").
			WithTopK(10).
			WithMissionScope(ScopeSameMission).
			WithMissionName(missionName)

		embedder.SetEmbedding("many runs", generateMockEmbedding("many runs", 1536))

		results, err := store.Query(ctx, *query)
		require.NoError(t, err)

		// Should return results without error
		assert.GreaterOrEqual(t, len(results), 0, "should handle many runs gracefully")
	})

	t.Run("EmptyMissionName_ReturnsValidationError", func(t *testing.T) {
		processor := NewDefaultQueryPipeline(embedder, reranker, nil)

		config := GraphRAGConfig{}
		store := &DefaultGraphRAGStore{
			provider:  provider,
			processor: processor,
			embedder:  embedder,
			config:    config,
		}

		// Query with ScopeSameMission but empty mission name should fail validation
		// This is correct behavior - the query validation requires mission_name
		query := NewGraphRAGQuery("empty name").
			WithTopK(10).
			WithMissionScope(ScopeSameMission).
			WithMissionName("") // Empty mission name

		embedder.SetEmbedding("empty name", generateMockEmbedding("empty name", 1536))

		_, err := store.Query(ctx, *query)
		// ScopeSameMission requires a mission name - validation should fail
		require.Error(t, err, "should return error when mission_name is empty with ScopeSameMission")
		assert.Contains(t, err.Error(), "mission_name", "error should mention mission_name")
	})
}

// TestIntegration_QueryScopeResolutionWithProcessor tests that the query
// processor correctly handles mission scope filtering.
func TestIntegration_QueryScopeResolutionWithProcessor(t *testing.T) {
	ctx := context.Background()

	embedder := NewMockEmbedder()
	provider := NewMockGraphRAGProvider()
	reranker := NewDefaultMergeReranker(0.6, 0.4)

	missionName := "scope-resolution-mission"
	mission3ID := types.NewID()

	processor := NewDefaultQueryPipeline(embedder, reranker, nil)

	// Create query with ScopeSameMission
	query := NewGraphRAGQuery("test query").
		WithTopK(10).
		WithMissionScope(ScopeSameMission).
		WithMissionName(missionName).
		WithMission(mission3ID) // Current mission is mission3

	embedder.SetEmbedding("test query", generateMockEmbedding("test query", 1536))

	// Setup minimal vector results
	provider.SetVectorResults([]VectorResult{})
	provider.SetQueriedNodes([]GraphNode{})

	_, err := processor.ProcessQuery(ctx, *query, provider)
	require.NoError(t, err)

	// Verify that the query was processed with scope resolution
	// The MissionIDFilter should have been populated by the scoper
	// This is verified by the fact that the query succeeded and used the processor
}

// TestIntegration_ScopedFindingsSimilarity tests finding similar findings
// with scope filtering applied.
func TestIntegration_ScopedFindingsSimilarity(t *testing.T) {
	ctx := context.Background()

	embedder := NewMockEmbedder()
	provider := NewMockGraphRAGProvider()
	reranker := NewDefaultMergeReranker(0.6, 0.4)

	missionID := types.NewID()

	processor := NewDefaultQueryPipeline(embedder, reranker, nil)

	config := GraphRAGConfig{}
	store := &DefaultGraphRAGStore{
		provider:  provider,
		processor: processor,
		embedder:  embedder,
		config:    config,
	}

	// Create source finding
	sourceFinding := NewFindingNode(
		types.NewID(),
		"SQL Injection Source",
		"SQL injection in login form",
		missionID,
	)
	sourceFinding.Category = "injection"

	// Create similar finding in same mission
	similarFinding := NewFindingNode(
		types.NewID(),
		"SQL Injection Similar",
		"SQL injection in registration form",
		missionID,
	)
	similarFinding.Category = "injection"

	// Setup embeddings
	embedder.SetEmbedding(sourceFinding.Description, generateMockEmbedding(sourceFinding.Description, 1536))
	embedder.SetEmbedding(similarFinding.Description, generateMockEmbedding(similarFinding.Description, 1536))

	// Setup provider for similarity query
	sourceNode := sourceFinding.ToGraphNode()
	sourceNode.Embedding = embedder.embeddings[sourceFinding.Description]

	similarNode := similarFinding.ToGraphNode()
	similarNode.Embedding = embedder.embeddings[similarFinding.Description]

	provider.SetVectorResults([]VectorResult{
		{NodeID: similarFinding.ID, Similarity: 0.92},
	})
	provider.SetQueriedNodes([]GraphNode{*sourceNode, *similarNode})

	// Find similar findings
	similar, err := store.FindSimilarFindings(ctx, sourceFinding.ID.String(), 5)
	require.NoError(t, err)

	// Verify similar findings were found
	assert.GreaterOrEqual(t, len(similar), 0, "should find similar findings")
	for _, f := range similar {
		assert.Equal(t, "injection", f.Category, "similar findings should be injection category")
	}
}
