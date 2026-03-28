package orchestrator

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestResultMerger_Merge_Empty(t *testing.T) {
	merger := NewResultMerger()

	results := merger.Merge(nil, nil, nil, 10)
	assert.Empty(t, results)
}

func TestResultMerger_Merge_MissionMemoryOnly(t *testing.T) {
	merger := NewResultMerger()

	missionResults := []MemoryEntry{
		{Key: "key1", Value: "value1", Score: 0.9, Timestamp: time.Now()},
		{Key: "key2", Value: "value2", Score: 0.8, Timestamp: time.Now()},
	}

	results := merger.Merge(missionResults, nil, nil, 10)

	assert.Len(t, results, 2)
	assert.Equal(t, "key1", results[0].ID)
	assert.Equal(t, "mission_memory", results[0].Source)
}

func TestResultMerger_Merge_LongTermMemoryOnly(t *testing.T) {
	merger := NewResultMerger()

	longTermResults := []MemoryEntry{
		{Key: "lt1", Value: "value1", Score: 0.95, Timestamp: time.Now()},
	}

	results := merger.Merge(nil, longTermResults, nil, 10)

	assert.Len(t, results, 1)
	assert.Equal(t, "lt1", results[0].ID)
	assert.Equal(t, "long_term_memory", results[0].Source)
}

func TestResultMerger_Merge_GraphOnly(t *testing.T) {
	merger := NewResultMerger()

	graphResults := []GraphEntry{
		{ID: "host-1", Type: "host", Score: 0.9, Source: "entity_lookup"},
		{ID: "port-1", Type: "port", Score: 0.8, Source: "relationship_traversal"},
	}

	results := merger.Merge(nil, nil, graphResults, 10)

	assert.Len(t, results, 2)
	assert.Equal(t, "graph_entity", results[0].Type)
}

func TestResultMerger_Merge_AllSources(t *testing.T) {
	merger := NewResultMerger()

	missionResults := []MemoryEntry{
		{Key: "m1", Value: "memory1", Score: 0.7, Timestamp: time.Now()},
	}
	longTermResults := []MemoryEntry{
		{Key: "lt1", Value: "longterm1", Score: 0.8, Timestamp: time.Now()},
	}
	graphResults := []GraphEntry{
		{ID: "g1", Type: "host", Score: 0.9, Source: "entity_lookup"},
	}

	results := merger.Merge(missionResults, longTermResults, graphResults, 10)

	assert.Len(t, results, 3)

	// Should have all three sources represented
	sources := make(map[string]bool)
	for _, r := range results {
		sources[r.Source] = true
	}
	assert.True(t, sources["mission_memory"])
	assert.True(t, sources["long_term_memory"])
	assert.Contains(t, sources, "graph_entity_lookup")
}

func TestResultMerger_Merge_LimitsResults(t *testing.T) {
	merger := NewResultMerger()

	missionResults := []MemoryEntry{
		{Key: "m1", Value: "v1", Score: 0.9, Timestamp: time.Now()},
		{Key: "m2", Value: "v2", Score: 0.8, Timestamp: time.Now()},
		{Key: "m3", Value: "v3", Score: 0.7, Timestamp: time.Now()},
		{Key: "m4", Value: "v4", Score: 0.6, Timestamp: time.Now()},
		{Key: "m5", Value: "v5", Score: 0.5, Timestamp: time.Now()},
	}

	results := merger.Merge(missionResults, nil, nil, 3)

	assert.Len(t, results, 3)
}

func TestResultMerger_Deduplicate(t *testing.T) {
	merger := NewResultMerger()

	results := []MergedResult{
		{ID: "id1", Score: 0.9},
		{ID: "id2", Score: 0.8},
		{ID: "id1", Score: 0.7}, // Duplicate with lower score
		{ID: "id3", Score: 0.6},
	}

	deduped := merger.Deduplicate(results)

	assert.Len(t, deduped, 3)

	// Check that id1 kept higher score
	for _, r := range deduped {
		if r.ID == "id1" {
			assert.Equal(t, 0.9, r.Score)
		}
	}
}

func TestResultMerger_Deduplicate_KeepsHigherScore(t *testing.T) {
	merger := NewResultMerger()

	results := []MergedResult{
		{ID: "id1", Score: 0.5},
		{ID: "id1", Score: 0.9}, // Higher score comes second
	}

	deduped := merger.Deduplicate(results)

	assert.Len(t, deduped, 1)
	assert.Equal(t, 0.9, deduped[0].Score)
}

func TestResultMerger_Rank(t *testing.T) {
	merger := NewResultMerger()

	results := []MergedResult{
		{ID: "low", Score: 0.3, Timestamp: time.Now()},
		{ID: "high", Score: 0.9, Timestamp: time.Now()},
		{ID: "medium", Score: 0.6, Timestamp: time.Now()},
	}

	merger.Rank(results)

	// Results should be sorted by score descending
	assert.True(t, results[0].Score >= results[1].Score)
	assert.True(t, results[1].Score >= results[2].Score)
}

func TestResultMerger_FilterByMinRelevance(t *testing.T) {
	merger := NewResultMerger()

	results := []MergedResult{
		{ID: "high", Score: 0.9},
		{ID: "medium", Score: 0.5},
		{ID: "low", Score: 0.2},
	}

	filtered := merger.FilterByMinRelevance(results, 0.4)

	assert.Len(t, filtered, 2)
	for _, r := range filtered {
		assert.GreaterOrEqual(t, r.Score, 0.4)
	}
}

func TestResultMerger_FilterByMinRelevance_ZeroThreshold(t *testing.T) {
	merger := NewResultMerger()

	results := []MergedResult{
		{ID: "1", Score: 0.9},
		{ID: "2", Score: 0.1},
	}

	// Zero threshold should return all
	filtered := merger.FilterByMinRelevance(results, 0.0)
	assert.Len(t, filtered, 2)
}

func TestResultMerger_CalculateRecencyScore(t *testing.T) {
	merger := NewResultMerger()
	now := time.Now()

	tests := []struct {
		name     string
		age      time.Duration
		minScore float64
		maxScore float64
	}{
		{
			name:     "recent (30 min)",
			age:      30 * time.Minute,
			minScore: 0.9,
			maxScore: 1.0,
		},
		{
			name:     "today (12 hours)",
			age:      12 * time.Hour,
			minScore: 0.7,
			maxScore: 0.9,
		},
		{
			name:     "this week (3 days)",
			age:      3 * 24 * time.Hour,
			minScore: 0.5,
			maxScore: 0.7,
		},
		{
			name:     "this month (2 weeks)",
			age:      14 * 24 * time.Hour,
			minScore: 0.3,
			maxScore: 0.5,
		},
		{
			name:     "old (2 months)",
			age:      60 * 24 * time.Hour,
			minScore: 0.1,
			maxScore: 0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timestamp := now.Add(-tt.age)
			score := merger.calculateRecencyScore(timestamp, now)
			assert.GreaterOrEqual(t, score, tt.minScore, "score should be >= %f", tt.minScore)
			assert.LessOrEqual(t, score, tt.maxScore, "score should be <= %f", tt.maxScore)
		})
	}
}

func TestResultMerger_CalculateImportanceScore(t *testing.T) {
	merger := NewResultMerger()

	// Findings should be most important
	findingScore := merger.calculateImportanceScore("finding")
	serviceScore := merger.calculateImportanceScore("service")
	hostScore := merger.calculateImportanceScore("host")

	assert.Greater(t, findingScore, serviceScore)
	assert.Greater(t, serviceScore, hostScore)
}

func TestResultMerger_CalculateImportanceScore_Unknown(t *testing.T) {
	merger := NewResultMerger()

	score := merger.calculateImportanceScore("unknown_type")
	assert.Equal(t, 0.5, score) // Default score
}
