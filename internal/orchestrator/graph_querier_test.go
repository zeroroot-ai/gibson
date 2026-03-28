package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNoOpGraphQuerier_EntityLookup(t *testing.T) {
	querier := NewNoOpGraphQuerier()
	ctx := context.Background()

	query := EntityQuery{
		EntityTypes: []string{"host"},
		MaxResults:  10,
	}

	results, err := querier.EntityLookup(ctx, query)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestNoOpGraphQuerier_RelationshipTraversal(t *testing.T) {
	querier := NewNoOpGraphQuerier()
	ctx := context.Background()

	query := RelationshipQuery{
		StartEntityID: "test-id",
		MaxDepth:      2,
	}

	results, err := querier.RelationshipTraversal(ctx, query)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestNoOpGraphQuerier_PatternMatch(t *testing.T) {
	querier := NewNoOpGraphQuerier()
	ctx := context.Background()

	query := PatternQuery{
		Pattern:    "host:h -[HAS_PORT]-> port:p",
		MaxResults: 10,
	}

	results, err := querier.PatternMatch(ctx, query)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestNoOpGraphQuerier_SemanticSearch(t *testing.T) {
	querier := NewNoOpGraphQuerier()
	ctx := context.Background()

	query := SemanticQuery{
		Query:      "find hosts",
		MaxResults: 10,
	}

	results, err := querier.SemanticSearch(ctx, query)
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestEntityQuery_Defaults(t *testing.T) {
	query := EntityQuery{}

	// Zero values should be valid
	assert.Empty(t, query.EntityTypes)
	assert.Empty(t, query.Filters)
	assert.Empty(t, query.MissionRunID)
	assert.Equal(t, 0, query.MaxResults)
	assert.Equal(t, 0, query.Offset)
}

func TestTimeRange_IsZero(t *testing.T) {
	tests := []struct {
		name     string
		tr       TimeRange
		expected bool
	}{
		{
			name:     "zero range",
			tr:       TimeRange{},
			expected: true,
		},
		{
			name:     "only start",
			tr:       TimeRange{Start: time.Now()},
			expected: false,
		},
		{
			name:     "only end",
			tr:       TimeRange{End: time.Now()},
			expected: false,
		},
		{
			name:     "both set",
			tr:       TimeRange{Start: time.Now().Add(-time.Hour), End: time.Now()},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.tr.IsZero())
		})
	}
}

func TestMissionScope_Constants(t *testing.T) {
	assert.Equal(t, MissionScope("current"), MissionScopeCurrent)
	assert.Equal(t, MissionScope("cross_mission"), MissionScopeCrossMission)
}

func TestEntityMatch_Fields(t *testing.T) {
	now := time.Now()
	match := EntityMatch{
		ID:           "test-id",
		Type:         "host",
		Properties:   map[string]interface{}{"ip": "192.168.1.1"},
		Score:        0.95,
		MissionRunID: "mission-123",
		DiscoveredAt: now,
		DiscoveredBy: "nmap",
	}

	assert.Equal(t, "test-id", match.ID)
	assert.Equal(t, "host", match.Type)
	assert.Equal(t, 0.95, match.Score)
	assert.Equal(t, "mission-123", match.MissionRunID)
	assert.Equal(t, now, match.DiscoveredAt)
	assert.Equal(t, "nmap", match.DiscoveredBy)
	assert.Equal(t, "192.168.1.1", match.Properties["ip"])
}

func TestRelatedEntity_Fields(t *testing.T) {
	relEntity := RelatedEntity{
		Entity: EntityMatch{
			ID:   "port-1",
			Type: "port",
		},
		Relationship: RelationshipInfo{
			Type:   "HAS_PORT",
			FromID: "host-1",
			ToID:   "port-1",
		},
		Depth: 1,
		Path:  "host-1 -[HAS_PORT]-> port-1",
	}

	assert.Equal(t, "port-1", relEntity.Entity.ID)
	assert.Equal(t, "HAS_PORT", relEntity.Relationship.Type)
	assert.Equal(t, 1, relEntity.Depth)
}

func TestPatternMatchResult_Fields(t *testing.T) {
	result := PatternMatchResult{
		Bindings: map[string]EntityMatch{
			"h": {ID: "host-1", Type: "host"},
			"p": {ID: "port-1", Type: "port"},
		},
		Relationships: []RelationshipInfo{
			{Type: "HAS_PORT", FromID: "host-1", ToID: "port-1"},
		},
		Score: 1.0,
	}

	assert.Len(t, result.Bindings, 2)
	assert.Contains(t, result.Bindings, "h")
	assert.Contains(t, result.Bindings, "p")
	assert.Len(t, result.Relationships, 1)
}

func TestRelationshipQuery_Defaults(t *testing.T) {
	query := RelationshipQuery{
		StartEntityID: "test-id",
	}

	assert.Equal(t, "test-id", query.StartEntityID)
	assert.Empty(t, query.RelationshipTypes)
	assert.Empty(t, query.Direction)
	assert.Equal(t, 0, query.MaxDepth)
	assert.Equal(t, 0, query.MaxResults)
	assert.False(t, query.IncludeProperties)
}

func TestSemanticQuery_Defaults(t *testing.T) {
	query := SemanticQuery{
		Query: "test query",
	}

	assert.Equal(t, "test query", query.Query)
	assert.Empty(t, query.EntityTypes)
	assert.Empty(t, query.MissionRunID)
	assert.Equal(t, 0.0, query.MinSimilarity)
	assert.Equal(t, 0, query.MaxResults)
}
