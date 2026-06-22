package graphrag

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// GraphRAGQuery represents a hybrid graph + vector search query.
// Combines semantic search (embeddings) with graph traversal for contextual retrieval.
type GraphRAGQuery struct {
	// Query inputs
	Text      string    `json:"text,omitempty"`      // Text to search for (will be embedded)
	Embedding []float64 `json:"embedding,omitempty"` // Pre-computed embedding vector

	// Search parameters
	TopK     int     `json:"top_k"`               // Number of results to return
	MaxHops  int     `json:"max_hops"`            // Maximum graph traversal depth
	MinScore float64 `json:"min_score,omitempty"` // Minimum similarity threshold (0-1)

	// Filters
	Filters   TraversalFilters `json:"filters,omitempty"`
	NodeTypes []NodeType       `json:"node_types,omitempty"` // Filter by node types
	MissionID *types.ID        `json:"mission_id,omitempty"` // Filter by mission

	// Mission scope filtering (Phase 2 - mission-scoped storage)
	MissionScope    MissionScope `json:"mission_scope,omitempty"`     // Query scope
	MissionName     string       `json:"mission_name,omitempty"`      // Mission name for same_mission scope
	MissionIDFilter []types.ID   `json:"mission_id_filter,omitempty"` // Resolved mission IDs to filter by
	MissionRunID    string       `json:"mission_run_id,omitempty"`    // Current mission run ID (injected by harness)

	// Scoring weights
	VectorWeight float64 `json:"vector_weight,omitempty"` // Weight for vector similarity (0-1)
	GraphWeight  float64 `json:"graph_weight,omitempty"`  // Weight for graph proximity (0-1)

	// Explicit routing flags (SDK v0.26.0+)
	ForceSemanticOnly   bool `json:"force_semantic_only,omitempty"`   // Skip structured fallback
	ForceStructuredOnly bool `json:"force_structured_only,omitempty"` // Skip vector search entirely
}

// NewGraphRAGQuery creates a new query from text.
func NewGraphRAGQuery(text string) *GraphRAGQuery {
	return &GraphRAGQuery{
		Text:         text,
		TopK:         10,
		MaxHops:      3,
		MinScore:     0.7,
		VectorWeight: 0.6,
		GraphWeight:  0.4,
		Filters:      TraversalFilters{},
	}
}

// NewGraphRAGQueryFromEmbedding creates a new query from a pre-computed embedding.
func NewGraphRAGQueryFromEmbedding(embedding []float64) *GraphRAGQuery {
	return &GraphRAGQuery{
		Embedding:    embedding,
		TopK:         10,
		MaxHops:      3,
		MinScore:     0.7,
		VectorWeight: 0.6,
		GraphWeight:  0.4,
		Filters:      TraversalFilters{},
	}
}

// WithTopK sets the number of results to return.
func (q *GraphRAGQuery) WithTopK(topK int) *GraphRAGQuery {
	q.TopK = topK
	return q
}

// WithMaxHops sets the maximum graph traversal depth.
func (q *GraphRAGQuery) WithMaxHops(maxHops int) *GraphRAGQuery {
	q.MaxHops = maxHops
	return q
}

// WithMinScore sets the minimum similarity threshold.
func (q *GraphRAGQuery) WithMinScore(minScore float64) *GraphRAGQuery {
	q.MinScore = minScore
	return q
}

// WithNodeTypes filters results to specific node types.
func (q *GraphRAGQuery) WithNodeTypes(types ...NodeType) *GraphRAGQuery {
	q.NodeTypes = types
	return q
}

// WithMission filters results to a specific mission.
func (q *GraphRAGQuery) WithMission(missionID types.ID) *GraphRAGQuery {
	q.MissionID = &missionID
	return q
}

// WithFilters sets the traversal filters.
func (q *GraphRAGQuery) WithFilters(filters TraversalFilters) *GraphRAGQuery {
	q.Filters = filters
	return q
}

// WithWeights sets the vector and graph scoring weights.
func (q *GraphRAGQuery) WithWeights(vectorWeight, graphWeight float64) *GraphRAGQuery {
	q.VectorWeight = vectorWeight
	q.GraphWeight = graphWeight
	return q
}

// WithMissionScope sets the mission scope for the query.
func (q *GraphRAGQuery) WithMissionScope(scope MissionScope) *GraphRAGQuery {
	q.MissionScope = scope
	return q
}

// WithMissionName sets the mission name for same_mission scope filtering.
func (q *GraphRAGQuery) WithMissionName(name string) *GraphRAGQuery {
	q.MissionName = name
	return q
}

// WithMissionIDFilter sets the resolved mission IDs to filter by.
func (q *GraphRAGQuery) WithMissionIDFilter(ids []types.ID) *GraphRAGQuery {
	q.MissionIDFilter = ids
	return q
}

// Validate validates the GraphRAGQuery fields.
func (q *GraphRAGQuery) Validate() error {
	// Check for conflicting routing flags
	if q.ForceSemanticOnly && q.ForceStructuredOnly {
		return NewInvalidQueryError("cannot set both force_semantic_only and force_structured_only")
	}

	// Must have either Text or Embedding (or NodeTypes for structured-only queries)
	if q.Text == "" && len(q.Embedding) == 0 && len(q.NodeTypes) == 0 {
		return NewInvalidQueryError("query must have either text, embedding, or node_types")
	}
	if q.Text != "" && len(q.Embedding) > 0 {
		return NewInvalidQueryError("query cannot have both text and embedding")
	}

	// Validate parameters
	if q.TopK <= 0 {
		return NewInvalidQueryError(fmt.Sprintf("top_k must be greater than 0, got %d", q.TopK))
	}
	if q.MaxHops < 0 {
		return NewInvalidQueryError(fmt.Sprintf("max_hops must be >= 0, got %d", q.MaxHops))
	}
	if q.MinScore < 0.0 || q.MinScore > 1.0 {
		return NewInvalidQueryError(fmt.Sprintf("min_score must be between 0.0 and 1.0, got %f", q.MinScore))
	}
	if q.VectorWeight < 0.0 || q.VectorWeight > 1.0 {
		return NewInvalidQueryError(fmt.Sprintf("vector_weight must be between 0.0 and 1.0, got %f", q.VectorWeight))
	}
	if q.GraphWeight < 0.0 || q.GraphWeight > 1.0 {
		return NewInvalidQueryError(fmt.Sprintf("graph_weight must be between 0.0 and 1.0, got %f", q.GraphWeight))
	}

	// Node type validation is now handled by the taxonomy system

	// Validate mission scope
	if q.MissionScope != "" {
		validScopes := map[MissionScope]bool{
			ScopeCurrentRun:  true,
			ScopeSameMission: true,
			ScopeAll:         true,
		}
		if !validScopes[q.MissionScope] {
			return NewInvalidQueryError(fmt.Sprintf("invalid mission scope: %s", q.MissionScope))
		}

		// If scope is same_mission, mission_name should be provided
		if q.MissionScope == ScopeSameMission && q.MissionName == "" {
			return NewInvalidQueryError("mission_name is required when mission_scope is 'same_mission'")
		}
	}

	return nil
}
