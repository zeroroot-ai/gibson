package graphrag

import (
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// GraphRAGResult represents a single result from a GraphRAG query.
// Includes the node, scoring information, and traversal path.
type GraphRAGResult struct {
	Node        GraphNode  `json:"node"`
	Score       float64    `json:"score"`        // Combined hybrid score
	VectorScore float64    `json:"vector_score"` // Cosine similarity (0-1)
	GraphScore  float64    `json:"graph_score"`  // Graph proximity score (0-1)
	Path        []types.ID `json:"path"`         // Path from query node to result node
	Distance    int        `json:"distance"`     // Graph distance (hops)
	Timestamp   time.Time  `json:"timestamp"`
}

// NewGraphRAGResult creates a new result with the given node and scores.
func NewGraphRAGResult(node GraphNode, vectorScore, graphScore float64) *GraphRAGResult {
	return &GraphRAGResult{
		Node:        node,
		VectorScore: vectorScore,
		GraphScore:  graphScore,
		Path:        []types.ID{},
		Distance:    0,
		Timestamp:   time.Now(),
	}
}

// WithPath sets the traversal path for the result.
func (r *GraphRAGResult) WithPath(path []types.ID) *GraphRAGResult {
	r.Path = path
	r.Distance = len(path) - 1 // Distance is number of edges
	return r
}

// ComputeScore computes the combined hybrid score using the given weights.
func (r *GraphRAGResult) ComputeScore(vectorWeight, graphWeight float64) {
	r.Score = (r.VectorScore * vectorWeight) + (r.GraphScore * graphWeight)
}

// Validate validates the GraphRAGResult fields.
func (r *GraphRAGResult) Validate() error {
	if err := r.Node.Validate(); err != nil {
		return fmt.Errorf("invalid node in result: %w", err)
	}
	if r.Score < 0.0 || r.Score > 1.0 {
		return fmt.Errorf("score must be between 0.0 and 1.0, got %f", r.Score)
	}
	if r.VectorScore < 0.0 || r.VectorScore > 1.0 {
		return fmt.Errorf("vector_score must be between 0.0 and 1.0, got %f", r.VectorScore)
	}
	if r.GraphScore < 0.0 || r.GraphScore > 1.0 {
		return fmt.Errorf("graph_score must be between 0.0 and 1.0, got %f", r.GraphScore)
	}
	if r.Distance < 0 {
		return fmt.Errorf("distance must be >= 0, got %d", r.Distance)
	}
	return nil
}
