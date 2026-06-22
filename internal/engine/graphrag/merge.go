package graphrag

import (
	"sort"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MergeReranker combines and reranks results from vector and graph searches.
// This interface enables hybrid retrieval by merging semantic similarity (vector)
// with structural proximity (graph) for more contextually relevant results.
//
// Implementations must handle:
// - Deduplication of nodes appearing in both result sets
// - Score normalization and combination using configurable weights
// - Ranking based on hybrid scores
// - Result limiting (topK)
type MergeReranker interface {
	// Merge combines vector search results with graph traversal results.
	// Deduplicates nodes by ID and creates MergedResult entries with both scores.
	// Nodes appearing in both result sets get both vector and graph scores.
	// Nodes only in vector results get zero graph score, and vice versa.
	Merge(vectorResults []VectorResult, graphResults []GraphNode) []MergedResult

	// Rerank scores and sorts merged results using weighted scoring.
	// Applies the scoring formula: finalScore = vectorWeight * vectorScore + graphWeight * graphScore
	// Returns the top-K results sorted by final score in descending order.
	// The query parameter can be used for query-time reranking strategies.
	Rerank(results []MergedResult, query string, topK int) []GraphRAGResult
}

// MergedResult represents an intermediate result combining vector and graph scores.
// Used during the merge phase before final reranking and conversion to GraphRAGResult.
type MergedResult struct {
	Node        GraphNode  `json:"node"`
	VectorScore float64    `json:"vector_score"` // Cosine similarity (0-1), 0 if not from vector search
	GraphScore  float64    `json:"graph_score"`  // Graph proximity (0-1), 0 if not from graph traversal
	Path        []types.ID `json:"path"`         // Graph traversal path (empty if not from traversal)
	Distance    int        `json:"distance"`     // Graph distance in hops (0 if not from traversal)
	InVector    bool       `json:"in_vector"`    // True if node was in vector results
	InGraph     bool       `json:"in_graph"`     // True if node was in graph results
}

// DefaultMergeReranker implements MergeReranker with standard hybrid scoring.
// Uses configurable vector and graph weights to compute final scores.
type DefaultMergeReranker struct {
	vectorWeight float64 // Weight for vector similarity scores (0-1)
	graphWeight  float64 // Weight for graph proximity scores (0-1)
}

// NewDefaultMergeReranker creates a new DefaultMergeReranker with the given weights.
// Weights should sum to approximately 1.0 for proper scoring.
// Common configurations:
// - Balanced: vectorWeight=0.5, graphWeight=0.5
// - Vector-biased: vectorWeight=0.7, graphWeight=0.3
// - Graph-biased: vectorWeight=0.3, graphWeight=0.7
func NewDefaultMergeReranker(vectorWeight, graphWeight float64) *DefaultMergeReranker {
	return &DefaultMergeReranker{
		vectorWeight: vectorWeight,
		graphWeight:  graphWeight,
	}
}

// Merge combines vector search results with graph traversal results.
// Deduplicates nodes by ID and preserves scores from both sources.
//
// Algorithm:
// 1. Create a map of node ID -> MergedResult for deduplication
// 2. Process vector results: add nodes with vector scores
// 3. Process graph results: update existing nodes or add new ones with graph scores
// 4. Return all merged results as a slice
func (m *DefaultMergeReranker) Merge(vectorResults []VectorResult, graphResults []GraphNode) []MergedResult {
	// Use map for O(1) lookup and deduplication
	resultMap := make(map[string]*MergedResult)

	// Process vector results first
	for _, vr := range vectorResults {
		nodeIDStr := vr.NodeID.String()
		resultMap[nodeIDStr] = &MergedResult{
			Node:        GraphNode{ID: vr.NodeID}, // Will be populated from provider
			VectorScore: vr.Similarity,
			GraphScore:  0.0, // Will be updated if node is also in graph results
			Path:        []types.ID{},
			Distance:    0,
			InVector:    true,
			InGraph:     false,
		}
	}

	// Process graph results - update existing or add new
	for _, gn := range graphResults {
		nodeIDStr := gn.ID.String()
		if existing, found := resultMap[nodeIDStr]; found {
			// Node already in vector results - update with graph data
			existing.Node = gn
			existing.GraphScore = computeGraphScore(gn)
			existing.Path = extractPath(gn)
			existing.Distance = len(existing.Path) - 1
			if existing.Distance < 0 {
				existing.Distance = 0
			}
			existing.InGraph = true
		} else {
			// New node from graph traversal only
			resultMap[nodeIDStr] = &MergedResult{
				Node:        gn,
				VectorScore: 0.0, // Not in vector results
				GraphScore:  computeGraphScore(gn),
				Path:        extractPath(gn),
				Distance:    len(extractPath(gn)) - 1,
				InVector:    false,
				InGraph:     true,
			}
			if resultMap[nodeIDStr].Distance < 0 {
				resultMap[nodeIDStr].Distance = 0
			}
		}
	}

	// Convert map to slice
	results := make([]MergedResult, 0, len(resultMap))
	for _, result := range resultMap {
		results = append(results, *result)
	}

	return results
}

// Rerank scores and sorts merged results using weighted scoring.
// Computes final hybrid score and returns top-K results.
//
// Scoring formula: finalScore = vectorWeight * vectorScore + graphWeight * graphScore
//
// The query parameter is currently unused but provided for future extensions
// like query-dependent reranking or semantic boosting.
func (m *DefaultMergeReranker) Rerank(results []MergedResult, query string, topK int) []GraphRAGResult {
	// Compute final scores for each result
	graphRAGResults := make([]GraphRAGResult, len(results))
	for i, merged := range results {
		// Compute hybrid score using configured weights
		finalScore := (m.vectorWeight * merged.VectorScore) + (m.graphWeight * merged.GraphScore)

		graphRAGResults[i] = GraphRAGResult{
			Node:        merged.Node,
			Score:       finalScore,
			VectorScore: merged.VectorScore,
			GraphScore:  merged.GraphScore,
			Path:        merged.Path,
			Distance:    merged.Distance,
		}
		graphRAGResults[i].ComputeScore(m.vectorWeight, m.graphWeight)
	}

	// Sort by final score in descending order (highest scores first)
	sort.Slice(graphRAGResults, func(i, j int) bool {
		return graphRAGResults[i].Score > graphRAGResults[j].Score
	})

	// Return top-K results
	if topK > 0 && topK < len(graphRAGResults) {
		return graphRAGResults[:topK]
	}
	return graphRAGResults
}

// computeGraphScore calculates a graph proximity score for a node.
// Higher scores indicate closer proximity to the query node.
//
// Current implementation uses a simple distance-based decay:
// - Score = 1.0 / (1.0 + distance)
// - This gives scores: 1-hop=0.5, 2-hops=0.33, 3-hops=0.25
//
// Future enhancements could include:
// - Relationship weight consideration
// - Path diversity scoring
// - Node importance/centrality
func computeGraphScore(node GraphNode) float64 {
	// Extract distance from node properties if available
	distance := 0
	if distProp := node.GetProperty("distance"); distProp != nil {
		if d, ok := distProp.(int); ok {
			distance = d
		} else if d, ok := distProp.(float64); ok {
			distance = int(d)
		}
	}

	// Simple distance-based decay: score = 1 / (1 + distance)
	// This ensures: direct connection (0 hops) = 1.0, 1 hop = 0.5, 2 hops = 0.33, etc.
	if distance == 0 {
		return 1.0
	}
	return 1.0 / (1.0 + float64(distance))
}

// extractPath extracts the traversal path from node properties.
// Returns the path as a slice of node IDs, or empty slice if no path exists.
//
// The path is typically stored in the node's properties during graph traversal.
// Format: []string of node ID strings, which are converted to types.ID.
func extractPath(node GraphNode) []types.ID {
	pathProp := node.GetProperty("path")
	if pathProp == nil {
		return []types.ID{}
	}

	// Try to parse path as []string
	if pathStrs, ok := pathProp.([]string); ok {
		path := make([]types.ID, len(pathStrs))
		for i, idStr := range pathStrs {
			id, err := types.ParseID(idStr)
			if err != nil {
				// Skip invalid IDs
				continue
			}
			path[i] = id
		}
		return path
	}

	// Try to parse path as []interface{} (from JSON unmarshaling)
	if pathInterfaces, ok := pathProp.([]interface{}); ok {
		path := make([]types.ID, 0, len(pathInterfaces))
		for _, idInterface := range pathInterfaces {
			if idStr, ok := idInterface.(string); ok {
				id, err := types.ParseID(idStr)
				if err != nil {
					continue
				}
				path = append(path, id)
			}
		}
		return path
	}

	return []types.ID{}
}

// MergeOptions contains configuration for the merge and rerank process.
// Allows fine-tuning of the hybrid retrieval behavior.
type MergeOptions struct {
	// VectorWeight is the weight for vector similarity scores (0-1).
	VectorWeight float64

	// GraphWeight is the weight for graph proximity scores (0-1).
	GraphWeight float64

	// TopK limits the number of final results.
	TopK int

	// DeduplicateByID removes duplicate nodes by ID (default: true).
	DeduplicateByID bool

	// BoostBothSources increases scores for nodes in both vector and graph results.
	// Multiplier applied to final score if node appears in both sources.
	BoostBothSources float64
}

// Validate checks if the MergeOptions are valid.
func (mo *MergeOptions) Validate() error {
	if mo.VectorWeight < 0.0 || mo.VectorWeight > 1.0 {
		return NewInvalidQueryError("vector_weight must be between 0.0 and 1.0")
	}
	if mo.GraphWeight < 0.0 || mo.GraphWeight > 1.0 {
		return NewInvalidQueryError("graph_weight must be between 0.0 and 1.0")
	}
	if mo.TopK <= 0 {
		return NewInvalidQueryError("top_k must be greater than 0")
	}
	if mo.BoostBothSources < 1.0 {
		return NewInvalidQueryError("boost_both_sources must be >= 1.0")
	}

	// Warn if weights don't sum to ~1.0 (not an error, but potentially unexpected)
	weightSum := mo.VectorWeight + mo.GraphWeight
	if weightSum < 0.99 || weightSum > 1.01 {
		// Note: In production, this could log a warning instead of returning an error
		// For now, we allow it but it's worth noting
	}

	return nil
}
