package graphrag

import (
	"github.com/zero-day-ai/gibson/internal/types"
)

// VectorResult represents a pure vector search result (no graph traversal).
// Used for initial similarity search before graph expansion.
type VectorResult struct {
	NodeID     types.ID       `json:"node_id"`
	Similarity float64        `json:"similarity"` // Cosine similarity (0-1)
	Embedding  []float64      `json:"embedding,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// NewVectorResult creates a new VectorResult.
func NewVectorResult(nodeID types.ID, similarity float64) *VectorResult {
	return &VectorResult{
		NodeID:     nodeID,
		Similarity: similarity,
		Metadata:   make(map[string]any),
	}
}

// WithEmbedding sets the embedding vector.
func (vr *VectorResult) WithEmbedding(embedding []float64) *VectorResult {
	vr.Embedding = embedding
	return vr
}

// WithMetadata sets metadata for the result.
func (vr *VectorResult) WithMetadata(metadata map[string]any) *VectorResult {
	vr.Metadata = metadata
	return vr
}
