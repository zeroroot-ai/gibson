// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package vector

import (
	"encoding/json"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// VectorRecord represents a stored vector with metadata.
// Used for semantic search in long-term memory.
type VectorRecord struct {
	ID        string         `json:"id"`
	Content   string         `json:"content"`
	Embedding []float64      `json:"embedding"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// vectorRecordJSON is the on-the-wire shape of a VectorRecord. created_at is
// serialized as a Unix-seconds NUMBER (not the default RFC3339 string) because
// the RediSearch index declares `$.created_at` as a NUMERIC field (see
// state.VectorIndex). A JSON string in a NUMERIC slot makes RediSearch reject
// the ENTIRE document at index time (FT.INFO hash_indexing_failures), which
// silently renders every stored vector unsearchable — both the @content
// full-text filter and the KNN vector clause return zero hits. Keeping the Go
// field a time.Time while marshaling it as a number satisfies the index
// contract without leaking the storage detail into callers.
type vectorRecordJSON struct {
	ID        string         `json:"id"`
	Content   string         `json:"content"`
	Embedding []float64      `json:"embedding"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt int64          `json:"created_at"`
}

// MarshalJSON serializes created_at as Unix seconds to match the NUMERIC index field.
func (vr VectorRecord) MarshalJSON() ([]byte, error) {
	return json.Marshal(vectorRecordJSON{
		ID:        vr.ID,
		Content:   vr.Content,
		Embedding: vr.Embedding,
		Metadata:  vr.Metadata,
		CreatedAt: vr.CreatedAt.Unix(),
	})
}

// UnmarshalJSON reads created_at as Unix seconds. For backward compatibility it
// also accepts the legacy RFC3339 string form so documents written before this
// fix still decode.
func (vr *VectorRecord) UnmarshalJSON(data []byte) error {
	var aux struct {
		ID        string          `json:"id"`
		Content   string          `json:"content"`
		Embedding []float64       `json:"embedding"`
		Metadata  map[string]any  `json:"metadata,omitempty"`
		CreatedAt json.RawMessage `json:"created_at"`
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	vr.ID = aux.ID
	vr.Content = aux.Content
	vr.Embedding = aux.Embedding
	vr.Metadata = aux.Metadata
	vr.CreatedAt = time.Time{}
	if len(aux.CreatedAt) > 0 && string(aux.CreatedAt) != "null" {
		var unix int64
		if err := json.Unmarshal(aux.CreatedAt, &unix); err == nil {
			vr.CreatedAt = time.Unix(unix, 0).UTC()
		} else {
			var rfc time.Time
			if err := json.Unmarshal(aux.CreatedAt, &rfc); err == nil {
				vr.CreatedAt = rfc
			}
		}
	}
	return nil
}

// Validate ensures the VectorRecord has valid fields.
// Returns a GibsonError if validation fails.
func (vr *VectorRecord) Validate() error {
	if vr.ID == "" {
		return types.NewError(ErrCodeVectorStoreFailed, "vector record ID cannot be empty")
	}
	if vr.Content == "" {
		return types.NewError(ErrCodeVectorStoreFailed, "vector record content cannot be empty")
	}
	if len(vr.Embedding) == 0 {
		return types.NewError(ErrCodeVectorStoreFailed, "vector record embedding cannot be empty")
	}
	return nil
}

// Dimensions returns the dimensionality of the embedding vector.
func (vr *VectorRecord) Dimensions() int {
	return len(vr.Embedding)
}

// VectorResult represents a vector search result with similarity score.
type VectorResult struct {
	Record VectorRecord `json:"record"`
	Score  float64      `json:"score"` // Cosine similarity (0-1, higher is better)
}
