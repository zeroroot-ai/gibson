package vector

import (
	"encoding/json"
	"fmt"
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

// NewVectorRecord creates a new VectorRecord with the current timestamp.
func NewVectorRecord(id, content string, embedding []float64, metadata map[string]any) *VectorRecord {
	return &VectorRecord{
		ID:        id,
		Content:   content,
		Embedding: embedding,
		Metadata:  metadata,
		CreatedAt: time.Now(),
	}
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

// VectorQuery represents a vector search query.
// It supports both text-based queries (which will be embedded) and
// pre-computed embedding queries.
type VectorQuery struct {
	Text      string         `json:"text,omitempty"`      // Text to embed and search
	Embedding []float64      `json:"embedding,omitempty"` // Pre-computed embedding
	TopK      int            `json:"top_k"`               // Number of results to return
	Filters   map[string]any `json:"filters,omitempty"`   // Metadata filters
	MinScore  float64        `json:"min_score,omitempty"` // Minimum similarity threshold (0-1)
}

// NewVectorQueryFromText creates a new VectorQuery from text.
// The text will be embedded by the embedder before searching.
func NewVectorQueryFromText(text string, topK int) *VectorQuery {
	return &VectorQuery{
		Text:     text,
		TopK:     topK,
		MinScore: 0.0, // No minimum threshold by default
	}
}

// NewVectorQueryFromEmbedding creates a new VectorQuery from a pre-computed embedding.
func NewVectorQueryFromEmbedding(embedding []float64, topK int) *VectorQuery {
	return &VectorQuery{
		Embedding: embedding,
		TopK:      topK,
		MinScore:  0.0, // No minimum threshold by default
	}
}

// WithFilters adds metadata filters to the query.
// Returns the query for method chaining.
func (vq *VectorQuery) WithFilters(filters map[string]any) *VectorQuery {
	vq.Filters = filters
	return vq
}

// WithMinScore sets the minimum similarity score threshold.
// Returns the query for method chaining.
func (vq *VectorQuery) WithMinScore(minScore float64) *VectorQuery {
	vq.MinScore = minScore
	return vq
}

// Validate ensures the VectorQuery has valid fields.
// Returns a GibsonError if validation fails.
func (vq *VectorQuery) Validate() error {
	// Must have at least one of Text or Embedding (both allowed for hybrid search)
	if vq.Text == "" && len(vq.Embedding) == 0 {
		return types.NewError(ErrCodeVectorSearchFailed, "vector query must have either text or embedding")
	}
	if vq.TopK <= 0 {
		return types.NewError(ErrCodeVectorSearchFailed,
			fmt.Sprintf("vector query top_k must be greater than 0, got %d", vq.TopK))
	}
	if vq.MinScore < 0 || vq.MinScore > 1 {
		return types.NewError(ErrCodeVectorSearchFailed,
			fmt.Sprintf("vector query min_score must be between 0 and 1, got %f", vq.MinScore))
	}
	return nil
}

// VectorResult represents a vector search result with similarity score.
type VectorResult struct {
	Record VectorRecord `json:"record"`
	Score  float64      `json:"score"` // Cosine similarity (0-1, higher is better)
}

// NewVectorResult creates a new VectorResult with the given record and score.
func NewVectorResult(record VectorRecord, score float64) *VectorResult {
	return &VectorResult{
		Record: record,
		Score:  score,
	}
}

// Validate ensures the VectorResult has valid fields.
// Returns a GibsonError if validation fails.
func (vr *VectorResult) Validate() error {
	if err := vr.Record.Validate(); err != nil {
		return types.WrapError(ErrCodeVectorSearchFailed, "vector result contains invalid record", err)
	}
	if vr.Score < 0 || vr.Score > 1 {
		return types.NewError(ErrCodeVectorSearchFailed,
			fmt.Sprintf("vector result score must be between 0 and 1, got %f", vr.Score))
	}
	return nil
}
