// Package reembed implements the per-tenant background job that brings a
// tenant's vector index and stored embeddings to consistency after the tenant's
// embedding model (or provider) changes.
//
// Why this exists. The RediSearch VECTOR field is created at a fixed dimension
// (state.VectorIndex(dim)). An index built at dim N cannot hold a dim M vector:
// a dimension mismatch silently fails RediSearch indexing of the WHOLE document
// (FT.INFO hash_indexing_failures), rendering the affected vectors search
// invisible. Changing a tenant's embedding model therefore REQUIRES dropping and
// recreating the index at the new model's dimension and re-embedding existing
// content with the new embedder. This is the wholesale mechanism (ADR-0027):
// there is no parallel "old vectors stay" path.
//
// The source of truth for re-embeddable content is VectorRecord.Content, the
// original text stored alongside every embedding. The job re-derives each
// vector from its own stored text, so the change is fully recoverable without an
// external document store.
//
// Per-tenant isolation. The job operates on a single *state.StateClient, which
// in production is the tenant's own database-per-tenant Redis. The marker, the
// vector documents (gibson:vector:*) and the index (gibson:idx:vectors) all live
// in that one keyspace, so passing the correct per-tenant StateClient is the
// whole of the isolation contract — never the shared client.
package reembed

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
)

// markerKey is the Redis key, within a tenant's StateClient keyspace, recording
// which embedding model and dimension the current vector index was built with.
// It lives under the gibson:vector: namespace so it is co-located with the
// vector documents and the per-tenant index it describes.
const markerKey = "gibson:vector:embedding_meta"

// IndexMarker records the embedding model and dimension a tenant's vector index
// was last (re)built with. Drift between this marker and the tenant's configured
// embedding model is exactly what triggers a re-embed: a different model name —
// or, more dangerously, a different output dimension — means the stored vectors
// are stale or outright incompatible with the live index.
type IndexMarker struct {
	// Model is the embedding model the index was built with, e.g.
	// "text-embedding-3-small".
	Model string `json:"model"`

	// Dim is the vector dimension the index was created at. It must equal
	// embedder.DimensionForModel(Model); it is persisted explicitly so drift
	// detection never has to re-resolve the table for the OLD model (which may
	// since have been removed from the registry).
	Dim int `json:"dim"`
}

// readMarker loads the persisted index marker for the tenant whose StateClient
// is given. A missing marker returns (nil, nil): an index that predates this
// machinery, or a fresh tenant, has no recorded build model and is treated as
// "unknown" by the caller (which then forces a recreate).
func readMarker(ctx context.Context, sc *state.StateClient) (*IndexMarker, error) {
	var m IndexMarker
	if err := sc.JSONGet(ctx, markerKey, "$", &m); err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}

// writeMarker persists the index marker for the tenant. It is written only after
// the index has been recreated and re-embedding has completed, so a marker on
// disk is a durable "the index is consistent at this model/dim" commit point.
func writeMarker(ctx context.Context, sc *state.StateClient, m IndexMarker) error {
	return sc.JSONSet(ctx, markerKey, "$", m)
}
