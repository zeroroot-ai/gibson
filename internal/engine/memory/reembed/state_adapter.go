package reembed

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/vector"
	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// stateAdapter binds the re-embed job's IndexStore + MarkerStore surfaces to a
// single tenant's *state.StateClient. Every operation runs in that StateClient's
// database (database-per-tenant in production), so isolation is structural: a
// stateAdapter can only ever touch the keyspace of the StateClient it was built
// with.
type stateAdapter struct {
	sc      *state.StateClient
	manager *state.IndexManager
}

// NewStateStore returns the IndexStore/MarkerStore pair backed by a tenant's
// StateClient. Pass the tenant's OWN database-per-tenant StateClient — never the
// shared one — so the recreate+re-embed pass operates on that tenant's vectors
// only.
//
// Both returned values are the same adapter; they are returned as two interfaces
// so the Job's dependencies stay explicit (recreate/list/store vs. read/write
// marker).
func NewStateStore(sc *state.StateClient) (IndexStore, MarkerStore) {
	a := &stateAdapter{
		sc:      sc,
		manager: state.NewIndexManager(sc.Client()),
	}
	return a, a
}

// RunForTenant is the wiring seam the daemon calls to reconcile one tenant's
// vector index against its CURRENT embedder. It assembles the StateClient-backed
// store, builds the Job, and runs a single idempotent pass. Call it whenever a
// tenant's embedding provider/model may have changed (on a provider-config write,
// at daemon startup for each tenant, or from a periodic reconcile worker) — it is
// a no-op when the configured model already matches the index marker, so calling
// it speculatively is cheap and safe.
//
// emb must be the tenant's configured embedder (embedder.NewFromProvider). sc
// must be the tenant's own per-tenant StateClient.
func RunForTenant(ctx context.Context, sc *state.StateClient, emb embedder.Embedder, opts ...Option) (Result, error) {
	index, marker := NewStateStore(sc)
	return NewJob(index, marker, emb, opts...).Run(ctx)
}

// RecreateIndex drops the vector index (preserving documents) and creates a
// fresh one sized to dim. FT.DROPINDEX leaves the gibson:vector:* JSON documents
// in place; they are re-indexed as the job re-stores them at the new dimension.
func (a *stateAdapter) RecreateIndex(ctx context.Context, dim int) error {
	def := state.VectorIndex(dim)
	if err := a.manager.DropIndex(ctx, def.Name); err != nil {
		return fmt.Errorf("drop vector index: %w", err)
	}
	if err := a.manager.EnsureIndex(ctx, def); err != nil {
		return fmt.Errorf("create vector index at dim %d: %w", dim, err)
	}
	return nil
}

// ListRecords enumerates every gibson:vector:* document via SCAN and decodes
// each into a VectorRecord. The decoded Content is the re-embeddable source
// text; the decoded Embedding's length lets the job skip records already at the
// target dimension on a resumed run.
func (a *stateAdapter) ListRecords(ctx context.Context) ([]vector.VectorRecord, error) {
	rdb := a.sc.Client()
	var (
		cursor  uint64
		records []vector.VectorRecord
	)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		keys, next, err := rdb.Scan(ctx, cursor, "gibson:vector:*", 100).Result()
		if err != nil {
			return nil, fmt.Errorf("scan vector keys: %w", err)
		}
		for _, key := range keys {
			// Skip the marker doc: it shares the gibson:vector: namespace but is
			// not a vector record.
			if key == markerKey {
				continue
			}
			var rec vector.VectorRecord
			if err := a.sc.JSONGet(ctx, key, "$", &rec); err != nil {
				if err == state.ErrNotFound {
					continue
				}
				return nil, fmt.Errorf("read vector document %q: %w", key, err)
			}
			rec.ID = strip(key)
			records = append(records, rec)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return records, nil
}

// StoreRecord re-stores a record at its canonical key, re-indexing it against
// the live index. It mirrors RedisVectorStore.Store's key convention so the
// re-embedded document lands exactly where the original was.
func (a *stateAdapter) StoreRecord(ctx context.Context, rec vector.VectorRecord) error {
	if err := rec.Validate(); err != nil {
		return types.WrapError(ErrCodeReembedFailed, "invalid re-embedded record", err)
	}
	key := fmt.Sprintf("gibson:vector:%s", rec.ID)
	return a.sc.JSONSet(ctx, key, "$", rec)
}

// ReadMarker / WriteMarker delegate to the package-level marker helpers, which
// operate on the same StateClient keyspace.
func (a *stateAdapter) ReadMarker(ctx context.Context) (*IndexMarker, error) {
	return readMarker(ctx, a.sc)
}

func (a *stateAdapter) WriteMarker(ctx context.Context, m IndexMarker) error {
	return writeMarker(ctx, a.sc, m)
}

// strip removes the "gibson:vector:" key prefix to recover the record ID.
func strip(key string) string {
	const prefix = "gibson:vector:"
	if len(key) > len(prefix) && key[:len(prefix)] == prefix {
		return key[len(prefix):]
	}
	return key
}
