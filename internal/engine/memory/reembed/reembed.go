package reembed

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/engine/memory/vector"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Error codes for the re-embed job. Distinct from the vector/embedder codes so a
// re-embed failure is attributable to this orchestration layer.
const (
	// ErrCodeReembedFailed is a generic re-embed failure (drift detection,
	// index recreation, or re-embedding could not complete).
	ErrCodeReembedFailed types.ErrorCode = "REEMBED_FAILED"

	// ErrCodeUnknownModel is returned when the tenant's configured embedding
	// model has no registered dimension. The job fails closed rather than guess
	// a dimension, because a wrong VECTOR dimension silently fails indexing of
	// the whole document.
	ErrCodeUnknownModel types.ErrorCode = "REEMBED_UNKNOWN_MODEL"
)

// IndexStore is the per-tenant index surface the job drives. It is satisfied by
// stateAdapter over a *state.StateClient and stubbed in tests, so the job's
// recreate-then-re-embed logic is exercisable without a live Redis.
//
// Implementations operate on ONE tenant's keyspace (gibson:vector:* and the
// gibson:idx:vectors index within that StateClient's database). The job never
// reaches across tenants.
type IndexStore interface {
	// RecreateIndex drops the existing vector index (if any) and creates a fresh
	// one sized to dim. Documents are NOT deleted by the drop — they are
	// re-indexed against the new index as they are re-stored. Idempotent: a
	// second call at the same dim is safe.
	RecreateIndex(ctx context.Context, dim int) error

	// ListRecords returns every vector document in the tenant's keyspace,
	// including its stored Content (the re-embeddable source text) and the
	// length of its currently-stored embedding (so the job can skip records
	// already at the target dimension on a resumed run).
	ListRecords(ctx context.Context) ([]vector.VectorRecord, error)

	// StoreRecord writes a record back (JSON.SET), re-indexing it against the
	// live index. The record carries its freshly-computed embedding.
	StoreRecord(ctx context.Context, rec vector.VectorRecord) error
}

// MarkerStore reads and writes the per-tenant "index was built with model X /
// dim N" marker. Split from IndexStore so tests can assert the commit-point
// semantics (marker written only after a successful pass) independently.
type MarkerStore interface {
	ReadMarker(ctx context.Context) (*IndexMarker, error)
	WriteMarker(ctx context.Context, m IndexMarker) error
}

// Job re-embeds a single tenant's stored content when its embedding model
// changes. It is constructed per tenant (the IndexStore/MarkerStore are bound to
// that tenant's StateClient) and is safe to run repeatedly: Run is idempotent
// and resumable.
type Job struct {
	index  IndexStore
	marker MarkerStore
	emb    embedder.Embedder
	logger *slog.Logger
	tenant string
	batch  int
}

// Option configures a Job.
type Option func(*Job)

// WithLogger sets the structured logger used for progress and fail-loud
// reporting. A nil logger falls back to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(j *Job) {
		if l != nil {
			j.logger = l
		}
	}
}

// WithTenant tags log lines with the tenant identifier. Purely observational;
// isolation is enforced by the bound IndexStore/MarkerStore, not this string.
func WithTenant(tenant string) Option {
	return func(j *Job) { j.tenant = tenant }
}

// WithBatchSize sets how many records are re-embedded per EmbedBatch call.
// Values <= 0 keep the default.
func WithBatchSize(n int) Option {
	return func(j *Job) {
		if n > 0 {
			j.batch = n
		}
	}
}

const defaultBatchSize = 64

// NewJob builds a re-embed job for one tenant. emb is the tenant's CURRENT
// embedder (built via embedder.NewFromProvider): its Model()/Dimensions() are
// the target the index is brought to.
func NewJob(index IndexStore, marker MarkerStore, emb embedder.Embedder, opts ...Option) *Job {
	j := &Job{
		index:  index,
		marker: marker,
		emb:    emb,
		logger: slog.Default(),
		batch:  defaultBatchSize,
	}
	for _, o := range opts {
		o(j)
	}
	return j
}

// Result summarises a Run.
type Result struct {
	// Changed is true when drift was detected and a recreate+re-embed pass ran.
	// False means the configured model already matched the marker — a no-op.
	Changed bool

	// Model / Dim are the target the index is now consistent at.
	Model string
	Dim   int

	// Reembedded is the number of documents whose embeddings were recomputed and
	// re-stored. On a successful pass this equals Total.
	Reembedded int

	// Total is the number of documents found in the tenant's keyspace.
	Total int
}

// Run detects whether the tenant's configured embedding model differs from the
// model its vector index was built with and, if so, recreates the index at the
// new dimension and re-embeds every stored document from its own Content.
//
// The pass is:
//
//  1. Resolve the target model+dim from the embedder. Unknown dimension → fail
//     closed (ErrCodeUnknownModel).
//  2. Read the persisted marker. If it already matches the target model+dim,
//     return a no-op Result (Changed=false). This is the common steady-state
//     path and the source of idempotency: once a pass commits the marker, a
//     re-run is a cheap no-op.
//  3. Recreate the index at the target dim (drop + create). Idempotent.
//  4. List all documents and re-embed any whose stored embedding length != the
//     target dim (a fully-completed prior pass leaves nothing to do; a partially
//     completed pass resumes from where it stopped). Re-store each, which
//     re-indexes it.
//  5. Only after every document is at the target dim, commit the marker. A crash
//     before this leaves the marker stale, so the next Run re-detects drift and
//     resumes — the tenant is never silently left half-reindexed.
func (j *Job) Run(ctx context.Context) (Result, error) {
	targetModel := j.emb.Model()
	targetDim := j.emb.Dimensions()
	if targetDim <= 0 {
		return Result{}, types.NewError(ErrCodeUnknownModel,
			fmt.Sprintf("embedder for model %q reports non-positive dimension %d", targetModel, targetDim))
	}

	log := j.logger.With(slog.String("tenant", j.tenant), slog.String("target_model", targetModel), slog.Int("target_dim", targetDim))

	marker, err := j.marker.ReadMarker(ctx)
	if err != nil {
		return Result{}, types.WrapError(ErrCodeReembedFailed, "failed to read embedding index marker", err)
	}

	if !drifted(marker, targetModel, targetDim) {
		log.Debug("re-embed: no embedding model change detected, nothing to do")
		return Result{Changed: false, Model: targetModel, Dim: targetDim}, nil
	}

	if marker == nil {
		log.Info("re-embed: no recorded build model for vector index; building at target model")
	} else {
		log.Info("re-embed: embedding model change detected",
			slog.String("old_model", marker.Model), slog.Int("old_dim", marker.Dim))
	}

	// Recreate the index at the new dimension before re-embedding. An index at
	// the old dim would silently reject the new vectors.
	if err := j.index.RecreateIndex(ctx, targetDim); err != nil {
		return Result{}, types.WrapError(ErrCodeReembedFailed, "failed to recreate vector index at new dimension", err)
	}
	log.Info("re-embed: recreated vector index at target dimension")

	res := Result{Changed: true, Model: targetModel, Dim: targetDim}

	records, err := j.index.ListRecords(ctx)
	if err != nil {
		return Result{}, types.WrapError(ErrCodeReembedFailed, "failed to list vector documents for re-embedding", err)
	}
	res.Total = len(records)

	// Re-embed every document from its own stored Content. We deliberately do
	// NOT try to skip documents that "look" already-converted: the only reliable
	// completion signal is the committed marker, not a per-document heuristic. A
	// stored embedding's LENGTH cannot distinguish "already re-embedded with the
	// new model" from "old vector that happens to share the new dimension" — a
	// same-dimension model change (e.g. cohere→voyage, both 1024) produces
	// stale-but-correctly-sized vectors that must still be replaced. Re-embedding
	// from Content is naturally idempotent: recomputing an already-current vector
	// rewrites an identical value. Resumability therefore lives entirely in the
	// marker — a failed Run leaves it stale and the next Run redoes the work.
	if err := j.reembedRecords(ctx, log, records, &res); err != nil {
		// Fail loud: do NOT commit the marker. The next Run re-detects drift
		// (marker still stale) and re-runs to completion.
		return res, err
	}

	if err := j.marker.WriteMarker(ctx, IndexMarker{Model: targetModel, Dim: targetDim}); err != nil {
		return res, types.WrapError(ErrCodeReembedFailed, "re-embedded all documents but failed to commit index marker", err)
	}

	log.Info("re-embed: completed", slog.Int("reembedded", res.Reembedded), slog.Int("total", res.Total))
	return res, nil
}

// reembedRecords re-embeds the given records in batches and re-stores each. On
// any error it returns immediately; the marker is not committed by the caller,
// so a resumed Run re-processes from the start (re-embedding is idempotent).
// res.Reembedded is advanced per successfully re-stored record.
func (j *Job) reembedRecords(ctx context.Context, log *slog.Logger, pending []vector.VectorRecord, res *Result) error {
	for start := 0; start < len(pending); start += j.batch {
		if err := ctx.Err(); err != nil {
			return types.WrapError(ErrCodeReembedFailed, "re-embed canceled", err)
		}

		end := start + j.batch
		if end > len(pending) {
			end = len(pending)
		}
		chunk := pending[start:end]

		texts := make([]string, len(chunk))
		for i, rec := range chunk {
			texts[i] = rec.Content
		}

		vectors, err := j.emb.EmbedBatch(ctx, texts)
		if err != nil {
			return types.WrapError(ErrCodeReembedFailed, "failed to re-embed document batch", err)
		}
		if len(vectors) != len(chunk) {
			return types.NewError(ErrCodeReembedFailed,
				fmt.Sprintf("embedder returned %d vectors for %d documents", len(vectors), len(chunk)))
		}

		for i, rec := range chunk {
			rec.Embedding = vectors[i]
			if err := j.index.StoreRecord(ctx, rec); err != nil {
				return types.WrapError(ErrCodeReembedFailed,
					fmt.Sprintf("failed to re-store re-embedded document %q", rec.ID), err)
			}
			res.Reembedded++
		}

		log.Info("re-embed: progress", slog.Int("done", res.Reembedded), slog.Int("total", len(pending)))
	}
	return nil
}

// drifted reports whether the configured target model/dim differs from what the
// index was built with. A nil marker (no recorded build model) counts as drift
// so an unmarked index is brought under management on first Run. Model
// comparison is case-insensitive and whitespace-insensitive to mirror the
// embedder package's normalisation; a dimension difference alone is sufficient
// to force a recreate.
func drifted(marker *IndexMarker, targetModel string, targetDim int) bool {
	if marker == nil {
		return true
	}
	if marker.Dim != targetDim {
		return true
	}
	return !embedder.SameModel(marker.Model, targetModel)
}
