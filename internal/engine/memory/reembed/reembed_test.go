package reembed

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/engine/memory/vector"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// fakeEmbedder is a deterministic in-memory embedder whose Model/Dimensions are
// fully controllable, and whose embeddings are sized to its dimension. It never
// hits a provider API.
type fakeEmbedder struct {
	model    string
	dim      int
	batchErr error // if set, EmbedBatch returns it
	calls    int
}

func (f *fakeEmbedder) Embed(ctx context.Context, text string) ([]float64, error) {
	return make([]float64, f.dim), nil
}

func (f *fakeEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float64, error) {
	f.calls++
	if f.batchErr != nil {
		return nil, f.batchErr
	}
	out := make([][]float64, len(texts))
	for i := range texts {
		v := make([]float64, f.dim)
		// Make the first element non-zero and content-derived so a test can
		// distinguish re-embedded vectors if needed.
		if f.dim > 0 && len(texts[i]) > 0 {
			v[0] = float64(len(texts[i]))
		}
		out[i] = v
	}
	return out, nil
}

func (f *fakeEmbedder) Dimensions() int                           { return f.dim }
func (f *fakeEmbedder) Model() string                             { return f.model }
func (f *fakeEmbedder) Health(context.Context) types.HealthStatus { return types.HealthStatus{} }

// fakeStore implements both IndexStore and MarkerStore against in-memory maps,
// so the recreate+re-embed flow is exercised without Redis. It records the
// dimension the index was last created at and the order of operations.
type fakeStore struct {
	marker *IndexMarker

	indexDim     int // dim the index was last (re)created at; 0 = never
	recreateN    int // number of RecreateIndex calls
	recreateErr  error
	listErr      error
	storeErrOnID map[string]error // per-ID StoreRecord error injection

	records map[string]vector.VectorRecord // by ID; embeddings are the stored ones
	ops     []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		records:      map[string]vector.VectorRecord{},
		storeErrOnID: map[string]error{},
	}
}

func (s *fakeStore) seed(rec vector.VectorRecord) {
	s.records[rec.ID] = rec
}

func (s *fakeStore) RecreateIndex(ctx context.Context, dim int) error {
	s.ops = append(s.ops, "recreate")
	if s.recreateErr != nil {
		return s.recreateErr
	}
	s.recreateN++
	s.indexDim = dim
	return nil
}

func (s *fakeStore) ListRecords(ctx context.Context) ([]vector.VectorRecord, error) {
	s.ops = append(s.ops, "list")
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]vector.VectorRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	// Deterministic order so per-record batch=1 tests are reproducible.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *fakeStore) StoreRecord(ctx context.Context, rec vector.VectorRecord) error {
	s.ops = append(s.ops, "store:"+rec.ID)
	if err := s.storeErrOnID[rec.ID]; err != nil {
		return err
	}
	s.records[rec.ID] = rec
	return nil
}

func (s *fakeStore) ReadMarker(ctx context.Context) (*IndexMarker, error) {
	if s.marker == nil {
		return nil, nil
	}
	cp := *s.marker
	return &cp, nil
}

func (s *fakeStore) WriteMarker(ctx context.Context, m IndexMarker) error {
	s.ops = append(s.ops, "write-marker")
	cp := m
	s.marker = &cp
	return nil
}

func rec(id, content string, dim int) vector.VectorRecord {
	return vector.VectorRecord{ID: id, Content: content, Embedding: make([]float64, dim)}
}

// --- change detection ---

func TestRun_NoDrift_IsNoOp(t *testing.T) {
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "text-embedding-3-small", Dim: 1536}
	store.seed(rec("a", "hello", 1536))

	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	job := NewJob(store, store, emb)

	res, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Changed {
		t.Fatalf("expected no-op, got Changed=true")
	}
	if store.recreateN != 0 {
		t.Fatalf("expected no index recreation, got %d", store.recreateN)
	}
	if emb.calls != 0 {
		t.Fatalf("expected no embed calls, got %d", emb.calls)
	}
}

func TestRun_NoDrift_CaseInsensitiveModel(t *testing.T) {
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "Text-Embedding-3-Small", Dim: 1536}
	emb := &fakeEmbedder{model: "text-embedding-3-small ", dim: 1536}

	res, err := NewJob(store, store, emb).Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Changed {
		t.Fatalf("case/whitespace-only model difference must not count as drift")
	}
}

func TestRun_DimensionChange_TriggersRecreateAndReembed(t *testing.T) {
	store := newFakeStore()
	// Index was built at 384 (old model); two docs stored at 384.
	store.marker = &IndexMarker{Model: "all-MiniLM-L6-v2", Dim: 384}
	store.seed(rec("a", "alpha", 384))
	store.seed(rec("b", "bravo", 384))

	// New model emits 1536-dim vectors.
	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	job := NewJob(store, store, emb)

	res, err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("expected Changed=true on dimension change")
	}
	if store.indexDim != 1536 {
		t.Fatalf("expected index recreated at dim 1536, got %d", store.indexDim)
	}
	if res.Reembedded != 2 {
		t.Fatalf("expected 2 docs re-embedded, got %d", res.Reembedded)
	}
	for id, r := range store.records {
		if len(r.Embedding) != 1536 {
			t.Fatalf("doc %q not re-embedded to 1536: got %d", id, len(r.Embedding))
		}
	}
	if store.marker == nil || store.marker.Dim != 1536 || store.marker.Model != "text-embedding-3-small" {
		t.Fatalf("marker not committed to new model/dim: %+v", store.marker)
	}
}

func TestRun_SameDimDifferentModel_TriggersReembed(t *testing.T) {
	// Both models are 1024-dim, but the model name differs: a model change with
	// the same dimension still requires re-embedding (different vector space).
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "cohere.embed-english-v3", Dim: 1024}
	store.seed(rec("a", "alpha", 1024))

	emb := &fakeEmbedder{model: "voyage-3", dim: 1024}
	res, err := NewJob(store, store, emb).Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("same-dim model change must trigger re-embed")
	}
	if res.Reembedded != 1 {
		t.Fatalf("expected 1 re-embedded, got %d", res.Reembedded)
	}
}

func TestRun_NoMarker_BuildsAtTargetModel(t *testing.T) {
	store := newFakeStore() // no marker
	store.seed(rec("a", "alpha", 384))

	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	res, err := NewJob(store, store, emb).Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("missing marker must be treated as drift")
	}
	if store.indexDim != 1536 || store.marker == nil || store.marker.Dim != 1536 {
		t.Fatalf("expected recreate+marker at 1536, got indexDim=%d marker=%+v", store.indexDim, store.marker)
	}
}

func TestRun_UnknownModelDimension_FailsClosed(t *testing.T) {
	store := newFakeStore()
	emb := &fakeEmbedder{model: "mystery", dim: 0} // non-positive dim
	_, err := NewJob(store, store, emb).Run(context.Background())
	if err == nil {
		t.Fatalf("expected fail-closed error for non-positive dimension")
	}
	var ge *types.GibsonError
	if !errors.As(err, &ge) || ge.Code != ErrCodeUnknownModel {
		t.Fatalf("expected ErrCodeUnknownModel, got %v", err)
	}
	if store.recreateN != 0 {
		t.Fatalf("must not recreate index when model dimension is unknown")
	}
}

// --- idempotency / resumability ---

func TestRun_Idempotent_SecondRunIsNoOp(t *testing.T) {
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "all-MiniLM-L6-v2", Dim: 384}
	store.seed(rec("a", "alpha", 384))
	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}

	first, err := NewJob(store, store, emb).Run(context.Background())
	if err != nil || !first.Changed {
		t.Fatalf("first run should change: res=%+v err=%v", first, err)
	}

	emb2 := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	second, err := NewJob(store, store, emb2).Run(context.Background())
	if err != nil {
		t.Fatalf("second run error: %v", err)
	}
	if second.Changed {
		t.Fatalf("second run must be a no-op after marker committed")
	}
	if emb2.calls != 0 {
		t.Fatalf("second run must not re-embed, got %d calls", emb2.calls)
	}
}

func TestRun_ResumesAfterPartialFailure(t *testing.T) {
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "all-MiniLM-L6-v2", Dim: 384}
	store.seed(rec("a", "alpha", 384))
	store.seed(rec("b", "bravo", 384))
	store.seed(rec("c", "charlie", 384))

	// Fail when storing "b" so the first pass converts only the doc(s) before it.
	store.storeErrOnID["b"] = errors.New("redis blip")

	// batch size 1 makes per-record ordering deterministic and the failure local.
	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	_, err := NewJob(store, store, emb, WithBatchSize(1)).Run(context.Background())
	if err == nil {
		t.Fatalf("expected error from injected store failure")
	}
	// Marker MUST remain stale so the next run re-detects drift.
	if store.marker == nil || store.marker.Dim != 384 {
		t.Fatalf("marker must not be committed on partial failure, got %+v", store.marker)
	}

	// Clear the failure and resume. Re-run should only re-embed docs still at the
	// old dimension (those not converted in pass 1), then commit the marker.
	store.storeErrOnID = map[string]error{}
	emb2 := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	res, err := NewJob(store, store, emb2, WithBatchSize(1)).Run(context.Background())
	if err != nil {
		t.Fatalf("resume run error: %v", err)
	}
	if !res.Changed {
		t.Fatalf("resume run should still see drift (marker stale)")
	}
	// Every doc must now be at 1536, and the marker committed.
	for id, r := range store.records {
		if len(r.Embedding) != 1536 {
			t.Fatalf("doc %q not at target dim after resume: %d", id, len(r.Embedding))
		}
	}
	if store.marker == nil || store.marker.Dim != 1536 {
		t.Fatalf("marker must be committed after successful resume, got %+v", store.marker)
	}
	// The resume run must have re-embedded every document to completion (the
	// marker is the only completion gate; redoing work is idempotent and safe).
	if res.Reembedded != 3 {
		t.Fatalf("resume run must re-embed all 3 docs, got %d", res.Reembedded)
	}
}

func TestRun_RecreateFailure_DoesNotCommitMarker(t *testing.T) {
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "all-MiniLM-L6-v2", Dim: 384}
	store.seed(rec("a", "alpha", 384))
	store.recreateErr = errors.New("FT.CREATE failed")

	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536}
	_, err := NewJob(store, store, emb).Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when index recreation fails")
	}
	if store.marker.Dim != 384 {
		t.Fatalf("marker must stay stale on recreate failure, got %+v", store.marker)
	}
}

func TestRun_EmbedBatchFailure_Propagates(t *testing.T) {
	store := newFakeStore()
	store.marker = &IndexMarker{Model: "all-MiniLM-L6-v2", Dim: 384}
	store.seed(rec("a", "alpha", 384))

	emb := &fakeEmbedder{model: "text-embedding-3-small", dim: 1536, batchErr: errors.New("provider 500")}
	_, err := NewJob(store, store, emb).Run(context.Background())
	if err == nil {
		t.Fatalf("expected error when EmbedBatch fails")
	}
	var ge *types.GibsonError
	if !errors.As(err, &ge) || ge.Code != ErrCodeReembedFailed {
		t.Fatalf("expected ErrCodeReembedFailed, got %v", err)
	}
	if store.marker.Dim != 384 {
		t.Fatalf("marker must stay stale when re-embed fails")
	}
}

// --- helper unit ---

func TestDrifted(t *testing.T) {
	cases := []struct {
		name   string
		marker *IndexMarker
		model  string
		dim    int
		want   bool
	}{
		{"nil marker drifts", nil, "m", 10, true},
		{"same model+dim no drift", &IndexMarker{Model: "m", Dim: 10}, "m", 10, false},
		{"dim change drifts", &IndexMarker{Model: "m", Dim: 10}, "m", 20, true},
		{"model change drifts", &IndexMarker{Model: "m", Dim: 10}, "n", 10, true},
		{"case-only no drift", &IndexMarker{Model: "M", Dim: 10}, "m", 10, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := drifted(c.marker, c.model, c.dim); got != c.want {
				t.Fatalf("drifted(%+v, %q, %d) = %v, want %v", c.marker, c.model, c.dim, got, c.want)
			}
		})
	}
}
