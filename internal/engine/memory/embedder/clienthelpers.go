package embedder

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// maxResponseBytes caps how much of an upstream response body we read into
// memory — both successful embedding payloads (bounded by model dimension × batch)
// and error bodies. 32 MiB comfortably holds a large batch of 3072-dim vectors.
const maxResponseBytes = 32 << 20

// resolveAndRegisterDimension looks up the output dimension for a model and
// records it in the model→dimension source of truth so the vector index sized
// from DimensionForModel matches what this embedder emits (#807). An unknown
// model fails closed: a wrong RediSearch VECTOR dimension silently fails
// indexing of the whole document, so we never guess. Operators serving a model
// outside the built-in table must RegisterModelDimension at startup first.
func resolveAndRegisterDimension(provider, model string) (int, error) {
	dim, ok := DimensionForModel(model)
	if !ok {
		return 0, types.NewError(ErrCodeInvalidConfig, fmt.Sprintf(
			"%s: unknown embedding model %q — no vector dimension is registered; register it via RegisterModelDimension before use",
			provider, model))
	}
	// Idempotent: re-registers the same mapping. RegisterModelDimension panics
	// only on a conflicting dimension, surfacing a contradiction at startup.
	RegisterModelDimension(model, dim)
	return dim, nil
}

// assertDimension fails closed when an upstream returns a vector whose length
// does not match the dimension the index was sized for. Storing a mismatched
// vector would silently fail RediSearch indexing of the whole document.
func assertDimension(provider string, want, got int) error {
	if want != got {
		return types.NewError(ErrCodeEmbeddingFailed, fmt.Sprintf(
			"%s: embedding dimension mismatch: index expects %d, provider returned %d",
			provider, want, got))
	}
	return nil
}

// firstNonEmptyStr returns the first non-empty string, or "" if all are empty.
func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// snippet returns a short, log-safe prefix of an upstream error body.
func snippet(b []byte) string {
	const max = 256
	s := string(b)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
