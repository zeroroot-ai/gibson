// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package embedder

import (
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

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

// assertDimension fails closed when the gateway returns a vector whose length
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
