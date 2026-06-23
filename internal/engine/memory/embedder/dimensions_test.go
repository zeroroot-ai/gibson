package embedder

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDimensionForModel_KnownModels(t *testing.T) {
	cases := []struct {
		model string
		dim   int
	}{
		{"all-MiniLM-L6-v2", 384},
		{"all-minilm-l6-v2", 384},     // case-insensitive
		{"  all-MiniLM-L6-v2  ", 384}, // trimmed
		{"text-embedding-3-small", 1536},
		{"text-embedding-3-large", 3072},
		{"amazon.titan-embed-text-v2:0", 1024},
		{"cohere.embed-english-v3", 1024},
		{"voyage-3", 1024},
	}
	for _, c := range cases {
		t.Run(c.model, func(t *testing.T) {
			dim, ok := DimensionForModel(c.model)
			require.True(t, ok, "model %q should be known", c.model)
			assert.Equal(t, c.dim, dim)
		})
	}
}

func TestDimensionForModel_UnknownFailsClosed(t *testing.T) {
	// An unknown model must return (0, false) so callers fail closed rather than
	// guess a dimension and silently corrupt the vector index.
	dim, ok := DimensionForModel("definitely-not-a-real-model")
	assert.False(t, ok)
	assert.Equal(t, 0, dim)
}

func TestDefaultEmbeddingDimensionIsMiniLM384(t *testing.T) {
	// The bundled/default path must still resolve to 384 — no behaviour change,
	// just no longer hardcoded.
	assert.Equal(t, 384, DefaultEmbeddingDimension)

	dim, ok := DimensionForModel(DefaultEmbeddingModel)
	require.True(t, ok)
	assert.Equal(t, 384, dim)
}

func TestRegisterModelDimension_Idempotent(t *testing.T) {
	RegisterModelDimension("test-embed-model-xyz", 256)
	dim, ok := DimensionForModel("test-embed-model-xyz")
	require.True(t, ok)
	assert.Equal(t, 256, dim)

	// Re-registering the same dimension is a no-op, not a panic.
	assert.NotPanics(t, func() { RegisterModelDimension("test-embed-model-xyz", 256) })

	// Registering a conflicting dimension panics to surface the contradiction.
	assert.Panics(t, func() { RegisterModelDimension("test-embed-model-xyz", 512) })
}

func TestMockEmbedder_ModelDerivesDimension(t *testing.T) {
	// End-to-end: the mock's reported model must derive its reported dimension,
	// proving the model→dimension derivation holds for the default embedder.
	m := NewMockEmbedder()
	assert.Equal(t, 384, m.Dimensions())

	dim, ok := DimensionForModel(m.Model())
	require.True(t, ok, "mock model %q must be in the dimension table", m.Model())
	assert.Equal(t, m.Dimensions(), dim)
}
