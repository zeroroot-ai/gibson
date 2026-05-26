package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestNewVectorStore_Embedded(t *testing.T) {
	cfg := VectorStoreConfig{
		Backend:    "embedded",
		Dimensions: 384,
	}

	store, err := NewVectorStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	// Verify it's an embedded store
	_, ok := store.(*EmbeddedVectorStore)
	assert.True(t, ok, "expected EmbeddedVectorStore type")
}

func TestNewVectorStore_EmbeddedDefault(t *testing.T) {
	// Empty backend should default to embedded
	cfg := VectorStoreConfig{
		Backend:    "",
		Dimensions: 384,
	}

	store, err := NewVectorStore(cfg)
	require.NoError(t, err)
	require.NotNil(t, store)
	defer store.Close()

	// Verify it's an embedded store
	_, ok := store.(*EmbeddedVectorStore)
	assert.True(t, ok, "expected EmbeddedVectorStore type when backend is empty")
}

func TestNewVectorStore_InvalidBackend(t *testing.T) {
	cfg := VectorStoreConfig{
		Backend:    "unknown",
		Dimensions: 384,
	}

	store, err := NewVectorStore(cfg)
	require.Error(t, err)
	assert.Nil(t, store)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeInvalidConfig, gibsonErr.Code)
	assert.Contains(t, err.Error(), "unknown backend 'unknown'")
	assert.Contains(t, err.Error(), "embedded, redis")
}

func TestNewVectorStore_InvalidDimensions(t *testing.T) {
	tests := []struct {
		name       string
		dimensions int
	}{
		{
			name:       "zero dimensions",
			dimensions: 0,
		},
		{
			name:       "negative dimensions",
			dimensions: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := VectorStoreConfig{
				Backend:    "embedded",
				Dimensions: tt.dimensions,
			}

			store, err := NewVectorStore(cfg)
			require.Error(t, err)
			assert.Nil(t, store)

			var gibsonErr *types.GibsonError
			require.ErrorAs(t, err, &gibsonErr)
			assert.Equal(t, ErrCodeInvalidConfig, gibsonErr.Code)
			assert.Contains(t, err.Error(), "dimensions must be positive")
		})
	}
}
