package vector

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
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

func TestNewVectorStore_Qdrant(t *testing.T) {
	t.Skip("Skipping Qdrant connection test - requires running Qdrant server")

	// This test verifies that the factory creates a Qdrant store with correct structure
	// It will fail to connect (no actual Qdrant server), but that's expected in unit tests
	cfg := VectorStoreConfig{
		Backend:    "qdrant",
		Dimensions: 384,
	}

	store, err := NewVectorStore(cfg)

	// We expect an error because there's no real Qdrant server running
	// The error could be either connection failure or collection creation failure
	if err != nil {
		// Verify it's either a connection error or store failed error, not a config error
		var gibsonErr *types.GibsonError
		require.ErrorAs(t, err, &gibsonErr)
		// Accept either connection error or store operation error
		assert.True(t,
			gibsonErr.Code == ErrCodeVectorStoreUnavailable || gibsonErr.Code == ErrCodeVectorStoreFailed,
			"expected connection or store error, not config error, got: %s", gibsonErr.Code)
	} else {
		// If somehow a connection succeeds (e.g., Qdrant running locally), verify the type
		require.NotNil(t, store)
		defer store.Close()
		_, ok := store.(*QdrantVectorStore)
		assert.True(t, ok, "expected QdrantVectorStore type")
	}
}

func TestNewVectorStore_Milvus(t *testing.T) {
	t.Skip("Skipping Milvus connection test - requires running Milvus server")

	// This test verifies that the factory creates a Milvus store with correct structure
	// It will fail to connect (no actual Milvus server), but that's expected in unit tests
	cfg := VectorStoreConfig{
		Backend:    "milvus",
		Dimensions: 384,
	}

	store, err := NewVectorStore(cfg)

	// We expect an error because there's no real Milvus server running
	// The error could be either connection failure or collection creation failure
	if err != nil {
		// Verify it's either a connection error or store failed error, not a config error
		var gibsonErr *types.GibsonError
		require.ErrorAs(t, err, &gibsonErr)
		// Accept either connection error or store operation error
		assert.True(t,
			gibsonErr.Code == ErrCodeVectorStoreUnavailable || gibsonErr.Code == ErrCodeVectorStoreFailed,
			"expected connection or store error, not config error, got: %s", gibsonErr.Code)
	} else {
		// If somehow a connection succeeds (e.g., Milvus running locally), verify the type
		require.NotNil(t, store)
		defer store.Close()
		_, ok := store.(*MilvusVectorStore)
		assert.True(t, ok, "expected MilvusVectorStore type")
	}
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
	assert.Contains(t, err.Error(), "embedded, redis, qdrant, milvus")
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

func TestNewVectorStore_QdrantWithInvalidDimensions(t *testing.T) {
	cfg := VectorStoreConfig{
		Backend:    "qdrant",
		Dimensions: 0,
	}

	store, err := NewVectorStore(cfg)
	require.Error(t, err)
	assert.Nil(t, store)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeInvalidConfig, gibsonErr.Code)
	assert.Contains(t, err.Error(), "dimensions must be positive")
}

func TestNewVectorStore_MilvusWithInvalidDimensions(t *testing.T) {
	cfg := VectorStoreConfig{
		Backend:    "milvus",
		Dimensions: -10,
	}

	store, err := NewVectorStore(cfg)
	require.Error(t, err)
	assert.Nil(t, store)

	var gibsonErr *types.GibsonError
	require.ErrorAs(t, err, &gibsonErr)
	assert.Equal(t, ErrCodeInvalidConfig, gibsonErr.Code)
	assert.Contains(t, err.Error(), "dimensions must be positive")
}
