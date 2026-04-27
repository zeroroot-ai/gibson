package vectordb_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/datapool/vectordb"
)

// TestQdrantDriver_InvalidConfig verifies the driver rejects missing addr.
func TestQdrantDriver_InvalidConfig(t *testing.T) {
	_, err := vectordb.NewQdrantDriver(vectordb.QdrantConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "addr is required")
}

// TestQdrantDriver_For_EmptyCollection verifies that For rejects an empty collection name.
func TestQdrantDriver_For_EmptyCollection(t *testing.T) {
	d, err := vectordb.NewQdrantDriver(vectordb.QdrantConfig{Addr: "localhost:6334"})
	require.NoError(t, err)
	defer d.Close()

	_, err = d.For(context.Background(), "")
	require.Error(t, err)
}

// TestQdrantDriver_For_ReturnsClient verifies that For returns a non-nil client for a valid collection.
func TestQdrantDriver_For_ReturnsClient(t *testing.T) {
	// TODO(database-per-tenant-data-plane B2): skip when real Qdrant not
	// available; the stub always returns a client.
	d, err := vectordb.NewQdrantDriver(vectordb.QdrantConfig{Addr: "localhost:6334"})
	require.NoError(t, err)
	defer d.Close()

	client, err := d.For(context.Background(), "tenant_acme")
	require.NoError(t, err)
	assert.NotNil(t, client)
}

// TestQdrantClient_StubErrors verifies that stub methods return "not implemented" errors.
// These tests will pass until the real implementation is wired in.
func TestQdrantClient_StubErrors(t *testing.T) {
	// Skip if a real Qdrant is available (integration mode would replace stubs).
	d, err := vectordb.NewQdrantDriver(vectordb.QdrantConfig{Addr: "localhost:6334"})
	require.NoError(t, err)
	defer d.Close()

	client, err := d.For(context.Background(), "tenant_test")
	require.NoError(t, err)

	t.Run("Upsert stub returns error for non-empty points", func(t *testing.T) {
		err := client.Upsert(context.Background(), []vectordb.Point{
			{ID: "1", Vector: []float32{0.1, 0.2}, Payload: nil},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("Upsert no-ops for empty slice", func(t *testing.T) {
		err := client.Upsert(context.Background(), nil)
		require.NoError(t, err)
	})

	t.Run("Search stub returns error", func(t *testing.T) {
		_, err := client.Search(context.Background(), []float32{0.1, 0.2}, 5, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})

	t.Run("Delete stub returns error", func(t *testing.T) {
		err := client.Delete(context.Background(), []string{"1", "2"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not yet implemented")
	})
}
