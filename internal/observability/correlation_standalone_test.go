//go:build standalone
// +build standalone

package observability_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/observability"
)

func TestCorrelationIDStandalone(t *testing.T) {
	t.Run("generates valid UUID", func(t *testing.T) {
		id := observability.GenerateCorrelationID()

		assert.NotEmpty(t, id)
		assert.False(t, id.IsZero())

		// Verify it's a valid UUID
		_, err := uuid.Parse(id.String())
		assert.NoError(t, err)
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		id1 := observability.GenerateCorrelationID()
		id2 := observability.GenerateCorrelationID()

		assert.NotEqual(t, id1, id2)
	})

	t.Run("validates correctly", func(t *testing.T) {
		validID := observability.GenerateCorrelationID()
		err := validID.Validate()
		assert.NoError(t, err)

		emptyID := observability.CorrelationID("")
		err = emptyID.Validate()
		assert.Error(t, err)

		invalidID := observability.CorrelationID("not-a-uuid")
		err = invalidID.Validate()
		assert.Error(t, err)
	})
}

func TestInMemoryCorrelationStoreStandalone(t *testing.T) {
	store := observability.NewInMemoryCorrelationStore()
	ctx := context.Background()

	t.Run("stores and retrieves correlations", func(t *testing.T) {
		nodeID := "node-1"
		spanID := "span-1"

		err := store.StoreCorrelation(ctx, nodeID, spanID)
		require.NoError(t, err)

		// Retrieve by node
		retrievedSpanID, err := store.GetSpanForNode(ctx, nodeID)
		require.NoError(t, err)
		assert.Equal(t, spanID, retrievedSpanID)

		// Retrieve by span
		retrievedNodeID, err := store.GetNodeForSpan(ctx, spanID)
		require.NoError(t, err)
		assert.Equal(t, nodeID, retrievedNodeID)
	})

	t.Run("handles errors", func(t *testing.T) {
		// Empty node ID
		err := store.StoreCorrelation(ctx, "", "span-1")
		assert.Error(t, err)

		// Empty span ID
		err = store.StoreCorrelation(ctx, "node-1", "")
		assert.Error(t, err)

		// Non-existent node
		_, err = store.GetSpanForNode(ctx, "non-existent")
		assert.Error(t, err)

		// Non-existent span
		_, err = store.GetNodeForSpan(ctx, "non-existent")
		assert.Error(t, err)
	})

	t.Run("overwrites existing correlations", func(t *testing.T) {
		store := observability.NewInMemoryCorrelationStore()

		// Store initial
		err := store.StoreCorrelation(ctx, "node-1", "span-1")
		require.NoError(t, err)

		// Overwrite
		err = store.StoreCorrelation(ctx, "node-1", "span-2")
		require.NoError(t, err)

		// Should have new correlation
		spanID, err := store.GetSpanForNode(ctx, "node-1")
		require.NoError(t, err)
		assert.Equal(t, "span-2", spanID)

		// Old correlation should be gone
		_, err = store.GetNodeForSpan(ctx, "span-1")
		assert.Error(t, err)
	})
}
