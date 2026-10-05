// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMockGraphRAGProvider_BasicOperations(t *testing.T) {
	// Test that the mock provider implements all operations correctly for testing
	provider := NewMockGraphRAGProvider()
	ctx := context.Background()

	// All operations should succeed with empty/nil results
	err := provider.Initialize(ctx)
	assert.NoError(t, err)

	nodes, err := provider.QueryNodes(ctx, *NewNodeQuery())
	assert.NoError(t, err)
	assert.Empty(t, nodes)

	rels, err := provider.QueryRelationships(ctx, *NewRelQuery())
	assert.NoError(t, err)
	assert.Empty(t, rels)

	traversed, err := provider.TraverseGraph(ctx, "test", 3, TraversalFilters{})
	assert.NoError(t, err)
	assert.Empty(t, traversed)

	vectorResults, err := provider.VectorSearch(ctx, []float64{0.1, 0.2}, 10, nil)
	assert.NoError(t, err)
	assert.Empty(t, vectorResults)

	health := provider.Health(ctx)
	assert.True(t, health.IsHealthy())

	err = provider.Close()
	assert.NoError(t, err)
}
