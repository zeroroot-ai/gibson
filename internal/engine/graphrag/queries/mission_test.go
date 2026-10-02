// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package queries

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// TestMissionQueries_CreateNodeDependency tests creating DEPENDS_ON relationships.
func TestMissionQueries_CreateNodeDependency(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	fromNodeID := types.NewID()
	toNodeID := types.NewID()

	// Mock successful relationship creation
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.NoError(t, err)
}

// TestMissionQueries_CreateNodeDependency_Idempotent tests that MERGE makes it idempotent.
func TestMissionQueries_CreateNodeDependency_Idempotent(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	fromNodeID := types.NewID()
	toNodeID := types.NewID()

	// First call - creates relationship
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.NoError(t, err)

	// Second call - same relationship, should succeed (MERGE is idempotent)
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.NoError(t, err, "MERGE should make CreateNodeDependency idempotent")
}

// TestMissionQueries_CreateMissionNode_NilNode tests error handling for nil node.
func TestMissionQueries_CreateMissionNode_NilNode(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)

	err = mq.CreateMissionNode(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission node cannot be nil")
}

// TestMissionQueries_CreateMissionRun_NoParentMission: CreateMissionRun MATCHes
// its parent Mission and CREATEs the run only if that match succeeds, so zero
// records means the Mission is not there. Treating that as success would leave
// a run node that belongs to nothing, and gibson#550 is the reader that
// traverses the edge this would not have drawn.
func TestMissionQueries_CreateMissionRun_NoParentMission(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()
	require.NoError(t, mock.Connect(ctx))
	defer func() { _ = mock.Close(ctx) }()

	mq := NewMissionQueries(mock)

	// The MATCH found no Mission, so the CREATE never ran and no row came back.
	mock.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})

	err := mq.CreateMissionRun(ctx, types.NewID(), types.NewID(), 1)
	require.Error(t, err, "a run with no parent Mission must be an error")
	assert.Contains(t, err.Error(), "mission not found")
}
