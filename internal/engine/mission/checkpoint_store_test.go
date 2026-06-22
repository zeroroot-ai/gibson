package mission

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// setupTestRedisCheckpointStore creates a test checkpoint store backed by miniredis.
//
// miniredis does not implement the RedisJSON module (JSON.SET, JSON.GET, JSON.DEL),
// so these tests are skipped unless the probe write succeeds. Use a real Redis Stack
// instance (or the integration tests under tests/integration/checkpoint/) when you
// need to exercise the full store.
func setupTestRedisCheckpointStore(t *testing.T) (*RedisCheckpointStore, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	// NewStateClient runs a MODULE LIST health check; miniredis returns an error
	// for that command which the client currently treats as "skip check" (returns
	// nil). Probe the actual JSON.SET command instead so we skip correctly when
	// RedisJSON is not available.
	stateClient, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Skipping: could not create Redis state client: %v", err)
	}

	// Probe RedisJSON availability. miniredis will fail with "unknown command".
	probeCtx := context.Background()
	if err := stateClient.JSONSet(probeCtx, "__probe__", "$", struct{}{}); err != nil {
		t.Skipf("Skipping: RedisJSON module not available (%v) — "+
			"run a Redis Stack instance or use tests/integration/checkpoint/", err)
	}
	// Clean up the probe key (best-effort).
	_ = stateClient.JSONDel(probeCtx, "__probe__", "$")

	store := NewRedisCheckpointStore(stateClient)
	return store, mr
}

func TestRedisCheckpointStore_Save(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	checkpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-2",
		CompletedNodes: map[string]NodeOutput{
			"node-1": {
				NodeID:   "node-1",
				Status:   "completed",
				Output:   map[string]any{"result": "success"},
				Duration: 5 * time.Second,
			},
		},
		InProgressNode: &InProgressNodeState{
			NodeID:     "node-2",
			StartedAt:  time.Now(),
			RetryCount: 0,
		},
		WorkingMemory: []byte(`{"context": "test"}`),
		MissionMemory: []byte(`{"findings": []}`),
		Findings:      []types.ID{types.NewID()},
		Metrics: MissionMetrics{
			TotalNodes:     3,
			CompletedNodes: 1,
			TotalFindings:  1,
			StartedAt:      time.Now(),
			LastUpdateAt:   time.Now(),
		},
		DAGState: &DAGTraversalState{
			PendingNodes: []string{"node-3"},
		},
	}

	err := store.Save(ctx, missionID, checkpoint)
	require.NoError(t, err)

	// Verify the checkpoint was saved
	exists, err := store.Exists(ctx, missionID)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisCheckpointStore_SaveNilCheckpoint(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	err := store.Save(ctx, missionID, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "checkpoint cannot be nil")
}

func TestRedisCheckpointStore_SaveZeroMissionID(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	checkpoint := &Checkpoint{
		MissionID: types.ID(""),
	}

	err := store.Save(ctx, types.ID(""), checkpoint)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mission ID cannot be zero")
}

func TestRedisCheckpointStore_Load(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Create and save a checkpoint
	originalCheckpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now().Truncate(time.Second), // Truncate for comparison
		CurrentNodeID: "node-2",
		CompletedNodes: map[string]NodeOutput{
			"node-1": {
				NodeID:   "node-1",
				Status:   "completed",
				Output:   map[string]any{"result": "success"},
				Duration: 5 * time.Second,
			},
		},
		WorkingMemory: []byte(`{"context": "test"}`),
		MissionMemory: []byte(`{"findings": []}`),
		Findings:      []types.ID{types.NewID()},
		Metrics: MissionMetrics{
			TotalNodes:     3,
			CompletedNodes: 1,
		},
		DAGState: &DAGTraversalState{
			PendingNodes: []string{"node-3"},
		},
	}

	err := store.Save(ctx, missionID, originalCheckpoint)
	require.NoError(t, err)

	// Load the checkpoint
	loadedCheckpoint, err := store.Load(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, loadedCheckpoint)

	// Verify checkpoint fields
	assert.Equal(t, originalCheckpoint.MissionID, loadedCheckpoint.MissionID)
	assert.Equal(t, originalCheckpoint.CurrentNodeID, loadedCheckpoint.CurrentNodeID)
	assert.Len(t, loadedCheckpoint.CompletedNodes, 1)
	assert.Contains(t, loadedCheckpoint.CompletedNodes, "node-1")
	assert.Equal(t, originalCheckpoint.Metrics.TotalNodes, loadedCheckpoint.Metrics.TotalNodes)
	assert.Equal(t, originalCheckpoint.Metrics.CompletedNodes, loadedCheckpoint.Metrics.CompletedNodes)
}

func TestRedisCheckpointStore_LoadNotFound(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Load non-existent checkpoint
	checkpoint, err := store.Load(ctx, missionID)
	require.NoError(t, err)
	assert.Nil(t, checkpoint)
}

func TestRedisCheckpointStore_LoadZeroMissionID(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()

	checkpoint, err := store.Load(ctx, types.ID(""))
	assert.Error(t, err)
	assert.Nil(t, checkpoint)
	assert.Contains(t, err.Error(), "mission ID cannot be zero")
}

func TestRedisCheckpointStore_Delete(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Create and save a checkpoint
	checkpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-1",
	}

	err := store.Save(ctx, missionID, checkpoint)
	require.NoError(t, err)

	// Verify it exists
	exists, err := store.Exists(ctx, missionID)
	require.NoError(t, err)
	assert.True(t, exists)

	// Delete the checkpoint
	err = store.Delete(ctx, missionID)
	require.NoError(t, err)

	// Verify it no longer exists
	exists, err = store.Exists(ctx, missionID)
	require.NoError(t, err)
	assert.False(t, exists)
}

func TestRedisCheckpointStore_DeleteNonExistent(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Delete non-existent checkpoint should not error
	err := store.Delete(ctx, missionID)
	require.NoError(t, err)
}

func TestRedisCheckpointStore_DeleteZeroMissionID(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()

	err := store.Delete(ctx, types.ID(""))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mission ID cannot be zero")
}

func TestRedisCheckpointStore_Exists(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Check non-existent checkpoint
	exists, err := store.Exists(ctx, missionID)
	require.NoError(t, err)
	assert.False(t, exists)

	// Save a checkpoint
	checkpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-1",
	}

	err = store.Save(ctx, missionID, checkpoint)
	require.NoError(t, err)

	// Check it now exists
	exists, err = store.Exists(ctx, missionID)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisCheckpointStore_ExistsZeroMissionID(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()

	exists, err := store.Exists(ctx, types.ID(""))
	assert.Error(t, err)
	assert.False(t, exists)
	assert.Contains(t, err.Error(), "mission ID cannot be zero")
}

func TestRedisCheckpointStore_WithPrefix(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	// Set custom prefix
	store = store.WithPrefix("custom-checkpoint")

	ctx := context.Background()
	missionID := types.NewID()

	checkpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-1",
	}

	err := store.Save(ctx, missionID, checkpoint)
	require.NoError(t, err)

	// Verify key uses custom prefix
	key := store.checkpointKey(missionID)
	assert.Contains(t, key, "custom-checkpoint")
}

func TestRedisCheckpointStore_WithTTL(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	// Set custom TTL
	customTTL := 1 * time.Hour
	store = store.WithTTL(customTTL)

	ctx := context.Background()
	missionID := types.NewID()

	checkpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-1",
	}

	err := store.Save(ctx, missionID, checkpoint)
	require.NoError(t, err)

	// Verify TTL is set (this would require accessing Redis directly)
	// For now, just verify the save succeeded
	exists, err := store.Exists(ctx, missionID)
	require.NoError(t, err)
	assert.True(t, exists)
}

func TestRedisCheckpointStore_SaveLoadRoundTrip(t *testing.T) {
	store, mr := setupTestRedisCheckpointStore(t)
	defer mr.Close()

	ctx := context.Background()
	missionID := types.NewID()

	// Create a comprehensive checkpoint with all fields
	originalCheckpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now().Truncate(time.Millisecond),
		CurrentNodeID: "node-2",
		CompletedNodes: map[string]NodeOutput{
			"node-1": {
				NodeID:   "node-1",
				Status:   "completed",
				Output:   map[string]any{"result": "success", "data": map[string]any{"nested": "value"}},
				Duration: 5 * time.Second,
			},
		},
		InProgressNode: &InProgressNodeState{
			NodeID:     "node-2",
			StartedAt:  time.Now().Truncate(time.Millisecond),
			RetryCount: 2,
		},
		WorkingMemory: []byte(`{"context": "test", "nested": {"key": "value"}}`),
		MissionMemory: []byte(`{"findings": ["f1", "f2"]}`),
		Findings:      []types.ID{types.NewID(), types.NewID()},
		Metrics: MissionMetrics{
			TotalNodes:         5,
			CompletedNodes:     2,
			FailedNodes:        0,
			TotalFindings:      2,
			FindingsBySeverity: map[string]int{"high": 1, "medium": 1},
			TotalTokens:        1000,
			TotalCost:          0.05,
			Duration:           10 * time.Second,
			StartedAt:          time.Now().Truncate(time.Millisecond),
			LastUpdateAt:       time.Now().Truncate(time.Millisecond),
		},
		DAGState: &DAGTraversalState{
			PendingNodes:  []string{"node-3", "node-4"},
			CurrentBranch: "main",
			ParallelState: map[string][]string{
				"parallel-1": {"node-1"},
			},
		},
	}

	// Save the checkpoint
	err := store.Save(ctx, missionID, originalCheckpoint)
	require.NoError(t, err)

	// Load the checkpoint
	loadedCheckpoint, err := store.Load(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, loadedCheckpoint)

	// Verify all fields match
	assert.Equal(t, originalCheckpoint.MissionID, loadedCheckpoint.MissionID)
	assert.Equal(t, originalCheckpoint.CurrentNodeID, loadedCheckpoint.CurrentNodeID)
	assert.Equal(t, len(originalCheckpoint.CompletedNodes), len(loadedCheckpoint.CompletedNodes))
	assert.NotNil(t, loadedCheckpoint.InProgressNode)
	assert.Equal(t, originalCheckpoint.InProgressNode.NodeID, loadedCheckpoint.InProgressNode.NodeID)
	assert.Equal(t, originalCheckpoint.InProgressNode.RetryCount, loadedCheckpoint.InProgressNode.RetryCount)
	assert.Equal(t, originalCheckpoint.WorkingMemory, loadedCheckpoint.WorkingMemory)
	assert.Equal(t, originalCheckpoint.MissionMemory, loadedCheckpoint.MissionMemory)
	assert.Equal(t, len(originalCheckpoint.Findings), len(loadedCheckpoint.Findings))
	assert.Equal(t, originalCheckpoint.Metrics.TotalNodes, loadedCheckpoint.Metrics.TotalNodes)
	assert.Equal(t, originalCheckpoint.Metrics.CompletedNodes, loadedCheckpoint.Metrics.CompletedNodes)
	assert.NotNil(t, loadedCheckpoint.DAGState)
	assert.Equal(t, len(originalCheckpoint.DAGState.PendingNodes), len(loadedCheckpoint.DAGState.PendingNodes))
	assert.Equal(t, originalCheckpoint.DAGState.CurrentBranch, loadedCheckpoint.DAGState.CurrentBranch)
}
