package checkpoint_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// createTestThreadManager creates a DefaultThreadManager for testing.
func createTestThreadManager(t *testing.T, stateClient *state.StateClient) *checkpoint.DefaultThreadManager {
	storeConfig := checkpoint.StoreConfig{
		KeyPrefix:  testKeyPrefix,
		DefaultTTL: 24 * time.Hour,
	}

	store := checkpoint.NewRedisCheckpointStore(stateClient, storeConfig)
	return checkpoint.NewThreadManager(store, store)
}

// TestThreadManager_CreateThread tests creating a primary thread.
func TestThreadManager_CreateThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()

	// Create thread
	thread, err := tm.CreateThread(ctx, missionID)
	require.NoError(t, err)
	assert.NotEmpty(t, thread.ID)
	assert.Equal(t, missionID, thread.MissionID)
	assert.Equal(t, checkpoint.ThreadStatusActive, thread.Status)
	assert.True(t, thread.IsPrimary())
	assert.False(t, thread.IsBranch())

	// Retrieve thread
	retrieved, err := tm.GetThread(ctx, thread.ID)
	require.NoError(t, err)
	assert.Equal(t, thread.ID, retrieved.ID)
	assert.Equal(t, thread.MissionID, retrieved.MissionID)
}

// TestThreadManager_CreateBranchThread tests creating a branch thread.
func TestThreadManager_CreateBranchThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()

	// Create parent thread
	parentThread, err := tm.CreateThread(ctx, missionID)
	require.NoError(t, err)

	// Create a checkpoint on the parent thread
	cp := checkpoint.NewCheckpoint(missionID, parentThread.ID)
	checksum, _ := cp.ComputeChecksum()
	cp.Checksum = checksum
	err = store.Save(ctx, cp)
	require.NoError(t, err)

	// Create branch thread
	branchThread, err := tm.CreateBranchThread(ctx, parentThread.ID, cp.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, branchThread.ID)
	assert.NotEqual(t, parentThread.ID, branchThread.ID)
	assert.Equal(t, missionID, branchThread.MissionID)
	assert.Equal(t, parentThread.ID, branchThread.ParentThread)
	assert.Equal(t, cp.ID, branchThread.BranchCheckpointID)
	assert.Equal(t, checkpoint.ThreadStatusActive, branchThread.Status)
	assert.False(t, branchThread.IsPrimary())
	assert.True(t, branchThread.IsBranch())
}

// TestThreadManager_ListThreads tests listing all threads for a mission.
func TestThreadManager_ListThreads(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()

	// Create multiple threads
	threads := make([]*checkpoint.Thread, 5)
	for i := 0; i < 5; i++ {
		thread, err := tm.CreateThread(ctx, missionID)
		require.NoError(t, err)
		threads[i] = thread
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	// List threads
	listed, err := tm.ListThreads(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, listed, 5)

	// Verify all thread IDs are present
	threadIDs := make(map[string]bool)
	for _, thread := range threads {
		threadIDs[thread.ID] = true
	}

	for _, thread := range listed {
		assert.True(t, threadIDs[thread.ID], "Thread ID should be in list")
		assert.Equal(t, missionID, thread.MissionID)
	}
}

// TestThreadManager_SubgraphThreadID tests hierarchical thread ID generation.
func TestThreadManager_SubgraphThreadID(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	parentThread := "thread-abc123"
	nodeID := "subgraph-node-1"

	// Generate subgraph thread ID
	subgraphThreadID := tm.GenerateSubgraphThreadID(parentThread, nodeID)

	// Verify format: {parent}:{node}:{uuid}
	assert.Contains(t, subgraphThreadID, parentThread)
	assert.Contains(t, subgraphThreadID, nodeID)

	// Verify parsing
	parent, node, uuid, err := checkpoint.ParseThreadID(subgraphThreadID)
	require.NoError(t, err)
	assert.Equal(t, parentThread, parent)
	assert.Equal(t, nodeID, node)
	assert.NotEmpty(t, uuid)

	// Verify subgraph detection
	assert.True(t, checkpoint.IsSubgraphThread(subgraphThreadID))
	assert.False(t, checkpoint.IsSubgraphThread(parentThread))
}

// TestThreadManager_ThreadStatusTransitions tests thread status updates.
func TestThreadManager_ThreadStatusTransitions(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()

	// Create thread
	thread, err := tm.CreateThread(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.ThreadStatusActive, thread.Status)

	// Pause thread
	err = tm.UpdateThreadStatus(ctx, thread.ID, checkpoint.ThreadStatusPaused)
	require.NoError(t, err)

	retrieved, err := tm.GetThread(ctx, thread.ID)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.ThreadStatusPaused, retrieved.Status)

	// Resume thread
	err = tm.UpdateThreadStatus(ctx, thread.ID, checkpoint.ThreadStatusActive)
	require.NoError(t, err)

	retrieved, err = tm.GetThread(ctx, thread.ID)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.ThreadStatusActive, retrieved.Status)

	// Complete thread
	err = tm.UpdateThreadStatus(ctx, thread.ID, checkpoint.ThreadStatusCompleted)
	require.NoError(t, err)

	retrieved, err = tm.GetThread(ctx, thread.ID)
	require.NoError(t, err)
	assert.Equal(t, checkpoint.ThreadStatusCompleted, retrieved.Status)
	assert.True(t, retrieved.Status.IsTerminal())

	// Cannot update terminal thread
	err = tm.UpdateThreadStatus(ctx, thread.ID, checkpoint.ThreadStatusActive)
	assert.Error(t, err, "Should not be able to update terminal thread")
}

// TestThreadManager_DeleteThread tests thread deletion.
func TestThreadManager_DeleteThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()

	// Create thread with checkpoints
	thread, err := tm.CreateThread(ctx, missionID)
	require.NoError(t, err)

	// Create checkpoints
	for i := 0; i < 3; i++ {
		cp := checkpoint.NewCheckpoint(missionID, thread.ID)
		checksum, _ := cp.ComputeChecksum()
		cp.Checksum = checksum
		err = store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Verify checkpoints exist
	checkpoints, err := store.ListByThread(ctx, thread.ID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, checkpoints, 3)

	// Delete thread
	err = tm.DeleteThread(ctx, thread.ID)
	require.NoError(t, err)

	// Verify thread is gone
	_, err = tm.GetThread(ctx, thread.ID)
	assert.Error(t, err)

	// Verify checkpoints are gone
	checkpoints, err = store.ListByThread(ctx, thread.ID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, checkpoints, 0)
}

// TestThreadManager_ThreadMetadata tests thread metadata handling.
func TestThreadManager_ThreadMetadata(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()

	// Create thread with metadata
	thread, err := tm.CreateThread(ctx, missionID,
		checkpoint.WithMetadata(map[string]string{
			"strategy": "aggressive",
			"priority": "high",
		}),
	)
	require.NoError(t, err)

	// Retrieve and verify metadata
	retrieved, err := tm.GetThread(ctx, thread.ID)
	require.NoError(t, err)
	assert.Equal(t, "aggressive", retrieved.Metadata["strategy"])
	assert.Equal(t, "high", retrieved.Metadata["priority"])
}

// TestThreadManager_MultiMissionIsolation tests that threads are isolated by mission.
func TestThreadManager_MultiMissionIsolation(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	tm := createTestThreadManager(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	mission1 := types.NewID()
	mission2 := types.NewID()

	// Create threads for mission 1
	for i := 0; i < 3; i++ {
		_, err := tm.CreateThread(ctx, mission1)
		require.NoError(t, err)
	}

	// Create threads for mission 2
	for i := 0; i < 5; i++ {
		_, err := tm.CreateThread(ctx, mission2)
		require.NoError(t, err)
	}

	// List threads for mission 1
	threads1, err := tm.ListThreads(ctx, mission1)
	require.NoError(t, err)
	assert.Len(t, threads1, 3)
	for _, thread := range threads1 {
		assert.Equal(t, mission1, thread.MissionID)
	}

	// List threads for mission 2
	threads2, err := tm.ListThreads(ctx, mission2)
	require.NoError(t, err)
	assert.Len(t, threads2, 5)
	for _, thread := range threads2 {
		assert.Equal(t, mission2, thread.MissionID)
	}

	// Verify no overlap
	ids1 := make(map[string]bool)
	for _, thread := range threads1 {
		ids1[thread.ID] = true
	}

	for _, thread := range threads2 {
		assert.False(t, ids1[thread.ID], "Thread from mission 2 should not appear in mission 1")
	}
}
