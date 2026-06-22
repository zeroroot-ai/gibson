//go:build skip_old_tests
// +build skip_old_tests

// NOTE: This file contains tests for the old mission-based API which has been removed.
// These tests need to be rewritten for the new mission definition API.
// Use -tags=skip_old_tests to run these (they will fail).

package mission

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

func TestCheckpointManager_Capture(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store)

	// Create a test mission
	mission := createTestMission(t)
	mission.Status = MissionStatusRunning
	mission.Metrics = &MissionMetrics{
		TotalNodes:     5,
		CompletedNodes: 2,
		TotalFindings:  3,
		StartedAt:      time.Now(),
	}
	require.NoError(t, store.Save(ctx, mission))

	// Create test mission and state
	wf := &mockMission{
		ID:    mission.MissionDefinitionID,
		Name:  "test-mission",
		Nodes: make(map[string]*mockMissionNode),
	}

	// Add some nodes
	wf.Nodes["node1"] = &mockMissionNode{ID: "node1", Name: "Node 1", Type: mockNodeTypeAgent}
	wf.Nodes["node2"] = &mockMissionNode{ID: "node2", Name: "Node 2", Type: mockNodeTypeAgent}
	wf.Nodes["node3"] = &mockMissionNode{ID: "node3", Name: "Node 3", Type: mockNodeTypeAgent}

	state := newMockMissionState(wf)
	state.Status = mockMissionStatusRunning

	// Mark some nodes as completed
	now := time.Now()
	state.MarkNodeStarted("node1")
	state.MarkNodeCompleted("node1", &mockNodeResult{
		NodeID:      "node1",
		Status:      mockNodeStatusCompleted,
		Output:      map[string]any{"result": "success"},
		CompletedAt: now,
	})

	state.MarkNodeStarted("node2")
	state.MarkNodeCompleted("node2", &mockNodeResult{
		NodeID:      "node2",
		Status:      mockNodeStatusCompleted,
		Output:      map[string]any{"result": "success"},
		CompletedAt: now,
	})

	// Capture checkpoint
	checkpoint, err := manager.Capture(ctx, mission.ID, state)
	require.NoError(t, err)
	require.NotNil(t, checkpoint)

	// Verify checkpoint fields
	assert.False(t, checkpoint.ID.IsZero(), "Checkpoint ID should not be zero")
	assert.Equal(t, 1, checkpoint.Version, "Checkpoint version should be 1")
	assert.NotEmpty(t, checkpoint.Checksum, "Checkpoint should have a checksum")
	assert.NotEmpty(t, checkpoint.CompletedNodes, "Checkpoint should have completed nodes")
	assert.Contains(t, checkpoint.CompletedNodes, "node1")
	assert.Contains(t, checkpoint.CompletedNodes, "node2")
	assert.Contains(t, checkpoint.PendingNodes, "node3")
	assert.NotNil(t, checkpoint.MetricsSnapshot, "Checkpoint should have metrics snapshot")
	assert.Equal(t, 2, checkpoint.MetricsSnapshot.CompletedNodes)
}

func TestCheckpointManager_Restore(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store)

	// Create a test mission
	mission := createTestMission(t)
	mission.Status = MissionStatusPaused
	mission.Metrics = &MissionMetrics{
		TotalNodes:     3,
		CompletedNodes: 1,
	}
	require.NoError(t, store.Save(ctx, mission))

	// Create and save a checkpoint
	originalCheckpoint := &MissionCheckpoint{
		ID:             types.NewID(),
		Version:        1,
		MissionState:   map[string]any{"status": "running"},
		CompletedNodes: []string{"node1"},
		PendingNodes:   []string{"node2", "node3"},
		NodeResults: map[string]any{
			"node1": map[string]any{"status": "completed"},
		},
		LastNodeID:     "node1",
		CheckpointedAt: time.Now(),
	}

	// Compute checksum for the original checkpoint
	tempManager := manager.(*DefaultCheckpointManager)
	checksum, err := tempManager.computeChecksum(originalCheckpoint)
	require.NoError(t, err)
	originalCheckpoint.Checksum = checksum

	// Save checkpoint
	require.NoError(t, store.SaveCheckpoint(ctx, mission.ID, originalCheckpoint))

	// Restore checkpoint
	restoredCheckpoint, err := manager.Restore(ctx, mission.ID)
	require.NoError(t, err)
	require.NotNil(t, restoredCheckpoint)

	// Verify restored checkpoint matches original
	assert.Equal(t, originalCheckpoint.ID, restoredCheckpoint.ID)
	assert.Equal(t, originalCheckpoint.Version, restoredCheckpoint.Version)
	assert.Equal(t, originalCheckpoint.Checksum, restoredCheckpoint.Checksum)
	assert.Equal(t, originalCheckpoint.CompletedNodes, restoredCheckpoint.CompletedNodes)
	assert.Equal(t, originalCheckpoint.PendingNodes, restoredCheckpoint.PendingNodes)
	assert.Equal(t, originalCheckpoint.LastNodeID, restoredCheckpoint.LastNodeID)
}

func TestCheckpointManager_Restore_NoCheckpoint(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store)

	// Create a test mission without a checkpoint
	mission := createTestMission(t)
	mission.Status = MissionStatusRunning
	require.NoError(t, store.Save(ctx, mission))

	// Restore should return nil when no checkpoint exists
	checkpoint, err := manager.Restore(ctx, mission.ID)
	require.NoError(t, err)
	assert.Nil(t, checkpoint, "Should return nil when no checkpoint exists")
}

func TestCheckpointManager_Restore_CorruptedCheckpoint(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store)

	// Create a test mission
	mission := createTestMission(t)
	mission.Status = MissionStatusPaused
	require.NoError(t, store.Save(ctx, mission))

	// Create a checkpoint with invalid checksum
	corruptedCheckpoint := &MissionCheckpoint{
		ID:             types.NewID(),
		Version:        1,
		MissionState:   map[string]any{"status": "running"},
		CompletedNodes: []string{"node1"},
		PendingNodes:   []string{"node2"},
		CheckpointedAt: time.Now(),
		Checksum:       "invalid_checksum_12345", // Invalid checksum
	}

	// Save corrupted checkpoint
	require.NoError(t, store.SaveCheckpoint(ctx, mission.ID, corruptedCheckpoint))

	// Restore should return error for corrupted checkpoint
	_, err := manager.Restore(ctx, mission.ID)
	require.Error(t, err)
	// The error should be a checkpoint error
	var missionErr *MissionError
	require.ErrorAs(t, err, &missionErr)
	assert.Equal(t, ErrMissionCheckpoint, missionErr.Code)
}

func TestCheckpointManager_List(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store)

	// Create a test mission
	mission := createTestMission(t)
	mission.Status = MissionStatusPaused
	require.NoError(t, store.Save(ctx, mission))

	// List should return empty when no checkpoints exist
	checkpoints, err := manager.List(ctx, mission.ID)
	require.NoError(t, err)
	assert.Empty(t, checkpoints)

	// Create and save a checkpoint
	checkpoint := &MissionCheckpoint{
		ID:             types.NewID(),
		Version:        1,
		MissionState:   map[string]any{"status": "running"},
		CompletedNodes: []string{"node1"},
		PendingNodes:   []string{"node2"},
		CheckpointedAt: time.Now(),
	}

	tempManager := manager.(*DefaultCheckpointManager)
	checksum, err := tempManager.computeChecksum(checkpoint)
	require.NoError(t, err)
	checkpoint.Checksum = checksum

	require.NoError(t, store.SaveCheckpoint(ctx, mission.ID, checkpoint))

	// List should return the checkpoint
	checkpoints, err = manager.List(ctx, mission.ID)
	require.NoError(t, err)
	assert.Len(t, checkpoints, 1)
	assert.Equal(t, checkpoint.ID, checkpoints[0].ID)
}

func TestCheckpointManager_AutoCheckpointInterval(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store).(*DefaultCheckpointManager)

	// Default interval should be 0 (disabled)
	assert.Equal(t, time.Duration(0), manager.GetAutoCheckpointInterval())

	// Set auto-checkpoint interval
	interval := 5 * time.Minute
	manager.SetAutoCheckpointInterval(interval)
	assert.Equal(t, interval, manager.GetAutoCheckpointInterval())

	// Disable auto-checkpoint
	manager.SetAutoCheckpointInterval(0)
	assert.Equal(t, time.Duration(0), manager.GetAutoCheckpointInterval())
}

func TestCheckpointManager_ChecksumValidation(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store).(*DefaultCheckpointManager)

	checkpoint := &MissionCheckpoint{
		ID:             types.NewID(),
		Version:        1,
		MissionState:   map[string]any{"status": "running", "node_count": 5},
		CompletedNodes: []string{"node1", "node2"},
		PendingNodes:   []string{"node3", "node4", "node5"},
		NodeResults: map[string]any{
			"node1": map[string]any{"status": "completed"},
		},
		LastNodeID:     "node2",
		CheckpointedAt: time.Now(),
	}

	// Compute checksum
	checksum1, err := manager.computeChecksum(checkpoint)
	require.NoError(t, err)
	assert.NotEmpty(t, checksum1)

	// Compute checksum again - should be identical
	checksum2, err := manager.computeChecksum(checkpoint)
	require.NoError(t, err)
	assert.Equal(t, checksum1, checksum2, "Checksum should be deterministic")

	// Modify checkpoint data
	checkpoint.CompletedNodes = append(checkpoint.CompletedNodes, "node3")

	// Checksum should be different after modification
	checksum3, err := manager.computeChecksum(checkpoint)
	require.NoError(t, err)
	assert.NotEqual(t, checksum1, checksum3, "Checksum should change after data modification")
}

func TestCheckpointManager_SerializeMissionState(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	manager := NewCheckpointManager(store).(*DefaultCheckpointManager)

	// Create test mission and state
	wf := &mockMission{
		ID:    types.NewID(),
		Name:  "test-mission",
		Nodes: make(map[string]*mockMissionNode),
	}
	wf.Nodes["node1"] = &mockMissionNode{ID: "node1", Name: "Node 1", Type: mockNodeTypeAgent}
	wf.Nodes["node2"] = &mockMissionNode{ID: "node2", Name: "Node 2", Type: mockNodeTypeAgent}

	state := newMockMissionState(wf)
	state.Status = mockMissionStatusRunning
	state.MarkNodeCompleted("node1", nil)

	// Serialize state
	serialized, err := manager.serializeMissionState(state)
	require.NoError(t, err)
	require.NotNil(t, serialized)

	// Verify serialized data contains expected fields
	assert.Contains(t, serialized, "mission_definition_id")
	assert.Contains(t, serialized, "status")
	assert.Contains(t, serialized, "started_at")
	assert.Contains(t, serialized, "node_states")

	// Verify mission ID is serialized correctly
	assert.Equal(t, wf.ID.String(), serialized["mission_definition_id"])
	assert.Equal(t, string(mockMissionStatusRunning), serialized["status"])

	// Verify node states are serialized
	nodeStates, ok := serialized["node_states"].(map[string]map[string]any)
	require.True(t, ok)
	assert.Contains(t, nodeStates, "node1")
	assert.Contains(t, nodeStates, "node2")
	assert.Equal(t, string(mockNodeStatusCompleted), nodeStates["node1"]["status"])
	assert.Equal(t, string(mockNodeStatusPending), nodeStates["node2"]["status"])
}
