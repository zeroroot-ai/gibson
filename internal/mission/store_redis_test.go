package mission

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupTestRedisStore creates a test Redis store with miniredis backend.
// Note: miniredis doesn't support RedisJSON or RediSearch modules,
// so tests focus on key naming, query building, and basic logic.
func setupTestRedisStore(t *testing.T) (*RedisMissionStore, *miniredis.Miniredis) {
	t.Helper()

	// Start miniredis
	mr := miniredis.RunT(t)

	// Create StateClient config pointing to miniredis
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	// Create StateClient - this will fail module check, so we create a basic one
	// For testing purposes, we'll skip the module check by directly creating the client
	client, err := createTestStateClient(mr.Addr())
	require.NoError(t, err)

	store := NewRedisMissionStore(client)
	return store, mr
}

// createTestStateClient creates a StateClient without module checks for testing.
func createTestStateClient(addr string) (*state.StateClient, error) {
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + addr

	// We can't use NewStateClient due to module checks
	// Instead, create a minimal client for testing
	// This is a simplified version - in real tests with Redis Stack, use NewStateClient
	return state.NewStateClient(cfg)
}

func TestRedisMissionStore_KeyNaming(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{
			name:     "missionKey",
			fn:       func() string { return missionKey(types.ID("abc123")) },
			expected: "gibson:mission:abc123",
		},
		{
			name:     "missionRunsKey",
			fn:       func() string { return missionRunsKey(types.ID("abc123")) },
			expected: "gibson:mission:abc123:runs",
		},
		{
			name:     "missionRunKey",
			fn:       func() string { return missionRunKey(types.ID("run456")) },
			expected: "gibson:mission_run:run456",
		},
		{
			name:     "missionEventsStream",
			fn:       func() string { return missionEventsStream(types.ID("abc123")) },
			expected: "gibson:stream:mission:abc123:events",
		},
		{
			name:     "missionCounterKey",
			fn:       func() string { return missionCounterKey("test-mission") },
			expected: "gibson:counter:mission:test-mission:run",
		},
		{
			name:     "missionByStatusKey",
			fn:       func() string { return missionByStatusKey(MissionStatusRunning) },
			expected: "gibson:mission:by_status:running",
		},
		{
			name:     "missionByStatusKey pending",
			fn:       func() string { return missionByStatusKey(MissionStatusPending) },
			expected: "gibson:mission:by_status:pending",
		},
		{
			name:     "missionByStatusKey completed",
			fn:       func() string { return missionByStatusKey(MissionStatusCompleted) },
			expected: "gibson:mission:by_status:completed",
		},
		{
			name:     "missionByTargetKey",
			fn:       func() string { return missionByTargetKey(types.ID("target123")) },
			expected: "gibson:mission:by_target:target123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.fn()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedisMissionStore_BuildSearchQuery(t *testing.T) {
	store := &RedisMissionStore{}

	tests := []struct {
		name     string
		filter   *MissionFilter
		expected string
	}{
		{
			name:     "nil filter returns wildcard",
			filter:   nil,
			expected: "*",
		},
		{
			name:     "empty filter returns wildcard",
			filter:   NewMissionFilter(),
			expected: "*",
		},
		{
			name: "status filter",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				status := MissionStatusRunning
				f.Status = &status
				return f
			}(),
			expected: "@status:{running}",
		},
		{
			name: "target_id filter",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				targetID := types.ID("target123")
				f.TargetID = &targetID
				return f
			}(),
			expected: "@target_id:{target123}",
		},
		{
			name: "workflow_id filter",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				workflowID := types.ID("workflow456")
				f.WorkflowID = &workflowID
				return f
			}(),
			expected: "@workflow_id:{workflow456}",
		},
		{
			name: "created_after filter",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				t := time.Unix(1234567890, 0)
				f.CreatedAfter = &t
				return f
			}(),
			expected: "@created_at:[1234567890 +inf]",
		},
		{
			name: "created_before filter",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				t := time.Unix(1234567890, 0)
				f.CreatedBefore = &t
				return f
			}(),
			expected: "@created_at:[-inf 1234567890]",
		},
		{
			name: "search_text filter",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				text := "test"
				f.SearchText = &text
				return f
			}(),
			expected: "(@name:test | @description:test)",
		},
		{
			name: "multiple filters combined",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				status := MissionStatusRunning
				f.Status = &status
				targetID := types.ID("target123")
				f.TargetID = &targetID
				return f
			}(),
			expected: "@status:{running} @target_id:{target123}",
		},
		{
			name: "all filters combined",
			filter: func() *MissionFilter {
				f := NewMissionFilter()
				status := MissionStatusRunning
				f.Status = &status
				targetID := types.ID("target123")
				f.TargetID = &targetID
				workflowID := types.ID("workflow456")
				f.WorkflowID = &workflowID
				after := time.Unix(1000000000, 0)
				f.CreatedAfter = &after
				before := time.Unix(2000000000, 0)
				f.CreatedBefore = &before
				text := "security"
				f.SearchText = &text
				return f
			}(),
			// Order may vary but all conditions should be present
			expected: "@status:{running} @target_id:{target123} @workflow_id:{workflow456} @created_at:[1000000000 +inf] @created_at:[-inf 2000000000] (@name:security | @description:security)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.buildSearchQuery(tt.filter)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedisMissionStore_SaveAndGet(t *testing.T) {
	// Skip this test if not running with Redis Stack (miniredis doesn't support JSON)
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:          types.NewID(),
		Name:        "test-mission",
		Description: "Test mission description",
		Status:      MissionStatusPending,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		Progress:    0.0,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Get mission
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.ID, retrieved.ID)
	assert.Equal(t, mission.Name, retrieved.Name)
	assert.Equal(t, mission.Status, retrieved.Status)
}

func TestRedisMissionStore_GetNotFound(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	// Try to get non-existent mission
	_, err := store.Get(ctx, types.ID("nonexistent"))
	require.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionStore_Update(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:          types.NewID(),
		Name:        "test-mission",
		Description: "Original description",
		Status:      MissionStatusPending,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Update mission
	mission.Description = "Updated description"
	mission.Status = MissionStatusRunning
	err = store.Update(ctx, mission)
	require.NoError(t, err)

	// Verify update
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.Equal(t, MissionStatusRunning, retrieved.Status)
}

func TestRedisMissionStore_UpdateStatus(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:         types.NewID(),
		Name:       "test-mission",
		Status:     MissionStatusPending,
		TargetID:   types.NewID(),
		WorkflowID: types.NewID(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Update status
	err = store.UpdateStatus(ctx, mission.ID, MissionStatusRunning)
	require.NoError(t, err)

	// Verify status update
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.Equal(t, MissionStatusRunning, retrieved.Status)
}

func TestRedisMissionStore_UpdateProgress(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:         types.NewID(),
		Name:       "test-mission",
		Status:     MissionStatusRunning,
		Progress:   0.0,
		TargetID:   types.NewID(),
		WorkflowID: types.NewID(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Update progress
	err = store.UpdateProgress(ctx, mission.ID, 0.5)
	require.NoError(t, err)

	// Verify progress update
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.Equal(t, 0.5, retrieved.Progress)
}

func TestRedisMissionStore_UpdateProgress_InvalidRange(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:         types.NewID(),
		Name:       "test-mission",
		Status:     MissionStatusRunning,
		TargetID:   types.NewID(),
		WorkflowID: types.NewID(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Try to update with invalid progress values
	err = store.UpdateProgress(ctx, mission.ID, -0.1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "between 0.0 and 1.0")

	err = store.UpdateProgress(ctx, mission.ID, 1.1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "between 0.0 and 1.0")
}

func TestRedisMissionStore_Delete(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:          types.NewID(),
		Name:        "test-mission",
		Status:      MissionStatusCompleted,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		CompletedAt: ptrTime(time.Now()),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Delete mission (terminal state)
	err = store.Delete(ctx, mission.ID)
	require.NoError(t, err)

	// Verify deletion
	_, err = store.Get(ctx, mission.ID)
	require.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionStore_DeleteNonTerminal(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:         types.NewID(),
		Name:       "test-mission",
		Status:     MissionStatusRunning, // Non-terminal state
		TargetID:   types.NewID(),
		WorkflowID: types.NewID(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Try to delete non-terminal mission
	err = store.Delete(ctx, mission.ID)
	require.Error(t, err)
	assert.True(t, IsInvalidStateError(err))
}

func TestRedisMissionStore_SaveCheckpoint(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	mission := &Mission{
		ID:         types.NewID(),
		Name:       "test-mission",
		Status:     MissionStatusRunning,
		TargetID:   types.NewID(),
		WorkflowID: types.NewID(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// Save mission
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Create checkpoint
	checkpoint := &MissionCheckpoint{
		ID:             types.NewID(),
		Version:        1,
		CompletedNodes: []string{"node1", "node2"},
		PendingNodes:   []string{"node3", "node4"},
		CheckpointedAt: time.Now(),
	}

	// Save checkpoint
	err = store.SaveCheckpoint(ctx, mission.ID, checkpoint)
	require.NoError(t, err)

	// Verify checkpoint was saved
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.Checkpoint)
	assert.Equal(t, checkpoint.ID, retrieved.Checkpoint.ID)
	assert.NotNil(t, retrieved.CheckpointAt)
}

func TestRedisMissionStore_IncrementRunNumber(t *testing.T) {
	// Skip this test if not running with Redis Stack
	t.Skip("Requires Redis Stack with RedisJSON module")

	store, mr := setupTestRedisStore(t)
	defer mr.Close()

	ctx := context.Background()

	missionName := "test-mission"

	// First increment should return 1
	runNumber1, err := store.IncrementRunNumber(ctx, missionName)
	require.NoError(t, err)
	assert.Equal(t, 1, runNumber1)

	// Second increment should return 2
	runNumber2, err := store.IncrementRunNumber(ctx, missionName)
	require.NoError(t, err)
	assert.Equal(t, 2, runNumber2)

	// Third increment should return 3
	runNumber3, err := store.IncrementRunNumber(ctx, missionName)
	require.NoError(t, err)
	assert.Equal(t, 3, runNumber3)
}

func TestRedisMissionStore_DefinitionMethods(t *testing.T) {
	store := &RedisMissionStore{}
	ctx := context.Background()

	// All definition methods should return errors indicating they're in etcd
	err := store.CreateDefinition(ctx, &MissionDefinition{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "etcd")

	_, err = store.GetDefinition(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "etcd")

	_, err = store.ListDefinitions(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "etcd")

	err = store.UpdateDefinition(ctx, &MissionDefinition{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "etcd")

	err = store.DeleteDefinition(ctx, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "etcd")
}

func TestRedisMissionStore_SaveValidation(t *testing.T) {
	store := &RedisMissionStore{}
	ctx := context.Background()

	tests := []struct {
		name      string
		mission   *Mission
		expectErr string
	}{
		{
			name:      "nil mission",
			mission:   nil,
			expectErr: "cannot be nil",
		},
		{
			name: "missing name",
			mission: &Mission{
				ID:         types.NewID(),
				TargetID:   types.NewID(),
				WorkflowID: types.NewID(),
				Status:     MissionStatusPending,
			},
			expectErr: "name is required",
		},
		{
			name: "missing target_id",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "test",
				WorkflowID: types.NewID(),
				Status:     MissionStatusPending,
			},
			expectErr: "target ID is required",
		},
		{
			name: "missing workflow_id",
			mission: &Mission{
				ID:       types.NewID(),
				Name:     "test",
				TargetID: types.NewID(),
				Status:   MissionStatusPending,
			},
			expectErr: "workflow ID is required",
		},
		{
			name: "missing status",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "test",
				TargetID:   types.NewID(),
				WorkflowID: types.NewID(),
			},
			expectErr: "status is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.Save(ctx, tt.mission)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectErr)
		})
	}
}

// Helper function to create time pointer
func ptrTime(t time.Time) *time.Time {
	return &t
}
