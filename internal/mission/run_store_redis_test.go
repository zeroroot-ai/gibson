package mission

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

func setupRedisRunStore(t *testing.T) (*RedisMissionRunStore, func()) {
	t.Helper()

	// Check if Redis is available by looking for REDIS_URL env var
	// If not set, skip tests requiring real Redis
	// These tests require Redis Stack with RedisJSON module
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	// Create state client
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379/15" // Use test database
	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Skipping test: Redis not available: %v", err)
	}

	// Create store
	store := NewRedisMissionRunStore(client)

	// Return cleanup function
	cleanup := func() {
		// Clean up test data
		ctx := context.Background()
		rdb := client.Client()
		rdb.FlushDB(ctx)
		client.Close()
	}

	return store, cleanup
}

func TestRedisMissionRunStore_Save(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()
	run := NewMissionRun(missionID, 1)

	// Test successful save
	err := store.Save(ctx, run)
	require.NoError(t, err)

	// Verify run was saved
	retrieved, err := store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, run.ID, retrieved.ID)
	assert.Equal(t, run.MissionID, retrieved.MissionID)
	assert.Equal(t, run.RunNumber, retrieved.RunNumber)
	assert.Equal(t, run.Status, retrieved.Status)

	// Verify sorted set entry
	count, err := store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRedisMissionRunStore_SaveNilRun(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	err := store.Save(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestRedisMissionRunStore_SaveInvalidRun(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	run := &MissionRun{
		ID:        types.NewID(),
		MissionID: types.NewID(),
		RunNumber: -1, // Invalid
		Status:    MissionRunStatusPending,
	}

	err := store.Save(ctx, run)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestRedisMissionRunStore_Get(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()
	run := NewMissionRun(missionID, 1)

	// Save run
	err := store.Save(ctx, run)
	require.NoError(t, err)

	// Test successful get
	retrieved, err := store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, run.ID, retrieved.ID)
	assert.Equal(t, run.MissionID, retrieved.MissionID)

	// Test get non-existent run
	nonExistentID := types.NewID()
	_, err = store.Get(ctx, nonExistentID)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionRunStore_GetByMissionAndNumber(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Save multiple runs
	run1 := NewMissionRun(missionID, 1)
	run2 := NewMissionRun(missionID, 2)
	run3 := NewMissionRun(missionID, 3)

	require.NoError(t, store.Save(ctx, run1))
	require.NoError(t, store.Save(ctx, run2))
	require.NoError(t, store.Save(ctx, run3))

	// Test successful lookup
	retrieved, err := store.GetByMissionAndNumber(ctx, missionID, 2)
	require.NoError(t, err)
	assert.Equal(t, run2.ID, retrieved.ID)
	assert.Equal(t, 2, retrieved.RunNumber)

	// Test non-existent run number
	_, err = store.GetByMissionAndNumber(ctx, missionID, 999)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))

	// Test non-existent mission
	_, err = store.GetByMissionAndNumber(ctx, types.NewID(), 1)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionRunStore_ListByMission(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Test empty list
	runs, err := store.ListByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Empty(t, runs)

	// Save runs in non-sequential order
	run2 := NewMissionRun(missionID, 2)
	run1 := NewMissionRun(missionID, 1)
	run3 := NewMissionRun(missionID, 3)

	require.NoError(t, store.Save(ctx, run2))
	require.NoError(t, store.Save(ctx, run1))
	require.NoError(t, store.Save(ctx, run3))

	// List should be ordered by run_number descending
	runs, err = store.ListByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, runs, 3)
	assert.Equal(t, 3, runs[0].RunNumber)
	assert.Equal(t, 2, runs[1].RunNumber)
	assert.Equal(t, 1, runs[2].RunNumber)

	// List for different mission should be empty
	otherMissionID := types.NewID()
	runs, err = store.ListByMission(ctx, otherMissionID)
	require.NoError(t, err)
	assert.Empty(t, runs)
}

func TestRedisMissionRunStore_GetLatestByMission(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Test no runs
	latest, err := store.GetLatestByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Nil(t, latest)

	// Save runs in random order
	run2 := NewMissionRun(missionID, 2)
	run1 := NewMissionRun(missionID, 1)
	run3 := NewMissionRun(missionID, 3)

	require.NoError(t, store.Save(ctx, run1))
	require.NoError(t, store.Save(ctx, run3))
	require.NoError(t, store.Save(ctx, run2))

	// Latest should be run 3
	latest, err = store.GetLatestByMission(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, run3.ID, latest.ID)
	assert.Equal(t, 3, latest.RunNumber)
}

func TestRedisMissionRunStore_GetNextRunNumber(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Test first run number
	nextNum, err := store.GetNextRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 1, nextNum)

	// Save a run
	run1 := NewMissionRun(missionID, 1)
	require.NoError(t, store.Save(ctx, run1))

	// Next should be 2
	nextNum, err = store.GetNextRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 2, nextNum)

	// Save more runs
	run2 := NewMissionRun(missionID, 2)
	run3 := NewMissionRun(missionID, 3)
	require.NoError(t, store.Save(ctx, run2))
	require.NoError(t, store.Save(ctx, run3))

	// Next should be 4
	nextNum, err = store.GetNextRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 4, nextNum)
}

func TestRedisMissionRunStore_Update(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()
	run := NewMissionRun(missionID, 1)

	// Save run
	err := store.Save(ctx, run)
	require.NoError(t, err)

	// Update run
	run.Status = MissionRunStatusRunning
	run.Progress = 0.5
	run.FindingsCount = 10

	err = store.Update(ctx, run)
	require.NoError(t, err)

	// Verify update
	retrieved, err := store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, MissionRunStatusRunning, retrieved.Status)
	assert.Equal(t, 0.5, retrieved.Progress)
	assert.Equal(t, 10, retrieved.FindingsCount)

	// Test update non-existent run
	nonExistentRun := NewMissionRun(missionID, 999)
	err = store.Update(ctx, nonExistentRun)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))

	// Test update with nil run
	err = store.Update(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestRedisMissionRunStore_UpdateStatus(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()
	run := NewMissionRun(missionID, 1)

	// Save run
	err := store.Save(ctx, run)
	require.NoError(t, err)

	// Update status to running (should set started_at)
	err = store.UpdateStatus(ctx, run.ID, MissionRunStatusRunning)
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, MissionRunStatusRunning, retrieved.Status)
	assert.NotNil(t, retrieved.StartedAt)
	assert.Nil(t, retrieved.CompletedAt)

	// Update status to completed (should set completed_at)
	err = store.UpdateStatus(ctx, run.ID, MissionRunStatusCompleted)
	require.NoError(t, err)

	retrieved, err = store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, MissionRunStatusCompleted, retrieved.Status)
	assert.NotNil(t, retrieved.StartedAt)
	assert.NotNil(t, retrieved.CompletedAt)

	// Test update non-existent run
	err = store.UpdateStatus(ctx, types.NewID(), MissionRunStatusFailed)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionRunStore_UpdateProgress(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()
	run := NewMissionRun(missionID, 1)

	// Save run
	err := store.Save(ctx, run)
	require.NoError(t, err)

	// Update progress
	err = store.UpdateProgress(ctx, run.ID, 0.75)
	require.NoError(t, err)

	retrieved, err := store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.Equal(t, 0.75, retrieved.Progress)

	// Test invalid progress values
	err = store.UpdateProgress(ctx, run.ID, -0.1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "between 0.0 and 1.0")

	err = store.UpdateProgress(ctx, run.ID, 1.5)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "between 0.0 and 1.0")

	// Test update non-existent run
	err = store.UpdateProgress(ctx, types.NewID(), 0.5)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionRunStore_GetActive(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Test no active runs
	active, err := store.GetActive(ctx)
	require.NoError(t, err)
	assert.Empty(t, active)

	// Save runs with different statuses
	runPending := NewMissionRun(missionID, 1)
	runRunning := NewMissionRun(missionID, 2)
	runRunning.Status = MissionRunStatusRunning
	runPaused := NewMissionRun(missionID, 3)
	runPaused.Status = MissionRunStatusPaused
	runCompleted := NewMissionRun(missionID, 4)
	runCompleted.Status = MissionRunStatusCompleted
	runFailed := NewMissionRun(missionID, 5)
	runFailed.Status = MissionRunStatusFailed

	require.NoError(t, store.Save(ctx, runPending))
	require.NoError(t, store.Save(ctx, runRunning))
	require.NoError(t, store.Save(ctx, runPaused))
	require.NoError(t, store.Save(ctx, runCompleted))
	require.NoError(t, store.Save(ctx, runFailed))

	// Get active runs (should only return running and paused)
	active, err = store.GetActive(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 2)

	// Verify active runs
	statuses := make(map[MissionRunStatus]bool)
	for _, run := range active {
		statuses[run.Status] = true
	}
	assert.True(t, statuses[MissionRunStatusRunning])
	assert.True(t, statuses[MissionRunStatusPaused])
	assert.False(t, statuses[MissionRunStatusPending])
	assert.False(t, statuses[MissionRunStatusCompleted])
	assert.False(t, statuses[MissionRunStatusFailed])
}

func TestRedisMissionRunStore_Delete(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Create completed run (terminal state)
	runCompleted := NewMissionRun(missionID, 1)
	runCompleted.Status = MissionRunStatusCompleted
	require.NoError(t, store.Save(ctx, runCompleted))

	// Create running run (non-terminal state)
	runRunning := NewMissionRun(missionID, 2)
	runRunning.Status = MissionRunStatusRunning
	require.NoError(t, store.Save(ctx, runRunning))

	// Test delete completed run
	err := store.Delete(ctx, runCompleted.ID)
	require.NoError(t, err)

	// Verify run was deleted
	_, err = store.Get(ctx, runCompleted.ID)
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))

	// Verify removed from sorted set
	count, err := store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 1, count) // Only running run remains

	// Test delete running run (should fail)
	err = store.Delete(ctx, runRunning.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "non-terminal")

	// Test delete non-existent run
	err = store.Delete(ctx, types.NewID())
	assert.Error(t, err)
	assert.True(t, IsNotFoundError(err))
}

func TestRedisMissionRunStore_CountByMission(t *testing.T) {
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Test count with no runs
	count, err := store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Add runs
	run1 := NewMissionRun(missionID, 1)
	run2 := NewMissionRun(missionID, 2)
	run3 := NewMissionRun(missionID, 3)

	require.NoError(t, store.Save(ctx, run1))
	require.NoError(t, store.Save(ctx, run2))
	require.NoError(t, store.Save(ctx, run3))

	// Test count
	count, err = store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// Count for different mission should be 0
	otherMissionID := types.NewID()
	count, err = store.CountByMission(ctx, otherMissionID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRedisMissionRunStore_CompleteMission(t *testing.T) {
	// Integration test: simulate a complete mission run lifecycle
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Get next run number
	nextNum, err := store.GetNextRunNumber(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 1, nextNum)

	// Create and save new run
	run := NewMissionRun(missionID, nextNum)
	run.Checkpoint = &MissionCheckpoint{
		ID:             types.NewID(),
		Version:        1,
		MissionState:   map[string]any{"step": "init"},
		CompletedNodes: []string{},
		PendingNodes:   []string{"node1"},
		NodeResults:    map[string]any{},
		LastNodeID:     "",
		CheckpointedAt: time.Now(),
		Checksum:       "abc123",
	}
	require.NoError(t, store.Save(ctx, run))

	// Update status to running
	require.NoError(t, store.UpdateStatus(ctx, run.ID, MissionRunStatusRunning))

	// Update progress periodically
	require.NoError(t, store.UpdateProgress(ctx, run.ID, 0.25))
	require.NoError(t, store.UpdateProgress(ctx, run.ID, 0.50))
	require.NoError(t, store.UpdateProgress(ctx, run.ID, 0.75))

	// Get active runs (should include this run)
	active, err := store.GetActive(ctx)
	require.NoError(t, err)
	assert.Len(t, active, 1)
	assert.Equal(t, run.ID, active[0].ID)

	// Complete the run
	run.Status = MissionRunStatusCompleted
	run.Progress = 1.0
	run.FindingsCount = 42
	now := time.Now()
	run.CompletedAt = &now
	require.NoError(t, store.Update(ctx, run))

	// Verify latest run
	latest, err := store.GetLatestByMission(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, latest)
	assert.Equal(t, run.ID, latest.ID)
	assert.Equal(t, MissionRunStatusCompleted, latest.Status)
	assert.Equal(t, 1.0, latest.Progress)
	assert.Equal(t, 42, latest.FindingsCount)
	assert.NotNil(t, latest.Checkpoint)

	// Get active runs (should be empty now)
	active, err = store.GetActive(ctx)
	require.NoError(t, err)
	assert.Empty(t, active)

	// Delete the completed run
	require.NoError(t, store.Delete(ctx, run.ID))

	// Verify deletion
	count, err := store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRedisMissionRunStore_ConcurrentUpdates(t *testing.T) {
	// Test concurrent updates to ensure Redis atomicity
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()
	run := NewMissionRun(missionID, 1)

	require.NoError(t, store.Save(ctx, run))

	// Simulate concurrent progress updates
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(progress float64) {
			err := store.UpdateProgress(ctx, run.ID, progress)
			assert.NoError(t, err)
			done <- true
		}(float64(i) / 10.0)
	}

	// Wait for all updates
	for i := 0; i < 10; i++ {
		<-done
	}

	// Run should still be valid
	retrieved, err := store.Get(ctx, run.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved)
}

func TestRedisMissionRunStore_SortedSetConsistency(t *testing.T) {
	// Test that sorted set stays in sync with documents
	store, cleanup := setupRedisRunStore(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Create multiple runs
	for i := 1; i <= 5; i++ {
		run := NewMissionRun(missionID, i)
		require.NoError(t, store.Save(ctx, run))
	}

	// Count should match
	count, err := store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 5, count)

	// List should return all runs
	runs, err := store.ListByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, runs, 5)

	// Delete some runs
	run2, err := store.GetByMissionAndNumber(ctx, missionID, 2)
	require.NoError(t, err)
	run2.Status = MissionRunStatusCompleted
	require.NoError(t, store.Update(ctx, run2))
	require.NoError(t, store.Delete(ctx, run2.ID))

	run4, err := store.GetByMissionAndNumber(ctx, missionID, 4)
	require.NoError(t, err)
	run4.Status = MissionRunStatusCompleted
	require.NoError(t, store.Update(ctx, run4))
	require.NoError(t, store.Delete(ctx, run4.ID))

	// Count should reflect deletions
	count, err = store.CountByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	// List should return remaining runs
	runs, err = store.ListByMission(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, runs, 3)

	// Verify correct runs remain
	runNumbers := []int{runs[0].RunNumber, runs[1].RunNumber, runs[2].RunNumber}
	assert.Contains(t, runNumbers, 1)
	assert.Contains(t, runNumbers, 3)
	assert.Contains(t, runNumbers, 5)
}
