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

// TestMissionRunIntegration tests the full mission run lifecycle.
func TestMissionRunIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Setup state client
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379/15" // Test database
	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Skipping test: Redis not available: %v", err)
	}
	defer client.Close()

	// Flush test database
	rdb := client.Client()
	rdb.FlushDB(ctx)

	// Create run store
	runStore := NewRedisMissionRunStore(client)

	missionID := types.NewID()

	// Test 1: Create first run
	t.Run("CreateFirstRun", func(t *testing.T) {
		runNumber, err := runStore.GetNextRunNumber(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 1, runNumber, "First run should be number 1")

		run := NewMissionRun(missionID, runNumber)
		run.MarkStarted()

		err = runStore.Save(ctx, run)
		require.NoError(t, err)

		// Verify retrieval
		retrieved, err := runStore.Get(ctx, run.ID)
		require.NoError(t, err)
		assert.Equal(t, run.ID, retrieved.ID)
		assert.Equal(t, runNumber, retrieved.RunNumber)
		assert.Equal(t, MissionRunStatusRunning, retrieved.Status)
	})

	// Test 2: Create second run (sequential numbering)
	t.Run("CreateSecondRun", func(t *testing.T) {
		runNumber, err := runStore.GetNextRunNumber(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 2, runNumber, "Second run should be number 2")

		run := NewMissionRun(missionID, runNumber)
		run.MarkStarted()

		err = runStore.Save(ctx, run)
		require.NoError(t, err)

		// Verify we can get it by mission and number
		retrieved, err := runStore.GetByMissionAndNumber(ctx, missionID, runNumber)
		require.NoError(t, err)
		assert.Equal(t, runNumber, retrieved.RunNumber)
	})

	// Test 3: Create third run and complete it
	t.Run("CreateAndCompleteRun", func(t *testing.T) {
		runNumber, err := runStore.GetNextRunNumber(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 3, runNumber, "Third run should be number 3")

		run := NewMissionRun(missionID, runNumber)
		run.MarkStarted()
		err = runStore.Save(ctx, run)
		require.NoError(t, err)

		// Simulate some findings
		run.IncrementFindings(5)
		run.MarkCompleted()

		err = runStore.Update(ctx, run)
		require.NoError(t, err)

		// Verify completion
		retrieved, err := runStore.Get(ctx, run.ID)
		require.NoError(t, err)
		assert.Equal(t, MissionRunStatusCompleted, retrieved.Status)
		assert.Equal(t, 5, retrieved.FindingsCount)
		assert.NotNil(t, retrieved.CompletedAt)
	})

	// Test 4: List all runs
	t.Run("ListRuns", func(t *testing.T) {
		runs, err := runStore.ListByMission(ctx, missionID)
		require.NoError(t, err)
		assert.Len(t, runs, 3, "Should have 3 runs")

		// Verify ordering (descending by run number)
		assert.Equal(t, 3, runs[0].RunNumber)
		assert.Equal(t, 2, runs[1].RunNumber)
		assert.Equal(t, 1, runs[2].RunNumber)
	})

	// Test 5: Get latest run
	t.Run("GetLatestRun", func(t *testing.T) {
		latest, err := runStore.GetLatestByMission(ctx, missionID)
		require.NoError(t, err)
		assert.NotNil(t, latest)
		assert.Equal(t, 3, latest.RunNumber)
	})

	// Test 6: Count runs
	t.Run("CountRuns", func(t *testing.T) {
		count, err := runStore.CountByMission(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 3, count)
	})

	// Test 7: Update run status
	t.Run("UpdateRunStatus", func(t *testing.T) {
		// Get the second run
		run, err := runStore.GetByMissionAndNumber(ctx, missionID, 2)
		require.NoError(t, err)

		// Mark it as failed
		err = runStore.UpdateStatus(ctx, run.ID, MissionRunStatusFailed)
		require.NoError(t, err)

		// Verify status changed
		updated, err := runStore.Get(ctx, run.ID)
		require.NoError(t, err)
		assert.Equal(t, MissionRunStatusFailed, updated.Status)
		assert.NotNil(t, updated.CompletedAt)
	})

	// Test 8: Update run progress
	t.Run("UpdateRunProgress", func(t *testing.T) {
		run, err := runStore.GetByMissionAndNumber(ctx, missionID, 1)
		require.NoError(t, err)

		err = runStore.UpdateProgress(ctx, run.ID, 0.75)
		require.NoError(t, err)

		updated, err := runStore.Get(ctx, run.ID)
		require.NoError(t, err)
		assert.Equal(t, 0.75, updated.Progress)
	})

	// Test 9: Multiple missions don't interfere
	t.Run("MultipleMissions", func(t *testing.T) {
		mission2ID := types.NewID()

		// Create run for second mission
		runNumber, err := runStore.GetNextRunNumber(ctx, mission2ID)
		require.NoError(t, err)
		assert.Equal(t, 1, runNumber, "First run for second mission should be 1")

		run := NewMissionRun(mission2ID, runNumber)
		err = runStore.Save(ctx, run)
		require.NoError(t, err)

		// Verify first mission still has 3 runs
		count1, err := runStore.CountByMission(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 3, count1)

		// Verify second mission has 1 run
		count2, err := runStore.CountByMission(ctx, mission2ID)
		require.NoError(t, err)
		assert.Equal(t, 1, count2)
	})

	// Test 10: Delete run
	t.Run("DeleteRun", func(t *testing.T) {
		// Get the completed run (run 3)
		run, err := runStore.GetByMissionAndNumber(ctx, missionID, 3)
		require.NoError(t, err)

		// Delete it
		err = runStore.Delete(ctx, run.ID)
		require.NoError(t, err)

		// Verify it's gone
		_, err = runStore.Get(ctx, run.ID)
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))

		// Verify count decreased
		count, err := runStore.CountByMission(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 2, count)
	})
}

// TestMissionRunConcurrency tests concurrent run creation.
func TestMissionRunConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.Background()

	// Setup state client
	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379/15"
	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Skipping test: Redis not available: %v", err)
	}
	defer client.Close()

	// Flush test database
	rdb := client.Client()
	rdb.FlushDB(ctx)

	// Create run store
	runStore := NewRedisMissionRunStore(client)

	missionID := types.NewID()
	numGoroutines := 10

	// Concurrently create runs
	results := make(chan int, numGoroutines)
	errors := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			runNumber, err := runStore.GetNextRunNumber(ctx, missionID)
			if err != nil {
				errors <- err
				return
			}

			run := NewMissionRun(missionID, runNumber)
			if err := runStore.Save(ctx, run); err != nil {
				errors <- err
				return
			}

			results <- runNumber
		}()
	}

	// Collect results
	runNumbers := make(map[int]int)
	for i := 0; i < numGoroutines; i++ {
		select {
		case num := <-results:
			runNumbers[num]++
		case err := <-errors:
			t.Fatalf("Error during concurrent run creation: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for concurrent runs")
		}
	}

	// Verify all run numbers are unique (no duplicates)
	for num, count := range runNumbers {
		assert.Equal(t, 1, count, "Run number %d should appear exactly once", num)
	}

	// Verify we got numbers 1-10
	assert.Len(t, runNumbers, numGoroutines)
	for i := 1; i <= numGoroutines; i++ {
		assert.Contains(t, runNumbers, i, "Should have run number %d", i)
	}
}

// TestMissionRunValidation tests run validation.
func TestMissionRunValidation(t *testing.T) {
	t.Run("ValidRun", func(t *testing.T) {
		run := NewMissionRun(types.NewID(), 1)
		err := run.Validate()
		assert.NoError(t, err)
	})

	t.Run("InvalidRunNumber", func(t *testing.T) {
		run := &MissionRun{
			ID:        types.NewID(),
			MissionID: types.NewID(),
			RunNumber: 0,
		}
		err := run.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "run_number must be >= 1")
	})

	t.Run("InvalidProgress", func(t *testing.T) {
		run := NewMissionRun(types.NewID(), 1)
		run.Progress = 1.5
		err := run.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "progress must be between 0.0 and 1.0")
	})

	t.Run("InvalidMissionID", func(t *testing.T) {
		run := &MissionRun{
			ID:        types.NewID(),
			MissionID: types.ID(""),
			RunNumber: 1,
		}
		err := run.Validate()
		assert.Error(t, err)
	})
}

// TestMissionRunStatusTransitions tests status transition methods.
func TestMissionRunStatusTransitions(t *testing.T) {
	run := NewMissionRun(types.NewID(), 1)

	// Initial state
	assert.Equal(t, MissionRunStatusPending, run.Status)
	assert.Nil(t, run.StartedAt)
	assert.Nil(t, run.CompletedAt)

	// Mark started
	run.MarkStarted()
	assert.Equal(t, MissionRunStatusRunning, run.Status)
	assert.NotNil(t, run.StartedAt)
	assert.Nil(t, run.CompletedAt)

	// Mark completed
	run.MarkCompleted()
	assert.Equal(t, MissionRunStatusCompleted, run.Status)
	assert.NotNil(t, run.StartedAt)
	assert.NotNil(t, run.CompletedAt)

	// Test failed transition
	run2 := NewMissionRun(types.NewID(), 2)
	run2.MarkStarted()
	run2.MarkFailed("test error")
	assert.Equal(t, MissionRunStatusFailed, run2.Status)
	assert.Equal(t, "test error", run2.Error)
	assert.NotNil(t, run2.CompletedAt)

	// Test cancelled transition
	run3 := NewMissionRun(types.NewID(), 3)
	run3.MarkStarted()
	run3.MarkCancelled()
	assert.Equal(t, MissionRunStatusCancelled, run3.Status)
	assert.NotNil(t, run3.CompletedAt)

	// Test paused transition
	run4 := NewMissionRun(types.NewID(), 4)
	run4.MarkStarted()
	run4.MarkPaused()
	assert.Equal(t, MissionRunStatusPaused, run4.Status)
	assert.Nil(t, run4.CompletedAt) // Paused doesn't set completed
}

// TestMissionRunTerminalStatus tests terminal status checking.
func TestMissionRunTerminalStatus(t *testing.T) {
	tests := []struct {
		status     MissionRunStatus
		isTerminal bool
	}{
		{MissionRunStatusPending, false},
		{MissionRunStatusRunning, false},
		{MissionRunStatusPaused, false},
		{MissionRunStatusCompleted, true},
		{MissionRunStatusFailed, true},
		{MissionRunStatusCancelled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.isTerminal, tt.status.IsTerminal())
		})
	}
}
