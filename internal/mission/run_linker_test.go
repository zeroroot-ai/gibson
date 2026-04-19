//go:build stale
// +build stale

// NOTE: this test references `NewDBMissionStore`, a SQL-backed constructor
// that was removed when the mission store moved to Redis. Kept behind the
// `stale` build tag so the file is preserved for future repair.

package mission

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestMissionRunLinker_CreateRun(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	linker := NewMissionRunLinker(store)
	ctx := context.Background()

	t.Run("create first run", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]
		mission := &Mission{
			ID:                  types.NewID(),
			Description:         "First run test",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}

		err := linker.CreateRun(ctx, missionName, mission)
		require.NoError(t, err)

		// Verify mission was saved with correct metadata
		saved, err := store.Get(ctx, mission.ID)
		require.NoError(t, err)
		assert.Equal(t, missionName, saved.Name)

		// Check run number is 1
		require.NotNil(t, saved.Metadata)
		runNum, ok := saved.Metadata["run_number"]
		require.True(t, ok)
		assert.Equal(t, 1, int(runNum.(float64)))

		// Check no previous run ID (this is the first run)
		_, hasPrevious := saved.Metadata["previous_run_id"]
		assert.False(t, hasPrevious)
	})

	t.Run("create second run links to first", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create first run
		firstMission := &Mission{
			ID:                  types.NewID(),
			Description:         "First run",
			Status:              MissionStatusCompleted,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		completedAt := time.Now()
		firstMission.CompletedAt = &completedAt

		err := linker.CreateRun(ctx, missionName, firstMission)
		require.NoError(t, err)

		// Create second run
		secondMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Second run",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now().Add(1 * time.Second),
			UpdatedAt:           time.Now().Add(1 * time.Second),
		}

		err = linker.CreateRun(ctx, missionName, secondMission)
		require.NoError(t, err)

		// Verify second run has correct metadata
		saved, err := store.Get(ctx, secondMission.ID)
		require.NoError(t, err)

		// Check run number is 2
		require.NotNil(t, saved.Metadata)
		runNum, ok := saved.Metadata["run_number"]
		require.True(t, ok)
		assert.Equal(t, 2, int(runNum.(float64)))

		// Check previous run ID links to first run
		prevRunIDStr, ok := saved.Metadata["previous_run_id"].(string)
		require.True(t, ok)
		prevRunID, err := types.ParseID(prevRunIDStr)
		require.NoError(t, err)
		assert.Equal(t, firstMission.ID, prevRunID)
	})

	t.Run("increment run number across multiple runs", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create 3 runs
		for i := 1; i <= 3; i++ {
			mission := &Mission{
				ID:                  types.NewID(),
				Description:         "Run " + string(rune(i)),
				Status:              MissionStatusCompleted,
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				CreatedAt:           time.Now().Add(time.Duration(i) * time.Second),
				UpdatedAt:           time.Now().Add(time.Duration(i) * time.Second),
			}
			completedAt := time.Now()
			mission.CompletedAt = &completedAt

			err := linker.CreateRun(ctx, missionName, mission)
			require.NoError(t, err)

			// Verify run number
			saved, err := store.Get(ctx, mission.ID)
			require.NoError(t, err)
			runNum := int(saved.Metadata["run_number"].(float64))
			assert.Equal(t, i, runNum, "Expected run number %d, got %d", i, runNum)
		}
	})

	t.Run("error when active run exists (running)", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a running mission
		runningMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Running mission",
			Status:              MissionStatusRunning,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		startedAt := time.Now()
		runningMission.StartedAt = &startedAt

		err := linker.CreateRun(ctx, missionName, runningMission)
		require.NoError(t, err)

		// Try to create another run with the same name
		newMission := &Mission{
			ID:                  types.NewID(),
			Description:         "New mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}

		err = linker.CreateRun(ctx, missionName, newMission)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "active run exists")
		assert.Contains(t, err.Error(), runningMission.ID.String())
	})

	t.Run("error when active run exists (paused)", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a paused mission
		pausedMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Paused mission",
			Status:              MissionStatusPaused,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		startedAt := time.Now()
		pausedMission.StartedAt = &startedAt

		err := linker.CreateRun(ctx, missionName, pausedMission)
		require.NoError(t, err)

		// Try to create another run with the same name
		newMission := &Mission{
			ID:                  types.NewID(),
			Description:         "New mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}

		err = linker.CreateRun(ctx, missionName, newMission)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "active run exists")
		assert.Contains(t, err.Error(), "paused")
	})

	t.Run("allow new run when previous is completed", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a completed mission
		completedMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Completed mission",
			Status:              MissionStatusCompleted,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		completedAt := time.Now()
		completedMission.CompletedAt = &completedAt

		err := linker.CreateRun(ctx, missionName, completedMission)
		require.NoError(t, err)

		// Create another run (should succeed)
		newMission := &Mission{
			ID:                  types.NewID(),
			Description:         "New mission",
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now().Add(1 * time.Second),
			UpdatedAt:           time.Now().Add(1 * time.Second),
		}

		err = linker.CreateRun(ctx, missionName, newMission)
		require.NoError(t, err)
	})

	t.Run("error when mission is nil", func(t *testing.T) {
		err := linker.CreateRun(ctx, "test-mission", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission cannot be nil")
	})

	t.Run("error when name is empty", func(t *testing.T) {
		mission := &Mission{
			ID:                  types.NewID(),
			Status:              MissionStatusPending,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}

		err := linker.CreateRun(ctx, "", mission)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission name cannot be empty")
	})
}

func TestMissionRunLinker_GetRunHistory(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	linker := NewMissionRunLinker(store)
	ctx := context.Background()

	t.Run("returns runs in descending order", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create 3 runs with different timestamps
		missionIDs := make([]types.ID, 3)
		for i := 0; i < 3; i++ {
			mission := &Mission{
				ID:                  types.NewID(),
				Description:         "Run " + string(rune(i+1)),
				Status:              MissionStatusCompleted,
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				CreatedAt:           time.Now().Add(time.Duration(i) * time.Second),
				UpdatedAt:           time.Now().Add(time.Duration(i) * time.Second),
			}
			completedAt := time.Now()
			mission.CompletedAt = &completedAt
			missionIDs[i] = mission.ID

			err := linker.CreateRun(ctx, missionName, mission)
			require.NoError(t, err)
		}

		// Get run history
		history, err := linker.GetRunHistory(ctx, missionName)
		require.NoError(t, err)
		require.Len(t, history, 3)

		// Verify ordering (most recent first)
		assert.Equal(t, missionIDs[2], history[0].MissionID)
		assert.Equal(t, missionIDs[1], history[1].MissionID)
		assert.Equal(t, missionIDs[0], history[2].MissionID)

		// Verify run numbers
		assert.Equal(t, 3, history[0].RunNumber)
		assert.Equal(t, 2, history[1].RunNumber)
		assert.Equal(t, 1, history[2].RunNumber)
	})

	t.Run("previous_run_id links correctly", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create 3 linked runs
		var previousID *types.ID
		for i := 0; i < 3; i++ {
			mission := &Mission{
				ID:                  types.NewID(),
				Description:         "Run " + string(rune(i+1)),
				Status:              MissionStatusCompleted,
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				CreatedAt:           time.Now().Add(time.Duration(i) * time.Second),
				UpdatedAt:           time.Now().Add(time.Duration(i) * time.Second),
			}
			completedAt := time.Now()
			mission.CompletedAt = &completedAt

			err := linker.CreateRun(ctx, missionName, mission)
			require.NoError(t, err)

			if i > 0 {
				require.NotNil(t, previousID, "Previous ID should be set for run %d", i+1)
			}

			previousID = &mission.ID
		}

		// Get run history
		history, err := linker.GetRunHistory(ctx, missionName)
		require.NoError(t, err)
		require.Len(t, history, 3)

		// Verify linkage (in reverse order since history is descending)
		// Run 1 (history[2]) should have no previous
		assert.Nil(t, history[2].PreviousRunID)

		// Run 2 (history[1]) should link to Run 1
		require.NotNil(t, history[1].PreviousRunID)
		assert.Equal(t, history[2].MissionID, *history[1].PreviousRunID)

		// Run 3 (history[0]) should link to Run 2
		require.NotNil(t, history[0].PreviousRunID)
		assert.Equal(t, history[1].MissionID, *history[0].PreviousRunID)
	})

	t.Run("empty history for non-existent mission", func(t *testing.T) {
		history, err := linker.GetRunHistory(ctx, "non-existent-mission")
		require.NoError(t, err)
		assert.Len(t, history, 0)
	})

	t.Run("error when name is empty", func(t *testing.T) {
		_, err := linker.GetRunHistory(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission name cannot be empty")
	})

	t.Run("includes status and timestamps", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a completed run
		createdTime := time.Now()
		completedTime := createdTime.Add(5 * time.Minute)

		mission := &Mission{
			ID:                  types.NewID(),
			Description:         "Test mission",
			Status:              MissionStatusCompleted,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           createdTime,
			UpdatedAt:           createdTime,
			CompletedAt:         &completedTime,
		}

		err := linker.CreateRun(ctx, missionName, mission)
		require.NoError(t, err)

		// Get run history
		history, err := linker.GetRunHistory(ctx, missionName)
		require.NoError(t, err)
		require.Len(t, history, 1)

		run := history[0]
		assert.Equal(t, MissionStatusCompleted, run.Status)
		assert.WithinDuration(t, createdTime, run.CreatedAt, 1*time.Second)
		require.NotNil(t, run.CompletedAt)
		assert.WithinDuration(t, completedTime, *run.CompletedAt, 1*time.Second)
	})
}

func TestMissionRunLinker_GetLatestRun(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	linker := NewMissionRunLinker(store)
	ctx := context.Background()

	t.Run("returns most recent run", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create 3 runs
		var latestID types.ID
		for i := 0; i < 3; i++ {
			mission := &Mission{
				ID:                  types.NewID(),
				Description:         "Run " + string(rune(i+1)),
				Status:              MissionStatusCompleted,
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				CreatedAt:           time.Now().Add(time.Duration(i) * time.Second),
				UpdatedAt:           time.Now().Add(time.Duration(i) * time.Second),
			}
			completedAt := time.Now()
			mission.CompletedAt = &completedAt

			err := linker.CreateRun(ctx, missionName, mission)
			require.NoError(t, err)

			latestID = mission.ID
		}

		// Get latest run
		latest, err := linker.GetLatestRun(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, latestID, latest.ID)
	})

	t.Run("error for non-existent mission", func(t *testing.T) {
		_, err := linker.GetLatestRun(ctx, "non-existent-mission")
		require.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("error when name is empty", func(t *testing.T) {
		_, err := linker.GetLatestRun(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission name cannot be empty")
	})
}

func TestMissionRunLinker_GetActiveRun(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	linker := NewMissionRunLinker(store)
	ctx := context.Background()

	t.Run("returns running mission", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a running mission
		runningMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Running mission",
			Status:              MissionStatusRunning,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		startedAt := time.Now()
		runningMission.StartedAt = &startedAt

		err := linker.CreateRun(ctx, missionName, runningMission)
		require.NoError(t, err)

		// Get active run
		active, err := linker.GetActiveRun(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, runningMission.ID, active.ID)
		assert.Equal(t, MissionStatusRunning, active.Status)
	})

	t.Run("returns paused mission", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a paused mission
		pausedMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Paused mission",
			Status:              MissionStatusPaused,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		startedAt := time.Now()
		pausedMission.StartedAt = &startedAt

		err := linker.CreateRun(ctx, missionName, pausedMission)
		require.NoError(t, err)

		// Get active run
		active, err := linker.GetActiveRun(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, pausedMission.ID, active.ID)
		assert.Equal(t, MissionStatusPaused, active.Status)
	})

	t.Run("prefers running over paused", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a paused mission first
		pausedMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Paused mission",
			Status:              MissionStatusPaused,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		startedAt := time.Now()
		pausedMission.StartedAt = &startedAt

		err := linker.CreateRun(ctx, missionName, pausedMission)
		require.NoError(t, err)

		// Update to completed to allow new run
		pausedMission.Status = MissionStatusCompleted
		completedAt := time.Now()
		pausedMission.CompletedAt = &completedAt
		err = store.Update(ctx, pausedMission)
		require.NoError(t, err)

		// Create a running mission
		runningMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Running mission",
			Status:              MissionStatusRunning,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now().Add(1 * time.Second),
			UpdatedAt:           time.Now().Add(1 * time.Second),
		}
		startedAt2 := time.Now()
		runningMission.StartedAt = &startedAt2

		err = linker.CreateRun(ctx, missionName, runningMission)
		require.NoError(t, err)

		// Get active run (should return running, not paused)
		active, err := linker.GetActiveRun(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, runningMission.ID, active.ID)
		assert.Equal(t, MissionStatusRunning, active.Status)
	})

	t.Run("error when no active run exists", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		// Create a completed mission
		completedMission := &Mission{
			ID:                  types.NewID(),
			Description:         "Completed mission",
			Status:              MissionStatusCompleted,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		completedAt := time.Now()
		completedMission.CompletedAt = &completedAt

		err := linker.CreateRun(ctx, missionName, completedMission)
		require.NoError(t, err)

		// Get active run (should return error)
		_, err = linker.GetActiveRun(ctx, missionName)
		require.Error(t, err)
		assert.True(t, IsNotFoundError(err))
		assert.Contains(t, err.Error(), "no active run")
	})

	t.Run("error for non-existent mission", func(t *testing.T) {
		_, err := linker.GetActiveRun(ctx, "non-existent-mission")
		require.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("error when name is empty", func(t *testing.T) {
		_, err := linker.GetActiveRun(ctx, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission name cannot be empty")
	})
}

func TestMissionRunLinker_EdgeCases(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	linker := NewMissionRunLinker(store)
	ctx := context.Background()

	t.Run("first run has no previous_run_id", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		mission := &Mission{
			ID:                  types.NewID(),
			Description:         "First run",
			Status:              MissionStatusCompleted,
			TargetID:            types.NewID(),
			MissionDefinitionID: types.NewID(),
			CreatedAt:           time.Now(),
			UpdatedAt:           time.Now(),
		}
		completedAt := time.Now()
		mission.CompletedAt = &completedAt

		err := linker.CreateRun(ctx, missionName, mission)
		require.NoError(t, err)

		// Get the mission and verify no previous run ID
		saved, err := store.Get(ctx, mission.ID)
		require.NoError(t, err)

		_, hasPrevious := saved.Metadata["previous_run_id"]
		assert.False(t, hasPrevious, "First run should not have previous_run_id")

		// Also verify through history
		history, err := linker.GetRunHistory(ctx, missionName)
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Nil(t, history[0].PreviousRunID, "First run should have nil PreviousRunID")
	})

	t.Run("handles missions with mixed statuses in history", func(t *testing.T) {
		missionName := "test-mission-" + types.NewID().String()[:8]

		statuses := []MissionStatus{
			MissionStatusCompleted,
			MissionStatusFailed,
			MissionStatusCancelled,
		}

		for i, status := range statuses {
			mission := &Mission{
				ID:                  types.NewID(),
				Description:         "Run with status " + string(status),
				Status:              status,
				TargetID:            types.NewID(),
				MissionDefinitionID: types.NewID(),
				CreatedAt:           time.Now().Add(time.Duration(i) * time.Second),
				UpdatedAt:           time.Now().Add(time.Duration(i) * time.Second),
			}
			completedAt := time.Now()
			mission.CompletedAt = &completedAt

			err := linker.CreateRun(ctx, missionName, mission)
			require.NoError(t, err)
		}

		// Get run history
		history, err := linker.GetRunHistory(ctx, missionName)
		require.NoError(t, err)
		require.Len(t, history, 3)

		// Verify statuses
		assert.Equal(t, MissionStatusCancelled, history[0].Status)
		assert.Equal(t, MissionStatusFailed, history[1].Status)
		assert.Equal(t, MissionStatusCompleted, history[2].Status)
	})
}
