//go:build stale
// +build stale

// NOTE: references the removed DB-backed mission store constructors
// (NewDBMissionStore / NewDBEventStore). Kept behind the `stale` build
// tag so the file is preserved for future repair but does not block
// `go vet` / `go test`. Rewrite against the Redis store and drop the tag.

package mission

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

func setupTestDB(t *testing.T) *database.DB {
	t.Helper()

	// Create temporary database file
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Open database
	db, err := database.Open(dbPath)
	require.NoError(t, err)

	// Initialize schema
	err = db.InitSchema()
	require.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		os.Remove(dbPath)
	})

	return db
}

func createTestMission(t *testing.T) *Mission {
	t.Helper()

	return &Mission{
		ID:                  types.NewID(),
		Name:                "test-mission-" + types.NewID().String()[:8],
		Description:         "Test mission description",
		Status:              MissionStatusPending,
		TargetID:            types.NewID(),
		MissionDefinitionID: types.NewID(),
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
	}
}

func TestDBMissionStore_Save(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	mission := createTestMission(t)

	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Verify mission was saved
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.Equal(t, mission.ID, retrieved.ID)
	assert.Equal(t, mission.Name, retrieved.Name)
	assert.Equal(t, mission.Status, retrieved.Status)
}

func TestDBMissionStore_Get(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	t.Run("existing mission", func(t *testing.T) {
		mission := createTestMission(t)
		err := store.Save(ctx, mission)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, mission.ID)
		require.NoError(t, err)
		assert.Equal(t, mission.ID, retrieved.ID)
	})

	t.Run("non-existent mission", func(t *testing.T) {
		_, err := store.Get(ctx, types.NewID())
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})
}

func TestDBMissionStore_List(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	// Create test missions
	missions := []*Mission{
		createTestMission(t),
		createTestMission(t),
		createTestMission(t),
	}

	for _, m := range missions {
		err := store.Save(ctx, m)
		require.NoError(t, err)
	}

	t.Run("list all", func(t *testing.T) {
		filter := NewMissionFilter()
		results, err := store.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 3)
	})

	t.Run("filter by status", func(t *testing.T) {
		filter := NewMissionFilter().WithStatus(MissionStatusPending)
		results, err := store.List(ctx, filter)
		require.NoError(t, err)
		for _, m := range results {
			assert.Equal(t, MissionStatusPending, m.Status)
		}
	})

	t.Run("pagination", func(t *testing.T) {
		filter := NewMissionFilter().WithPagination(2, 0)
		results, err := store.List(ctx, filter)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(results), 2)
	})
}

func TestDBMissionStore_Update(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	mission := createTestMission(t)
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Update mission
	mission.Status = MissionStatusRunning
	mission.Description = "Updated description"
	startedAt := time.Now()
	mission.StartedAt = &startedAt

	err = store.Update(ctx, mission)
	require.NoError(t, err)

	// Verify update
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.Equal(t, MissionStatusRunning, retrieved.Status)
	assert.Equal(t, "Updated description", retrieved.Description)
	assert.NotNil(t, retrieved.StartedAt)
}

func TestDBMissionStore_Delete(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	t.Run("delete terminal mission", func(t *testing.T) {
		mission := createTestMission(t)
		mission.Status = MissionStatusCompleted
		err := store.Save(ctx, mission)
		require.NoError(t, err)

		err = store.Delete(ctx, mission.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = store.Get(ctx, mission.ID)
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("cannot delete non-terminal mission", func(t *testing.T) {
		mission := createTestMission(t)
		mission.Status = MissionStatusRunning
		err := store.Save(ctx, mission)
		require.NoError(t, err)

		err = store.Delete(ctx, mission.ID)
		assert.Error(t, err)
		assert.True(t, IsInvalidStateError(err))
	})
}

func TestDBMissionStore_GetByTarget(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	targetID := types.NewID()

	// Create missions with same target
	for i := 0; i < 3; i++ {
		mission := createTestMission(t)
		mission.TargetID = targetID
		err := store.Save(ctx, mission)
		require.NoError(t, err)
	}

	results, err := store.GetByTarget(ctx, targetID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 3)
	for _, m := range results {
		assert.Equal(t, targetID, m.TargetID)
	}
}

func TestDBMissionStore_GetActive(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	// Create running mission
	running := createTestMission(t)
	running.Status = MissionStatusRunning
	err := store.Save(ctx, running)
	require.NoError(t, err)

	// Create paused mission
	paused := createTestMission(t)
	paused.Status = MissionStatusPaused
	err = store.Save(ctx, paused)
	require.NoError(t, err)

	// Create completed mission (should not be returned)
	completed := createTestMission(t)
	completed.Status = MissionStatusCompleted
	err = store.Save(ctx, completed)
	require.NoError(t, err)

	results, err := store.GetActive(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2)

	for _, m := range results {
		assert.True(t, m.Status == MissionStatusRunning || m.Status == MissionStatusPaused)
	}
}

func TestDBMissionStore_SaveCheckpoint(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	mission := createTestMission(t)
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	checkpoint := &MissionCheckpoint{
		CompletedNodes: []string{"node1", "node2"},
		PendingNodes:   []string{"node3", "node4"},
		LastNodeID:     "node2",
		CheckpointedAt: time.Now(),
		MissionState:   map[string]any{"key": "value"},
		NodeResults:    map[string]any{"node1": "result1"},
	}

	err = store.SaveCheckpoint(ctx, mission.ID, checkpoint)
	require.NoError(t, err)

	// Verify checkpoint was saved
	retrieved, err := store.Get(ctx, mission.ID)
	require.NoError(t, err)
	assert.NotNil(t, retrieved.Checkpoint)
	assert.Equal(t, checkpoint.LastNodeID, retrieved.Checkpoint.LastNodeID)
	assert.Equal(t, len(checkpoint.CompletedNodes), len(retrieved.Checkpoint.CompletedNodes))
}

func TestDBMissionStore_Count(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	// Create test missions
	for i := 0; i < 5; i++ {
		mission := createTestMission(t)
		err := store.Save(ctx, mission)
		require.NoError(t, err)
	}

	count, err := store.Count(ctx, NewMissionFilter())
	require.NoError(t, err)
	assert.GreaterOrEqual(t, count, 5)
}

func TestMissionFilter(t *testing.T) {
	filter := NewMissionFilter()
	assert.Equal(t, 100, filter.Limit)
	assert.Equal(t, 0, filter.Offset)

	filter = filter.
		WithStatus(MissionStatusRunning).
		WithPagination(50, 10)

	assert.Equal(t, MissionStatusRunning, *filter.Status)
	assert.Equal(t, 50, filter.Limit)
	assert.Equal(t, 10, filter.Offset)
}

func TestDBMissionStore_GetByNameAndStatus(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	missionName := "test-mission-" + types.NewID().String()[:8]

	// Create missions with same name but different statuses
	pendingMission := createTestMission(t)
	pendingMission.Name = missionName
	pendingMission.Status = MissionStatusPending
	err := store.Save(ctx, pendingMission)
	require.NoError(t, err)

	runningMission := createTestMission(t)
	runningMission.Name = missionName
	runningMission.Status = MissionStatusRunning
	err = store.Save(ctx, runningMission)
	require.NoError(t, err)

	completedMission := createTestMission(t)
	completedMission.Name = missionName
	completedMission.Status = MissionStatusCompleted
	err = store.Save(ctx, completedMission)
	require.NoError(t, err)

	t.Run("get pending mission", func(t *testing.T) {
		retrieved, err := store.GetByNameAndStatus(ctx, missionName, MissionStatusPending)
		require.NoError(t, err)
		assert.Equal(t, pendingMission.ID, retrieved.ID)
		assert.Equal(t, MissionStatusPending, retrieved.Status)
	})

	t.Run("get running mission", func(t *testing.T) {
		retrieved, err := store.GetByNameAndStatus(ctx, missionName, MissionStatusRunning)
		require.NoError(t, err)
		assert.Equal(t, runningMission.ID, retrieved.ID)
		assert.Equal(t, MissionStatusRunning, retrieved.Status)
	})

	t.Run("get completed mission", func(t *testing.T) {
		retrieved, err := store.GetByNameAndStatus(ctx, missionName, MissionStatusCompleted)
		require.NoError(t, err)
		assert.Equal(t, completedMission.ID, retrieved.ID)
		assert.Equal(t, MissionStatusCompleted, retrieved.Status)
	})

	t.Run("non-existent name and status combination", func(t *testing.T) {
		_, err := store.GetByNameAndStatus(ctx, missionName, MissionStatusFailed)
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("non-existent name", func(t *testing.T) {
		_, err := store.GetByNameAndStatus(ctx, "non-existent-mission", MissionStatusPending)
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})
}

func TestDBMissionStore_ListByName(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	missionName := "test-mission-" + types.NewID().String()[:8]

	// Create multiple missions with same name but different run numbers
	missions := make([]*Mission, 5)
	for i := 0; i < 5; i++ {
		mission := createTestMission(t)
		mission.Name = missionName
		mission.RunNumber = i + 1
		mission.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		err := store.Save(ctx, mission)
		require.NoError(t, err)
		missions[i] = mission
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	t.Run("list all runs for name", func(t *testing.T) {
		results, err := store.ListByName(ctx, missionName, 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 5)

		// Verify ordering (descending by run_number, highest first)
		for i := 0; i < len(results)-1; i++ {
			assert.True(t, results[i].RunNumber >= results[i+1].RunNumber,
				"Results should be ordered by run_number DESC")
		}
	})

	t.Run("list with limit", func(t *testing.T) {
		results, err := store.ListByName(ctx, missionName, 3)
		require.NoError(t, err)
		assert.Equal(t, 3, len(results))

		// Should get the 3 highest run numbers
		for i := 0; i < len(results)-1; i++ {
			assert.True(t, results[i].RunNumber >= results[i+1].RunNumber)
		}
	})

	t.Run("list non-existent mission name", func(t *testing.T) {
		results, err := store.ListByName(ctx, "non-existent-mission", 10)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("list with zero limit uses default", func(t *testing.T) {
		results, err := store.ListByName(ctx, missionName, 0)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(results), 5)
	})
}

func TestDBMissionStore_GetLatestByName(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	missionName := "test-mission-" + types.NewID().String()[:8]

	// Create missions with different run numbers
	var latestMission *Mission
	for i := 0; i < 3; i++ {
		mission := createTestMission(t)
		mission.Name = missionName
		mission.Description = fmt.Sprintf("Run %d", i+1)
		mission.RunNumber = i + 1
		err := store.Save(ctx, mission)
		require.NoError(t, err)
		latestMission = mission
		time.Sleep(10 * time.Millisecond) // Ensure different timestamps
	}

	t.Run("get latest mission", func(t *testing.T) {
		retrieved, err := store.GetLatestByName(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, latestMission.ID, retrieved.ID)
		assert.Equal(t, "Run 3", retrieved.Description)
		assert.Equal(t, missionName, retrieved.Name)
		assert.Equal(t, 3, retrieved.RunNumber)
	})

	t.Run("non-existent mission name", func(t *testing.T) {
		_, err := store.GetLatestByName(ctx, "non-existent-mission")
		assert.Error(t, err)
		assert.True(t, IsNotFoundError(err))
	})
}

func TestDBMissionStore_IncrementRunNumber(t *testing.T) {
	db := setupTestDB(t)
	store := NewDBMissionStore(db)
	ctx := context.Background()

	missionName := "test-mission-" + types.NewID().String()[:8]

	t.Run("first run number is 1", func(t *testing.T) {
		runNumber, err := store.IncrementRunNumber(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, 1, runNumber)
	})

	t.Run("increment from existing runs", func(t *testing.T) {
		// Create missions with run numbers using the run_number column
		for i := 1; i <= 3; i++ {
			mission := createTestMission(t)
			mission.Name = missionName
			mission.RunNumber = i
			err := store.Save(ctx, mission)
			require.NoError(t, err)
		}

		// Next run number should be 4
		runNumber, err := store.IncrementRunNumber(ctx, missionName)
		require.NoError(t, err)
		assert.Equal(t, 4, runNumber)
	})

	t.Run("get next run number for concurrent saves", func(t *testing.T) {
		testName := "concurrent-mission-" + types.NewID().String()[:8]

		// IncrementRunNumber returns the next available run number
		// Without any existing missions, all calls should return 1
		// (atomicity is achieved at the CreateRun level, not here)
		runNumber, err := store.IncrementRunNumber(ctx, testName)
		require.NoError(t, err)
		assert.Equal(t, 1, runNumber)

		// Save a mission with run number 1
		mission := createTestMission(t)
		mission.Name = testName
		mission.RunNumber = 1
		err = store.Save(ctx, mission)
		require.NoError(t, err)

		// Now next run number should be 2
		runNumber, err = store.IncrementRunNumber(ctx, testName)
		require.NoError(t, err)
		assert.Equal(t, 2, runNumber)
	})

	t.Run("increment for missions with run_number column", func(t *testing.T) {
		testName := "run-number-column-" + types.NewID().String()[:8]

		// Create missions with run_number column values
		mission1 := createTestMission(t)
		mission1.Name = testName
		mission1.RunNumber = 1
		mission1.Metadata = map[string]any{"other": "data"}
		err := store.Save(ctx, mission1)
		require.NoError(t, err)

		mission2 := createTestMission(t)
		mission2.Name = testName
		mission2.RunNumber = 2
		err = store.Save(ctx, mission2)
		require.NoError(t, err)

		runNumber, err := store.IncrementRunNumber(ctx, testName)
		require.NoError(t, err)
		assert.Equal(t, 3, runNumber)
	})
}
