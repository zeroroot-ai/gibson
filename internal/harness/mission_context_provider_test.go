package harness

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ────────────────────────────────────────────────────────────────────────────
// Mock Mission Store
// ────────────────────────────────────────────────────────────────────────────

// mockMissionStore is a test implementation of MissionStore.
type mockMissionStore struct {
	missions       map[types.ID]MissionData
	missionsByName map[string][]MissionData
}

// newMockMissionStore creates a new mock store for testing.
func newMockMissionStore() *mockMissionStore {
	return &mockMissionStore{
		missions:       make(map[types.ID]MissionData),
		missionsByName: make(map[string][]MissionData),
	}
}

// addMission adds a mission to the mock store.
func (m *mockMissionStore) addMission(mission MissionData) {
	m.missions[mission.ID] = mission
	m.missionsByName[mission.Name] = append(m.missionsByName[mission.Name], mission)
}

// Get retrieves a mission by ID.
func (m *mockMissionStore) Get(ctx context.Context, id types.ID) (MissionData, error) {
	mission, ok := m.missions[id]
	if !ok {
		return MissionData{}, &notFoundError{id: id.String()}
	}
	return mission, nil
}

// ListByName retrieves all missions with the given name, ordered by run number descending.
func (m *mockMissionStore) ListByName(ctx context.Context, name string, limit int) ([]MissionData, error) {
	missions := m.missionsByName[name]
	if missions == nil {
		return []MissionData{}, nil
	}

	// Sort by run number descending (most recent first)
	sorted := make([]MissionData, len(missions))
	copy(sorted, missions)

	// Simple bubble sort for test data
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].RunNumber > sorted[i].RunNumber {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && len(sorted) > limit {
		sorted = sorted[:limit]
	}

	return sorted, nil
}

// notFoundError simulates a not found error.
type notFoundError struct {
	id string
}

func (e *notFoundError) Error() string {
	return "mission not found: " + e.id
}

// ────────────────────────────────────────────────────────────────────────────
// Test Helper Functions
// ────────────────────────────────────────────────────────────────────────────

// createTestMission creates a test mission with sensible defaults.
func createTestMission(name string, runNumber int) MissionData {
	return MissionData{
		ID:            types.NewID(),
		Name:          name,
		Status:        "completed",
		RunNumber:     runNumber,
		FindingsCount: 0,
		CreatedAt:     time.Now().Add(-time.Duration(runNumber) * time.Hour),
	}
}

// createTestMissionWithFindings creates a test mission with findings.
func createTestMissionWithFindings(name string, runNumber int, findingsCount int) MissionData {
	mission := createTestMission(name, runNumber)
	mission.FindingsCount = findingsCount
	return mission
}

// createTestMissionWithCheckpoint creates a test mission with a checkpoint.
func createTestMissionWithCheckpoint(name string, runNumber int, lastNodeID string) MissionData {
	mission := createTestMission(name, runNumber)
	mission.Checkpoint = &MissionCheckpointData{
		LastNodeID: lastNodeID,
	}
	return mission
}

// createTestMissionWithPreviousRun creates a test mission linked to a previous run.
func createTestMissionWithPreviousRun(name string, runNumber int, previousRunID types.ID) MissionData {
	mission := createTestMission(name, runNumber)
	mission.PreviousRunID = &previousRunID
	return mission
}

// ────────────────────────────────────────────────────────────────────────────
// GetContext Tests
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContextProvider_GetContext(t *testing.T) {
	ctx := context.Background()

	t.Run("first run context", func(t *testing.T) {
		// Setup mission with RunNumber=1, no PreviousRunID, no Checkpoint
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)
		require.NotNil(t, execCtx)

		// Assert - first run characteristics
		assert.Equal(t, mission.ID, execCtx.MissionID)
		assert.Equal(t, mission.Name, execCtx.MissionName)
		assert.Equal(t, 1, execCtx.RunNumber)
		assert.False(t, execCtx.IsResumed, "first run should not be resumed")
		assert.Empty(t, execCtx.ResumedFromNode, "first run has no resumed node")
		assert.Nil(t, execCtx.PreviousRunID, "first run has no previous run")
		assert.Empty(t, execCtx.PreviousRunStatus, "first run has no previous status")
		assert.Equal(t, 0, execCtx.TotalFindingsAllRuns)
		assert.Equal(t, "first_run", execCtx.MemoryContinuity)
	})

	t.Run("resumed run context", func(t *testing.T) {
		// Setup mission with Checkpoint set
		store := newMockMissionStore()
		mission := createTestMissionWithCheckpoint("test-mission", 1, "recon-node")
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)
		require.NotNil(t, execCtx)

		// Assert - resumed run characteristics
		assert.True(t, execCtx.IsResumed, "mission with checkpoint should be resumed")
		assert.Equal(t, "recon-node", execCtx.ResumedFromNode)
		assert.Equal(t, "resumed", execCtx.MemoryContinuity)
	})

	t.Run("subsequent run context", func(t *testing.T) {
		// Setup mission with RunNumber=3, PreviousRunID set
		store := newMockMissionStore()

		// Create previous run
		previousMission := createTestMission("test-mission", 2)
		previousMission.Status = "completed"
		store.addMission(previousMission)

		// Create current run
		currentMission := createTestMissionWithPreviousRun("test-mission", 3, previousMission.ID)
		store.addMission(currentMission)

		provider := NewMissionContextProvider(store, currentMission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)
		require.NotNil(t, execCtx)

		// Assert - subsequent run characteristics
		assert.Equal(t, 3, execCtx.RunNumber)
		assert.NotNil(t, execCtx.PreviousRunID)
		assert.Equal(t, previousMission.ID, *execCtx.PreviousRunID)
		assert.Equal(t, "completed", execCtx.PreviousRunStatus)
		assert.Equal(t, "new_run_with_history", execCtx.MemoryContinuity)
	})

	t.Run("accumulates findings across runs", func(t *testing.T) {
		// Setup 3 runs with findings
		store := newMockMissionStore()

		// Run 1: 5 findings
		run1 := createTestMissionWithFindings("test-mission", 1, 5)
		store.addMission(run1)

		// Run 2: 3 findings
		run2 := createTestMissionWithFindings("test-mission", 2, 3)
		run2.PreviousRunID = &run1.ID
		store.addMission(run2)

		// Run 3 (current): 7 findings
		run3 := createTestMissionWithFindings("test-mission", 3, 7)
		run3.PreviousRunID = &run2.ID
		store.addMission(run3)

		provider := NewMissionContextProvider(store, run3, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)
		require.NotNil(t, execCtx)

		// Assert - total findings is sum of all runs (5 + 3 + 7 = 15)
		assert.Equal(t, 15, execCtx.TotalFindingsAllRuns)
	})

	t.Run("caches context on subsequent calls", func(t *testing.T) {
		// Setup
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// First call
		ctx1, err := provider.GetContext(ctx)
		require.NoError(t, err)

		// Second call
		ctx2, err := provider.GetContext(ctx)
		require.NoError(t, err)

		// Assert - should return same instance (pointer equality)
		assert.Same(t, ctx1, ctx2, "context should be cached")
	})

	t.Run("handles previous run retrieval error gracefully", func(t *testing.T) {
		// Setup mission with PreviousRunID that doesn't exist in store
		store := newMockMissionStore()
		nonExistentID := types.NewID()
		mission := createTestMissionWithPreviousRun("test-mission", 2, nonExistentID)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute - should not error even though previous run doesn't exist
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)
		require.NotNil(t, execCtx)

		// Assert - PreviousRunID is set but status is empty
		assert.NotNil(t, execCtx.PreviousRunID)
		assert.Empty(t, execCtx.PreviousRunStatus)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// GetRunHistory Tests
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContextProvider_GetRunHistory(t *testing.T) {
	ctx := context.Background()

	t.Run("returns all runs in order", func(t *testing.T) {
		// Setup 3 runs with different run numbers
		store := newMockMissionStore()

		run1 := createTestMission("test-mission", 1)
		run2 := createTestMission("test-mission", 2)
		run3 := createTestMission("test-mission", 3)

		store.addMission(run1)
		store.addMission(run2)
		store.addMission(run3)

		provider := NewMissionContextProvider(store, run3, noopLogger())

		// Execute
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)
		require.Len(t, history, 3)

		// Assert - returns 3 summaries in descending order (most recent first)
		assert.Equal(t, 3, history[0].RunNumber)
		assert.Equal(t, 2, history[1].RunNumber)
		assert.Equal(t, 1, history[2].RunNumber)

		// Verify run details
		assert.Equal(t, run3.ID, history[0].MissionID)
		assert.Equal(t, run2.ID, history[1].MissionID)
		assert.Equal(t, run1.ID, history[2].MissionID)
	})

	t.Run("empty for first run", func(t *testing.T) {
		// Setup single run
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)

		// Assert - returns 1 run (current)
		require.Len(t, history, 1)
		assert.Equal(t, mission.ID, history[0].MissionID)
		assert.Equal(t, 1, history[0].RunNumber)
	})

	t.Run("includes findings count in summaries", func(t *testing.T) {
		// Setup runs with different findings counts
		store := newMockMissionStore()

		run1 := createTestMissionWithFindings("test-mission", 1, 10)
		run2 := createTestMissionWithFindings("test-mission", 2, 5)

		store.addMission(run1)
		store.addMission(run2)

		provider := NewMissionContextProvider(store, run2, noopLogger())

		// Execute
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)
		require.Len(t, history, 2)

		// Assert - findings counts are included
		assert.Equal(t, 5, history[0].FindingsCount)  // run2
		assert.Equal(t, 10, history[1].FindingsCount) // run1
	})

	t.Run("includes status and timestamps", func(t *testing.T) {
		// Setup run with specific status
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		mission.Status = "completed"
		completedTime := time.Now()
		mission.CompletedAt = &completedTime
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)
		require.Len(t, history, 1)

		// Assert - status and timestamps are included
		assert.Equal(t, "completed", history[0].Status)
		assert.NotNil(t, history[0].CompletedAt)
		assert.Equal(t, completedTime, *history[0].CompletedAt)
	})

	t.Run("respects limit parameter", func(t *testing.T) {
		// Setup many runs
		store := newMockMissionStore()
		for i := 1; i <= 150; i++ {
			mission := createTestMission("test-mission", i)
			store.addMission(mission)
		}

		lastMission := createTestMission("test-mission", 150)
		provider := NewMissionContextProvider(store, lastMission, noopLogger())

		// Execute - default limit is 100
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)

		// Assert - should be limited to 100
		assert.LessOrEqual(t, len(history), 100)
	})

	t.Run("only returns runs for same mission name", func(t *testing.T) {
		// Setup runs with different mission names
		store := newMockMissionStore()

		mission1 := createTestMission("mission-a", 1)
		mission2 := createTestMission("mission-a", 2)
		mission3 := createTestMission("mission-b", 1)

		store.addMission(mission1)
		store.addMission(mission2)
		store.addMission(mission3)

		provider := NewMissionContextProvider(store, mission2, noopLogger())

		// Execute
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)

		// Assert - only returns mission-a runs
		require.Len(t, history, 2)
		assert.Equal(t, "mission-a", mission1.Name)
		assert.Equal(t, "mission-a", mission2.Name)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// GetPreviousRun Tests
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContextProvider_GetPreviousRun(t *testing.T) {
	ctx := context.Background()

	t.Run("returns previous run", func(t *testing.T) {
		// Setup with PreviousRunID
		store := newMockMissionStore()

		previousMission := createTestMissionWithFindings("test-mission", 1, 8)
		previousMission.Status = "completed"
		store.addMission(previousMission)

		currentMission := createTestMissionWithPreviousRun("test-mission", 2, previousMission.ID)
		store.addMission(currentMission)

		provider := NewMissionContextProvider(store, currentMission, noopLogger())

		// Execute
		prevRun, err := provider.GetPreviousRun(ctx)
		require.NoError(t, err)
		require.NotNil(t, prevRun)

		// Assert - returns previous run summary
		assert.Equal(t, previousMission.ID, prevRun.MissionID)
		assert.Equal(t, 1, prevRun.RunNumber)
		assert.Equal(t, "completed", prevRun.Status)
		assert.Equal(t, 8, prevRun.FindingsCount)
	})

	t.Run("returns nil for first run", func(t *testing.T) {
		// Setup with no PreviousRunID
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		prevRun, err := provider.GetPreviousRun(ctx)
		require.NoError(t, err)

		// Assert - returns nil, no error
		assert.Nil(t, prevRun)
	})

	t.Run("returns nil when previous run not found", func(t *testing.T) {
		// Setup with PreviousRunID that doesn't exist
		store := newMockMissionStore()
		nonExistentID := types.NewID()
		mission := createTestMissionWithPreviousRun("test-mission", 2, nonExistentID)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		prevRun, err := provider.GetPreviousRun(ctx)
		require.NoError(t, err)

		// Assert - returns nil gracefully (logs warning but doesn't error)
		assert.Nil(t, prevRun)
	})

	t.Run("includes all run summary fields", func(t *testing.T) {
		// Setup with complete previous run data
		store := newMockMissionStore()

		previousMission := createTestMissionWithFindings("test-mission", 1, 12)
		previousMission.Status = "failed"
		completedTime := time.Now().Add(-2 * time.Hour)
		previousMission.CompletedAt = &completedTime
		store.addMission(previousMission)

		currentMission := createTestMissionWithPreviousRun("test-mission", 2, previousMission.ID)
		store.addMission(currentMission)

		provider := NewMissionContextProvider(store, currentMission, noopLogger())

		// Execute
		prevRun, err := provider.GetPreviousRun(ctx)
		require.NoError(t, err)
		require.NotNil(t, prevRun)

		// Assert - all fields are populated
		assert.Equal(t, previousMission.ID, prevRun.MissionID)
		assert.Equal(t, 1, prevRun.RunNumber)
		assert.Equal(t, "failed", prevRun.Status)
		assert.Equal(t, 12, prevRun.FindingsCount)
		assert.NotNil(t, prevRun.CompletedAt)
		assert.Equal(t, completedTime, *prevRun.CompletedAt)
		assert.Equal(t, previousMission.CreatedAt, prevRun.CreatedAt)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// IsResumedRun Tests
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContextProvider_IsResumedRun(t *testing.T) {
	t.Run("true when checkpoint exists", func(t *testing.T) {
		// Setup mission with checkpoint
		store := newMockMissionStore()
		mission := createTestMissionWithCheckpoint("test-mission", 1, "exploit-node")
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		isResumed := provider.IsResumedRun()

		// Assert
		assert.True(t, isResumed)
	})

	t.Run("false when no checkpoint", func(t *testing.T) {
		// Setup mission without checkpoint
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		isResumed := provider.IsResumedRun()

		// Assert
		assert.False(t, isResumed)
	})

	t.Run("false when checkpoint is nil", func(t *testing.T) {
		// Setup mission with explicitly nil checkpoint
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		mission.Checkpoint = nil
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		isResumed := provider.IsResumedRun()

		// Assert
		assert.False(t, isResumed)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Memory Continuity Tests
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContextProvider_MemoryContinuity(t *testing.T) {
	ctx := context.Background()

	t.Run("first_run for new mission", func(t *testing.T) {
		// Setup first run
		store := newMockMissionStore()
		mission := createTestMission("test-mission", 1)
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)

		// Assert
		assert.Equal(t, "first_run", execCtx.MemoryContinuity)
	})

	t.Run("resumed for checkpoint mission", func(t *testing.T) {
		// Setup resumed run
		store := newMockMissionStore()
		mission := createTestMissionWithCheckpoint("test-mission", 1, "analysis-node")
		store.addMission(mission)

		provider := NewMissionContextProvider(store, mission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)

		// Assert
		assert.Equal(t, "resumed", execCtx.MemoryContinuity)
	})

	t.Run("new_run_with_history for subsequent runs", func(t *testing.T) {
		// Setup subsequent run
		store := newMockMissionStore()

		previousMission := createTestMission("test-mission", 1)
		store.addMission(previousMission)

		currentMission := createTestMissionWithPreviousRun("test-mission", 2, previousMission.ID)
		store.addMission(currentMission)

		provider := NewMissionContextProvider(store, currentMission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)

		// Assert
		assert.Equal(t, "new_run_with_history", execCtx.MemoryContinuity)
	})

	t.Run("resumed takes precedence over history", func(t *testing.T) {
		// Setup resumed run with previous runs (resumed should win)
		store := newMockMissionStore()

		previousMission := createTestMission("test-mission", 1)
		store.addMission(previousMission)

		currentMission := createTestMissionWithCheckpoint("test-mission", 2, "post-exploit")
		currentMission.PreviousRunID = &previousMission.ID
		store.addMission(currentMission)

		provider := NewMissionContextProvider(store, currentMission, noopLogger())

		// Execute
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)

		// Assert - resumed takes precedence
		assert.Equal(t, "resumed", execCtx.MemoryContinuity)
		assert.True(t, execCtx.IsResumed)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Integration Tests
// ────────────────────────────────────────────────────────────────────────────

func TestMissionContextProvider_CompleteScenario(t *testing.T) {
	ctx := context.Background()

	t.Run("multi-run mission lifecycle", func(t *testing.T) {
		// Setup a complete multi-run scenario
		store := newMockMissionStore()

		// Run 1: Initial mission with findings
		run1 := createTestMissionWithFindings("web-pentest", 1, 3)
		run1.Status = "completed"
		store.addMission(run1)

		// Run 2: Second run finds more issues
		run2 := createTestMissionWithFindings("web-pentest", 2, 5)
		run2.Status = "completed"
		run2.PreviousRunID = &run1.ID
		store.addMission(run2)

		// Run 3: Current run, resumed from checkpoint
		run3 := createTestMissionWithCheckpoint("web-pentest", 3, "privilege-escalation")
		run3.FindingsCount = 2
		run3.PreviousRunID = &run2.ID
		store.addMission(run3)

		provider := NewMissionContextProvider(store, run3, noopLogger())

		// Test GetContext
		execCtx, err := provider.GetContext(ctx)
		require.NoError(t, err)
		assert.Equal(t, run3.ID, execCtx.MissionID)
		assert.Equal(t, "web-pentest", execCtx.MissionName)
		assert.Equal(t, 3, execCtx.RunNumber)
		assert.True(t, execCtx.IsResumed)
		assert.Equal(t, "privilege-escalation", execCtx.ResumedFromNode)
		assert.Equal(t, 10, execCtx.TotalFindingsAllRuns) // 3 + 5 + 2
		assert.Equal(t, "resumed", execCtx.MemoryContinuity)

		// Test GetRunHistory
		history, err := provider.GetRunHistory(ctx)
		require.NoError(t, err)
		require.Len(t, history, 3)
		assert.Equal(t, 3, history[0].RunNumber)
		assert.Equal(t, 2, history[1].RunNumber)
		assert.Equal(t, 1, history[2].RunNumber)

		// Test GetPreviousRun
		prevRun, err := provider.GetPreviousRun(ctx)
		require.NoError(t, err)
		require.NotNil(t, prevRun)
		assert.Equal(t, run2.ID, prevRun.MissionID)
		assert.Equal(t, 5, prevRun.FindingsCount)

		// Test IsResumedRun
		assert.True(t, provider.IsResumedRun())
	})
}

// ────────────────────────────────────────────────────────────────────────────
// Test Utilities
// ────────────────────────────────────────────────────────────────────────────

// noopLogger returns a no-op logger for tests.
func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{
		Level: slog.LevelError, // Only log errors to reduce noise
	}))
}
