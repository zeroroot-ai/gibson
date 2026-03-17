package harness

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zero-day-ai/gibson/internal/checkpoint"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MockThreadedCheckpointer is a mock implementation of checkpoint.ThreadedCheckpointer
type MockThreadedCheckpointer struct {
	mock.Mock
}

func (m *MockThreadedCheckpointer) CreateThread(ctx context.Context, missionID types.ID, opts ...checkpoint.ThreadOption) (string, error) {
	args := m.Called(ctx, missionID, opts)
	return args.String(0), args.Error(1)
}

func (m *MockThreadedCheckpointer) GetThread(ctx context.Context, threadID string) (*checkpoint.Thread, error) {
	args := m.Called(ctx, threadID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*checkpoint.Thread), args.Error(1)
}

func (m *MockThreadedCheckpointer) ListThreads(ctx context.Context, missionID types.ID) ([]*checkpoint.Thread, error) {
	args := m.Called(ctx, missionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*checkpoint.Thread), args.Error(1)
}

func (m *MockThreadedCheckpointer) Checkpoint(ctx context.Context, threadID string, state *checkpoint.ExecutionState) (*checkpoint.Checkpoint, error) {
	args := m.Called(ctx, threadID, state)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*checkpoint.Checkpoint), args.Error(1)
}

func (m *MockThreadedCheckpointer) Restore(ctx context.Context, threadID string, checkpointID string) (*checkpoint.ExecutionState, error) {
	args := m.Called(ctx, threadID, checkpointID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*checkpoint.ExecutionState), args.Error(1)
}

func (m *MockThreadedCheckpointer) GetLatestCheckpoint(ctx context.Context, threadID string) (*checkpoint.Checkpoint, error) {
	args := m.Called(ctx, threadID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*checkpoint.Checkpoint), args.Error(1)
}

func (m *MockThreadedCheckpointer) GetCheckpointHistory(ctx context.Context, threadID string, opts checkpoint.HistoryOptions) ([]*checkpoint.Checkpoint, error) {
	args := m.Called(ctx, threadID, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*checkpoint.Checkpoint), args.Error(1)
}

func (m *MockThreadedCheckpointer) UpdateState(ctx context.Context, checkpointID string, updates checkpoint.StateUpdates) (*checkpoint.Checkpoint, error) {
	args := m.Called(ctx, checkpointID, updates)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*checkpoint.Checkpoint), args.Error(1)
}

func (m *MockThreadedCheckpointer) DeleteThread(ctx context.Context, threadID string) error {
	args := m.Called(ctx, threadID)
	return args.Error(0)
}

func (m *MockThreadedCheckpointer) ApplyRetentionPolicy(ctx context.Context, threadID string) error {
	args := m.Called(ctx, threadID)
	return args.Error(0)
}

func TestHarnessCheckpointMethods_GetCurrentCheckpoint(t *testing.T) {
	t.Run("checkpointing disabled", func(t *testing.T) {
		// Create harness with nil checkpointer (disabled)
		h := NewHarnessCheckpointMethods(nil, "thread-123", "mission-456", 1)

		cp, err := h.GetCurrentCheckpoint()
		assert.Nil(t, cp)
		assert.Equal(t, ErrCheckpointingDisabled, err)
	})

	t.Run("get current checkpoint success", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		missionID := types.ID("mission-123")
		threadID := "thread-456"

		// Create expected checkpoint
		expectedCP := &checkpoint.Checkpoint{
			ID:        "checkpoint-789",
			ThreadID:  threadID,
			MissionID: missionID,
			CreatedAt: time.Now(),
			Label:     "test-checkpoint",
		}

		// Setup mock expectation
		mockCP.On("GetLatestCheckpoint", mock.Anything, threadID).Return(expectedCP, nil)

		// Create harness with mock
		h := NewHarnessCheckpointMethods(mockCP, threadID, missionID, 1)

		// Call method
		cp, err := h.GetCurrentCheckpoint()

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, cp)
		assert.Equal(t, expectedCP.ID, cp.ID)
		assert.Equal(t, expectedCP.ThreadID, cp.ThreadID)
		assert.Equal(t, expectedCP.Label, cp.Label)

		mockCP.AssertExpectations(t)
	})
}

func TestHarnessCheckpointMethods_GetCheckpointHistory(t *testing.T) {
	t.Run("checkpointing disabled", func(t *testing.T) {
		h := NewHarnessCheckpointMethods(nil, "thread-123", "mission-456", 1)

		history, err := h.GetCheckpointHistory(10)
		assert.Nil(t, history)
		assert.Equal(t, ErrCheckpointingDisabled, err)
	})

	t.Run("get history success", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		missionID := types.ID("mission-123")
		threadID := "thread-456"

		// Create expected checkpoints
		expectedHistory := []*checkpoint.Checkpoint{
			{
				ID:        "checkpoint-3",
				ThreadID:  threadID,
				MissionID: missionID,
				CreatedAt: time.Now(),
				Label:     "latest",
			},
			{
				ID:        "checkpoint-2",
				ThreadID:  threadID,
				MissionID: missionID,
				CreatedAt: time.Now().Add(-1 * time.Hour),
				Label:     "middle",
			},
			{
				ID:        "checkpoint-1",
				ThreadID:  threadID,
				MissionID: missionID,
				CreatedAt: time.Now().Add(-2 * time.Hour),
				Label:     "oldest",
			},
		}

		// Setup mock expectation
		expectedOpts := checkpoint.HistoryOptions{
			Limit:     10,
			Ascending: false,
		}
		mockCP.On("GetCheckpointHistory", mock.Anything, threadID, expectedOpts).Return(expectedHistory, nil)

		// Create harness with mock
		h := NewHarnessCheckpointMethods(mockCP, threadID, missionID, 1)

		// Call method
		history, err := h.GetCheckpointHistory(10)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, history)
		assert.Len(t, history, 3)
		assert.Equal(t, "checkpoint-3", history[0].ID)
		assert.Equal(t, "latest", history[0].Label)

		mockCP.AssertExpectations(t)
	})
}

func TestHarnessCheckpointMethods_CreateCheckpoint(t *testing.T) {
	t.Run("checkpointing disabled", func(t *testing.T) {
		h := NewHarnessCheckpointMethods(nil, "thread-123", "mission-456", 1)

		cp, err := h.CreateCheckpoint("test-label")
		assert.Nil(t, cp)
		assert.Equal(t, ErrCheckpointingDisabled, err)
	})

	t.Run("create checkpoint not yet implemented", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		missionID := types.ID("mission-123")
		threadID := "thread-456"

		// Create harness with mock
		h := NewHarnessCheckpointMethods(mockCP, threadID, missionID, 1)

		// Call method
		cp, err := h.CreateCheckpoint("test-label")

		// Assertions - should return not implemented error
		assert.Nil(t, cp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "agent-initiated checkpoints not yet implemented")
	})
}

func TestHarnessCheckpointMethods_GetPreviousRunCheckpoint(t *testing.T) {
	t.Run("checkpointing disabled", func(t *testing.T) {
		h := NewHarnessCheckpointMethods(nil, "thread-123", "mission-456", 2)

		cp, err := h.GetPreviousRunCheckpoint(1)
		assert.Nil(t, cp)
		assert.Equal(t, ErrCheckpointingDisabled, err)
	})

	t.Run("invalid runOffset", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		h := NewHarnessCheckpointMethods(mockCP, "thread-123", "mission-456", 2)

		cp, err := h.GetPreviousRunCheckpoint(0)
		assert.Nil(t, cp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "runOffset must be >= 1")
	})

	t.Run("runOffset too large", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		h := NewHarnessCheckpointMethods(mockCP, "thread-123", "mission-456", 2)

		// Setup mock to return threads
		mockCP.On("ListThreads", mock.Anything, mock.Anything).Return([]*checkpoint.Thread{}, nil)

		cp, err := h.GetPreviousRunCheckpoint(5)
		assert.Nil(t, cp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no run exists at offset")
	})

	t.Run("get previous run checkpoint success", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		missionID := types.ID("mission-123")
		currentThreadID := "thread-current"
		previousThreadID := "thread-previous"
		currentRun := 2
		previousRun := 1

		// Create threads with run_number metadata
		threads := []*checkpoint.Thread{
			{
				ID:        currentThreadID,
				MissionID: missionID,
				Metadata: map[string]string{
					"run_number": "2",
				},
			},
			{
				ID:        previousThreadID,
				MissionID: missionID,
				Metadata: map[string]string{
					"run_number": "1",
				},
			},
		}

		// Create expected checkpoint from previous run
		expectedCP := &checkpoint.Checkpoint{
			ID:        "checkpoint-prev",
			ThreadID:  previousThreadID,
			MissionID: missionID,
			CreatedAt: time.Now().Add(-24 * time.Hour),
			Label:     "previous-run-final",
		}

		// Setup mock expectations
		mockCP.On("ListThreads", mock.Anything, missionID).Return(threads, nil)
		mockCP.On("GetLatestCheckpoint", mock.Anything, previousThreadID).Return(expectedCP, nil)

		// Create harness with mock
		h := NewHarnessCheckpointMethods(mockCP, currentThreadID, missionID, currentRun)

		// Call method
		cp, err := h.GetPreviousRunCheckpoint(1)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, cp)
		assert.Equal(t, "checkpoint-prev", cp.ID)
		assert.Equal(t, previousThreadID, cp.ThreadID)

		mockCP.AssertExpectations(t)
	})
}

func TestNewHarnessCheckpointMethods(t *testing.T) {
	t.Run("with nil checkpointer", func(t *testing.T) {
		h := NewHarnessCheckpointMethods(nil, "thread-123", "mission-456", 1)

		assert.NotNil(t, h)
		assert.False(t, h.enabled)
		assert.Nil(t, h.checkpointer)
		assert.Equal(t, "thread-123", h.threadID)
		assert.Equal(t, types.ID("mission-456"), h.missionID)
		assert.Equal(t, 1, h.runNumber)
	})

	t.Run("with valid checkpointer", func(t *testing.T) {
		mockCP := &MockThreadedCheckpointer{}
		h := NewHarnessCheckpointMethods(mockCP, "thread-123", "mission-456", 2)

		assert.NotNil(t, h)
		assert.True(t, h.enabled)
		assert.NotNil(t, h.checkpointer)
		assert.Equal(t, "thread-123", h.threadID)
		assert.Equal(t, types.ID("mission-456"), h.missionID)
		assert.Equal(t, 2, h.runNumber)
	})
}
