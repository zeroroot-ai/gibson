package checkpoint

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// MockCheckpointStore implements CheckpointStore for testing.
type MockCheckpointStore struct {
	checkpoints map[string]*Checkpoint
	threads     map[string][]*Checkpoint
}

func NewMockCheckpointStore() *MockCheckpointStore {
	return &MockCheckpointStore{
		checkpoints: make(map[string]*Checkpoint),
		threads:     make(map[string][]*Checkpoint),
	}
}

func (m *MockCheckpointStore) SaveCheckpoint(ctx context.Context, checkpoint *Checkpoint) error {
	m.checkpoints[checkpoint.ID] = checkpoint
	m.threads[checkpoint.ThreadID] = append(m.threads[checkpoint.ThreadID], checkpoint)
	return nil
}

func (m *MockCheckpointStore) GetCheckpoint(ctx context.Context, checkpointID string) (*Checkpoint, error) {
	cp, exists := m.checkpoints[checkpointID]
	if !exists {
		return nil, ErrCheckpointNotFound
	}
	return cp, nil
}

func (m *MockCheckpointStore) ListCheckpoints(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error) {
	return m.threads[threadID], nil
}

func (m *MockCheckpointStore) DeleteCheckpoint(ctx context.Context, checkpointID string) error {
	cp, exists := m.checkpoints[checkpointID]
	if !exists {
		return ErrCheckpointNotFound
	}

	delete(m.checkpoints, checkpointID)

	// Remove from thread list
	threadCheckpoints := m.threads[cp.ThreadID]
	for i, threadCp := range threadCheckpoints {
		if threadCp.ID == checkpointID {
			m.threads[cp.ThreadID] = append(threadCheckpoints[:i], threadCheckpoints[i+1:]...)
			break
		}
	}

	return nil
}

func (m *MockCheckpointStore) DeleteThreadCheckpoints(ctx context.Context, threadID string) error {
	for _, cp := range m.threads[threadID] {
		delete(m.checkpoints, cp.ID)
	}
	delete(m.threads, threadID)
	return nil
}

func (m *MockCheckpointStore) GetLatestCheckpoint(ctx context.Context, threadID string) (*Checkpoint, error) {
	checkpoints := m.threads[threadID]
	if len(checkpoints) == 0 {
		return nil, ErrCheckpointNotFound
	}

	latest := checkpoints[0]
	for _, cp := range checkpoints {
		if cp.CreatedAt.After(latest.CreatedAt) {
			latest = cp
		}
	}

	return latest, nil
}

func TestCheckpointPolicy_ShouldCheckpoint(t *testing.T) {
	tests := []struct {
		name     string
		config   PolicyConfig
		event    CheckpointEvent
		expected bool
	}{
		{
			name:   "shutdown event always checkpoints",
			config: DefaultPolicyConfig(),
			event: CheckpointEvent{
				Type:      CheckpointEventShutdown,
				NodeID:    "node1",
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name:   "explicit event always checkpoints",
			config: DefaultPolicyConfig(),
			event: CheckpointEvent{
				Type:      CheckpointEventExplicit,
				NodeID:    "node1",
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name:   "error event always checkpoints",
			config: DefaultPolicyConfig(),
			event: CheckpointEvent{
				Type:      CheckpointEventError,
				NodeID:    "node1",
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name:   "branch event always checkpoints",
			config: DefaultPolicyConfig(),
			event: CheckpointEvent{
				Type:      CheckpointEventBranch,
				NodeID:    "node1",
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name:   "super step with auto checkpoint enabled",
			config: DefaultPolicyConfig(),
			event: CheckpointEvent{
				Type:      CheckpointEventSuperStep,
				NodeID:    "node1",
				Timestamp: time.Now(),
			},
			expected: true,
		},
		{
			name: "super step with auto checkpoint disabled",
			config: PolicyConfig{
				AutoCheckpoint: false,
			},
			event: CheckpointEvent{
				Type:      CheckpointEventSuperStep,
				NodeID:    "node1",
				Timestamp: time.Now(),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewMockCheckpointStore()
			policy := NewCheckpointPolicy(store, tt.config)

			result := policy.ShouldCheckpoint(context.Background(), tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckpointPolicy_ShouldCheckpoint_RateLimiting(t *testing.T) {
	config := DefaultPolicyConfig()
	config.MinCheckpointInterval = 1 * time.Second

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	threadID := "thread1"
	event := CheckpointEvent{
		Type:      CheckpointEventSuperStep,
		NodeID:    "node1",
		Timestamp: time.Now(),
		Metadata:  map[string]string{"thread_id": threadID},
	}

	// First checkpoint should succeed
	result := policy.ShouldCheckpoint(context.Background(), event)
	assert.True(t, result)

	// Record the checkpoint
	policy.RecordCheckpoint(threadID, time.Now())

	// Immediate second checkpoint should be rate limited
	result = policy.ShouldCheckpoint(context.Background(), event)
	assert.False(t, result)

	// After waiting, checkpoint should succeed
	time.Sleep(1100 * time.Millisecond)
	result = policy.ShouldCheckpoint(context.Background(), event)
	assert.True(t, result)
}

func TestCheckpointPolicy_GetRetentionConfig(t *testing.T) {
	config := DefaultPolicyConfig()
	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	tests := []struct {
		name     string
		status   MissionStatus
		expected RetentionMode
	}{
		{
			name:     "completed mission uses completed retention",
			status:   MissionStatusCompleted,
			expected: RetentionFinalOnly,
		},
		{
			name:     "failed mission uses failed retention",
			status:   MissionStatusFailed,
			expected: RetentionAll,
		},
		{
			name:     "cancelled mission uses cancelled retention",
			status:   MissionStatusCancelled,
			expected: RetentionFinalOnly,
		},
		{
			name:     "running mission has no TTL",
			status:   MissionStatusRunning,
			expected: config.DefaultMode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retentionConfig := policy.GetRetentionConfig(tt.status)
			assert.Equal(t, tt.expected, retentionConfig.Mode)

			if tt.status == MissionStatusRunning {
				assert.Equal(t, time.Duration(0), retentionConfig.TTL)
			}
		})
	}
}

func TestCheckpointPolicy_ApplyRetention_FinalOnly(t *testing.T) {
	config := DefaultPolicyConfig()
	config.CompletedRetention.Mode = RetentionFinalOnly

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	ctx := context.Background()
	missionID := types.NewID()
	threadID := "thread1"

	// Create multiple checkpoints
	for i := 0; i < 5; i++ {
		cp := NewCheckpoint(missionID, threadID)
		cp.ID = cp.ID + string(rune('0'+i)) // Make IDs unique
		cp.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		require.NoError(t, store.SaveCheckpoint(ctx, cp))
	}

	// Apply retention for completed mission
	err := policy.ApplyRetention(ctx, threadID, MissionStatusCompleted)
	require.NoError(t, err)

	// Only the last checkpoint should remain
	checkpoints, err := store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, checkpoints, 1)
}

func TestCheckpointPolicy_ApplyRetention_All(t *testing.T) {
	config := DefaultPolicyConfig()
	config.FailedRetention.Mode = RetentionAll
	config.FailedRetention.TTL = 0

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	ctx := context.Background()
	missionID := types.NewID()
	threadID := "thread1"

	// Create multiple checkpoints
	checkpointCount := 5
	for i := 0; i < checkpointCount; i++ {
		cp := NewCheckpoint(missionID, threadID)
		cp.ID = cp.ID + string(rune('0'+i))
		cp.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		require.NoError(t, store.SaveCheckpoint(ctx, cp))
	}

	// Apply retention for failed mission
	err := policy.ApplyRetention(ctx, threadID, MissionStatusFailed)
	require.NoError(t, err)

	// All checkpoints should remain
	checkpoints, err := store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, checkpoints, checkpointCount)
}

func TestCheckpointPolicy_ApplyRetention_Labeled(t *testing.T) {
	config := DefaultPolicyConfig()
	config.CompletedRetention.Mode = RetentionLabeled

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	ctx := context.Background()
	missionID := types.NewID()
	threadID := "thread1"

	// Create checkpoints with some labeled
	for i := 0; i < 5; i++ {
		cp := NewCheckpoint(missionID, threadID)
		cp.ID = cp.ID + string(rune('0'+i))
		cp.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)

		// Label every other checkpoint
		if i%2 == 0 {
			cp.Label = "milestone"
		}

		require.NoError(t, store.SaveCheckpoint(ctx, cp))
	}

	// Apply retention
	err := policy.ApplyRetention(ctx, threadID, MissionStatusCompleted)
	require.NoError(t, err)

	// Only labeled checkpoints and the last one should remain
	checkpoints, err := store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	require.NoError(t, err)

	// Should have checkpoints 0, 2, 4 (labeled) + 4 (last one, which is already labeled)
	assert.Len(t, checkpoints, 3)

	for _, cp := range checkpoints {
		assert.NotEqual(t, "", cp.Label)
	}
}

func TestCheckpointPolicy_ApplyRetention_MaxCount(t *testing.T) {
	config := DefaultPolicyConfig()
	config.CompletedRetention.Mode = RetentionAll
	config.CompletedRetention.MaxCount = 3
	config.CompletedRetention.TTL = 0

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	ctx := context.Background()
	missionID := types.NewID()
	threadID := "thread1"

	// Create more checkpoints than MaxCount
	for i := 0; i < 5; i++ {
		cp := NewCheckpoint(missionID, threadID)
		cp.ID = cp.ID + string(rune('0'+i))
		cp.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		require.NoError(t, store.SaveCheckpoint(ctx, cp))
	}

	// Apply retention
	err := policy.ApplyRetention(ctx, threadID, MissionStatusCompleted)
	require.NoError(t, err)

	// Should only keep MaxCount checkpoints (the newest ones)
	checkpoints, err := store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, checkpoints, 3)
}

func TestCheckpointPolicy_ApplyRetention_TTL(t *testing.T) {
	config := DefaultPolicyConfig()
	config.CompletedRetention.Mode = RetentionAll
	config.CompletedRetention.TTL = 1 * time.Hour
	config.CompletedRetention.MaxCount = 0

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	ctx := context.Background()
	missionID := types.NewID()
	threadID := "thread1"

	// Create checkpoints with different ages
	now := time.Now()
	checkpoints := []*Checkpoint{
		{
			ID:        "old1",
			ThreadID:  threadID,
			MissionID: missionID,
			CreatedAt: now.Add(-3 * time.Hour), // Expired
		},
		{
			ID:        "old2",
			ThreadID:  threadID,
			MissionID: missionID,
			CreatedAt: now.Add(-2 * time.Hour), // Expired
		},
		{
			ID:        "recent",
			ThreadID:  threadID,
			MissionID: missionID,
			CreatedAt: now.Add(-30 * time.Minute), // Not expired
		},
	}

	for _, cp := range checkpoints {
		require.NoError(t, store.SaveCheckpoint(ctx, cp))
	}

	// Apply retention
	err := policy.ApplyRetention(ctx, threadID, MissionStatusCompleted)
	require.NoError(t, err)

	// Only recent checkpoints should remain
	remaining, err := store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, remaining, 1)
	assert.Equal(t, "recent", remaining[0].ID)
}

func TestCheckpointPolicy_ApplyRetention_RunningMission(t *testing.T) {
	config := DefaultPolicyConfig()

	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	ctx := context.Background()
	missionID := types.NewID()
	threadID := "thread1"

	// Create checkpoints
	for i := 0; i < 5; i++ {
		cp := NewCheckpoint(missionID, threadID)
		cp.ID = cp.ID + string(rune('0'+i))
		cp.CreatedAt = time.Now().Add(time.Duration(i) * time.Second)
		require.NoError(t, store.SaveCheckpoint(ctx, cp))
	}

	// Apply retention for running mission
	err := policy.ApplyRetention(ctx, threadID, MissionStatusRunning)
	require.NoError(t, err)

	// All checkpoints should remain (never delete for running missions)
	checkpoints, err := store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, checkpoints, 5)
}

func TestCheckpointPolicy_MissionOverrides(t *testing.T) {
	config := DefaultPolicyConfig()
	store := NewMockCheckpointStore()
	policy := NewCheckpointPolicy(store, config)

	missionID := types.NewID()
	overrideConfig := RetentionConfig{
		Mode:        RetentionAll,
		TTL:         24 * time.Hour,
		MaxCount:    50,
		MinInterval: 10 * time.Second,
	}

	// Set override
	policy.SetMissionOverride(missionID, overrideConfig)

	// Get override
	retrieved, exists := policy.GetMissionOverride(missionID)
	assert.True(t, exists)
	assert.Equal(t, overrideConfig.Mode, retrieved.Mode)
	assert.Equal(t, overrideConfig.TTL, retrieved.TTL)

	// Clear override
	policy.ClearMissionOverride(missionID)
	_, exists = policy.GetMissionOverride(missionID)
	assert.False(t, exists)
}

func TestCheckpointEvent_WithMetadata(t *testing.T) {
	event := NewCheckpointEvent(CheckpointEventSuperStep, "node1")
	event = event.WithMetadata("key1", "value1")
	event = event.WithMetadata("key2", "value2")

	assert.Equal(t, "value1", event.Metadata["key1"])
	assert.Equal(t, "value2", event.Metadata["key2"])
}

func TestMissionStatus_IsTerminal(t *testing.T) {
	tests := []struct {
		status   MissionStatus
		expected bool
	}{
		{MissionStatusCompleted, true},
		{MissionStatusFailed, true},
		{MissionStatusCancelled, true},
		{MissionStatusRunning, false},
		{MissionStatusPaused, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.status.IsTerminal())
		})
	}
}

func TestDefaultPolicyConfig(t *testing.T) {
	config := DefaultPolicyConfig()

	assert.True(t, config.AutoCheckpoint)
	assert.Equal(t, RetentionErrorOnly, config.DefaultMode)
	assert.Equal(t, 7*24*time.Hour, config.DefaultTTL)
	assert.Equal(t, 100, config.MaxCheckpoints)
	assert.NotNil(t, config.PerMissionOverrides)
}

// Additional alias methods for CheckpointStore compatibility

func (m *MockCheckpointStore) Delete(ctx context.Context, checkpointID string) error {
	return m.DeleteCheckpoint(ctx, checkpointID)
}

func (m *MockCheckpointStore) DeleteMany(ctx context.Context, checkpointIDs []string) error {
	for _, id := range checkpointIDs {
		if err := m.DeleteCheckpoint(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockCheckpointStore) Load(ctx context.Context, checkpointID string) (*Checkpoint, error) {
	return m.GetCheckpoint(ctx, checkpointID)
}

func (m *MockCheckpointStore) GetLatest(ctx context.Context, threadID string) (*Checkpoint, error) {
	return m.GetLatestCheckpoint(ctx, threadID)
}

func (m *MockCheckpointStore) GetLatestByThread(ctx context.Context, threadID string) (*Checkpoint, error) {
	return m.GetLatestCheckpoint(ctx, threadID)
}

func (m *MockCheckpointStore) ListByThread(ctx context.Context, threadID string, opts HistoryOptions) ([]*Checkpoint, error) {
	return m.ListCheckpoints(ctx, threadID, HistoryOptions{})
}

func (m *MockCheckpointStore) DeleteThread(ctx context.Context, threadID string) error {
	return m.DeleteThreadCheckpoints(ctx, threadID)
}

func (m *MockCheckpointStore) Save(ctx context.Context, checkpoint *Checkpoint) error {
	return m.SaveCheckpoint(ctx, checkpoint)
}

// Thread-related methods (required by CheckpointStore in store.go)

func (m *MockCheckpointStore) SaveThread(ctx context.Context, thread *Thread) error {
	// Not needed for policy tests, but required by interface
	return nil
}

func (m *MockCheckpointStore) GetThread(ctx context.Context, threadID string) (*Thread, error) {
	// Not needed for policy tests, but required by interface
	return nil, ErrThreadNotFound
}

func (m *MockCheckpointStore) ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error) {
	// Not needed for policy tests, but required by interface
	return []*Thread{}, nil
}
