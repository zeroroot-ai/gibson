package mission

import (
	"context"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockCheckpointer implements checkpoint.ThreadedCheckpointer for testing
type mockCheckpointer struct {
	checkpoints map[string]*checkpoint.Checkpoint
	threads     map[string]*checkpoint.Thread
}

func newMockCheckpointer() *mockCheckpointer {
	return &mockCheckpointer{
		checkpoints: make(map[string]*checkpoint.Checkpoint),
		threads:     make(map[string]*checkpoint.Thread),
	}
}

func (m *mockCheckpointer) CreateThread(ctx context.Context, missionID types.ID, opts ...checkpoint.ThreadOption) (string, error) {
	thread := checkpoint.NewThread(missionID)
	for _, opt := range opts {
		opt(thread)
	}
	m.threads[thread.ID] = thread
	return thread.ID, nil
}

func (m *mockCheckpointer) GetThread(ctx context.Context, threadID string) (*checkpoint.Thread, error) {
	thread, ok := m.threads[threadID]
	if !ok {
		return nil, checkpoint.ErrThreadNotFound
	}
	return thread, nil
}

func (m *mockCheckpointer) ListThreads(ctx context.Context, missionID types.ID) ([]*checkpoint.Thread, error) {
	var threads []*checkpoint.Thread
	for _, t := range m.threads {
		if t.MissionID == missionID {
			threads = append(threads, t)
		}
	}
	return threads, nil
}

func (m *mockCheckpointer) Checkpoint(ctx context.Context, threadID string, state *checkpoint.ExecutionState) (*checkpoint.Checkpoint, error) {
	chkpt := checkpoint.NewCheckpoint(state.MissionID, threadID)
	chkpt.CurrentNodeID = state.CurrentNodeID
	chkpt.NodeStates = state.NodeStates
	chkpt.CompletedNodes = state.CompletedResults
	chkpt.PendingNodes = state.PendingQueue
	m.checkpoints[chkpt.ID] = chkpt

	// Update thread
	if thread, ok := m.threads[threadID]; ok {
		thread.AddCheckpoint(chkpt.ID)
	}

	return chkpt, nil
}

func (m *mockCheckpointer) Restore(ctx context.Context, threadID string, checkpointID string) (*checkpoint.ExecutionState, error) {
	chkpt, ok := m.checkpoints[checkpointID]
	if !ok {
		return nil, checkpoint.ErrCheckpointNotFound
	}
	return checkpoint.FromCheckpoint(chkpt)
}

func (m *mockCheckpointer) GetLatestCheckpoint(ctx context.Context, threadID string) (*checkpoint.Checkpoint, error) {
	var latest *checkpoint.Checkpoint
	for _, chkpt := range m.checkpoints {
		if chkpt.ThreadID == threadID {
			if latest == nil || chkpt.CreatedAt.After(latest.CreatedAt) {
				latest = chkpt
			}
		}
	}
	if latest == nil {
		return nil, checkpoint.ErrCheckpointNotFound
	}
	return latest, nil
}

func (m *mockCheckpointer) GetCheckpointHistory(ctx context.Context, threadID string, opts checkpoint.HistoryOptions) ([]*checkpoint.Checkpoint, error) {
	var history []*checkpoint.Checkpoint
	for _, chkpt := range m.checkpoints {
		if chkpt.ThreadID == threadID {
			history = append(history, chkpt)
		}
	}
	return history, nil
}

func (m *mockCheckpointer) UpdateState(ctx context.Context, checkpointID string, updates checkpoint.StateUpdates) (*checkpoint.Checkpoint, error) {
	return nil, nil
}

func (m *mockCheckpointer) DeleteThread(ctx context.Context, threadID string) error {
	delete(m.threads, threadID)
	return nil
}

func (m *mockCheckpointer) ApplyRetentionPolicy(ctx context.Context, threadID string) error {
	return nil
}

// mockRestorer implements checkpoint.StateRestorer for testing
type mockRestorer struct {
	checkpointer *mockCheckpointer
}

func (m *mockRestorer) Restore(ctx context.Context, chkpt *checkpoint.Checkpoint) (*checkpoint.ExecutionState, error) {
	return checkpoint.FromCheckpoint(chkpt)
}

func (m *mockRestorer) Validate(chkpt *checkpoint.Checkpoint) error {
	return nil
}

func (m *mockRestorer) RestoreFromID(ctx context.Context, threadID string, checkpointID string) (*checkpoint.ExecutionState, error) {
	return m.checkpointer.Restore(ctx, threadID, checkpointID)
}

func (m *mockRestorer) RestoreLatest(ctx context.Context, threadID string) (*checkpoint.ExecutionState, error) {
	chkpt, err := m.checkpointer.GetLatestCheckpoint(ctx, threadID)
	if err != nil {
		return nil, err
	}
	return m.Restore(ctx, chkpt)
}

// mockThreadManager implements checkpoint.ThreadManager for testing
type mockThreadManager struct {
	checkpointer *mockCheckpointer
}

func (m *mockThreadManager) CreateThread(ctx context.Context, missionID types.ID, opts ...checkpoint.ThreadOption) (*checkpoint.Thread, error) {
	threadID, err := m.checkpointer.CreateThread(ctx, missionID, opts...)
	if err != nil {
		return nil, err
	}
	return m.checkpointer.GetThread(ctx, threadID)
}

func (m *mockThreadManager) CreateBranchThread(ctx context.Context, parentThreadID string, branchCheckpointID string, opts ...checkpoint.ThreadOption) (*checkpoint.Thread, error) {
	return nil, nil
}

func (m *mockThreadManager) GetThread(ctx context.Context, threadID string) (*checkpoint.Thread, error) {
	return m.checkpointer.GetThread(ctx, threadID)
}

func (m *mockThreadManager) ListThreads(ctx context.Context, missionID types.ID) ([]*checkpoint.Thread, error) {
	return m.checkpointer.ListThreads(ctx, missionID)
}

func (m *mockThreadManager) UpdateThreadStatus(ctx context.Context, threadID string, status checkpoint.ThreadStatus) error {
	return nil
}

func (m *mockThreadManager) DeleteThread(ctx context.Context, threadID string) error {
	return m.checkpointer.DeleteThread(ctx, threadID)
}

func (m *mockThreadManager) GenerateSubgraphThreadID(parentThread string, nodeID string) string {
	return parentThread + ":" + nodeID + ":test"
}

// mockMissionStore implements MissionStore for testing
type mockMissionStore struct {
	missions map[types.ID]*Mission
}

func newMockMissionStore() *mockMissionStore {
	return &mockMissionStore{
		missions: make(map[types.ID]*Mission),
	}
}

func (m *mockMissionStore) Get(ctx context.Context, id types.ID) (*Mission, error) {
	mission, ok := m.missions[id]
	if !ok {
		return nil, NewNotFoundError(id.String())
	}
	return mission, nil
}

func (m *mockMissionStore) Save(ctx context.Context, mission *Mission) error {
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockMissionStore) Update(ctx context.Context, mission *Mission) error {
	m.missions[mission.ID] = mission
	return nil
}

func (m *mockMissionStore) Delete(ctx context.Context, id types.ID) error {
	delete(m.missions, id)
	return nil
}

func (m *mockMissionStore) List(ctx context.Context, filter *MissionFilter) ([]*Mission, error) {
	var missions []*Mission
	for _, mission := range m.missions {
		// Simple filtering for testing
		if filter != nil && filter.ExcludeStatus != nil {
			skip := false
			for _, status := range filter.ExcludeStatus {
				if mission.Status == status {
					skip = true
					break
				}
			}
			if skip {
				continue
			}
		}
		missions = append(missions, mission)
	}
	return missions, nil
}

func (m *mockMissionStore) UpdateStatus(ctx context.Context, id types.ID, status MissionStatus) error {
	mission, ok := m.missions[id]
	if !ok {
		return NewNotFoundError(id.String())
	}
	mission.Status = status
	return nil
}

func (m *mockMissionStore) Count(ctx context.Context, filter *MissionFilter) (int, error) {
	return len(m.missions), nil
}

func (m *mockMissionStore) GetDefinition(ctx context.Context, name string) (*missionv1.MissionDefinition, error) {
	return nil, nil
}

func (m *mockMissionStore) CreateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	return nil
}

func (m *mockMissionStore) ListDefinitions(ctx context.Context) ([]*missionv1.MissionDefinition, error) {
	return nil, nil
}

func (m *mockMissionStore) UpdateDefinition(ctx context.Context, def *missionv1.MissionDefinition) error {
	return nil
}

func (m *mockMissionStore) DeleteDefinition(ctx context.Context, name string) error {
	return nil
}

// Unused interface methods — stubbed to satisfy MissionStore. These tests only
// exercise Get/Save/Update/UpdateStatus/Count/List; the rest return nil to
// complete the contract.

func (m *mockMissionStore) GetByName(ctx context.Context, name string) (*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	return nil
}

func (m *mockMissionStore) GetByTarget(ctx context.Context, targetID types.ID) ([]*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) GetActive(ctx context.Context) ([]*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *MissionCheckpoint) error {
	return nil
}

func (m *mockMissionStore) GetByNameAndStatus(ctx context.Context, name string, status MissionStatus) (*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) ListByName(ctx context.Context, name string, limit int) ([]*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) GetLatestByName(ctx context.Context, name string) (*Mission, error) {
	return nil, nil
}

func (m *mockMissionStore) IncrementRunNumber(ctx context.Context, name string) (int, error) {
	return 0, nil
}

func (m *mockMissionStore) FindOrCreateByName(ctx context.Context, mission *Mission) (*Mission, bool, error) {
	return mission, false, nil
}

func TestPauseWithCheckpoint(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	checkpointer := newMockCheckpointer()
	restorer := &mockRestorer{checkpointer: checkpointer}
	threadManager := &mockThreadManager{checkpointer: checkpointer}
	store := newMockMissionStore()

	// Create controller checkpoint methods
	ccm := NewControllerCheckpointMethods(checkpointer, restorer, store, threadManager, nil)

	// Create a test mission
	missionID := types.NewID()
	mission := &Mission{
		ID:     missionID,
		Name:   "Test Mission",
		Status: MissionStatusRunning,
	}
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Create execution state
	threadID, err := checkpointer.CreateThread(ctx, missionID)
	require.NoError(t, err)

	state := checkpoint.NewExecutionState(missionID, threadID)
	state.CurrentNodeID = "node1"
	state.AddNodeState("node1", &checkpoint.NodeState{
		NodeID: "node1",
		Status: checkpoint.NodeStatusRunning,
	})

	// Test pause with checkpoint
	chkpt, err := ccm.PauseWithCheckpoint(ctx, missionID, state)
	require.NoError(t, err)
	assert.NotNil(t, chkpt)
	assert.Equal(t, missionID, chkpt.MissionID)
	assert.Equal(t, threadID, chkpt.ThreadID)

	// Verify mission status updated
	updatedMission, err := store.Get(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, MissionStatusPaused, updatedMission.Status)
	assert.NotNil(t, updatedMission.CheckpointAt)
}

func TestResumeFromCheckpoint(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	checkpointer := newMockCheckpointer()
	restorer := &mockRestorer{checkpointer: checkpointer}
	threadManager := &mockThreadManager{checkpointer: checkpointer}
	store := newMockMissionStore()

	// Create controller checkpoint methods
	ccm := NewControllerCheckpointMethods(checkpointer, restorer, store, threadManager, nil)

	// Create a test mission
	missionID := types.NewID()
	mission := &Mission{
		ID:     missionID,
		Name:   "Test Mission",
		Status: MissionStatusPaused,
	}
	err := store.Save(ctx, mission)
	require.NoError(t, err)

	// Create thread and checkpoint
	threadID, err := checkpointer.CreateThread(ctx, missionID)
	require.NoError(t, err)

	state := checkpoint.NewExecutionState(missionID, threadID)
	state.CurrentNodeID = "node2"
	state.PendingQueue = []string{"node2", "node3"}
	state.AddNodeState("node1", &checkpoint.NodeState{
		NodeID: "node1",
		Status: checkpoint.NodeStatusCompleted,
	})

	chkpt, err := checkpointer.Checkpoint(ctx, threadID, state)
	require.NoError(t, err)

	// Test resume from checkpoint
	result, err := ccm.ResumeFromCheckpoint(ctx, missionID)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, state.MissionID, result.State.MissionID)
	assert.Equal(t, state.ThreadID, result.State.ThreadID)
	assert.Equal(t, chkpt.ID, result.Checkpoint.ID)

	// Verify mission status updated
	updatedMission, err := store.Get(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, MissionStatusRunning, updatedMission.Status)
}

func TestDiscoverIncompleteMissions(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	checkpointer := newMockCheckpointer()
	restorer := &mockRestorer{checkpointer: checkpointer}
	threadManager := &mockThreadManager{checkpointer: checkpointer}
	store := newMockMissionStore()

	// Create controller checkpoint methods
	ccm := NewControllerCheckpointMethods(checkpointer, restorer, store, threadManager, nil)

	// Create incomplete missions
	for i := 0; i < 3; i++ {
		missionID := types.NewID()
		mission := &Mission{
			ID:     missionID,
			Name:   "Incomplete Mission",
			Status: MissionStatusPaused,
		}
		err := store.Save(ctx, mission)
		require.NoError(t, err)

		// Create thread and checkpoint
		threadID, err := checkpointer.CreateThread(ctx, missionID)
		require.NoError(t, err)

		state := checkpoint.NewExecutionState(missionID, threadID)
		_, err = checkpointer.Checkpoint(ctx, threadID, state)
		require.NoError(t, err)
	}

	// Create completed mission (should not be included)
	completedID := types.NewID()
	completedMission := &Mission{
		ID:     completedID,
		Name:   "Completed Mission",
		Status: MissionStatusCompleted,
	}
	err := store.Save(ctx, completedMission)
	require.NoError(t, err)

	// Test discover incomplete missions
	incomplete, err := ccm.DiscoverIncompleteMissions(ctx)
	require.NoError(t, err)
	assert.Len(t, incomplete, 3)

	for _, inc := range incomplete {
		assert.NotNil(t, inc.LastCheckpoint)
		assert.NotEmpty(t, inc.RecoveryOptions)
		assert.Len(t, inc.RecoveryOptions, 3) // resume, replay, fail
	}
}

func TestAcquireLock(t *testing.T) {
	ctx := context.Background()

	// Setup mocks
	checkpointer := newMockCheckpointer()
	restorer := &mockRestorer{checkpointer: checkpointer}
	threadManager := &mockThreadManager{checkpointer: checkpointer}
	store := newMockMissionStore()

	// Create controller checkpoint methods
	ccm := NewControllerCheckpointMethods(checkpointer, restorer, store, threadManager, nil)

	missionID := types.NewID()

	// Acquire lock
	unlock, err := ccm.AcquireLock(ctx, missionID)
	require.NoError(t, err)
	assert.NotNil(t, unlock)

	// Release lock
	unlock()

	// Acquire again (should succeed since we released)
	unlock2, err := ccm.AcquireLock(ctx, missionID)
	require.NoError(t, err)
	assert.NotNil(t, unlock2)
	unlock2()
}
