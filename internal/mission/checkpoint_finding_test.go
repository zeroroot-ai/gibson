package mission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/types"
)

// mockFindingLister is a test double for FindingLister.
type mockFindingLister struct {
	ids []types.ID
	err error
}

func (m *mockFindingLister) ListByMission(_ context.Context, _ types.ID) ([]types.ID, error) {
	return m.ids, m.err
}

// checkpointTestStore is a minimal MissionStore for CheckpointManager finding tests.
// Only Get and SaveCheckpoint need real implementations.
type checkpointTestStore struct {
	mission *Mission
}

func (s *checkpointTestStore) Get(_ context.Context, _ types.ID) (*Mission, error) {
	if s.mission == nil {
		return nil, errors.New("mission not found")
	}
	return s.mission, nil
}
func (s *checkpointTestStore) Save(_ context.Context, m *Mission) error { s.mission = m; return nil }
func (s *checkpointTestStore) SaveCheckpoint(_ context.Context, _ types.ID, _ *MissionCheckpoint) error {
	return nil
}
func (s *checkpointTestStore) GetByName(_ context.Context, _ string) (*Mission, error) {
	return nil, nil
}
func (s *checkpointTestStore) List(_ context.Context, _ *MissionFilter) ([]*Mission, error) {
	return nil, nil
}
func (s *checkpointTestStore) Update(_ context.Context, _ *Mission) error { return nil }
func (s *checkpointTestStore) UpdateStatus(_ context.Context, _ types.ID, _ MissionStatus) error {
	return nil
}
func (s *checkpointTestStore) UpdateProgress(_ context.Context, _ types.ID, _ float64) error {
	return nil
}
func (s *checkpointTestStore) Delete(_ context.Context, _ types.ID) error { return nil }
func (s *checkpointTestStore) GetByTarget(_ context.Context, _ types.ID) ([]*Mission, error) {
	return nil, nil
}
func (s *checkpointTestStore) GetActive(_ context.Context) ([]*Mission, error) { return nil, nil }
func (s *checkpointTestStore) Count(_ context.Context, _ *MissionFilter) (int, error) {
	return 0, nil
}
func (s *checkpointTestStore) GetByNameAndStatus(_ context.Context, _ string, _ MissionStatus) (*Mission, error) {
	return nil, nil
}
func (s *checkpointTestStore) ListByName(_ context.Context, _ string, _ int) ([]*Mission, error) {
	return nil, nil
}
func (s *checkpointTestStore) GetLatestByName(_ context.Context, _ string) (*Mission, error) {
	return nil, nil
}
func (s *checkpointTestStore) IncrementRunNumber(_ context.Context, _ string) (int, error) {
	return 0, nil
}
func (s *checkpointTestStore) FindOrCreateByName(_ context.Context, m *Mission) (*Mission, bool, error) {
	return m, true, nil
}
func (s *checkpointTestStore) CreateDefinition(_ context.Context, _ *MissionDefinition) error {
	return nil
}
func (s *checkpointTestStore) GetDefinition(_ context.Context, _ string) (*MissionDefinition, error) {
	return nil, nil
}
func (s *checkpointTestStore) ListDefinitions(_ context.Context) ([]*MissionDefinition, error) {
	return nil, nil
}
func (s *checkpointTestStore) UpdateDefinition(_ context.Context, _ *MissionDefinition) error {
	return nil
}
func (s *checkpointTestStore) DeleteDefinition(_ context.Context, _ string) error { return nil }

// Compile-time assertion.
var _ MissionStore = (*checkpointTestStore)(nil)

// newCheckpointTestMission returns a minimal Mission for checkpoint tests.
func newCheckpointTestMission() *Mission {
	id := types.NewID()
	wfID := types.NewID()
	now := time.Now()
	nowUT := NewUnixTime(now)
	return &Mission{
		ID:                  id,
		MissionDefinitionID: wfID,
		Status:              MissionStatusRunning,
		CreatedAt:           nowUT,
		UpdatedAt:           nowUT,
		Metrics:             &MissionMetrics{StartedAt: now},
	}
}

// newCheckpointTestState returns a minimal MissionState with one completed node.
func newCheckpointTestState(missionID types.ID) *MissionState {
	now := time.Now()
	return &MissionState{
		MissionID: missionID,
		Status:    MissionStatusRunning,
		StartedAt: now,
		NodeStates: map[string]*NodeState{
			"node1": {
				Status:      NodeStatusCompleted,
				StartedAt:   &now,
				CompletedAt: &now,
			},
		},
		Results: map[string]*NodeResult{},
	}
}

func TestCheckpointManager_FindingLister_ThreeIDs(t *testing.T) {
	mission := newCheckpointTestMission()
	store := &checkpointTestStore{mission: mission}

	ids := []types.ID{types.NewID(), types.NewID(), types.NewID()}
	lister := &mockFindingLister{ids: ids}

	manager := NewCheckpointManager(store, lister)
	state := newCheckpointTestState(mission.ID)

	ctx := context.Background()
	checkpoint, err := manager.Capture(ctx, mission.ID, state)
	require.NoError(t, err)
	require.NotNil(t, checkpoint)

	assert.Len(t, checkpoint.FindingIDs, 3, "checkpoint should carry 3 finding IDs")
	for _, id := range ids {
		assert.Contains(t, checkpoint.FindingIDs, id)
	}
}

func TestCheckpointManager_FindingLister_Error_FallsBackToEmpty(t *testing.T) {
	mission := newCheckpointTestMission()
	store := &checkpointTestStore{mission: mission}

	lister := &mockFindingLister{err: errors.New("redis unavailable")}

	manager := NewCheckpointManager(store, lister)
	state := newCheckpointTestState(mission.ID)

	ctx := context.Background()
	// Capture must succeed even when the lister fails.
	checkpoint, err := manager.Capture(ctx, mission.ID, state)
	require.NoError(t, err)
	require.NotNil(t, checkpoint)

	assert.Empty(t, checkpoint.FindingIDs, "finding IDs should be empty on lister error")
}

func TestCheckpointManager_NilFindingLister_SilentlyEmpty(t *testing.T) {
	mission := newCheckpointTestMission()
	store := &checkpointTestStore{mission: mission}

	// Pass nil lister — no finding collection attempted.
	manager := NewCheckpointManager(store, nil)
	state := newCheckpointTestState(mission.ID)

	ctx := context.Background()
	checkpoint, err := manager.Capture(ctx, mission.ID, state)
	require.NoError(t, err)
	require.NotNil(t, checkpoint)

	assert.Empty(t, checkpoint.FindingIDs, "nil lister should produce empty finding IDs")
}
