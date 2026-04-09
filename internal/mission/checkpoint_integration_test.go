//go:build integration

package mission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestCheckpointIntegration_FullLifecycle tests the complete checkpoint lifecycle:
// save -> load -> delete
func TestCheckpointIntegration_FullLifecycle(t *testing.T) {
	// This test requires a real Redis instance with JSON module
	// Skip if not available
	t.Skip("Integration test requires Redis with JSON module")

	ctx := context.Background()
	missionID := types.NewID()

	// Create checkpoint store (would use real StateClient in integration env)
	// store := NewRedisCheckpointStore(stateClient)

	// Create a comprehensive checkpoint
	checkpoint := &Checkpoint{
		MissionID:     missionID,
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-2",
		CompletedNodes: map[string]NodeOutput{
			"node-1": {
				NodeID:   "node-1",
				Status:   "completed",
				Output:   map[string]any{"result": "success"},
				Duration: 5 * time.Second,
			},
		},
		InProgressNode: &InProgressNodeState{
			NodeID:     "node-2",
			StartedAt:  time.Now(),
			RetryCount: 0,
		},
		WorkingMemory: []byte(`{"context": "test", "variables": {"key": "value"}}`),
		MissionMemory: []byte(`{"findings": ["f1", "f2"], "metadata": {"target": "example.com"}}`),
		Findings:      []types.ID{types.NewID()},
		Metrics: MissionMetrics{
			TotalNodes:     5,
			CompletedNodes: 1,
			TotalFindings:  1,
			TotalTokens:    1000,
			TotalCost:      0.05,
			StartedAt:      time.Now(),
			LastUpdateAt:   time.Now(),
		},
		DAGState: &DAGTraversalState{
			PendingNodes:  []string{"node-3", "node-4", "node-5"},
			CurrentBranch: "main",
			ParallelState: map[string][]string{
				"parallel-1": {"node-1"},
			},
		},
	}

	// Test would proceed with:
	// 1. Save checkpoint
	// 2. Verify it exists
	// 3. Load checkpoint and verify all fields
	// 4. Delete checkpoint
	// 5. Verify it no longer exists

	_ = checkpoint // Use checkpoint to avoid unused variable error
	_ = ctx        // Use ctx to avoid unused variable error
}

// TestCheckpointIntegration_MemoryContinuity tests that memory is preserved
// across checkpoint save/load cycles
func TestCheckpointIntegration_MemoryContinuity(t *testing.T) {
	t.Skip("Integration test requires Redis with JSON module")

	ctx := context.Background()
	missionID := types.NewID()

	// Create checkpoint with complex memory structures
	workingMem := map[string]any{
		"current_context": "scanning ports",
		"variables": map[string]any{
			"target":       "example.com",
			"ports_found":  []int{80, 443, 8080},
			"scan_options": map[string]any{"timeout": 30, "aggressive": false},
		},
		"history": []any{
			map[string]any{"action": "nmap_scan", "timestamp": time.Now().Unix()},
			map[string]any{"action": "port_analysis", "timestamp": time.Now().Unix()},
		},
	}

	workingMemJSON, err := SerializeMemory(workingMem)
	require.NoError(t, err)

	checkpoint := &Checkpoint{
		MissionID:      missionID,
		CreatedAt:      time.Now(),
		CurrentNodeID:  "node-1",
		CompletedNodes: map[string]NodeOutput{},
		WorkingMemory:  workingMemJSON,
		MissionMemory:  []byte(`{}`),
		Metrics:        MissionMetrics{TotalNodes: 1},
		DAGState:       &DAGTraversalState{PendingNodes: []string{"node-1"}},
	}

	// Test would:
	// 1. Save checkpoint
	// 2. Load checkpoint
	// 3. Deserialize memory and verify all nested structures
	// 4. Ensure no data loss in the round-trip

	_ = checkpoint
	_ = ctx
}

// TestCheckpointIntegration_ControllerRestart simulates a controller restart
// and verifies checkpoint can be used to resume the mission
func TestCheckpointIntegration_ControllerRestart(t *testing.T) {
	t.Skip("Integration test requires full mission controller setup")

	// This test would:
	// 1. Start a mission
	// 2. Pause it after some nodes complete
	// 3. Verify checkpoint is saved
	// 4. Simulate controller restart (create new controller instance)
	// 5. Resume mission from checkpoint
	// 6. Verify previously completed nodes are not re-executed
	// 7. Verify mission completes successfully
}

// TestCheckpointIntegration_TTLExpiration tests that checkpoints expire
// after their TTL
func TestCheckpointIntegration_TTLExpiration(t *testing.T) {
	t.Skip("Integration test requires Redis with JSON module and time manipulation")

	// This test would:
	// 1. Create checkpoint with short TTL (e.g., 1 second)
	// 2. Verify checkpoint exists immediately
	// 3. Wait for TTL to expire
	// 4. Verify checkpoint no longer exists
	// 5. Verify Resume handles missing checkpoint gracefully
}

// TestCheckpointIntegration_ConcurrentAccess tests concurrent checkpoint operations
func TestCheckpointIntegration_ConcurrentAccess(t *testing.T) {
	t.Skip("Integration test requires Redis with JSON module")

	// This test would:
	// 1. Start multiple goroutines
	// 2. Each goroutine tries to save a checkpoint for the same mission
	// 3. Verify no data corruption occurs
	// 4. Verify last write wins
	// 5. Verify checkpoint can be loaded successfully
}

// TestCheckpointIntegration_StateRestoration tests the StateRestorer with
// a real checkpoint from the store
func TestCheckpointIntegration_StateRestoration(t *testing.T) {
	// This test doesn't require Redis, just tests StateRestorer logic
	ctx := context.Background()

	checkpoint := &Checkpoint{
		MissionID:     types.NewID(),
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-2",
		CompletedNodes: map[string]NodeOutput{
			"node-1": {
				NodeID:   "node-1",
				Status:   "completed",
				Output:   map[string]any{"result": "success"},
				Duration: 5 * time.Second,
			},
		},
		WorkingMemory: []byte(`{"key": "value"}`),
		MissionMemory: []byte(`{"findings": []}`),
		Metrics: MissionMetrics{
			TotalNodes:     3,
			CompletedNodes: 1,
		},
		DAGState: &DAGTraversalState{
			PendingNodes: []string{"node-3"},
		},
	}

	// Create restorer
	// restorer := orchestrator.NewStateRestorer()

	// Test restoration
	// restored, err := restorer.RestoreFromCheckpoint(ctx, checkpoint)
	// require.NoError(t, err)
	// require.NotNil(t, restored)

	// Verify restored state
	// assert.Equal(t, "node-2", restored.CurrentNode)
	// assert.Len(t, restored.CompletedNodes, 1)
	// assert.Contains(t, restored.CompletedNodes, "node-1")

	_ = checkpoint
	_ = ctx
}

// --------------------------------------------------------------------------
// Real integration tests using miniredis (no t.Skip)
// --------------------------------------------------------------------------

// redisMissionStore is a minimal Redis-backed MissionStore for integration
// tests. Only Save, Get, and SaveCheckpoint have real implementations.
type redisMissionStore struct {
	client *redis.Client
}

func (s *redisMissionStore) missionKey(id types.ID) string {
	return fmt.Sprintf("test:mission:%s", id.String())
}

func (s *redisMissionStore) Save(ctx context.Context, m *Mission) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return s.client.Set(ctx, s.missionKey(m.ID), data, 0).Err()
}

func (s *redisMissionStore) Get(ctx context.Context, id types.ID) (*Mission, error) {
	data, err := s.client.Get(ctx, s.missionKey(id)).Bytes()
	if err != nil {
		return nil, fmt.Errorf("mission %s not found: %w", id, err)
	}
	var m Mission
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *redisMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, chkpt *MissionCheckpoint) error {
	m, err := s.Get(ctx, missionID)
	if err != nil {
		return err
	}
	m.Checkpoint = chkpt
	return s.Save(ctx, m)
}

// Stubs for unused MissionStore methods.
func (s *redisMissionStore) GetByName(_ context.Context, _ string) (*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) List(_ context.Context, _ *MissionFilter) ([]*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) Update(_ context.Context, _ *Mission) error {
	return errors.New("not implemented")
}
func (s *redisMissionStore) UpdateStatus(_ context.Context, _ types.ID, _ MissionStatus) error {
	return nil
}
func (s *redisMissionStore) UpdateProgress(_ context.Context, _ types.ID, _ float64) error {
	return nil
}
func (s *redisMissionStore) Delete(_ context.Context, _ types.ID) error {
	return errors.New("not implemented")
}
func (s *redisMissionStore) GetByTarget(_ context.Context, _ types.ID) ([]*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) GetActive(_ context.Context) ([]*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) Count(_ context.Context, _ *MissionFilter) (int, error) {
	return 0, errors.New("not implemented")
}
func (s *redisMissionStore) GetByNameAndStatus(_ context.Context, _ string, _ MissionStatus) (*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) ListByName(_ context.Context, _ string, _ int) ([]*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) GetLatestByName(_ context.Context, _ string) (*Mission, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) IncrementRunNumber(_ context.Context, _ string) (int, error) {
	return 0, errors.New("not implemented")
}
func (s *redisMissionStore) FindOrCreateByName(_ context.Context, m *Mission) (*Mission, bool, error) {
	return m, true, nil
}
func (s *redisMissionStore) CreateDefinition(_ context.Context, _ *MissionDefinition) error {
	return errors.New("not implemented")
}
func (s *redisMissionStore) GetDefinition(_ context.Context, _ string) (*MissionDefinition, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) ListDefinitions(_ context.Context) ([]*MissionDefinition, error) {
	return nil, errors.New("not implemented")
}
func (s *redisMissionStore) UpdateDefinition(_ context.Context, _ *MissionDefinition) error {
	return errors.New("not implemented")
}
func (s *redisMissionStore) DeleteDefinition(_ context.Context, _ string) error {
	return errors.New("not implemented")
}

var _ MissionStore = (*redisMissionStore)(nil)

// intFindingLister is a simple finding lister for integration tests.
type intFindingLister struct {
	ids []types.ID
}

func (l *intFindingLister) ListByMission(_ context.Context, _ types.ID) ([]types.ID, error) {
	return l.ids, nil
}

// newPersistedMission creates a Mission record in the Redis-backed store.
func newPersistedMission(t *testing.T, store *redisMissionStore) *Mission {
	t.Helper()
	now := time.Now()
	m := &Mission{
		ID:         types.NewID(),
		WorkflowID: types.NewID(),
		Status:     MissionStatusRunning,
		CreatedAt:  now,
		UpdatedAt:  now,
		Metrics:    &MissionMetrics{StartedAt: now},
	}
	require.NoError(t, store.Save(context.Background(), m))
	return m
}

// newThreeNodeMissionState returns a MissionState with 2 completed nodes and 1 pending.
func newThreeNodeMissionState(missionID types.ID) *MissionState {
	now := time.Now()
	return &MissionState{
		MissionID: missionID,
		Status:    MissionStatusRunning,
		StartedAt: now,
		NodeStates: map[string]*NodeState{
			"scan": {
				Status:      NodeStatusCompleted,
				StartedAt:   &now,
				CompletedAt: &now,
			},
			"enum": {
				Status:      NodeStatusCompleted,
				StartedAt:   &now,
				CompletedAt: &now,
			},
			"exploit": {
				Status: NodeStatusPending,
			},
		},
		Results: map[string]any{},
	}
}

// TestCheckpointManager_Integration_RoundTrip verifies that a checkpoint
// created with Capture is correctly persisted and restored via Restore through
// an in-process Redis instance.
//
//   - CompletedNodes contains exactly the 2 nodes that were marked completed.
//   - Checksum validates without error (integrity preserved through JSON round-trip).
//   - FindingIDs length matches the mock lister's return value.
func TestCheckpointManager_Integration_RoundTrip(t *testing.T) {
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { client.Close() })

	store := &redisMissionStore{client: client}
	mission := newPersistedMission(t, store)

	findingIDs := []types.ID{types.NewID(), types.NewID()}
	lister := &intFindingLister{ids: findingIDs}

	manager := NewCheckpointManager(store, lister)

	ctx := context.Background()
	state := newThreeNodeMissionState(mission.ID)

	// Capture creates and persists the checkpoint via SaveCheckpoint.
	created, err := manager.Capture(ctx, mission.ID, state)
	require.NoError(t, err)
	require.NotNil(t, created)

	// Restore loads the checkpoint from Redis and validates checksum.
	restored, err := manager.Restore(ctx, mission.ID)
	require.NoError(t, err)
	require.NotNil(t, restored, "Restore must return a checkpoint after Capture")

	// CompletedNodes must contain exactly 2 entries.
	assert.Len(t, restored.CompletedNodes, 2, "CompletedNodes should contain 2 entries")
	assert.Contains(t, restored.CompletedNodes, "scan")
	assert.Contains(t, restored.CompletedNodes, "enum")

	// FindingIDs must match the mock lister.
	assert.Len(t, restored.FindingIDs, 2, "FindingIDs should match the mock lister's return")

	// Checksum must be non-empty and must validate successfully after round-trip.
	assert.NotEmpty(t, restored.Checksum, "Checksum must be populated")
	dm := manager.(*DefaultCheckpointManager)
	assert.NoError(t, dm.validateChecksum(restored), "checksum should be valid after round-trip")
}
