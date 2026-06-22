package mission

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// trackingOrchestrator records which Execute path was taken.
type trackingOrchestrator struct {
	executeCount               int
	executeFromCheckpointCount int
	lastCheckpoint             *MissionCheckpoint
}

func (t *trackingOrchestrator) Execute(_ context.Context, _ *Mission) (*MissionResult, error) {
	t.executeCount++
	return &MissionResult{Status: MissionStatusCompleted}, nil
}

func (t *trackingOrchestrator) ExecuteFromCheckpoint(_ context.Context, m *Mission, cp *MissionCheckpoint) (*MissionResult, error) {
	t.executeFromCheckpointCount++
	t.lastCheckpoint = cp
	return &MissionResult{MissionID: m.ID, Status: MissionStatusCompleted}, nil
}

func (t *trackingOrchestrator) StopMission(_ context.Context, _ types.ID) error {
	return nil
}

// Compile-time assertion.
var _ MissionOrchestrator = (*trackingOrchestrator)(nil)

// TestMissionOrchestrator_ExecuteFromCheckpoint_Interface verifies the interface
// is satisfied and ExecuteFromCheckpoint can be called with a checkpoint.
func TestMissionOrchestrator_ExecuteFromCheckpoint_Interface(t *testing.T) {
	orch := &trackingOrchestrator{}
	mission := &Mission{ID: types.NewID()}

	cp := &MissionCheckpoint{
		ID:             types.NewID(),
		CompletedNodes: []string{"node-1", "node-2"},
	}

	ctx := context.Background()
	result, err := orch.ExecuteFromCheckpoint(ctx, mission, cp)
	require.NoError(t, err)
	assert.Equal(t, MissionStatusCompleted, result.Status)
	assert.Equal(t, 1, orch.executeFromCheckpointCount)
	assert.Equal(t, cp, orch.lastCheckpoint)
}

// TestMissionOrchestrator_Execute_NoCheckpoint verifies Execute is called
// (not ExecuteFromCheckpoint) when no checkpoint is provided.
func TestMissionOrchestrator_Execute_NoCheckpoint(t *testing.T) {
	orch := &trackingOrchestrator{}
	mission := &Mission{ID: types.NewID()}

	ctx := context.Background()
	result, err := orch.Execute(ctx, mission)
	require.NoError(t, err)
	assert.Equal(t, MissionStatusCompleted, result.Status)
	assert.Equal(t, 1, orch.executeCount)
	assert.Equal(t, 0, orch.executeFromCheckpointCount)
}
