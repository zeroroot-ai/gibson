package orchestrator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestStateRestorer_RestoreFromCheckpoint(t *testing.T) {
	restorer := NewStateRestorer()
	ctx := context.Background()

	// Create a valid checkpoint
	checkpoint := &mission.Checkpoint{
		MissionID:     types.NewID(),
		CreatedAt:     time.Now(),
		CurrentNodeID: "node-2",
		CompletedNodes: map[string]mission.NodeOutput{
			"node-1": {
				NodeID:   "node-1",
				Status:   "completed",
				Output:   map[string]any{"result": "success"},
				Duration: 5 * time.Second,
			},
		},
		InProgressNode: &mission.InProgressNodeState{
			NodeID:     "node-2",
			StartedAt:  time.Now(),
			RetryCount: 1,
		},
		WorkingMemory: []byte(`{"key1": "value1", "key2": 42}`),
		MissionMemory: []byte(`{"findings": ["f1", "f2"]}`),
		Findings:      []types.ID{types.NewID()},
		Metrics: mission.MissionMetrics{
			TotalNodes:     3,
			CompletedNodes: 1,
		},
		DAGState: &mission.DAGTraversalState{
			PendingNodes:  []string{"node-3"},
			CurrentBranch: "main",
			ParallelState: map[string][]string{
				"parallel-1": {"node-1"},
			},
		},
	}

	// Restore the checkpoint
	restored, err := restorer.RestoreFromCheckpoint(ctx, checkpoint)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify restored state
	assert.Equal(t, checkpoint.CurrentNodeID, restored.CurrentNode)
	assert.Len(t, restored.CompletedNodes, 1)
	assert.Contains(t, restored.CompletedNodes, "node-1")
	assert.Len(t, restored.PendingQueue, 1)
	assert.Contains(t, restored.PendingQueue, "node-3")

	// Verify in-progress node
	assert.NotNil(t, restored.InProgressNode)
	assert.Equal(t, "node-2", restored.InProgressNode.NodeID)
	assert.Equal(t, 1, restored.InProgressNode.RetryCount)

	// Verify parallel state
	assert.NotNil(t, restored.ParallelState)
	assert.Contains(t, restored.ParallelState, "parallel-1")

	// Verify memory deserialization
	assert.NotNil(t, restored.WorkingMemory)
	assert.Equal(t, "value1", restored.WorkingMemory["key1"])
	assert.Equal(t, float64(42), restored.WorkingMemory["key2"]) // JSON unmarshals numbers as float64

	assert.NotNil(t, restored.MissionMemory)
	findings, ok := restored.MissionMemory["findings"].([]any)
	assert.True(t, ok)
	assert.Len(t, findings, 2)
}

func TestStateRestorer_RestoreFromCheckpoint_NilCheckpoint(t *testing.T) {
	restorer := NewStateRestorer()
	ctx := context.Background()

	restored, err := restorer.RestoreFromCheckpoint(ctx, nil)
	assert.Error(t, err)
	assert.Nil(t, restored)
	assert.Contains(t, err.Error(), "checkpoint cannot be nil")
}

func TestStateRestorer_RestoreFromCheckpoint_EmptyMemory(t *testing.T) {
	restorer := NewStateRestorer()
	ctx := context.Background()

	checkpoint := &mission.Checkpoint{
		MissionID:      types.NewID(),
		CreatedAt:      time.Now(),
		CurrentNodeID:  "node-1",
		CompletedNodes: map[string]mission.NodeOutput{},
		WorkingMemory:  []byte{}, // Empty memory
		MissionMemory:  []byte{}, // Empty memory
		Metrics: mission.MissionMetrics{
			TotalNodes: 1,
		},
		DAGState: &mission.DAGTraversalState{
			PendingNodes: []string{"node-1"},
		},
	}

	restored, err := restorer.RestoreFromCheckpoint(ctx, checkpoint)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify empty memory is initialized
	assert.NotNil(t, restored.WorkingMemory)
	assert.Len(t, restored.WorkingMemory, 0)
	assert.NotNil(t, restored.MissionMemory)
	assert.Len(t, restored.MissionMemory, 0)
}

func TestStateRestorer_RestoreFromCheckpoint_CorruptedWorkingMemory(t *testing.T) {
	restorer := NewStateRestorer()
	ctx := context.Background()

	checkpoint := &mission.Checkpoint{
		MissionID:      types.NewID(),
		CreatedAt:      time.Now(),
		CurrentNodeID:  "node-1",
		CompletedNodes: map[string]mission.NodeOutput{},
		WorkingMemory:  []byte(`{invalid json`), // Corrupted JSON
		MissionMemory:  []byte(`{}`),
		Metrics: mission.MissionMetrics{
			TotalNodes: 1,
		},
		DAGState: &mission.DAGTraversalState{
			PendingNodes: []string{"node-1"},
		},
	}

	// Should return partial state with error
	restored, err := restorer.RestoreFromCheckpoint(ctx, checkpoint)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize working memory")
	require.NotNil(t, restored) // Partial state should be returned

	// Verify we got the other fields
	assert.Equal(t, checkpoint.CurrentNodeID, restored.CurrentNode)
}

func TestStateRestorer_RestoreFromCheckpoint_CorruptedMissionMemory(t *testing.T) {
	restorer := NewStateRestorer()
	ctx := context.Background()

	checkpoint := &mission.Checkpoint{
		MissionID:      types.NewID(),
		CreatedAt:      time.Now(),
		CurrentNodeID:  "node-1",
		CompletedNodes: map[string]mission.NodeOutput{},
		WorkingMemory:  []byte(`{}`),
		MissionMemory:  []byte(`{invalid json`), // Corrupted JSON
		Metrics: mission.MissionMetrics{
			TotalNodes: 1,
		},
		DAGState: &mission.DAGTraversalState{
			PendingNodes: []string{"node-1"},
		},
	}

	// Should return partial state with error
	restored, err := restorer.RestoreFromCheckpoint(ctx, checkpoint)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize mission memory")
	require.NotNil(t, restored) // Partial state should be returned

	// Verify we got the other fields
	assert.Equal(t, checkpoint.CurrentNodeID, restored.CurrentNode)
}

func TestStateRestorer_ValidateCheckpoint(t *testing.T) {
	restorer := NewStateRestorer()

	tests := []struct {
		name        string
		checkpoint  *mission.Checkpoint
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid checkpoint",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.NewID(),
				CreatedAt:      time.Now(),
				CompletedNodes: map[string]mission.NodeOutput{},
				Metrics: mission.MissionMetrics{
					TotalNodes: 1,
				},
			},
			expectError: false,
		},
		{
			name:        "nil checkpoint",
			checkpoint:  nil,
			expectError: true,
			errorMsg:    "checkpoint is nil",
		},
		{
			name: "zero mission ID",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.ID(""),
				CreatedAt:      time.Now(),
				CompletedNodes: map[string]mission.NodeOutput{},
			},
			expectError: true,
			errorMsg:    "zero mission ID",
		},
		{
			name: "zero creation time",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.NewID(),
				CreatedAt:      time.Time{},
				CompletedNodes: map[string]mission.NodeOutput{},
			},
			expectError: true,
			errorMsg:    "zero creation time",
		},
		{
			name: "nil completed nodes",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.NewID(),
				CreatedAt:      time.Now(),
				CompletedNodes: nil,
			},
			expectError: true,
			errorMsg:    "nil completed nodes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := restorer.ValidateCheckpoint(tt.checkpoint)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStateRestorer_ValidateCheckpointWithDefinition(t *testing.T) {
	restorer := NewStateRestorer()

	// Create a test mission definition
	def := &mission.MissionDefinition{
		Name:        "test-mission",
		Description: "Test mission for validation",
		Nodes: []*mission.NodeDefinition{
			{ID: "node-1", Name: "Node 1", Type: "agent"},
			{ID: "node-2", Name: "Node 2", Type: "agent"},
			{ID: "node-3", Name: "Node 3", Type: "agent"},
		},
	}

	tests := []struct {
		name        string
		checkpoint  *mission.Checkpoint
		definition  *mission.MissionDefinition
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid checkpoint with definition",
			checkpoint: &mission.Checkpoint{
				MissionID:     types.NewID(),
				CreatedAt:     time.Now(),
				CurrentNodeID: "node-2",
				CompletedNodes: map[string]mission.NodeOutput{
					"node-1": {NodeID: "node-1"},
				},
				DAGState: &mission.DAGTraversalState{
					PendingNodes: []string{"node-3"},
				},
			},
			definition:  def,
			expectError: false,
		},
		{
			name: "nil definition",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.NewID(),
				CreatedAt:      time.Now(),
				CompletedNodes: map[string]mission.NodeOutput{},
			},
			definition:  nil,
			expectError: true,
			errorMsg:    "mission definition is nil",
		},
		{
			name: "current node not in definition",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.NewID(),
				CreatedAt:      time.Now(),
				CurrentNodeID:  "invalid-node",
				CompletedNodes: map[string]mission.NodeOutput{},
			},
			definition:  def,
			expectError: true,
			errorMsg:    "current node \"invalid-node\" not found",
		},
		{
			name: "completed node not in definition",
			checkpoint: &mission.Checkpoint{
				MissionID:     types.NewID(),
				CreatedAt:     time.Now(),
				CurrentNodeID: "node-1",
				CompletedNodes: map[string]mission.NodeOutput{
					"invalid-node": {NodeID: "invalid-node"},
				},
			},
			definition:  def,
			expectError: true,
			errorMsg:    "completed node \"invalid-node\" not found",
		},
		{
			name: "pending node not in definition",
			checkpoint: &mission.Checkpoint{
				MissionID:      types.NewID(),
				CreatedAt:      time.Now(),
				CurrentNodeID:  "node-1",
				CompletedNodes: map[string]mission.NodeOutput{},
				DAGState: &mission.DAGTraversalState{
					PendingNodes: []string{"invalid-node"},
				},
			},
			definition:  def,
			expectError: true,
			errorMsg:    "pending node \"invalid-node\" not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := restorer.ValidateCheckpointWithDefinition(tt.checkpoint, tt.definition)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStateRestorer_RestoreFromCheckpoint_ComplexMemory(t *testing.T) {
	restorer := NewStateRestorer()
	ctx := context.Background()

	// Create complex memory structures
	workingMem := map[string]any{
		"string_value": "test",
		"int_value":    42,
		"nested": map[string]any{
			"level2": map[string]any{
				"level3": "deep value",
			},
		},
		"array": []any{1, 2, 3, "four"},
	}

	missionMem := map[string]any{
		"findings": []any{
			map[string]any{"id": "f1", "severity": "high"},
			map[string]any{"id": "f2", "severity": "medium"},
		},
		"context": map[string]any{
			"target": "example.com",
			"ports":  []any{80, 443, 8080},
		},
	}

	workingJSON, err := json.Marshal(workingMem)
	require.NoError(t, err)

	missionJSON, err := json.Marshal(missionMem)
	require.NoError(t, err)

	checkpoint := &mission.Checkpoint{
		MissionID:      types.NewID(),
		CreatedAt:      time.Now(),
		CurrentNodeID:  "node-1",
		CompletedNodes: map[string]mission.NodeOutput{},
		WorkingMemory:  workingJSON,
		MissionMemory:  missionJSON,
		Metrics: mission.MissionMetrics{
			TotalNodes: 1,
		},
		DAGState: &mission.DAGTraversalState{
			PendingNodes: []string{"node-1"},
		},
	}

	restored, err := restorer.RestoreFromCheckpoint(ctx, checkpoint)
	require.NoError(t, err)
	require.NotNil(t, restored)

	// Verify complex working memory structure
	assert.Equal(t, "test", restored.WorkingMemory["string_value"])
	assert.Equal(t, float64(42), restored.WorkingMemory["int_value"])

	nested, ok := restored.WorkingMemory["nested"].(map[string]any)
	require.True(t, ok)
	level2, ok := nested["level2"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "deep value", level2["level3"])

	array, ok := restored.WorkingMemory["array"].([]any)
	require.True(t, ok)
	assert.Len(t, array, 4)

	// Verify complex mission memory structure
	findings, ok := restored.MissionMemory["findings"].([]any)
	require.True(t, ok)
	assert.Len(t, findings, 2)

	context, ok := restored.MissionMemory["context"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "example.com", context["target"])

	ports, ok := context["ports"].([]any)
	require.True(t, ok)
	assert.Len(t, ports, 3)
}
