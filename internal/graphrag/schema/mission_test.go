package schema

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/types"
)

func TestMissionStatus_Validate(t *testing.T) {
	tests := []struct {
		name    string
		status  MissionStatus
		wantErr bool
	}{
		{
			name:    "valid pending status",
			status:  MissionStatusPending,
			wantErr: false,
		},
		{
			name:    "valid running status",
			status:  MissionStatusRunning,
			wantErr: false,
		},
		{
			name:    "valid completed status",
			status:  MissionStatusCompleted,
			wantErr: false,
		},
		{
			name:    "valid failed status",
			status:  MissionStatusFailed,
			wantErr: false,
		},
		{
			name:    "invalid status",
			status:  MissionStatus("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.status.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMissionNodeStatus_Validate(t *testing.T) {
	tests := []struct {
		name    string
		status  MissionNodeStatus
		wantErr bool
	}{
		{
			name:    "valid pending status",
			status:  MissionNodeStatusPending,
			wantErr: false,
		},
		{
			name:    "valid ready status",
			status:  MissionNodeStatusReady,
			wantErr: false,
		},
		{
			name:    "valid running status",
			status:  MissionNodeStatusRunning,
			wantErr: false,
		},
		{
			name:    "valid completed status",
			status:  MissionNodeStatusCompleted,
			wantErr: false,
		},
		{
			name:    "valid failed status",
			status:  MissionNodeStatusFailed,
			wantErr: false,
		},
		{
			name:    "valid skipped status",
			status:  MissionNodeStatusSkipped,
			wantErr: false,
		},
		{
			name:    "invalid status",
			status:  MissionNodeStatus("invalid"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.status.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMissionNodeType_Validate(t *testing.T) {
	tests := []struct {
		name     string
		nodeType MissionNodeType
		wantErr  bool
	}{
		{
			name:     "valid agent type",
			nodeType: MissionNodeTypeAgent,
			wantErr:  false,
		},
		{
			name:     "valid tool type",
			nodeType: MissionNodeTypeTool,
			wantErr:  false,
		},
		{
			name:     "invalid type",
			nodeType: MissionNodeType("invalid"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.nodeType.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRetryPolicy_Validate(t *testing.T) {
	tests := []struct {
		name    string
		policy  *RetryPolicy
		wantErr bool
	}{
		{
			name: "valid policy",
			policy: &RetryPolicy{
				MaxRetries: 3,
				Backoff:    time.Second,
				Strategy:   "exponential",
				MaxBackoff: time.Minute,
			},
			wantErr: false,
		},
		{
			name: "valid policy with linear strategy",
			policy: &RetryPolicy{
				MaxRetries: 5,
				Backoff:    2 * time.Second,
				Strategy:   "linear",
			},
			wantErr: false,
		},
		{
			name: "negative max retries",
			policy: &RetryPolicy{
				MaxRetries: -1,
				Backoff:    time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative backoff",
			policy: &RetryPolicy{
				MaxRetries: 3,
				Backoff:    -time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid strategy",
			policy: &RetryPolicy{
				MaxRetries: 3,
				Backoff:    time.Second,
				Strategy:   "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.policy.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRetryPolicy_ToJSON(t *testing.T) {
	policy := &RetryPolicy{
		MaxRetries: 3,
		Backoff:    time.Second,
		Strategy:   "exponential",
		MaxBackoff: time.Minute,
	}

	jsonStr, err := policy.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonStr)

	// Verify it's valid JSON and can be unmarshaled
	var decoded RetryPolicy
	err = json.Unmarshal([]byte(jsonStr), &decoded)
	require.NoError(t, err)
	assert.Equal(t, policy.MaxRetries, decoded.MaxRetries)
	assert.Equal(t, policy.Backoff, decoded.Backoff)
	assert.Equal(t, policy.Strategy, decoded.Strategy)
}

func TestNewMission(t *testing.T) {
	id := types.NewID()
	name := "test-mission"
	description := "Test mission description"
	objective := "Test objective"
	targetRef := "test-target"
	yamlSource := "mission:\n  name: test"

	mission := NewMission(id, name, description, objective, targetRef, yamlSource)

	assert.Equal(t, id, mission.ID)
	assert.Equal(t, name, mission.Name)
	assert.Equal(t, description, mission.Description)
	assert.Equal(t, objective, mission.Objective)
	assert.Equal(t, targetRef, mission.TargetRef)
	assert.Equal(t, yamlSource, mission.YAMLSource)
	assert.Equal(t, MissionStatusPending, mission.Status)
	assert.NotZero(t, mission.CreatedAt)
	assert.Nil(t, mission.StartedAt)
	assert.Nil(t, mission.CompletedAt)
}

func TestMission_Validate(t *testing.T) {
	tests := []struct {
		name    string
		mission *Mission
		wantErr bool
	}{
		{
			name: "valid mission",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "test-mission",
				TargetRef:  "test-target",
				Status:     MissionStatusPending,
				YAMLSource: "mission:\n  name: test",
			},
			wantErr: false,
		},
		{
			name: "empty name",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "",
				TargetRef:  "test-target",
				Status:     MissionStatusPending,
				YAMLSource: "mission:\n  name: test",
			},
			wantErr: true,
		},
		{
			name: "empty target ref (allowed for discovery missions)",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "test-mission",
				TargetRef:  "", // Empty target_ref is allowed for orchestration/discovery missions
				Status:     MissionStatusPending,
				YAMLSource: "mission:\n  name: test",
			},
			wantErr: false, // Empty target_ref is now allowed
		},
		{
			name: "empty yaml source",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "test-mission",
				TargetRef:  "test-target",
				Status:     MissionStatusPending,
				YAMLSource: "",
			},
			wantErr: true,
		},
		{
			name: "invalid status",
			mission: &Mission{
				ID:         types.NewID(),
				Name:       "test-mission",
				TargetRef:  "test-target",
				Status:     MissionStatus("invalid"),
				YAMLSource: "mission:\n  name: test",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.mission.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMission_StatusTransitions(t *testing.T) {
	mission := NewMission(
		types.NewID(),
		"test-mission",
		"description",
		"objective",
		"target",
		"yaml",
	)

	// Initially pending
	assert.Equal(t, MissionStatusPending, mission.Status)
	assert.Nil(t, mission.StartedAt)
	assert.Nil(t, mission.CompletedAt)

	// Mark started
	mission.MarkStarted()
	assert.Equal(t, MissionStatusRunning, mission.Status)
	assert.NotNil(t, mission.StartedAt)
	assert.Nil(t, mission.CompletedAt)

	// Mark completed
	mission.MarkCompleted()
	assert.Equal(t, MissionStatusCompleted, mission.Status)
	assert.NotNil(t, mission.StartedAt)
	assert.NotNil(t, mission.CompletedAt)
}

func TestMission_FailedTransition(t *testing.T) {
	mission := NewMission(
		types.NewID(),
		"test-mission",
		"description",
		"objective",
		"target",
		"yaml",
	)

	mission.MarkStarted()
	mission.MarkFailed()

	assert.Equal(t, MissionStatusFailed, mission.Status)
	assert.NotNil(t, mission.CompletedAt)
}

func TestMission_WithMethods(t *testing.T) {
	mission := NewMission(
		types.NewID(),
		"test-mission",
		"description",
		"objective",
		"target",
		"yaml",
	)

	startTime := time.Now()
	completedTime := time.Now().Add(time.Hour)

	mission.WithStatus(MissionStatusRunning).
		WithStartedAt(startTime).
		WithCompletedAt(completedTime)

	assert.Equal(t, MissionStatusRunning, mission.Status)
	assert.Equal(t, startTime, *mission.StartedAt)
	assert.Equal(t, completedTime, *mission.CompletedAt)
}

func TestNewMissionNode(t *testing.T) {
	id := types.NewID()
	missionID := types.NewID()
	name := "test-node"
	description := "Test node description"

	node := NewMissionNode(id, missionID, MissionNodeTypeAgent, name, description)

	assert.Equal(t, id, node.ID)
	assert.Equal(t, missionID, node.MissionID)
	assert.Equal(t, MissionNodeTypeAgent, node.Type)
	assert.Equal(t, name, node.Name)
	assert.Equal(t, description, node.Description)
	assert.Equal(t, MissionNodeStatusPending, node.Status)
	assert.False(t, node.IsDynamic)
	assert.NotNil(t, node.TaskConfig)
	assert.NotZero(t, node.CreatedAt)
	assert.NotZero(t, node.UpdatedAt)
}

func TestNewAgentNode(t *testing.T) {
	id := types.NewID()
	missionID := types.NewID()
	agentName := "test-agent"

	node := NewAgentNode(id, missionID, "test-node", "description", agentName)

	assert.Equal(t, MissionNodeTypeAgent, node.Type)
	assert.Equal(t, agentName, node.AgentName)
	assert.Empty(t, node.ToolName)
}

func TestNewToolNode(t *testing.T) {
	id := types.NewID()
	missionID := types.NewID()
	toolName := "test-tool"

	node := NewToolNode(id, missionID, "test-node", "description", toolName)

	assert.Equal(t, MissionNodeTypeTool, node.Type)
	assert.Equal(t, toolName, node.ToolName)
	assert.Empty(t, node.AgentName)
}

func TestMissionNode_Validate(t *testing.T) {
	tests := []struct {
		name    string
		node    *MissionNode
		wantErr bool
	}{
		{
			name: "valid agent node",
			node: &MissionNode{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				Type:      MissionNodeTypeAgent,
				Name:      "test-node",
				AgentName: "test-agent",
				Status:    MissionNodeStatusPending,
			},
			wantErr: false,
		},
		{
			name: "valid tool node",
			node: &MissionNode{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				Type:      MissionNodeTypeTool,
				Name:      "test-node",
				ToolName:  "test-tool",
				Status:    MissionNodeStatusPending,
			},
			wantErr: false,
		},
		{
			name: "agent node without agent name",
			node: &MissionNode{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				Type:      MissionNodeTypeAgent,
				Name:      "test-node",
				Status:    MissionNodeStatusPending,
			},
			wantErr: true,
		},
		{
			name: "tool node without tool name",
			node: &MissionNode{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				Type:      MissionNodeTypeTool,
				Name:      "test-node",
				Status:    MissionNodeStatusPending,
			},
			wantErr: true,
		},
		{
			name: "empty name",
			node: &MissionNode{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				Type:      MissionNodeTypeAgent,
				Name:      "",
				AgentName: "test-agent",
				Status:    MissionNodeStatusPending,
			},
			wantErr: true,
		},
		{
			name: "invalid retry policy",
			node: &MissionNode{
				ID:        types.NewID(),
				MissionID: types.NewID(),
				Type:      MissionNodeTypeAgent,
				Name:      "test-node",
				AgentName: "test-agent",
				Status:    MissionNodeStatusPending,
				RetryPolicy: &RetryPolicy{
					MaxRetries: -1,
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.node.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMissionNode_WithMethods(t *testing.T) {
	node := NewAgentNode(
		types.NewID(),
		types.NewID(),
		"test-node",
		"description",
		"test-agent",
	)

	timeout := 5 * time.Minute
	retryPolicy := &RetryPolicy{
		MaxRetries: 3,
		Backoff:    time.Second,
	}
	taskConfig := map[string]any{
		"key": "value",
	}

	node.WithStatus(MissionNodeStatusReady).
		WithTimeout(timeout).
		WithRetryPolicy(retryPolicy).
		WithTaskConfig(taskConfig)

	assert.Equal(t, MissionNodeStatusReady, node.Status)
	assert.Equal(t, timeout, node.Timeout)
	assert.Equal(t, retryPolicy, node.RetryPolicy)
	assert.Equal(t, taskConfig, node.TaskConfig)
}

func TestMissionNode_MarkDynamic(t *testing.T) {
	node := NewAgentNode(
		types.NewID(),
		types.NewID(),
		"test-node",
		"description",
		"test-agent",
	)

	assert.False(t, node.IsDynamic)
	assert.Empty(t, node.SpawnedBy)

	spawnedBy := "execution-123"
	node.MarkDynamic(spawnedBy)

	assert.True(t, node.IsDynamic)
	assert.Equal(t, spawnedBy, node.SpawnedBy)
}

func TestMissionNode_TaskConfigJSON(t *testing.T) {
	node := NewAgentNode(
		types.NewID(),
		types.NewID(),
		"test-node",
		"description",
		"test-agent",
	)

	t.Run("empty config", func(t *testing.T) {
		jsonStr, err := node.TaskConfigJSON()
		require.NoError(t, err)
		assert.Equal(t, "{}", jsonStr)
	})

	t.Run("with config", func(t *testing.T) {
		node.TaskConfig = map[string]any{
			"timeout": 60,
			"retries": 3,
			"mode":    "aggressive",
		}

		jsonStr, err := node.TaskConfigJSON()
		require.NoError(t, err)
		assert.NotEmpty(t, jsonStr)

		// Verify it's valid JSON
		var decoded map[string]any
		err = json.Unmarshal([]byte(jsonStr), &decoded)
		require.NoError(t, err)
		assert.Equal(t, float64(60), decoded["timeout"]) // JSON numbers decode as float64
		assert.Equal(t, float64(3), decoded["retries"])
		assert.Equal(t, "aggressive", decoded["mode"])
	})
}

func TestMissionNode_RetryPolicyJSON(t *testing.T) {
	node := NewAgentNode(
		types.NewID(),
		types.NewID(),
		"test-node",
		"description",
		"test-agent",
	)

	t.Run("no retry policy", func(t *testing.T) {
		jsonStr, err := node.RetryPolicyJSON()
		require.NoError(t, err)
		assert.Equal(t, "{}", jsonStr)
	})

	t.Run("with retry policy", func(t *testing.T) {
		node.RetryPolicy = &RetryPolicy{
			MaxRetries: 5,
			Backoff:    time.Second,
			Strategy:   "exponential",
		}

		jsonStr, err := node.RetryPolicyJSON()
		require.NoError(t, err)
		assert.NotEmpty(t, jsonStr)

		// Verify it's valid JSON
		var decoded RetryPolicy
		err = json.Unmarshal([]byte(jsonStr), &decoded)
		require.NoError(t, err)
		assert.Equal(t, 5, decoded.MaxRetries)
		assert.Equal(t, time.Second, decoded.Backoff)
		assert.Equal(t, "exponential", decoded.Strategy)
	})
}

func TestConstants(t *testing.T) {
	// Test label constants
	assert.Equal(t, "Mission", LabelMission)
	assert.Equal(t, "MissionNode", LabelMissionNode)

	// Test mission status constants
	assert.Equal(t, "pending", MissionStatusPending.String())
	assert.Equal(t, "running", MissionStatusRunning.String())
	assert.Equal(t, "completed", MissionStatusCompleted.String())
	assert.Equal(t, "failed", MissionStatusFailed.String())

	// Test mission node status constants
	assert.Equal(t, "pending", MissionNodeStatusPending.String())
	assert.Equal(t, "ready", MissionNodeStatusReady.String())
	assert.Equal(t, "running", MissionNodeStatusRunning.String())
	assert.Equal(t, "completed", MissionNodeStatusCompleted.String())
	assert.Equal(t, "failed", MissionNodeStatusFailed.String())
	assert.Equal(t, "skipped", MissionNodeStatusSkipped.String())

	// Test mission node type constants
	assert.Equal(t, "agent", MissionNodeTypeAgent.String())
	assert.Equal(t, "tool", MissionNodeTypeTool.String())
}
