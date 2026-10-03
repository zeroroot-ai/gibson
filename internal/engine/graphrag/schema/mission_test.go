// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package schema

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

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

// testMission is the shape a :Mission read decodes into. The package has no
// constructor: nothing here writes a :Mission node (see doc.go).
func testMission() *Mission {
	return &Mission{
		ID:          types.NewID(),
		Name:        "test-mission",
		Description: "description",
		Objective:   "objective",
		TargetRef:   "target",
		Status:      MissionStatusPending,
		CreatedAt:   time.Now(),
		YAMLSource:  "yaml",
	}
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
