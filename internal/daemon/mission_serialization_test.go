package daemon

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestMissionSerializationRoundTrip tests that mission definitions can be
// serialized to JSON (as stored in the database) and then deserialized back
// correctly. This is the core fix for the pause/resume bug.
func TestMissionSerializationRoundTrip(t *testing.T) {
	// Create a realistic mission definition with various node types
	original := &mission.MissionDefinition{
		ID:          types.NewID(),
		Name:        "test-mission",
		Description: "Test mission for serialization round-trip",
		Version:     "1.0.0",
		TargetRef:   "test-target",
		Nodes: map[string]*mission.MissionNode{
			"recon": {
				ID:        "recon",
				Type:      mission.NodeTypeAgent,
				Name:      "Network Reconnaissance",
				AgentName: "network-recon",
				Timeout:   10 * time.Minute,
				AgentTask: &agent.Task{
					Name:        "initial-recon",
					Description: "Perform initial network reconnaissance",
					Goal:        "Discover network topology and services",
					Context: map[string]any{
						"target": "example.com",
						"scope":  "internal",
					},
					Timeout: 10 * time.Minute,
				},
				RetryPolicy: &mission.RetryPolicy{
					MaxRetries:      3,
					BackoffStrategy: mission.BackoffExponential,
					InitialDelay:    1 * time.Second,
					MaxDelay:        30 * time.Second,
					Multiplier:      2.0,
				},
			},
			"port-scan": {
				ID:       "port-scan",
				Type:     mission.NodeTypeTool,
				Name:     "Port Scanner",
				ToolName: "nmap",
				ToolInput: map[string]any{
					"target": "example.com",
					"ports":  "1-1024",
					"flags":  "-sV -sC",
				},
				Timeout:      5 * time.Minute,
				Dependencies: []string{"recon"},
			},
			"data-fetch": {
				ID:           "data-fetch",
				Type:         mission.NodeTypePlugin,
				Name:         "Fetch Target Data",
				PluginName:   "target-db",
				PluginMethod: "query",
				PluginParams: map[string]any{
					"query":  "SELECT * FROM targets WHERE name = ?",
					"params": []string{"example.com"},
				},
				Dependencies: []string{"port-scan"},
			},
		},
		Edges: []mission.MissionEdge{
			{From: "recon", To: "port-scan"},
			{From: "port-scan", To: "data-fetch"},
		},
		EntryPoints: []string{"recon"},
		ExitPoints:  []string{"data-fetch"},
		Metadata: map[string]any{
			"author":     "test",
			"priority":   "high",
			"tags":       []string{"recon", "scanning"},
			"max_agents": 5,
		},
		CreatedAt: time.Now().UTC(),
	}

	// Simulate what happens during mission pause:
	// 1. Mission definition is serialized to JSON for storage
	missionDefinitionJSON, err := json.Marshal(original)
	require.NoError(t, err)
	require.NotEmpty(t, missionDefinitionJSON)

	// 2. During resume, we parse the JSON back
	parsed, err := mission.ParseDefinitionFromJSON(missionDefinitionJSON)
	require.NoError(t, err, "ParseDefinitionFromJSON should succeed")
	require.NotNil(t, parsed, "Parsed definition should not be nil")

	// Verify core fields survived round-trip
	assert.Equal(t, original.ID, parsed.ID, "ID should match")
	assert.Equal(t, original.Name, parsed.Name, "Name should match")
	assert.Equal(t, original.Description, parsed.Description, "Description should match")
	assert.Equal(t, original.Version, parsed.Version, "Version should match")
	assert.Equal(t, original.TargetRef, parsed.TargetRef, "TargetRef should match")

	// Verify nodes
	require.Len(t, parsed.Nodes, 3, "Should have 3 nodes")

	// Verify agent node - THIS IS THE CRITICAL TEST
	// The bug was that agent_name (JSON) wasn't being parsed because
	// the YAML parser expected "agent" field
	reconNode := parsed.Nodes["recon"]
	require.NotNil(t, reconNode, "Recon node should exist")
	assert.Equal(t, "recon", reconNode.ID, "Node ID should match")
	assert.Equal(t, mission.NodeTypeAgent, reconNode.Type, "Node type should be agent")
	assert.Equal(t, "network-recon", reconNode.AgentName, "AgentName should be parsed correctly from JSON agent_name field")
	assert.Equal(t, 10*time.Minute, reconNode.Timeout, "Timeout should be parsed correctly from nanoseconds")

	// Verify retry policy durations survived round-trip
	require.NotNil(t, reconNode.RetryPolicy, "Retry policy should exist")
	assert.Equal(t, 3, reconNode.RetryPolicy.MaxRetries)
	assert.Equal(t, mission.BackoffExponential, reconNode.RetryPolicy.BackoffStrategy)
	assert.Equal(t, 1*time.Second, reconNode.RetryPolicy.InitialDelay, "InitialDelay should survive round-trip")
	assert.Equal(t, 30*time.Second, reconNode.RetryPolicy.MaxDelay, "MaxDelay should survive round-trip")
	assert.Equal(t, 2.0, reconNode.RetryPolicy.Multiplier)

	// Verify tool node
	portScanNode := parsed.Nodes["port-scan"]
	require.NotNil(t, portScanNode, "Port scan node should exist")
	assert.Equal(t, mission.NodeTypeTool, portScanNode.Type)
	assert.Equal(t, "nmap", portScanNode.ToolName, "ToolName should be parsed correctly from JSON tool_name field")
	assert.Equal(t, 5*time.Minute, portScanNode.Timeout)
	assert.Equal(t, []string{"recon"}, portScanNode.Dependencies)

	// Verify plugin node
	dataFetchNode := parsed.Nodes["data-fetch"]
	require.NotNil(t, dataFetchNode, "Data fetch node should exist")
	assert.Equal(t, mission.NodeTypePlugin, dataFetchNode.Type)
	assert.Equal(t, "target-db", dataFetchNode.PluginName, "PluginName should be parsed correctly from JSON plugin_name field")
	assert.Equal(t, "query", dataFetchNode.PluginMethod, "PluginMethod should be parsed correctly from JSON plugin_method field")
	assert.Equal(t, []string{"port-scan"}, dataFetchNode.Dependencies)

	// Verify edges
	assert.Len(t, parsed.Edges, 2)
	assert.Equal(t, original.Edges, parsed.Edges)

	// Verify entry/exit points
	assert.Equal(t, original.EntryPoints, parsed.EntryPoints)
	assert.Equal(t, original.ExitPoints, parsed.ExitPoints)
}

// TestMissionSerializationWithComplexStructures tests serialization of
// missions with parallel nodes, conditions, and nested structures
func TestMissionSerializationWithComplexStructures(t *testing.T) {
	original := &mission.MissionDefinition{
		Name:    "complex-mission",
		Version: "2.0.0",
		Nodes: map[string]*mission.MissionNode{
			"parallel-scan": {
				ID:   "parallel-scan",
				Type: mission.NodeTypeParallel,
				Name: "Parallel Scanning",
				SubNodes: []*mission.MissionNode{
					{
						ID:        "sub-agent-1",
						Type:      mission.NodeTypeAgent,
						AgentName: "agent-1",
						Timeout:   5 * time.Minute,
					},
					{
						ID:       "sub-tool-1",
						Type:     mission.NodeTypeTool,
						ToolName: "tool-1",
						Timeout:  3 * time.Minute,
					},
				},
			},
			"condition-check": {
				ID:   "condition-check",
				Type: mission.NodeTypeCondition,
				Condition: &mission.NodeCondition{
					Expression:  "findings.count > 0",
					TrueBranch:  []string{"exploit"},
					FalseBranch: []string{"cleanup"},
				},
			},
			"join-point": {
				ID:           "join-point",
				Type:         mission.NodeTypeJoin,
				Dependencies: []string{"parallel-scan", "condition-check"},
			},
		},
	}

	// Serialize and deserialize
	missionDefinitionJSON, err := json.Marshal(original)
	require.NoError(t, err)

	parsed, err := mission.ParseDefinitionFromJSON(missionDefinitionJSON)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Verify parallel node with sub-nodes
	parallelNode := parsed.Nodes["parallel-scan"]
	require.NotNil(t, parallelNode)
	assert.Equal(t, mission.NodeTypeParallel, parallelNode.Type)
	require.Len(t, parallelNode.SubNodes, 2)

	// Verify sub-nodes maintained their types and fields
	assert.Equal(t, mission.NodeTypeAgent, parallelNode.SubNodes[0].Type)
	assert.Equal(t, "agent-1", parallelNode.SubNodes[0].AgentName)
	assert.Equal(t, 5*time.Minute, parallelNode.SubNodes[0].Timeout)

	assert.Equal(t, mission.NodeTypeTool, parallelNode.SubNodes[1].Type)
	assert.Equal(t, "tool-1", parallelNode.SubNodes[1].ToolName)
	assert.Equal(t, 3*time.Minute, parallelNode.SubNodes[1].Timeout)

	// Verify condition node
	condNode := parsed.Nodes["condition-check"]
	require.NotNil(t, condNode)
	assert.Equal(t, mission.NodeTypeCondition, condNode.Type)
	require.NotNil(t, condNode.Condition)
	assert.Equal(t, "findings.count > 0", condNode.Condition.Expression)
	assert.Equal(t, []string{"exploit"}, condNode.Condition.TrueBranch)
	assert.Equal(t, []string{"cleanup"}, condNode.Condition.FalseBranch)

	// Verify join node
	joinNode := parsed.Nodes["join-point"]
	require.NotNil(t, joinNode)
	assert.Equal(t, mission.NodeTypeJoin, joinNode.Type)
	assert.Equal(t, []string{"parallel-scan", "condition-check"}, joinNode.Dependencies)
}

// TestMissionSerializationFieldNameMapping verifies that JSON field names
// (agent_name, tool_name, plugin_name, etc.) are correctly mapped to Go struct
// fields during deserialization. This was the root cause of the bug.
func TestMissionSerializationFieldNameMapping(t *testing.T) {
	// Create JSON with the exact field names that get stored in the database
	jsonData := `{
		"id": "01234567-89ab-cdef-0123-456789abcdef",
		"name": "field-mapping-test",
		"nodes": {
			"agent1": {
				"id": "agent1",
				"type": "agent",
				"agent_name": "test-agent",
				"timeout": 600000000000,
				"agent_task": {
					"name": "test-task",
					"context": {"target": "example.com"}
				}
			},
			"tool1": {
				"id": "tool1",
				"type": "tool",
				"tool_name": "test-tool",
				"tool_input": {"param": "value"},
				"timeout": 300000000000
			},
			"plugin1": {
				"id": "plugin1",
				"type": "plugin",
				"plugin_name": "test-plugin",
				"plugin_method": "query",
				"plugin_params": {"query": "SELECT *"}
			}
		}
	}`

	parsed, err := mission.ParseDefinitionFromJSON([]byte(jsonData))
	require.NoError(t, err)
	require.NotNil(t, parsed)

	// Verify agent_name (JSON) -> AgentName (Go)
	agent := parsed.Nodes["agent1"]
	require.NotNil(t, agent)
	assert.Equal(t, "test-agent", agent.AgentName, "agent_name JSON field should map to AgentName Go field")
	assert.Equal(t, 10*time.Minute, agent.Timeout, "timeout as integer nanoseconds should map to time.Duration")

	// Verify tool_name (JSON) -> ToolName (Go)
	tool := parsed.Nodes["tool1"]
	require.NotNil(t, tool)
	assert.Equal(t, "test-tool", tool.ToolName, "tool_name JSON field should map to ToolName Go field")
	assert.Equal(t, 5*time.Minute, tool.Timeout)

	// Verify plugin_name and plugin_method (JSON) -> PluginName and PluginMethod (Go)
	plugin := parsed.Nodes["plugin1"]
	require.NotNil(t, plugin)
	assert.Equal(t, "test-plugin", plugin.PluginName, "plugin_name JSON field should map to PluginName Go field")
	assert.Equal(t, "query", plugin.PluginMethod, "plugin_method JSON field should map to PluginMethod Go field")
}
