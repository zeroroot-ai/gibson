package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// createTestMissionRun creates a test MissionRun for use in tests
func createTestMissionRun(missionID types.ID) *mission.MissionRun {
	return &mission.MissionRun{
		ID:        types.NewID(),
		MissionID: missionID,
		RunNumber: 1,
		Status:    mission.MissionRunStatusRunning,
		Progress:  0.0,
	}
}

// addMissionBootstrapMocks adds the standard mock results for Mission and MissionRun creation
// (CreateMission and CreateMissionRun) that are called at the start of Bootstrap.
func addMissionBootstrapMocks(mockClient *graph.MockGraphClient) {
	// 1. CreateMission - returns id
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "test-mission-id"},
		},
	})
	// 2. CreateMissionRun - returns run_id
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"run_id": "mission-run-123"},
		},
	})
}

// TestGraphBootstrapper_Bootstrap_SimpleWorkflow tests bootstrapping a simple 2-node workflow with one dependency.
// This verifies that missions and nodes are created correctly, and dependency relationships are established.
func TestGraphBootstrapper_Bootstrap_SimpleWorkflow(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to return successful results for all operations
	// 1. CreateMission - returns id
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "test-mission-id"},
		},
	})
	// 2. CreateMissionRun - returns run_id
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"run_id": "mission-run-123"},
		},
	})
	// 3. Node 1 creation (MERGE returns id)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "node-1-id"},
		},
	})
	// 4. Node 2 creation (MERGE returns id)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "node-2-id"},
		},
	})
	// 5. Dependency creation (MERGE returns count)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Test Mission",
		Description: "Test mission for bootstrapper",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with 2 nodes: node-2 depends on node-1
	def := &mission.MissionDefinition{
		Name:        "Test Mission",
		Description: "Test mission workflow. This validates bootstrapping.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:          "node-1",
				Type:        mission.NodeTypeAgent,
				Description: "First node",
				AgentName:   "test-agent-1",
				AgentTask: &agent.Task{
					Name:        "Task 1",
					Description: "First task",
					Goal:        "Complete first task",
					Input:       map[string]any{"param": "value1"},
				},
				Dependencies: []string{}, // No dependencies (entry point)
			},
			"node-2": {
				ID:          "node-2",
				Type:        mission.NodeTypeAgent,
				Description: "Second node",
				AgentName:   "test-agent-2",
				AgentTask: &agent.Task{
					Name:        "Task 2",
					Description: "Second task",
					Goal:        "Complete second task",
					Input:       map[string]any{"param": "value2"},
				},
				Dependencies: []string{"node-1"}, // Depends on node-1
			},
		},
	}

	// Bootstrap the mission
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.NoError(t, err, "Bootstrap should complete without error")

	// Verify that the correct number of queries were executed
	// Should be: 1 create mission + 1 create run + 2 nodes + 1 dependency = 5 queries
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 5, "Should have executed 5 queries (create mission + create run + 2 nodes + 1 dependency)")
}

// TestGraphBootstrapper_Bootstrap_NoDependencies tests bootstrapping a workflow where all nodes have no dependencies.
// All nodes should be created with status "ready" since they can execute immediately.
func TestGraphBootstrapper_Bootstrap_NoDependencies(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to return successful results
	// 1. CreateMission - returns id
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "test-mission-id"},
		},
	})
	// 2. CreateMissionRun - returns run_id
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"run_id": "mission-run-123"},
		},
	})
	// 3. Node 1 creation
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "node-1-id"},
		},
	})
	// 4. Node 2 creation
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "node-2-id"},
		},
	})
	// 5. Node 3 creation
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "node-3-id"},
		},
	})

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Parallel Mission",
		Description: "Mission with parallel nodes",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with 3 nodes, none with dependencies
	def := &mission.MissionDefinition{
		Name:        "Parallel Mission",
		Description: "All nodes can execute in parallel.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:           "node-1",
				Type:         mission.NodeTypeAgent,
				Description:  "First parallel node",
				AgentName:    "agent-1",
				AgentTask:    &agent.Task{Name: "Task 1", Goal: "Goal 1", Input: map[string]any{}},
				Dependencies: []string{}, // No dependencies
			},
			"node-2": {
				ID:           "node-2",
				Type:         mission.NodeTypeAgent,
				Description:  "Second parallel node",
				AgentName:    "agent-2",
				AgentTask:    &agent.Task{Name: "Task 2", Goal: "Goal 2", Input: map[string]any{}},
				Dependencies: []string{}, // No dependencies
			},
			"node-3": {
				ID:           "node-3",
				Type:         mission.NodeTypeTool,
				Description:  "Third parallel node",
				ToolName:     "tool-1",
				ToolInput:    map[string]any{"input": "value"},
				Dependencies: []string{}, // No dependencies
			},
		},
	}

	// Bootstrap the mission
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.NoError(t, err, "Bootstrap should complete without error")

	// Verify queries were executed for create mission + create run + 3 nodes (no dependencies)
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 5, "Should have executed 5 queries (create mission + create run + 3 nodes)")

	// Verify all nodes were created by checking query parameters
	// All nodes should have status "ready" since they have no dependencies
	// Skip first 2 calls (CreateMission + CreateMissionRun)
	for i, call := range calls[2:] {
		params := call.Args[1].(map[string]any)
		status, ok := params["status"].(string)
		require.True(t, ok, "Query %d should have status parameter", i+1)
		assert.Equal(t, "ready", status, "Node %d should have status 'ready' (no dependencies)", i+1)
	}
}

// TestGraphBootstrapper_Bootstrap_CreateMissionError tests that Bootstrap propagates errors from CreateMission.
func TestGraphBootstrapper_Bootstrap_CreateMissionError(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to return error on Query (used by CreateMission)
	mockClient.SetQueryError(fmt.Errorf("database connection lost"))

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Test Mission",
		Description: "Test mission",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create simple mission definition
	def := &mission.MissionDefinition{
		Name:        "Test Mission",
		Description: "Test workflow.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:           "node-1",
				Type:         mission.NodeTypeAgent,
				Description:  "Test node",
				AgentName:    "test-agent",
				AgentTask:    &agent.Task{Name: "Task", Goal: "Goal", Input: map[string]any{}},
				Dependencies: []string{},
			},
		},
	}

	// Bootstrap should fail with error from CreateMission (first query)
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.Error(t, err, "Bootstrap should return error when CreateMission fails")
	assert.Contains(t, err.Error(), "failed to create mission in graph", "Error should mention mission creation failure")
}

// TestGraphBootstrapper_Bootstrap_CreateWorkflowNodeError tests that Bootstrap propagates errors from CreateWorkflowNode.
func TestGraphBootstrapper_Bootstrap_CreateWorkflowNodeError(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to succeed for Mission and MissionRun but fail for workflow node creation
	addMissionBootstrapMocks(mockClient)
	// Return empty result for node creation (simulates failure)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{}, // Empty result indicates node creation issue
	})

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Test Mission",
		Description: "Test mission",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with one node
	def := &mission.MissionDefinition{
		Name:        "Test Mission",
		Description: "Test workflow.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:           "node-1",
				Type:         mission.NodeTypeAgent,
				Description:  "Test node",
				AgentName:    "test-agent",
				AgentTask:    &agent.Task{Name: "Task", Goal: "Goal", Input: map[string]any{}},
				Dependencies: []string{},
			},
		},
	}

	// Bootstrap should fail with error from CreateWorkflowNode
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.Error(t, err, "Bootstrap should return error when CreateWorkflowNode fails")
	assert.Contains(t, err.Error(), "failed to create workflow node", "Error should mention workflow node creation failure")
	assert.Contains(t, err.Error(), "node-1", "Error should include the node ID that failed")
}

// TestGraphBootstrapper_Bootstrap_ComplexDAG tests bootstrapping a more complex workflow with multiple dependencies.
func TestGraphBootstrapper_Bootstrap_ComplexDAG(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to return successful results for all operations
	addMissionBootstrapMocks(mockClient)
	// Node creations (4 nodes)
	for i := 0; i < 4; i++ {
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": fmt.Sprintf("node-%d-id", i+1)}},
		})
	}
	// Dependency creations (3 dependencies: node-2->node-1, node-3->node-1, node-4->node-2, node-4->node-3)
	// Actually 4 dependencies total (node-4 has 2)
	for i := 0; i < 4; i++ {
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"count": int64(1)}},
		})
	}

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Complex Mission",
		Description: "Mission with complex DAG",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with complex DAG:
	// node-1 (entry) -> node-2 -> node-4
	//                -> node-3 -> node-4
	// node-4 depends on both node-2 and node-3
	def := &mission.MissionDefinition{
		Name:        "Complex Mission",
		Description: "Complex DAG workflow.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:           "node-1",
				Type:         mission.NodeTypeAgent,
				Description:  "Entry node",
				AgentName:    "agent-1",
				AgentTask:    &agent.Task{Name: "Task 1", Goal: "Goal 1", Input: map[string]any{}},
				Dependencies: []string{},
			},
			"node-2": {
				ID:           "node-2",
				Type:         mission.NodeTypeAgent,
				Description:  "Second level node A",
				AgentName:    "agent-2",
				AgentTask:    &agent.Task{Name: "Task 2", Goal: "Goal 2", Input: map[string]any{}},
				Dependencies: []string{"node-1"},
			},
			"node-3": {
				ID:           "node-3",
				Type:         mission.NodeTypeAgent,
				Description:  "Second level node B",
				AgentName:    "agent-3",
				AgentTask:    &agent.Task{Name: "Task 3", Goal: "Goal 3", Input: map[string]any{}},
				Dependencies: []string{"node-1"},
			},
			"node-4": {
				ID:           "node-4",
				Type:         mission.NodeTypeAgent,
				Description:  "Final node",
				AgentName:    "agent-4",
				AgentTask:    &agent.Task{Name: "Task 4", Goal: "Goal 4", Input: map[string]any{}},
				Dependencies: []string{"node-2", "node-3"},
			},
		},
	}

	// Bootstrap the mission
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.NoError(t, err, "Bootstrap should complete without error")

	// Verify correct number of queries
	// 1 create mission + 1 create run + 4 nodes + 4 dependencies = 10 queries
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 10, "Should have executed 10 queries")
}

// TestGraphBootstrapper_Bootstrap_MissionWithToolNode tests bootstrapping a mission with a tool node.
func TestGraphBootstrapper_Bootstrap_MissionWithToolNode(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to return successful results
	addMissionBootstrapMocks(mockClient)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": "node-1-id"}},
	})

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Tool Mission",
		Description: "Mission with tool node",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with a tool node
	def := &mission.MissionDefinition{
		Name:        "Tool Mission",
		Description: "Mission with tool node.",
		Nodes: map[string]*mission.MissionNode{
			"tool-node-1": {
				ID:          "tool-node-1",
				Type:        mission.NodeTypeTool,
				Description: "Tool execution node",
				ToolName:    "port-scanner",
				ToolInput: map[string]any{
					"target": "192.168.1.0/24",
					"ports":  "1-1024",
				},
				Timeout:      5 * time.Minute,
				Dependencies: []string{},
			},
		},
	}

	// Bootstrap the mission
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.NoError(t, err, "Bootstrap should complete without error")

	// Verify queries were executed
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 3, "Should have executed 3 queries (create mission + create run + tool node)")
}

// TestGraphBootstrapper_Bootstrap_MissionWithRetryPolicy tests that retry policies are properly serialized.
func TestGraphBootstrapper_Bootstrap_MissionWithRetryPolicy(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to return successful results
	addMissionBootstrapMocks(mockClient)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": "node-1-id"}},
	})

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Retry Mission",
		Description: "Mission with retry policy",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with a node that has a retry policy
	def := &mission.MissionDefinition{
		Name:        "Retry Mission",
		Description: "Mission with retry policy.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:          "node-1",
				Type:        mission.NodeTypeAgent,
				Description: "Node with retry policy",
				AgentName:   "resilient-agent",
				AgentTask:   &agent.Task{Name: "Task", Goal: "Goal", Input: map[string]any{}},
				RetryPolicy: &mission.RetryPolicy{
					MaxRetries:      3,
					InitialDelay:    1 * time.Second,
					MaxDelay:        10 * time.Second,
					BackoffStrategy: mission.BackoffExponential,
				},
				Dependencies: []string{},
			},
		},
	}

	// Bootstrap the mission
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.NoError(t, err, "Bootstrap should complete without error")

	// Verify queries were executed
	calls := mockClient.GetCallsByMethod("Query")
	assert.Len(t, calls, 3, "Should have executed 3 queries (create mission + create run + node)")

	// Verify retry policy was included in the node creation query (skip first 2 queries)
	nodeQueryCall := calls[2]
	params := nodeQueryCall.Args[1].(map[string]any)
	assert.NotNil(t, params["retry_policy"], "Retry policy should be included in node parameters")
}

// TestGraphBootstrapper_Bootstrap_DependencyNotFound tests error handling when a dependency node doesn't exist.
func TestGraphBootstrapper_Bootstrap_DependencyNotFound(t *testing.T) {
	ctx := context.Background()
	logger := slog.Default()

	// Create mock graph client
	mockClient := graph.NewMockGraphClient()
	err := mockClient.Connect(ctx)
	require.NoError(t, err)

	// Configure mock to succeed for Mission, MissionRun, and nodes
	addMissionBootstrapMocks(mockClient)
	mockClient.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{{"id": "node-1-id"}},
	})

	// Create bootstrapper
	bootstrapper := NewGraphBootstrapper(mockClient, logger)

	// Create test mission
	missionID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:          missionID,
		Name:        "Invalid Mission",
		Description: "Mission with invalid dependency",
		Status:      mission.MissionStatusRunning,
		TargetID:    types.NewID(),
		WorkflowID:  types.NewID(),
		StartedAt:   mission.NewUnixTimePtr(&now),
	}

	// Create mission definition with a node that references non-existent dependency
	def := &mission.MissionDefinition{
		Name:        "Invalid Mission",
		Description: "Mission with invalid dependency.",
		Nodes: map[string]*mission.MissionNode{
			"node-1": {
				ID:           "node-1",
				Type:         mission.NodeTypeAgent,
				Description:  "Node with invalid dependency",
				AgentName:    "agent-1",
				AgentTask:    &agent.Task{Name: "Task", Goal: "Goal", Input: map[string]any{}},
				Dependencies: []string{"nonexistent-node"}, // This node doesn't exist
			},
		},
	}

	// Bootstrap should fail due to missing dependency in nodeIDMap
	run := createTestMissionRun(m.ID)
	result, err := bootstrapper.Bootstrap(ctx, m, def, run)
	_ = result // Bootstrap result contains MissionRunID
	require.Error(t, err, "Bootstrap should fail when dependency doesn't exist")
	assert.Contains(t, err.Error(), "dependency node ID", "Error should mention missing dependency")
	assert.Contains(t, err.Error(), "nonexistent-node", "Error should include the missing node ID")
}

// TestGraphBootstrapper_ConvertToSchemaMission tests the mission conversion logic.
func TestGraphBootstrapper_ConvertToSchemaMission(t *testing.T) {
	// Create test mission
	missionID := types.NewID()
	targetID := types.NewID()
	now := time.Now()
	m := &mission.Mission{
		ID:           missionID,
		Name:         "Test Mission",
		Description:  "Test mission description",
		Status:       mission.MissionStatusRunning,
		TargetID:     targetID,
		WorkflowJSON: `{"name": "test", "nodes": []}`,
		StartedAt:    mission.NewUnixTimePtr(&now),
	}

	// Create mission definition
	def := &mission.MissionDefinition{
		Name:        "Test Mission",
		Description: "This is a test mission. It validates conversion logic.",
	}

	// Convert to schema mission
	schemaMission := convertToSchemaMission(m, def)

	// Verify conversion
	assert.Equal(t, missionID, schemaMission.ID, "Mission ID should match")
	assert.Equal(t, "Test Mission", schemaMission.Name, "Mission name should match")
	assert.Equal(t, "Test mission description", schemaMission.Description, "Mission description should match")
	assert.Equal(t, string(targetID), schemaMission.TargetRef, "Target ref should match")
	assert.NotNil(t, schemaMission.StartedAt, "Started at should be set")
	assert.Equal(t, "This is a test mission.", schemaMission.Objective, "Objective should be first sentence")
}

// TestGraphBootstrapper_ConvertToSchemaNode tests the node conversion logic.
func TestGraphBootstrapper_ConvertToSchemaNode(t *testing.T) {
	missionID := types.NewID()

	t.Run("agent node with dependencies", func(t *testing.T) {
		nodeDef := &mission.MissionNode{
			ID:          "agent-node-1",
			Type:        mission.NodeTypeAgent,
			Description: "Test agent node",
			AgentName:   "test-agent",
			AgentTask: &agent.Task{
				Name:        "Test Task",
				Description: "Task description",
				Goal:        "Complete task",
				Input:       map[string]any{"key": "value"},
			},
			Timeout:      5 * time.Minute,
			Dependencies: []string{"dep-1"}, // Has dependencies
		}

		schemaNode := convertToSchemaNode(missionID, nodeDef, true)

		assert.False(t, schemaNode.ID.IsZero(), "Node ID should be generated")
		assert.Equal(t, missionID, schemaNode.MissionID, "Mission ID should match")
		assert.Equal(t, "agent-node-1", schemaNode.Name, "Node name should be definition ID")
		assert.Equal(t, "test-agent", schemaNode.AgentName, "Agent name should match")
		assert.Equal(t, 5*time.Minute, schemaNode.Timeout, "Timeout should match")
		assert.Equal(t, "pending", string(schemaNode.Status), "Node with dependencies should have pending status")
		assert.False(t, schemaNode.IsDynamic, "Static nodes should not be dynamic")
	})

	t.Run("tool node without dependencies", func(t *testing.T) {
		nodeDef := &mission.MissionNode{
			ID:          "tool-node-1",
			Type:        mission.NodeTypeTool,
			Description: "Test tool node",
			ToolName:    "port-scanner",
			ToolInput: map[string]any{
				"target": "192.168.1.1",
				"ports":  "80,443",
			},
			Dependencies: []string{}, // No dependencies
		}

		schemaNode := convertToSchemaNode(missionID, nodeDef, false)

		assert.Equal(t, "tool-node-1", schemaNode.Name, "Node name should be definition ID")
		assert.Equal(t, "port-scanner", schemaNode.ToolName, "Tool name should match")
		assert.Equal(t, "ready", string(schemaNode.Status), "Node without dependencies should have ready status")
		assert.Contains(t, schemaNode.TaskConfig, "target", "Task config should include tool input")
	})
}
