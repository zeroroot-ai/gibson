package queries

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestMissionQueries_GetMission tests retrieving a mission by ID.
func TestMissionQueries_GetMission(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()

	// Mock mission data
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"m": map[string]any{
					"id":          missionID.String(),
					"name":        "test-mission",
					"description": "Test description",
					"objective":   "Test objective",
					"target_ref":  "test-target",
					"status":      "pending",
					"yaml_source": "yaml: test",
					"created_at":  time.Now(),
				},
			},
		},
	})

	mission, err := mq.GetMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, missionID, mission.ID)
	assert.Equal(t, "test-mission", mission.Name)
	assert.Equal(t, schema.MissionStatusPending, mission.Status)
}

// TestMissionQueries_GetMission_NotFound tests retrieving non-existent mission.
func TestMissionQueries_GetMission_NotFound(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()

	// Mock empty result
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{},
	})

	_, err = mq.GetMission(ctx, missionID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestMissionQueries_GetMissionNodes tests retrieving all nodes for a mission.
func TestMissionQueries_GetMissionNodes(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	node1ID := types.NewID()
	node2ID := types.NewID()

	// Mock nodes
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"n": map[string]any{
					"id":          node1ID.String(),
					"mission_id":  missionID.String(),
					"type":        "agent",
					"name":        "node-1",
					"description": "First node",
					"status":      "pending",
					"is_dynamic":  false,
					"agent_name":  "test-agent",
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
			{
				"n": map[string]any{
					"id":          node2ID.String(),
					"mission_id":  missionID.String(),
					"type":        "tool",
					"name":        "node-2",
					"description": "Second node",
					"status":      "ready",
					"is_dynamic":  false,
					"tool_name":   "test-tool",
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
		},
	})

	nodes, err := mq.GetMissionNodes(ctx, missionID)
	require.NoError(t, err)
	require.Len(t, nodes, 2)
	assert.Equal(t, node1ID, nodes[0].ID)
	assert.Equal(t, node2ID, nodes[1].ID)
	assert.Equal(t, "test-agent", nodes[0].AgentName)
	assert.Equal(t, "test-tool", nodes[1].ToolName)
}

// TestMissionQueries_GetMissionDecisions tests retrieving decisions in order.
func TestMissionQueries_GetMissionDecisions(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	decision1ID := types.NewID()
	decision2ID := types.NewID()

	modificationsJSON, _ := json.Marshal(map[string]any{"param": "value"})

	// Mock decisions - ordered by iteration
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"d": map[string]any{
					"id":                  decision1ID.String(),
					"mission_id":          missionID.String(),
					"iteration":           int64(1),
					"action":              "execute_agent",
					"target_node_id":      "node-1",
					"reasoning":           "First decision",
					"confidence":          0.9,
					"modifications":       string(modificationsJSON),
					"graph_state_summary": "Initial state",
					"prompt_tokens":       int64(100),
					"completion_tokens":   int64(50),
					"latency_ms":          int64(200),
					"timestamp":           time.Now(),
					"created_at":          time.Now(),
					"updated_at":          time.Now(),
				},
			},
			{
				"d": map[string]any{
					"id":                  decision2ID.String(),
					"mission_id":          missionID.String(),
					"iteration":           int64(2),
					"action":              "skip_agent",
					"target_node_id":      "node-2",
					"reasoning":           "Second decision",
					"confidence":          0.8,
					"modifications":       "{}",
					"graph_state_summary": "Updated state",
					"prompt_tokens":       int64(120),
					"completion_tokens":   int64(60),
					"latency_ms":          int64(250),
					"timestamp":           time.Now().Add(time.Second),
					"created_at":          time.Now().Add(time.Second),
					"updated_at":          time.Now().Add(time.Second),
				},
			},
		},
	})

	decisions, err := mq.GetMissionDecisions(ctx, missionID)
	require.NoError(t, err)
	require.Len(t, decisions, 2)

	// Verify order by iteration
	assert.Equal(t, 1, decisions[0].Iteration)
	assert.Equal(t, 2, decisions[1].Iteration)

	// Verify decision details
	assert.Equal(t, schema.DecisionActionExecuteAgent, decisions[0].Action)
	assert.Equal(t, schema.DecisionActionSkipAgent, decisions[1].Action)
	assert.Equal(t, "First decision", decisions[0].Reasoning)
	assert.Equal(t, 0.9, decisions[0].Confidence)

	// Verify modifications were parsed
	assert.NotEmpty(t, decisions[0].Modifications)
	assert.Equal(t, "value", decisions[0].Modifications["param"])
}

// TestMissionQueries_GetNodeExecutions tests retrieving executions for a node.
func TestMissionQueries_GetNodeExecutions(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()
	exec1ID := types.NewID()
	exec2ID := types.NewID()

	configJSON, _ := json.Marshal(map[string]any{"key": "value"})
	resultJSON, _ := json.Marshal(map[string]any{"output": "result"})
	now := time.Now()
	completed := now.Add(5 * time.Second)

	// Mock executions
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"e": map[string]any{
					"id":              exec1ID.String(),
					"mission_node_id": nodeID.String(),
					"mission_id":      missionID.String(),
					"status":          "completed",
					"started_at":      now,
					"completed_at":    completed,
					"attempt":         int64(1),
					"config_used":     string(configJSON),
					"result":          string(resultJSON),
					"error":           "",
					"created_at":      now,
					"updated_at":      completed,
				},
			},
			{
				"e": map[string]any{
					"id":              exec2ID.String(),
					"mission_node_id": nodeID.String(),
					"mission_id":      missionID.String(),
					"status":          "running",
					"started_at":      now.Add(10 * time.Second),
					"attempt":         int64(1),
					"config_used":     "{}",
					"result":          "{}",
					"error":           "",
					"created_at":      now.Add(10 * time.Second),
					"updated_at":      now.Add(10 * time.Second),
				},
			},
		},
	})

	executions, err := mq.GetNodeExecutions(ctx, nodeID)
	require.NoError(t, err)
	require.Len(t, executions, 2)

	// Verify first execution (completed)
	assert.Equal(t, exec1ID, executions[0].ID)
	assert.Equal(t, schema.ExecutionStatusCompleted, executions[0].Status)
	assert.NotNil(t, executions[0].CompletedAt)
	assert.Equal(t, "value", executions[0].ConfigUsed["key"])
	assert.Equal(t, "result", executions[0].Result["output"])

	// Verify second execution (running)
	assert.Equal(t, exec2ID, executions[1].ID)
	assert.Equal(t, schema.ExecutionStatusRunning, executions[1].Status)
	assert.Nil(t, executions[1].CompletedAt)
}

// TestMissionQueries_GetReadyNodes tests the ready nodes query.
func TestMissionQueries_GetReadyNodes(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	readyNodeID := types.NewID()

	// Mock one ready node
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"n": map[string]any{
					"id":          readyNodeID.String(),
					"mission_id":  missionID.String(),
					"type":        "agent",
					"name":        "ready-node",
					"description": "Node ready to execute",
					"status":      "ready",
					"is_dynamic":  false,
					"agent_name":  "test-agent",
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
		},
	})

	nodes, err := mq.GetReadyNodes(ctx, missionID)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, readyNodeID, nodes[0].ID)
	assert.Equal(t, schema.MissionNodeStatusReady, nodes[0].Status)
}

// TestMissionQueries_GetNodeDependencies tests retrieving node dependencies.
func TestMissionQueries_GetNodeDependencies(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()
	dep1ID := types.NewID()
	dep2ID := types.NewID()

	// Mock dependencies
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"dep": map[string]any{
					"id":          dep1ID.String(),
					"mission_id":  missionID.String(),
					"type":        "agent",
					"name":        "dep-1",
					"description": "First dependency",
					"status":      "completed",
					"is_dynamic":  false,
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
			{
				"dep": map[string]any{
					"id":          dep2ID.String(),
					"mission_id":  missionID.String(),
					"type":        "tool",
					"name":        "dep-2",
					"description": "Second dependency",
					"status":      "completed",
					"is_dynamic":  false,
					"created_at":  time.Now().Add(time.Second),
					"updated_at":  time.Now().Add(time.Second),
				},
			},
		},
	})

	deps, err := mq.GetNodeDependencies(ctx, nodeID)
	require.NoError(t, err)
	require.Len(t, deps, 2)
	assert.Equal(t, dep1ID, deps[0].ID)
	assert.Equal(t, dep2ID, deps[1].ID)
	assert.Equal(t, schema.MissionNodeStatusCompleted, deps[0].Status)
}

// TestMissionQueries_GetMissionStats tests computing mission statistics.
func TestMissionQueries_GetMissionStats(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	now := time.Now()

	// Mock stats result
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"total_nodes":      int64(5),
				"completed_nodes":  int64(3),
				"failed_nodes":     int64(1),
				"pending_nodes":    int64(1),
				"total_decisions":  int64(10),
				"total_executions": int64(4),
				"start_time":       now,
				"end_time":         now.Add(time.Hour),
			},
		},
	})

	stats, err := mq.GetMissionStats(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 5, stats.TotalNodes)
	assert.Equal(t, 3, stats.CompletedNodes)
	assert.Equal(t, 1, stats.FailedNodes)
	assert.Equal(t, 1, stats.PendingNodes)
	assert.Equal(t, 10, stats.TotalDecisions)
	assert.Equal(t, 4, stats.TotalExecutions)
	assert.Equal(t, now, stats.StartTime)
	assert.Equal(t, now.Add(time.Hour), stats.EndTime)
}

// TestMissionQueries_IntegrationScenario tests a realistic usage scenario.
func TestMissionQueries_IntegrationScenario(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()

	// Scenario: Query mission execution progress

	// Step 1: Get mission
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"m": map[string]any{
					"id":          missionID.String(),
					"name":        "integration-mission",
					"description": "Integration test mission",
					"objective":   "Test integration",
					"target_ref":  "test-target",
					"status":      "running",
					"yaml_source": "yaml: test",
					"created_at":  time.Now(),
				},
			},
		},
	})
	mission, err := mq.GetMission(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, schema.MissionStatusRunning, mission.Status)

	// Step 2: Get all nodes
	node1ID := types.NewID()
	node2ID := types.NewID()
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"n": map[string]any{
					"id":          node1ID.String(),
					"mission_id":  missionID.String(),
					"type":        "agent",
					"name":        "node-1",
					"description": "First node",
					"status":      "completed",
					"is_dynamic":  false,
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
			{
				"n": map[string]any{
					"id":          node2ID.String(),
					"mission_id":  missionID.String(),
					"type":        "agent",
					"name":        "node-2",
					"description": "Second node",
					"status":      "ready",
					"is_dynamic":  false,
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
		},
	})
	nodes, err := mq.GetMissionNodes(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)

	// Step 3: Get ready nodes
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"n": map[string]any{
					"id":          node2ID.String(),
					"mission_id":  missionID.String(),
					"type":        "agent",
					"name":        "node-2",
					"description": "Second node",
					"status":      "ready",
					"is_dynamic":  false,
					"created_at":  time.Now(),
					"updated_at":  time.Now(),
				},
			},
		},
	})
	readyNodes, err := mq.GetReadyNodes(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, readyNodes, 1)
	assert.Equal(t, node2ID, readyNodes[0].ID)

	// Step 4: Get decisions
	decisionID := types.NewID()
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"d": map[string]any{
					"id":            decisionID.String(),
					"mission_id":    missionID.String(),
					"iteration":     int64(1),
					"action":        "execute_agent",
					"reasoning":     "Execute first node",
					"confidence":    0.95,
					"modifications": "{}",
					"timestamp":     time.Now(),
					"created_at":    time.Now(),
					"updated_at":    time.Now(),
				},
			},
		},
	})
	decisions, err := mq.GetMissionDecisions(ctx, missionID)
	require.NoError(t, err)
	assert.Len(t, decisions, 1)

	// Step 5: Get stats
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"total_nodes":      int64(2),
				"completed_nodes":  int64(1),
				"failed_nodes":     int64(0),
				"pending_nodes":    int64(1),
				"total_decisions":  int64(1),
				"total_executions": int64(1),
				"start_time":       time.Now(),
			},
		},
	})
	stats, err := mq.GetMissionStats(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 2, stats.TotalNodes)
	assert.Equal(t, 1, stats.CompletedNodes)
	assert.Equal(t, 1, stats.PendingNodes)

	// Verify all queries executed
	assert.Greater(t, mock.CallCount(), 5)
}

// TestMissionQueries_EmptyResults tests handling of empty query results.
func TestMissionQueries_EmptyResults(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	nodeID := types.NewID()

	t.Run("no nodes", func(t *testing.T) {
		mock.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})
		nodes, err := mq.GetMissionNodes(ctx, missionID)
		require.NoError(t, err)
		assert.Empty(t, nodes)
	})

	t.Run("no decisions", func(t *testing.T) {
		mock.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})
		decisions, err := mq.GetMissionDecisions(ctx, missionID)
		require.NoError(t, err)
		assert.Empty(t, decisions)
	})

	t.Run("no executions", func(t *testing.T) {
		mock.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})
		execs, err := mq.GetNodeExecutions(ctx, nodeID)
		require.NoError(t, err)
		assert.Empty(t, execs)
	})

	t.Run("no ready nodes", func(t *testing.T) {
		mock.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})
		nodes, err := mq.GetReadyNodes(ctx, missionID)
		require.NoError(t, err)
		assert.Empty(t, nodes)
	})

	t.Run("no dependencies", func(t *testing.T) {
		mock.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})
		deps, err := mq.GetNodeDependencies(ctx, nodeID)
		require.NoError(t, err)
		assert.Empty(t, deps)
	})
}

// TestMissionQueries_CreateNodeDependency tests creating DEPENDS_ON relationships.
func TestMissionQueries_CreateNodeDependency(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	fromNodeID := types.NewID()
	toNodeID := types.NewID()

	// Mock successful relationship creation
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.NoError(t, err)
}

// TestMissionQueries_CreateNodeDependency_NodeNotFound tests error when nodes don't exist.
func TestMissionQueries_CreateNodeDependency_NodeNotFound(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	fromNodeID := types.NewID()
	toNodeID := types.NewID()

	// Mock empty result (nodes not found)
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.Error(t, err)

	// Verify it's a typed error with correct code
	gibsonErr, ok := err.(*types.GibsonError)
	require.True(t, ok, "expected *types.GibsonError")
	assert.Equal(t, graph.ErrCodeGraphNodeNotFound, gibsonErr.Code)
	assert.Contains(t, err.Error(), "not found")
	assert.Contains(t, err.Error(), fromNodeID.String())
	assert.Contains(t, err.Error(), toNodeID.String())
}

// TestMissionQueries_CreateNodeDependency_Idempotent tests that MERGE makes it idempotent.
func TestMissionQueries_CreateNodeDependency_Idempotent(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	fromNodeID := types.NewID()
	toNodeID := types.NewID()

	// First call - creates relationship
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.NoError(t, err)

	// Second call - same relationship, should succeed (MERGE is idempotent)
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"count": int64(1)},
		},
	})

	err = mq.CreateNodeDependency(ctx, fromNodeID, toNodeID)
	require.NoError(t, err, "MERGE should make CreateNodeDependency idempotent")
}

// TestMissionQueries_CreateMission tests creating a mission node.
func TestMissionQueries_CreateMission(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	now := time.Now()

	mission := &schema.Mission{
		ID:          missionID,
		Name:        "test-mission",
		Description: "Test mission description",
		Objective:   "Test objective",
		TargetRef:   "target-123",
		Status:      schema.MissionStatusPending,
		YAMLSource:  "mission: test",
		CreatedAt:   now,
		StartedAt:   nil,
	}

	// Mock successful creation
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": missionID.String()},
		},
	})

	err = mq.CreateMission(ctx, mission)
	require.NoError(t, err)

	// Verify query was called
	assert.Greater(t, mock.CallCount(), 0)
}

// TestMissionQueries_CreateMission_NilMission tests error handling for nil mission.
func TestMissionQueries_CreateMission_NilMission(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)

	err = mq.CreateMission(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission cannot be nil")
}

// TestMissionQueries_CreateMission_Idempotent tests MERGE idempotency.
func TestMissionQueries_CreateMission_Idempotent(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	now := time.Now()

	mission := &schema.Mission{
		ID:          missionID,
		Name:        "test-mission",
		Description: "Test mission",
		Objective:   "Test objective",
		TargetRef:   "target-123",
		Status:      schema.MissionStatusPending,
		YAMLSource:  "mission: test",
		CreatedAt:   now,
	}

	// First call - creates mission
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": missionID.String()},
		},
	})

	err = mq.CreateMission(ctx, mission)
	require.NoError(t, err)

	// Second call - updates mission status, should not error (MERGE)
	mission.Status = schema.MissionStatusRunning
	startedAt := now.Add(time.Minute)
	mission.StartedAt = &startedAt

	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": missionID.String()},
		},
	})

	err = mq.CreateMission(ctx, mission)
	require.NoError(t, err, "MERGE should make CreateMission idempotent")
}

// TestMissionQueries_CreateMission_WithStartedAt tests creating mission with started_at timestamp.
func TestMissionQueries_CreateMission_WithStartedAt(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	now := time.Now()
	startedAt := now.Add(time.Second)

	mission := &schema.Mission{
		ID:          missionID,
		Name:        "test-mission",
		Description: "Test mission",
		Objective:   "Test objective",
		TargetRef:   "target-123",
		Status:      schema.MissionStatusRunning,
		YAMLSource:  "mission: test",
		CreatedAt:   now,
		StartedAt:   &startedAt,
	}

	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": missionID.String()},
		},
	})

	err = mq.CreateMission(ctx, mission)
	require.NoError(t, err)
}

// TestMissionQueries_CreateMissionNode tests creating a mission node.
func TestMissionQueries_CreateMissionNode(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()
	now := time.Now()

	node := &schema.MissionNode{
		ID:          nodeID,
		MissionID:   missionID,
		Type:        schema.MissionNodeTypeAgent,
		Name:        "test-node",
		Description: "Test node description",
		AgentName:   "test-agent",
		Status:      schema.MissionNodeStatusPending,
		Timeout:     5 * time.Minute,
		TaskConfig:  map[string]any{"key": "value"},
		IsDynamic:   false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// Mock successful creation with PART_OF relationship
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": nodeID.String()},
		},
	})

	err = mq.CreateMissionNode(ctx, node)
	require.NoError(t, err)

	// Verify query was called
	assert.Greater(t, mock.CallCount(), 0)
}

// TestMissionQueries_CreateMissionNode_NilNode tests error handling for nil node.
func TestMissionQueries_CreateMissionNode_NilNode(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)

	err = mq.CreateMissionNode(ctx, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mission node cannot be nil")
}

// TestMissionQueries_CreateMissionNode_MissionNotFound tests error when mission doesn't exist.
func TestMissionQueries_CreateMissionNode_MissionNotFound(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()

	node := &schema.MissionNode{
		ID:          nodeID,
		MissionID:   missionID,
		Type:        schema.MissionNodeTypeAgent,
		Name:        "test-node",
		Description: "Test node",
		AgentName:   "test-agent",
		Status:      schema.MissionNodeStatusPending,
		Timeout:     5 * time.Minute,
		TaskConfig:  map[string]any{},
		IsDynamic:   false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Mock empty result (mission not found)
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{},
	})

	err = mq.CreateMissionNode(ctx, node)
	require.Error(t, err)

	// Verify it's a typed error with correct code
	gibsonErr, ok := err.(*types.GibsonError)
	require.True(t, ok, "expected *types.GibsonError")
	assert.Equal(t, graph.ErrCodeGraphNodeNotFound, gibsonErr.Code)
	assert.Contains(t, err.Error(), "mission")
	assert.Contains(t, err.Error(), missionID.String())
}

// TestMissionQueries_CreateMissionNode_Idempotent tests MERGE idempotency.
func TestMissionQueries_CreateMissionNode_Idempotent(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()
	now := time.Now()

	node := &schema.MissionNode{
		ID:          nodeID,
		MissionID:   missionID,
		Type:        schema.MissionNodeTypeAgent,
		Name:        "test-node",
		Description: "Test node",
		AgentName:   "test-agent",
		Status:      schema.MissionNodeStatusPending,
		Timeout:     5 * time.Minute,
		TaskConfig:  map[string]any{"key": "value"},
		IsDynamic:   false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	// First call - creates node with PART_OF relationship
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": nodeID.String()},
		},
	})

	err = mq.CreateMissionNode(ctx, node)
	require.NoError(t, err)

	// Second call - updates node, should not error (MERGE)
	node.Status = schema.MissionNodeStatusReady
	node.UpdatedAt = now.Add(time.Minute)

	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": nodeID.String()},
		},
	})

	err = mq.CreateMissionNode(ctx, node)
	require.NoError(t, err, "MERGE should make CreateMissionNode idempotent")
}

// TestMissionQueries_CreateMissionNode_WithRetryPolicy tests creating node with retry policy.
func TestMissionQueries_CreateMissionNode_WithRetryPolicy(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()
	now := time.Now()

	retryPolicy := &schema.RetryPolicy{
		MaxRetries: 3,
		Backoff:    time.Second,
		Strategy:   "exponential",
		MaxBackoff: 30 * time.Second,
	}

	node := &schema.MissionNode{
		ID:          nodeID,
		MissionID:   missionID,
		Type:        schema.MissionNodeTypeTool,
		Name:        "test-tool-node",
		Description: "Test tool node",
		ToolName:    "test-tool",
		Status:      schema.MissionNodeStatusPending,
		Timeout:     2 * time.Minute,
		RetryPolicy: retryPolicy,
		TaskConfig:  map[string]any{"input": "test"},
		IsDynamic:   false,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": nodeID.String()},
		},
	})

	err = mq.CreateMissionNode(ctx, node)
	require.NoError(t, err)
}

// TestMissionQueries_CreateMissionNode_DynamicNode tests creating a dynamic node.
func TestMissionQueries_CreateMissionNode_DynamicNode(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	nodeID := types.NewID()
	missionID := types.NewID()
	parentNodeID := types.NewID()
	now := time.Now()

	node := &schema.MissionNode{
		ID:          nodeID,
		MissionID:   missionID,
		Type:        schema.MissionNodeTypeAgent,
		Name:        "dynamic-node",
		Description: "Dynamically spawned node",
		AgentName:   "spawned-agent",
		Status:      schema.MissionNodeStatusPending,
		Timeout:     5 * time.Minute,
		TaskConfig:  map[string]any{},
		IsDynamic:   true,
		SpawnedBy:   parentNodeID.String(),
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": nodeID.String()},
		},
	})

	err = mq.CreateMissionNode(ctx, node)
	require.NoError(t, err)
}

// TestMissionQueries_GetMissionNodeDependencies tests batch fetching of node dependencies.
func TestMissionQueries_GetMissionNodeDependencies(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	node1ID := types.NewID()
	node2ID := types.NewID()
	node3ID := types.NewID()

	// Mock dependency data:
	// node1 -> no dependencies (entry point)
	// node2 -> depends on node1
	// node3 -> depends on node1 and node2
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"node_id":      node1ID.String(),
				"dependencies": []any{}, // No dependencies
			},
			{
				"node_id":      node2ID.String(),
				"dependencies": []any{node1ID.String()},
			},
			{
				"node_id":      node3ID.String(),
				"dependencies": []any{node1ID.String(), node2ID.String()},
			},
		},
	})

	depMap, err := mq.GetMissionNodeDependencies(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, depMap)

	// Verify dependency map structure
	assert.Len(t, depMap, 3)
	assert.Empty(t, depMap[node1ID.String()], "node1 should have no dependencies")
	assert.Equal(t, []string{node1ID.String()}, depMap[node2ID.String()])
	assert.ElementsMatch(t, []string{node1ID.String(), node2ID.String()}, depMap[node3ID.String()])
}

// TestMissionQueries_GetMissionNodeDependencies_NoDependencies tests mission with no dependencies.
func TestMissionQueries_GetMissionNodeDependencies_NoDependencies(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()
	node1ID := types.NewID()
	node2ID := types.NewID()

	// All nodes have no dependencies (parallel execution)
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"node_id":      node1ID.String(),
				"dependencies": []any{},
			},
			{
				"node_id":      node2ID.String(),
				"dependencies": []any{},
			},
		},
	})

	depMap, err := mq.GetMissionNodeDependencies(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, depMap)

	assert.Len(t, depMap, 2)
	assert.Empty(t, depMap[node1ID.String()])
	assert.Empty(t, depMap[node2ID.String()])
}

// TestMissionQueries_GetMissionNodeDependencies_EmptyMission tests mission with no nodes.
func TestMissionQueries_GetMissionNodeDependencies_EmptyMission(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()

	// Mock empty result - no nodes in mission
	mock.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{},
	})

	depMap, err := mq.GetMissionNodeDependencies(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, depMap)
	assert.Empty(t, depMap)
}

// TestMissionQueries_GetMissionNodeDependencies_QueryError tests error handling.
func TestMissionQueries_GetMissionNodeDependencies_QueryError(t *testing.T) {
	mock := graph.NewMockGraphClient()
	ctx := context.Background()

	err := mock.Connect(ctx)
	require.NoError(t, err)
	defer mock.Close(ctx)

	mq := NewMissionQueries(mock)
	missionID := types.NewID()

	// Mock query error
	mock.SetQueryError(assert.AnError)

	depMap, err := mq.GetMissionNodeDependencies(ctx, missionID)
	require.Error(t, err)
	assert.Nil(t, depMap)
	assert.Contains(t, err.Error(), "failed to query mission node dependencies")
}
