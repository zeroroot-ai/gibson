package queries

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestNewExecutionQueries tests ExecutionQueries constructor
func TestNewExecutionQueries(t *testing.T) {
	mockClient := graph.NewMockGraphClient()
	queries := NewExecutionQueries(mockClient)

	assert.NotNil(t, queries)
	assert.NotNil(t, queries.client)
}

// TestCreateAgentExecution tests agent execution creation
func TestCreateAgentExecution(t *testing.T) {
	t.Run("successful creation", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": "exec-123"}},
		})

		queries := NewExecutionQueries(mockClient)
		exec := schema.NewAgentExecution("node-123", types.NewID())
		err := queries.CreateAgentExecution(context.Background(), exec)

		require.NoError(t, err)
	})

	t.Run("nil execution", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		queries := NewExecutionQueries(mockClient)

		err := queries.CreateAgentExecution(context.Background(), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "execution cannot be nil")
	})
}

// TestUpdateExecution tests execution updates
func TestUpdateExecution(t *testing.T) {
	t.Run("successful update", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": "exec-123"}},
		})

		queries := NewExecutionQueries(mockClient)
		exec := schema.NewAgentExecution("node-123", types.NewID()).
			WithID(types.NewID()).
			MarkCompleted()

		err := queries.UpdateExecution(context.Background(), exec)
		require.NoError(t, err)
	})
}

// TestCreateDecision tests decision creation
func TestCreateDecision(t *testing.T) {
	missionID := types.NewID()

	t.Run("successful creation", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": "decision-123"}},
		})

		queries := NewExecutionQueries(mockClient)
		decision := schema.NewDecision(missionID, 1, schema.DecisionActionExecuteAgent).
			WithReasoning("Need to scan for vulnerabilities")

		err := queries.CreateDecision(context.Background(), decision)
		require.NoError(t, err)
	})
}

// TestLinkExecutionToFindings tests linking executions to findings
func TestLinkExecutionToFindings(t *testing.T) {
	validExecID := types.NewID().String()

	t.Run("successful link", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"linked_count": 2}},
		})

		queries := NewExecutionQueries(mockClient)
		findingIDs := []string{"finding-1", "finding-2"}
		err := queries.LinkExecutionToFindings(context.Background(), validExecID, findingIDs)

		require.NoError(t, err)
	})

	t.Run("empty execID", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		queries := NewExecutionQueries(mockClient)

		err := queries.LinkExecutionToFindings(context.Background(), "", []string{"finding-1"})
		require.Error(t, err)
	})
}

// TestGetMissionDecisions tests retrieving mission decisions
func TestGetMissionDecisions(t *testing.T) {
	missionID := types.NewID()

	t.Run("successful query", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{
					"d": map[string]any{
						"id":         types.NewID().String(),
						"mission_id": missionID.String(),
						"iteration":  float64(1),
						"timestamp":  time.Now().Format(time.RFC3339),
						"action":     string(schema.DecisionActionExecuteAgent),
						"reasoning":  "Initial scan",
						"confidence": 0.95,
						"created_at": time.Now().Format(time.RFC3339),
						"updated_at": time.Now().Format(time.RFC3339),
					},
				},
			},
		})

		queries := NewExecutionQueries(mockClient)
		decisions, err := queries.GetMissionDecisions(context.Background(), missionID.String())

		require.NoError(t, err)
		assert.Len(t, decisions, 1)
	})
}

// TestGetNodeExecutions tests retrieving node executions
func TestGetNodeExecutions(t *testing.T) {
	nodeID := "node-123"
	missionID := types.NewID()

	t.Run("successful query", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{
					"e": map[string]any{
						"id":              types.NewID().String(),
						"mission_node_id": nodeID,
						"mission_id":      missionID.String(),
						"status":          string(schema.ExecutionStatusCompleted),
						"started_at":      time.Now().Format(time.RFC3339),
						"attempt":         float64(1),
						"created_at":      time.Now().Format(time.RFC3339),
						"updated_at":      time.Now().Format(time.RFC3339),
					},
				},
			},
		})

		queries := NewExecutionQueries(mockClient)
		executions, err := queries.GetNodeExecutions(context.Background(), nodeID)

		require.NoError(t, err)
		assert.Len(t, executions, 1)
	})
}

// TestCreateToolExecution tests tool execution creation
func TestCreateToolExecution(t *testing.T) {
	agentExecID := types.NewID()

	t.Run("successful creation", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{{"id": "tool-123"}},
		})

		queries := NewExecutionQueries(mockClient)
		tool := schema.NewToolExecution(agentExecID, "nmap_scan")

		err := queries.CreateToolExecution(context.Background(), tool)
		require.NoError(t, err)
	})
}

// TestGetExecutionTools tests retrieving execution tools
func TestGetExecutionTools(t *testing.T) {
	execID := types.NewID()

	t.Run("successful query", func(t *testing.T) {
		mockClient := graph.NewMockGraphClient()
		mockClient.Connect(context.Background())
		mockClient.AddQueryResult(graph.QueryResult{
			Records: []map[string]any{
				{
					"t": map[string]any{
						"id":                 types.NewID().String(),
						"agent_execution_id": execID.String(),
						"tool_name":          "nmap",
						"status":             string(schema.ExecutionStatusCompleted),
						"started_at":         time.Now().Format(time.RFC3339),
						"created_at":         time.Now().Format(time.RFC3339),
						"updated_at":         time.Now().Format(time.RFC3339),
					},
				},
			},
		})

		queries := NewExecutionQueries(mockClient)
		tools, err := queries.GetExecutionTools(context.Background(), execID.String())

		require.NoError(t, err)
		assert.Len(t, tools, 1)
	})
}

// TestStructToProps tests struct to properties conversion
func TestStructToProps(t *testing.T) {
	exec := schema.NewAgentExecution("node-123", types.NewID())

	props, err := structToProps(exec)
	require.NoError(t, err)
	assert.NotEmpty(t, props)
	assert.Contains(t, props, "id")
}
