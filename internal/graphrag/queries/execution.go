// Package queries provides high-level query interfaces for Gibson graph operations.
// ExecutionQueries handles execution tracking including agent executions, decisions,
// and tool invocations within the orchestrator mission.
//
// Tenant isolation is provided by the per-tenant Neo4j database (database-per-tenant
// data-plane). No WHERE n.tenant_id clause is used or permitted in this package
// (C1/C2/C3/C18 closure).
package queries

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ExecutionQueries provides methods for tracking orchestrator execution state.
// All methods are context-aware and return typed errors for better error handling.
// Tenant isolation is structural: every query runs against the per-tenant Neo4j
// database; no tenant_id property filter is used or required.
type ExecutionQueries struct {
	client graph.GraphClient
}

// NewExecutionQueries creates a new ExecutionQueries instance.
// The client must be connected before using any query methods.
func NewExecutionQueries(client graph.GraphClient) *ExecutionQueries {
	return &ExecutionQueries{
		client: client,
	}
}

// CreateAgentExecution creates an agent execution node and links it to the mission node.
// The execution is validated before creation and linked via :EXECUTES relationship.
// Returns an error if validation fails or if the mission node doesn't exist.
func (eq *ExecutionQueries) CreateAgentExecution(ctx context.Context, exec *schema.AgentExecution) error {
	if exec == nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "execution cannot be nil")
	}

	// Validate execution before creating
	if err := exec.Validate(); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid agent execution", err)
	}

	// Convert execution to properties map
	props, err := structToProps(exec)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			"failed to convert execution to properties", err)
	}

	// Create execution node and link to mission node in a single query.
	// No WHERE n.tenant_id clause: the per-tenant database is the boundary.
	cypher := `
		CREATE (e:AgentExecution)
		SET e = $props
		WITH e
		MATCH (n:MissionNode {id: $nodeId})
		CREATE (e)-[:EXECUTES]->(n)
		RETURN e.id as id
	`

	params := map[string]any{
		"props":  props,
		"nodeId": exec.MissionNodeID,
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			fmt.Sprintf("failed to create agent execution for node %s", exec.MissionNodeID), err)
	}

	// Verify that the mission node exists
	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("mission node %s not found", exec.MissionNodeID))
	}

	return nil
}

// UpdateExecution updates an existing execution's status, results, and completion time.
func (eq *ExecutionQueries) UpdateExecution(ctx context.Context, exec *schema.AgentExecution) error {
	if exec == nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "execution cannot be nil")
	}

	// Validate execution
	if err := exec.Validate(); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid agent execution", err)
	}

	// Update timestamp
	exec.UpdatedAt = time.Now()

	// Build update properties
	props, err := structToProps(exec)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			"failed to convert execution to properties", err)
	}

	// No WHERE e.tenant_id clause: per-tenant database is the boundary.
	cypher := `
		MATCH (e:AgentExecution {id: $id})
		SET e += $props
		RETURN e.id as id
	`

	params := map[string]any{
		"id":    exec.ID.String(),
		"props": props,
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphQueryFailed,
			fmt.Sprintf("failed to update execution %s", exec.ID), err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("execution %s not found", exec.ID))
	}

	return nil
}

// CreateDecision stores an orchestrator decision with full reasoning and context.
func (eq *ExecutionQueries) CreateDecision(ctx context.Context, decision *schema.Decision) error {
	if decision == nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "decision cannot be nil")
	}

	// Validate decision
	if err := decision.Validate(); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid decision", err)
	}

	// Convert decision to properties
	props, err := structToProps(decision)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			"failed to convert decision to properties", err)
	}

	// No WHERE m.tenant_id clause: per-tenant database is the boundary.
	cypher := `
		CREATE (d:Decision)
		SET d = $props
		WITH d
		MATCH (m:Mission {id: $missionId})
		CREATE (m)-[:HAS_DECISION]->(d)
		RETURN d.id as id
	`

	params := map[string]any{
		"props":     props,
		"missionId": decision.MissionID.String(),
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			fmt.Sprintf("failed to create decision for mission %s", decision.MissionID), err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("mission %s not found", decision.MissionID))
	}

	return nil
}

// LinkExecutionToFindings creates :PRODUCED relationships from an execution to findings.
func (eq *ExecutionQueries) LinkExecutionToFindings(ctx context.Context, execID string, findingIDs []string) error {
	if execID == "" {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "execID cannot be empty")
	}
	if len(findingIDs) == 0 {
		return nil // Nothing to link
	}

	// Validate execution ID format
	if _, err := types.ParseID(execID); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid execution ID format", err)
	}

	// No WHERE tenant_id clause: per-tenant database is the boundary.
	cypher := `
		MATCH (e:AgentExecution {id: $execId})
		WITH e
		UNWIND $findingIds as findingId
		MATCH (f:Finding {id: findingId})
		MERGE (e)-[:PRODUCED]->(f)
		RETURN count(*) as linked_count
	`

	params := map[string]any{
		"execId":     execID,
		"findingIds": findingIDs,
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphRelationshipCreateFailed,
			fmt.Sprintf("failed to link execution %s to findings", execID), err)
	}

	// Check if execution exists (result will be empty if execution not found)
	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("execution %s not found", execID))
	}

	return nil
}

// GetMissionDecisions retrieves all decisions for a mission ordered by iteration.
func (eq *ExecutionQueries) GetMissionDecisions(ctx context.Context, missionID string) ([]*schema.Decision, error) {
	if missionID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "missionID cannot be empty")
	}

	// Validate mission ID format
	if _, err := types.ParseID(missionID); err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid mission ID format", err)
	}

	// No WHERE m.tenant_id clause: per-tenant database is the boundary.
	cypher := `
		MATCH (m:Mission {id: $missionId})-[:HAS_DECISION]->(d:Decision)
		RETURN d
		ORDER BY d.iteration ASC, d.timestamp ASC
	`

	params := map[string]any{
		"missionId": missionID,
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphQueryFailed,
			fmt.Sprintf("failed to query decisions for mission %s", missionID), err)
	}

	// Parse decisions from results
	decisions := make([]*schema.Decision, 0, len(result.Records))
	for _, record := range result.Records {
		decisionProps, ok := record["d"].(map[string]any)
		if !ok {
			continue
		}

		decision, err := propsToDecision(decisionProps)
		if err != nil {
			// Log error but continue processing other records
			continue
		}

		decisions = append(decisions, decision)
	}

	return decisions, nil
}

// GetNodeExecutions retrieves all execution attempts for a mission node.
func (eq *ExecutionQueries) GetNodeExecutions(ctx context.Context, nodeID string) ([]*schema.AgentExecution, error) {
	if nodeID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "nodeID cannot be empty")
	}

	// No WHERE n.tenant_id clause: per-tenant database is the boundary.
	cypher := `
		MATCH (e:AgentExecution)-[:EXECUTES]->(n:MissionNode {id: $nodeId})
		RETURN e
		ORDER BY e.attempt ASC, e.started_at ASC
	`

	params := map[string]any{
		"nodeId": nodeID,
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphQueryFailed,
			fmt.Sprintf("failed to query executions for node %s", nodeID), err)
	}

	// Parse executions from results
	executions := make([]*schema.AgentExecution, 0, len(result.Records))
	for _, record := range result.Records {
		execProps, ok := record["e"].(map[string]any)
		if !ok {
			continue
		}

		execution, err := propsToAgentExecution(execProps)
		if err != nil {
			// Log error but continue processing other records
			continue
		}

		executions = append(executions, execution)
	}

	return executions, nil
}

// CreateToolExecution creates a tool execution node linked to an agent execution.
func (eq *ExecutionQueries) CreateToolExecution(ctx context.Context, tool *schema.ToolExecution) error {
	if tool == nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "tool execution cannot be nil")
	}

	// Validate tool execution
	if err := tool.Validate(); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid tool execution", err)
	}

	// Convert to properties
	props, err := structToProps(tool)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			"failed to convert tool execution to properties", err)
	}

	// No WHERE e.tenant_id clause: per-tenant database is the boundary.
	cypher := `
		CREATE (t:ToolExecution)
		SET t = $props
		WITH t
		MATCH (e:AgentExecution {id: $agentExecId})
		CREATE (e)-[:USED_TOOL]->(t)
		RETURN t.id as id
	`

	params := map[string]any{
		"props":       props,
		"agentExecId": tool.AgentExecutionID.String(),
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			fmt.Sprintf("failed to create tool execution for agent %s", tool.AgentExecutionID), err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("agent execution %s not found", tool.AgentExecutionID))
	}

	return nil
}

// GetExecutionTools retrieves all tool executions for an agent execution.
func (eq *ExecutionQueries) GetExecutionTools(ctx context.Context, execID string) ([]*schema.ToolExecution, error) {
	if execID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "execID cannot be empty")
	}

	// Validate execution ID format
	if _, err := types.ParseID(execID); err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid execution ID format", err)
	}

	// No WHERE e.tenant_id clause: per-tenant database is the boundary.
	cypher := `
		MATCH (e:AgentExecution {id: $execId})-[:USED_TOOL]->(t:ToolExecution)
		RETURN t
		ORDER BY t.started_at ASC
	`

	params := map[string]any{
		"execId": execID,
	}

	result, err := eq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphQueryFailed,
			fmt.Sprintf("failed to query tools for execution %s", execID), err)
	}

	// Parse tool executions from results
	tools := make([]*schema.ToolExecution, 0, len(result.Records))
	for _, record := range result.Records {
		toolProps, ok := record["t"].(map[string]any)
		if !ok {
			continue
		}

		tool, err := propsToToolExecution(toolProps)
		if err != nil {
			// Log error but continue processing other records
			continue
		}

		tools = append(tools, tool)
	}

	return tools, nil
}

// structToProps converts a struct to a map[string]any for Neo4j properties.
// Uses JSON marshaling/unmarshaling for type conversion.
// Nested maps and slices are serialized to JSON strings since Neo4j doesn't support them directly.
func structToProps(v any) (map[string]any, error) {
	// Marshal to JSON
	data, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct: %w", err)
	}

	// Unmarshal to map
	var props map[string]any
	if err := json.Unmarshal(data, &props); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to map: %w", err)
	}

	// Convert nested maps/slices to JSON strings since Neo4j doesn't support them
	for key, val := range props {
		if val == nil {
			continue
		}
		switch v := val.(type) {
		case map[string]any:
			// Serialize nested map to JSON string
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize %s to JSON: %w", key, err)
			}
			props[key] = string(jsonBytes)
		case []any:
			// Serialize slice to JSON string
			jsonBytes, err := json.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("failed to serialize %s to JSON: %w", key, err)
			}
			props[key] = string(jsonBytes)
		}
	}

	return props, nil
}

// propsToAgentExecution converts Neo4j properties to an AgentExecution struct.
func propsToAgentExecution(props map[string]any) (*schema.AgentExecution, error) {
	// Marshal props to JSON
	data, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}

	// Unmarshal to struct
	var exec schema.AgentExecution
	if err := json.Unmarshal(data, &exec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to AgentExecution: %w", err)
	}

	return &exec, nil
}

// propsToDecision converts Neo4j properties to a Decision struct.
func propsToDecision(props map[string]any) (*schema.Decision, error) {
	data, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}

	var decision schema.Decision
	if err := json.Unmarshal(data, &decision); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to Decision: %w", err)
	}

	return &decision, nil
}

// propsToToolExecution converts Neo4j properties to a ToolExecution struct.
func propsToToolExecution(props map[string]any) (*schema.ToolExecution, error) {
	data, err := json.Marshal(props)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal properties: %w", err)
	}

	var tool schema.ToolExecution
	if err := json.Unmarshal(data, &tool); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to ToolExecution: %w", err)
	}

	return &tool, nil
}
