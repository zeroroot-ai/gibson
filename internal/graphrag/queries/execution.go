// Package queries provides high-level query interfaces for Gibson graph operations.
// ExecutionQueries handles execution tracking including agent executions, decisions,
// and tool invocations within the orchestrator mission.
package queries

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/sdk/auth"
	"github.com/zero-day-ai/gibson/internal/types"
)

// tenantFromCtx extracts the tenant ID from the context and returns an error
// if it is missing. All GraphRAG execution queries require tenant isolation.
func tenantFromCtx(ctx context.Context) (string, error) {
	tid := auth.TenantStringFromContext(ctx)
	if tid == "" {
		return "", fmt.Errorf("tenant_id required for GraphRAG queries")
	}
	return tid, nil
}

// ExecutionQueries provides methods for tracking orchestrator execution state.
// All methods are context-aware and return typed errors for better error handling.
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
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return err
	}

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

	// Create execution node and link to mission node in a single query
	// This ensures atomicity and prevents orphaned execution nodes
	cypher := `
		CREATE (e:AgentExecution)
		SET e = $props
		WITH e
		MATCH (n:MissionNode {id: $nodeId})
		WHERE n.tenant_id = $tenant_id
		CREATE (e)-[:EXECUTES]->(n)
		RETURN e.id as id
	`

	params := map[string]any{
		"props":     props,
		"nodeId":    exec.MissionNodeID,
		"tenant_id": tenantID,
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
// This is typically called when an execution completes or fails.
// Returns an error if the execution doesn't exist or if validation fails.
func (eq *ExecutionQueries) UpdateExecution(ctx context.Context, exec *schema.AgentExecution) error {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return err
	}

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

	cypher := `
		MATCH (e:AgentExecution {id: $id})
		WHERE e.tenant_id = $tenant_id
		SET e += $props
		RETURN e.id as id
	`

	params := map[string]any{
		"id":        exec.ID.String(),
		"props":     props,
		"tenant_id": tenantID,
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
// Decisions are linked to the mission for audit trail purposes.
// The Langfuse correlation ID enables tracing decisions back to LLM calls.
func (eq *ExecutionQueries) CreateDecision(ctx context.Context, decision *schema.Decision) error {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return err
	}

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

	// Create decision node and link to mission
	cypher := `
		CREATE (d:Decision)
		SET d = $props
		WITH d
		MATCH (m:Mission {id: $missionId})
		WHERE m.tenant_id = $tenant_id
		CREATE (m)-[:HAS_DECISION]->(d)
		RETURN d.id as id
	`

	params := map[string]any{
		"props":     props,
		"missionId": decision.MissionID.String(),
		"tenant_id": tenantID,
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
// This enables tracking which execution produced which findings for provenance.
// Returns an error if the execution doesn't exist. Missing findings are skipped silently.
func (eq *ExecutionQueries) LinkExecutionToFindings(ctx context.Context, execID string, findingIDs []string) error {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return err
	}

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

	// Create relationships in batch for better performance
	cypher := `
		MATCH (e:AgentExecution {id: $execId})
		WHERE e.tenant_id = $tenant_id
		WITH e
		UNWIND $findingIds as findingId
		MATCH (f:Finding {id: findingId})
		WHERE f.tenant_id = $tenant_id
		MERGE (e)-[:PRODUCED]->(f)
		RETURN count(*) as linked_count
	`

	params := map[string]any{
		"execId":     execID,
		"findingIds": findingIDs,
		"tenant_id":  tenantID,
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
// This provides a complete audit trail of the orchestrator's decision-making process.
// Returns an empty slice if no decisions exist for the mission.
func (eq *ExecutionQueries) GetMissionDecisions(ctx context.Context, missionID string) ([]*schema.Decision, error) {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if missionID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "missionID cannot be empty")
	}

	// Validate mission ID format
	if _, err := types.ParseID(missionID); err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid mission ID format", err)
	}

	cypher := `
		MATCH (m:Mission {id: $missionId})-[:HAS_DECISION]->(d:Decision)
		WHERE m.tenant_id = $tenant_id
		RETURN d
		ORDER BY d.iteration ASC, d.timestamp ASC
	`

	params := map[string]any{
		"missionId": missionID,
		"tenant_id": tenantID,
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
// This is useful for tracking retry attempts and execution history.
// Results are ordered by attempt number ascending.
func (eq *ExecutionQueries) GetNodeExecutions(ctx context.Context, nodeID string) ([]*schema.AgentExecution, error) {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if nodeID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "nodeID cannot be empty")
	}

	cypher := `
		MATCH (e:AgentExecution)-[:EXECUTES]->(n:MissionNode {id: $nodeId})
		WHERE n.tenant_id = $tenant_id
		RETURN e
		ORDER BY e.attempt ASC, e.started_at ASC
	`

	params := map[string]any{
		"nodeId":    nodeID,
		"tenant_id": tenantID,
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
// This tracks individual tool invocations within an agent's execution.
// Returns an error if the parent agent execution doesn't exist.
func (eq *ExecutionQueries) CreateToolExecution(ctx context.Context, tool *schema.ToolExecution) error {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return err
	}

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

	// Create tool execution node and link to agent execution
	cypher := `
		CREATE (t:ToolExecution)
		SET t = $props
		WITH t
		MATCH (e:AgentExecution {id: $agentExecId})
		WHERE e.tenant_id = $tenant_id
		CREATE (e)-[:USED_TOOL]->(t)
		RETURN t.id as id
	`

	params := map[string]any{
		"props":       props,
		"agentExecId": tool.AgentExecutionID.String(),
		"tenant_id":   tenantID,
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
// This provides insight into which tools were used during an agent's execution.
// Results are ordered by start time ascending.
func (eq *ExecutionQueries) GetExecutionTools(ctx context.Context, execID string) ([]*schema.ToolExecution, error) {
	tenantID, err := tenantFromCtx(ctx)
	if err != nil {
		return nil, err
	}

	if execID == "" {
		return nil, types.NewError(graph.ErrCodeGraphInvalidQuery, "execID cannot be empty")
	}

	// Validate execution ID format
	if _, err := types.ParseID(execID); err != nil {
		return nil, types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid execution ID format", err)
	}

	cypher := `
		MATCH (e:AgentExecution {id: $execId})-[:USED_TOOL]->(t:ToolExecution)
		WHERE e.tenant_id = $tenant_id
		RETURN t
		ORDER BY t.started_at ASC
	`

	params := map[string]any{
		"execId":    execID,
		"tenant_id": tenantID,
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
// Handles time.Time fields by converting to RFC3339 strings.
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
// Handles type conversions and null values gracefully.
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
