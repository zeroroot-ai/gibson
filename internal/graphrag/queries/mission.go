// Package queries provides specialized Cypher query functions for mission execution tracking.
package queries

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// toInt64 safely converts various numeric types to int64.
// Neo4j driver returns int64, but JSON unmarshaling or other sources may return float64.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		return int64(n), true
	case int:
		return int64(n), true
	case int32:
		return int64(n), true
	default:
		return 0, false
	}
}

// MissionQueries provides high-level query operations for mission execution data.
type MissionQueries struct {
	client graph.GraphClient
}

// NewMissionQueries creates a new MissionQueries with the given graph client.
func NewMissionQueries(client graph.GraphClient) *MissionQueries {
	return &MissionQueries{
		client: client,
	}
}

// CreateMission creates or updates a mission node in the graph.
// Uses MERGE on ID for idempotency - the SQLite mission ID is stable (same across runs).
// All runs of the same mission share one Mission node in Neo4j with the same stable ID.
// On create, sets all properties. On match, updates status and latest run info.
// Returns an error if validation fails or if the database operation fails.
func (mq *MissionQueries) CreateMission(ctx context.Context, m *schema.Mission) error {
	if m == nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "mission cannot be nil")
	}

	// Validate mission before creating
	if err := m.Validate(); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid mission", err)
	}

	// Build Cypher query with MERGE on ID (SQLite mission ID is stable across runs)
	// This ensures all runs of the same mission share one Mission node
	cypher := `
		MERGE (m:Mission {id: $id})
		ON CREATE SET
			m.name = $name,
			m.description = $description,
			m.objective = $objective,
			m.target_ref = $target_ref,
			m.status = $status,
			m.yaml_source = $yaml_source,
			m.created_at = datetime($created_at),
			m.started_at = CASE WHEN $started_at IS NOT NULL THEN datetime($started_at) ELSE NULL END
		ON MATCH SET
			m.status = $status,
			m.target_ref = $target_ref,
			m.started_at = CASE WHEN $started_at IS NOT NULL THEN datetime($started_at) ELSE m.started_at END
		RETURN m.id as id
	`

	// Build parameters map
	params := map[string]any{
		graphrag.PropID:          m.ID.String(),
		graphrag.PropName:        m.Name,
		graphrag.PropDescription: m.Description,
		"objective":              m.Objective,
		"target_ref":             m.TargetRef,
		graphrag.PropStatus:      m.Status.String(),
		"yaml_source":            m.YAMLSource,
		graphrag.PropCreatedAt:   m.CreatedAt.UTC().Format(time.RFC3339Nano),
	}

	// Add optional started_at timestamp
	if m.StartedAt != nil {
		params["started_at"] = m.StartedAt.UTC().Format(time.RFC3339Nano)
	} else {
		params["started_at"] = nil
	}

	// Execute query
	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			fmt.Sprintf("failed to create mission %s", m.Name), err)
	}

	// Verify result (should always have one record with MERGE)
	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeCreateFailed,
			fmt.Sprintf("no result returned when creating mission %s", m.Name))
	}

	return nil
}

// GetMission retrieves a mission by ID.
func (mq *MissionQueries) GetMission(ctx context.Context, missionID types.ID) (*schema.Mission, error) {
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		RETURN properties(m) as m
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("mission not found: %s", missionID)
	}

	return recordToMission(result.Records[0]["m"])
}

// GetMissionNodes retrieves all mission nodes for a mission.
func (mq *MissionQueries) GetMissionNodes(ctx context.Context, missionID types.ID) ([]*schema.MissionNode, error) {
	cypher := `
		MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		RETURN properties(n) as n
		ORDER BY n.created_at
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	nodes := make([]*schema.MissionNode, 0, len(result.Records))
	for _, record := range result.Records {
		node, err := recordToMissionNode(record["n"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission node: %w", err)
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// GetMissionDecisions retrieves all orchestrator decisions for a mission, ordered by iteration.
func (mq *MissionQueries) GetMissionDecisions(ctx context.Context, missionID types.ID) ([]*schema.Decision, error) {
	cypher := `
		MATCH (m:Mission {id: $mission_id})-[:HAS_DECISION]->(d:Decision)
		RETURN properties(d) as d
		ORDER BY d.iteration, d.timestamp
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	decisions := make([]*schema.Decision, 0, len(result.Records))
	for _, record := range result.Records {
		decision, err := recordToDecision(record["d"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse decision: %w", err)
		}
		decisions = append(decisions, decision)
	}

	return decisions, nil
}

// GetNodeExecutions retrieves all executions for a specific mission node.
func (mq *MissionQueries) GetNodeExecutions(ctx context.Context, nodeID types.ID) ([]*schema.AgentExecution, error) {
	cypher := `
		MATCH (e:AgentExecution)-[:EXECUTES]->(n:MissionNode {id: $node_id})
		RETURN properties(e) as e
		ORDER BY e.started_at
	`

	params := map[string]any{
		"node_id": nodeID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	executions := make([]*schema.AgentExecution, 0, len(result.Records))
	for _, record := range result.Records {
		exec, err := recordToAgentExecution(record["e"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse execution: %w", err)
		}
		executions = append(executions, exec)
	}

	return executions, nil
}

// GetReadyNodes returns mission nodes that are ready to execute.
// A node is ready if all its dependencies have status "completed".
func (mq *MissionQueries) GetReadyNodes(ctx context.Context, missionID types.ID) ([]*schema.MissionNode, error) {
	cypher := `
		MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		WHERE n.status = 'ready'
		AND NOT EXISTS {
			MATCH (n)-[:DEPENDS_ON]->(dep:MissionNode)
			WHERE dep.status <> 'completed'
		}
		RETURN properties(n) as n
		ORDER BY n.created_at
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	nodes := make([]*schema.MissionNode, 0, len(result.Records))
	for _, record := range result.Records {
		node, err := recordToMissionNode(record["n"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse mission node: %w", err)
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// GetNodeDependencies returns the nodes that a given node depends on.
func (mq *MissionQueries) GetNodeDependencies(ctx context.Context, nodeID types.ID) ([]*schema.MissionNode, error) {
	cypher := `
		MATCH (n:MissionNode {id: $node_id})-[:DEPENDS_ON]->(dep:MissionNode)
		RETURN properties(dep) as dep
		ORDER BY dep.created_at
	`

	params := map[string]any{
		"node_id": nodeID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	nodes := make([]*schema.MissionNode, 0, len(result.Records))
	for _, record := range result.Records {
		node, err := recordToMissionNode(record["dep"])
		if err != nil {
			return nil, fmt.Errorf("failed to parse dependency node: %w", err)
		}
		nodes = append(nodes, node)
	}

	return nodes, nil
}

// GetMissionNodeDependencies returns all node dependencies for a mission in a single batch query.
// This avoids N+1 queries by fetching all dependency relationships at once.
// Returns a map of nodeID -> []dependencyNodeIDs.
// Nodes with no dependencies will have an empty slice in the map.
func (mq *MissionQueries) GetMissionNodeDependencies(ctx context.Context, missionID types.ID) (map[string][]string, error) {
	cypher := `
		MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		OPTIONAL MATCH (n)-[:DEPENDS_ON]->(dep:MissionNode)
		RETURN n.id as node_id, collect(dep.id) as dependencies
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query mission node dependencies: %w", err)
	}

	// Build dependency map
	depMap := make(map[string][]string, len(result.Records))
	for _, record := range result.Records {
		nodeID, ok := record["node_id"].(string)
		if !ok {
			continue
		}

		// Handle dependencies list
		deps := []string{}
		if depList, ok := record["dependencies"].([]any); ok {
			for _, dep := range depList {
				if depID, ok := dep.(string); ok && depID != "" {
					deps = append(deps, depID)
				}
			}
		}

		depMap[nodeID] = deps
	}

	return depMap, nil
}

// CreateNodeDependency creates a DEPENDS_ON relationship between two mission nodes.
// The relationship direction is: (fromNodeID)-[:DEPENDS_ON]->(toNodeID), meaning
// fromNodeID depends on toNodeID (fromNodeID must wait for toNodeID to complete).
// Uses MERGE for idempotency - safe to call multiple times with same nodes.
// Returns an error if either node is not found.
func (mq *MissionQueries) CreateNodeDependency(ctx context.Context, fromNodeID, toNodeID types.ID) error {
	cypher := `
		MATCH (from:MissionNode {id: $from_id})
		MATCH (to:MissionNode {id: $to_id})
		MERGE (from)-[:DEPENDS_ON]->(to)
		RETURN count(*) as count
	`

	params := map[string]any{
		"from_id": fromNodeID.String(),
		"to_id":   toNodeID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphRelationshipCreateFailed,
			fmt.Sprintf("failed to create dependency from %s to %s", fromNodeID, toNodeID), err)
	}

	// If no records returned, one or both nodes don't exist
	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("one or both nodes not found: from=%s, to=%s", fromNodeID, toNodeID))
	}

	return nil
}

// CreateMissionNode creates a new mission node and links it to its mission.
// Uses MERGE for idempotency and creates the PART_OF relationship in the same query.
// Returns an error if validation fails or if the mission doesn't exist.
func (mq *MissionQueries) CreateMissionNode(ctx context.Context, node *schema.MissionNode) error {
	if node == nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "mission node cannot be nil")
	}

	// Validate node before creating
	if err := node.Validate(); err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"invalid mission node", err)
	}

	// Serialize JSON fields
	taskConfigJSON, err := node.TaskConfigJSON()
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"failed to marshal task config", err)
	}

	retryPolicyJSON, err := node.RetryPolicyJSON()
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphInvalidQuery,
			"failed to marshal retry policy", err)
	}

	// Create mission node with MERGE for idempotency
	// Also creates PART_OF relationship to mission in the same query
	// Match Mission by ID (stable SQLite ID)
	cypher := `
		MERGE (n:MissionNode {id: $id})
		SET n.mission_id = $mission_id,
			n.type = $type,
			n.name = $name,
			n.description = $description,
			n.agent_name = $agent_name,
			n.tool_name = $tool_name,
			n.timeout = $timeout,
			n.retry_policy = $retry_policy,
			n.task_config = $task_config,
			n.status = $status,
			n.is_dynamic = $is_dynamic,
			n.spawned_by = $spawned_by,
			n.created_at = $created_at,
			n.updated_at = $updated_at
		WITH n
		MATCH (m:Mission {id: $mission_id})
		MERGE (n)-[:PART_OF]->(m)
		RETURN n.id as id
	`

	params := map[string]any{
		"id":           node.ID.String(),
		"mission_id":   node.MissionID.String(),
		"type":         string(node.Type),
		"name":         node.Name,
		"description":  node.Description,
		"agent_name":   node.AgentName,
		"tool_name":    node.ToolName,
		"timeout":      node.Timeout.Milliseconds(),
		"retry_policy": retryPolicyJSON,
		"task_config":  taskConfigJSON,
		"status":       string(node.Status),
		"is_dynamic":   node.IsDynamic,
		"spawned_by":   node.SpawnedBy,
		"created_at":   node.CreatedAt.UTC().Format(time.RFC3339Nano),
		"updated_at":   node.UpdatedAt.UTC().Format(time.RFC3339Nano),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			fmt.Sprintf("failed to create mission node %s", node.ID), err)
	}

	// Verify that the mission exists
	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound,
			fmt.Sprintf("mission %s not found", node.MissionID))
	}

	return nil
}

// GetMissionStats returns execution statistics for a mission.
type MissionStats struct {
	TotalNodes      int       `json:"total_nodes"`
	CompletedNodes  int       `json:"completed_nodes"`
	FailedNodes     int       `json:"failed_nodes"`
	PendingNodes    int       `json:"pending_nodes"`
	TotalDecisions  int       `json:"total_decisions"`
	TotalExecutions int       `json:"total_executions"`
	StartTime       time.Time `json:"start_time,omitempty"`
	EndTime         time.Time `json:"end_time,omitempty"`
}

// GetMissionStats computes execution statistics for a mission.
func (mq *MissionQueries) GetMissionStats(ctx context.Context, missionID types.ID) (*MissionStats, error) {
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		OPTIONAL MATCH (n:MissionNode)-[:PART_OF]->(m)
		OPTIONAL MATCH (d:Decision)-[:PART_OF]->(m)
		OPTIONAL MATCH (e:AgentExecution)-[:EXECUTES]->(n)
		RETURN
			COUNT(DISTINCT n) as total_nodes,
			COUNT(DISTINCT CASE WHEN n.status = 'completed' THEN n END) as completed_nodes,
			COUNT(DISTINCT CASE WHEN n.status = 'failed' THEN n END) as failed_nodes,
			COUNT(DISTINCT CASE WHEN n.status = 'pending' OR n.status = 'ready' THEN n END) as pending_nodes,
			COUNT(DISTINCT d) as total_decisions,
			COUNT(DISTINCT e) as total_executions,
			m.created_at as start_time,
			m.completed_at as end_time
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, err
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("mission not found: %s", missionID)
	}

	record := result.Records[0]
	totalNodes, _ := toInt64(record["total_nodes"])
	completedNodes, _ := toInt64(record["completed_nodes"])
	failedNodes, _ := toInt64(record["failed_nodes"])
	pendingNodes, _ := toInt64(record["pending_nodes"])
	totalDecisions, _ := toInt64(record["total_decisions"])
	totalExecutions, _ := toInt64(record["total_executions"])
	stats := &MissionStats{
		TotalNodes:      int(totalNodes),
		CompletedNodes:  int(completedNodes),
		FailedNodes:     int(failedNodes),
		PendingNodes:    int(pendingNodes),
		TotalDecisions:  int(totalDecisions),
		TotalExecutions: int(totalExecutions),
	}

	if startTime, ok := record["start_time"].(time.Time); ok {
		stats.StartTime = startTime
	}
	if endTime, ok := record["end_time"].(time.Time); ok {
		stats.EndTime = endTime
	}

	return stats, nil
}

// Helper functions to convert Neo4j records to schema types

func recordToMission(data any) (*schema.Mission, error) {
	m, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid mission data type: %T", data)
	}

	idStr, _ := m["id"].(string)
	id, err := types.ParseID(idStr)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	// Use safe accessors: a missing graph property yields a nil map value, and a
	// bare `.(string)` on nil panics (crashed the daemon during mission
	// observation when optional fields like objective/yaml_source were unset).
	mission := &schema.Mission{
		ID:          id,
		Name:        mapStr(m, "name"),
		Description: mapStr(m, "description"),
		Objective:   mapStr(m, "objective"),
		TargetRef:   mapStr(m, "target_ref"),
		Status:      schema.MissionStatus(mapStr(m, "status")),
		YAMLSource:  mapStr(m, "yaml_source"),
	}

	if createdAt, ok := m["created_at"].(time.Time); ok {
		mission.CreatedAt = createdAt
	}
	if startedAt, ok := m["started_at"].(time.Time); ok {
		mission.StartedAt = &startedAt
	}
	if completedAt, ok := m["completed_at"].(time.Time); ok {
		mission.CompletedAt = &completedAt
	}

	return mission, nil
}

// mapStr safely reads a string property from a graph-record map. A missing key
// or nil/non-string value yields "" instead of panicking on a bare assertion.
func mapStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func recordToMissionNode(data any) (*schema.MissionNode, error) {
	n, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid mission node data type: %T", data)
	}

	nodeIDStr, _ := n["id"].(string)
	id, err := types.ParseID(nodeIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid node ID: %w", err)
	}

	missionIDStr, _ := n["mission_id"].(string)
	missionID, err := types.ParseID(missionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	isDynamic, _ := n["is_dynamic"].(bool)
	node := &schema.MissionNode{
		ID:          id,
		MissionID:   missionID,
		Type:        schema.MissionNodeType(mapStr(n, "type")),
		Name:        mapStr(n, "name"),
		Description: mapStr(n, "description"),
		Status:      schema.MissionNodeStatus(mapStr(n, "status")),
		IsDynamic:   isDynamic,
		TaskConfig:  make(map[string]any),
	}

	if agentName, ok := n["agent_name"].(string); ok && agentName != "" {
		node.AgentName = agentName
	}
	if toolName, ok := n["tool_name"].(string); ok && toolName != "" {
		node.ToolName = toolName
	}
	if spawnedBy, ok := n["spawned_by"].(string); ok && spawnedBy != "" {
		node.SpawnedBy = spawnedBy
	}
	if timeout, ok := toInt64(n["timeout"]); ok && timeout > 0 {
		node.Timeout = time.Duration(timeout) * time.Millisecond
	}
	if createdAt, ok := n["created_at"].(time.Time); ok {
		node.CreatedAt = createdAt
	}
	if updatedAt, ok := n["updated_at"].(time.Time); ok {
		node.UpdatedAt = updatedAt
	}

	// Parse JSON fields
	if taskConfigStr, ok := n["task_config"].(string); ok && taskConfigStr != "" && taskConfigStr != "{}" {
		if err := json.Unmarshal([]byte(taskConfigStr), &node.TaskConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal task_config: %w", err)
		}
	}

	if retryPolicyStr, ok := n["retry_policy"].(string); ok && retryPolicyStr != "" && retryPolicyStr != "{}" {
		var retryPolicy schema.RetryPolicy
		if err := json.Unmarshal([]byte(retryPolicyStr), &retryPolicy); err != nil {
			return nil, fmt.Errorf("failed to unmarshal retry_policy: %w", err)
		}
		node.RetryPolicy = &retryPolicy
	}

	return node, nil
}

func recordToDecision(data any) (*schema.Decision, error) {
	d, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid decision data type: %T", data)
	}

	decIDStr, _ := d["id"].(string)
	id, err := types.ParseID(decIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid decision ID: %w", err)
	}

	decMissionIDStr, _ := d["mission_id"].(string)
	missionID, err := types.ParseID(decMissionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	iteration, _ := toInt64(d["iteration"])
	confidence, _ := d["confidence"].(float64)
	decision := &schema.Decision{
		ID:            id,
		MissionID:     missionID,
		Iteration:     int(iteration),
		Action:        schema.DecisionAction(mapStr(d, "action")),
		Reasoning:     mapStr(d, "reasoning"),
		Confidence:    confidence,
		Modifications: make(map[string]any),
	}

	if targetNodeID, ok := d["target_node_id"].(string); ok && targetNodeID != "" {
		decision.TargetNodeID = targetNodeID
	}
	if graphStateSummary, ok := d["graph_state_summary"].(string); ok {
		decision.GraphStateSummary = graphStateSummary
	}
	if promptTokens, ok := toInt64(d["prompt_tokens"]); ok {
		decision.PromptTokens = int(promptTokens)
	}
	if completionTokens, ok := toInt64(d["completion_tokens"]); ok {
		decision.CompletionTokens = int(completionTokens)
	}
	if latencyMs, ok := toInt64(d["latency_ms"]); ok {
		decision.LatencyMs = int(latencyMs)
	}
	if timestamp, ok := d["timestamp"].(time.Time); ok {
		decision.Timestamp = timestamp
	}
	if createdAt, ok := d["created_at"].(time.Time); ok {
		decision.CreatedAt = createdAt
	}
	if updatedAt, ok := d["updated_at"].(time.Time); ok {
		decision.UpdatedAt = updatedAt
	}

	// Parse modifications JSON
	if modsStr, ok := d["modifications"].(string); ok && modsStr != "" && modsStr != "{}" {
		if err := json.Unmarshal([]byte(modsStr), &decision.Modifications); err != nil {
			return nil, fmt.Errorf("failed to unmarshal modifications: %w", err)
		}
	}

	return decision, nil
}

// CreateMissionRun creates a new mission_run node and links it to its Mission.
// Each call creates a NEW node - run numbers must be unique per mission.
// Returns the generated mission run ID.
//
// IMPORTANT: Uses lowercase :mission_run label to match GraphLoader expectations.
// The GraphLoader attaches discovered nodes (hosts, ports, etc.) to mission_run
// via BELONGS_TO relationships, so the label must be consistent.
//
// Parameters:
//   - ctx: Context for cancellation
//   - missionID: The stable SQLite mission ID (used to match Mission node)
//   - runID: The SQLite mission_run ID (stored on mission_run node)
//   - runNumber: Sequential run number (1, 2, 3...)
//
// Returns:
//   - error: Any error during creation
func (mq *MissionQueries) CreateMissionRun(ctx context.Context, missionID types.ID, runID types.ID, runNumber int) error {
	if err := missionID.Validate(); err != nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "invalid mission ID")
	}
	if err := runID.Validate(); err != nil {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "invalid run ID")
	}
	if runNumber < 1 {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "run number must be >= 1")
	}

	// Use lowercase :mission_run to match GraphLoader's attachToMissionRun() expectations
	// GraphLoader queries: MATCH (run:mission_run {id: $run_id})
	// Match Mission by ID (stable SQLite ID)
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		CREATE (r:mission_run {
			id: $run_id,
			mission_id: $mission_id,
			run_number: $run_number,
			status: 'running',
			created_at: datetime()
		})
		CREATE (r)-[:BELONGS_TO]->(m)
		RETURN r.id as run_id
	`

	params := map[string]any{
		graphrag.PropMissionID: missionID.String(),
		"run_id":               runID.String(),
		"run_number":           runNumber,
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphNodeCreateFailed,
			"failed to create mission run", err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeCreateFailed,
			"mission not found - cannot create mission_run without parent Mission")
	}

	return nil
}

// UpdateMissionRunStatus updates the status of a mission run.
// Valid statuses: running, completed, failed, cancelled.
// Terminal statuses (completed, failed, cancelled) also set completed_at.
func (mq *MissionQueries) UpdateMissionRunStatus(ctx context.Context, runID string, status string) error {
	if runID == "" {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "run ID cannot be empty")
	}

	validStatuses := map[string]bool{"running": true, "completed": true, "failed": true, "cancelled": true}
	if !validStatuses[status] {
		return types.NewError(graph.ErrCodeGraphInvalidQuery, "invalid status: "+status)
	}

	// Use lowercase :mission_run to match CreateMissionRun
	cypher := `
		MATCH (r:mission_run {id: $run_id})
		SET r.status = $status, r.updated_at = datetime()
	`

	// For terminal states, set completed_at
	if status == "completed" || status == "failed" || status == "cancelled" {
		cypher += `, r.completed_at = datetime()`
	}

	cypher += `
		RETURN r.id as run_id
	`

	params := map[string]any{
		"run_id": runID,
		"status": status,
	}

	result, err := mq.client.Query(ctx, cypher, params)
	if err != nil {
		return types.WrapError(graph.ErrCodeGraphQueryFailed,
			"failed to update mission run status", err)
	}

	if len(result.Records) == 0 {
		return types.NewError(graph.ErrCodeGraphNodeNotFound, "mission run not found")
	}

	return nil
}

func recordToAgentExecution(data any) (*schema.AgentExecution, error) {
	e, ok := data.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("invalid agent execution data type: %T", data)
	}

	execIDStr, _ := e["id"].(string)
	id, err := types.ParseID(execIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid execution ID: %w", err)
	}

	execMissionIDStr, _ := e["mission_id"].(string)
	missionID, err := types.ParseID(execMissionIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	attempt, _ := toInt64(e["attempt"])
	exec := &schema.AgentExecution{
		ID:            id,
		MissionNodeID: mapStr(e, "mission_node_id"),
		MissionID:     missionID,
		Status:        schema.ExecutionStatus(mapStr(e, "status")),
		Attempt:       int(attempt),
		Error:         "",
		ConfigUsed:    make(map[string]any),
		Result:        make(map[string]any),
	}

	if startedAt, ok := e["started_at"].(time.Time); ok {
		exec.StartedAt = startedAt
	}
	if completedAt, ok := e["completed_at"].(time.Time); ok {
		exec.CompletedAt = &completedAt
	}
	if errorMsg, ok := e["error"].(string); ok {
		exec.Error = errorMsg
	}
	if createdAt, ok := e["created_at"].(time.Time); ok {
		exec.CreatedAt = createdAt
	}
	if updatedAt, ok := e["updated_at"].(time.Time); ok {
		exec.UpdatedAt = updatedAt
	}

	// Parse JSON fields
	if configStr, ok := e["config_used"].(string); ok && configStr != "" && configStr != "{}" {
		if err := json.Unmarshal([]byte(configStr), &exec.ConfigUsed); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config_used: %w", err)
		}
	}

	if resultStr, ok := e["result"].(string); ok && resultStr != "" && resultStr != "{}" {
		if err := json.Unmarshal([]byte(resultStr), &exec.Result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return exec, nil
}
