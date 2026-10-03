// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package queries provides specialized Cypher query functions for mission execution tracking.
package queries

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

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
			n.target_id = $target_id,
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
		"target_id":    node.TargetID,
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

// Helper functions to convert Neo4j records to schema types

// CreateMissionRun creates a new :MissionRun node and links it to its Mission.
// Each call creates a NEW node - run numbers must be unique per mission.
// Returns the generated mission run ID.
//
// The label was the lowercase :mission_run, chosen to match a GraphLoader that
// attached discovered nodes to a run via BELONGS_TO. That package was deleted in
// gibson#1266, and the comment here then justified the case with "existing
// graphs use it" — an estate that no longer exists.
//
// A lowercase label can never carry a Taxonomy uniqueness constraint: Neo4j
// labels are case sensitive and constraintStatements only emits the Taxonomy's
// PascalCase labels, so `:mission_run` was outside the schema by construction.
// It is :MissionRun now, promoted into the Taxonomy at v4 (gibson#550).
//
// Parameters:
//   - ctx: Context for cancellation
//   - missionID: The stable SQLite mission ID (used to match Mission node)
//   - runID: The SQLite mission_run ID (stored on the MissionRun node)
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

	// Match Mission by ID (stable SQLite ID)
	cypher := `
		MATCH (m:Mission {id: $mission_id})
		CREATE (r:MissionRun {
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
			"mission not found - cannot create MissionRun without parent Mission")
	}

	return nil
}
