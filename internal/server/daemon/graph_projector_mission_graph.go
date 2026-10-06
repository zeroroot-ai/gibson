// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — graph_projector_mission_graph.go
//
// The writes of the per-run mission graph: one :MissionRun for each run, one
// :MissionNode for each projected work node, and the DEPENDS_ON edges between
// them. The per-run graph bootstrap (graph_bootstrap.go) decides what to write.
// The graph projector writes it, because the projector is the one writer of
// the knowledge graph (ADR-0112, gibson#673). Before this file, the bootstrap
// wrote through GraphClient.Query, which picked a write transaction from the
// statement text.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
	"github.com/zeroroot-ai/sdk/auth"
)

// MissionRunProjection is the :MissionRun node shape: one execution of a
// mission.
type MissionRunProjection struct {
	// ID is the run id. It is the node identity.
	ID string
	// MissionID is the mission of the run. The Mission node is MATCHed, never
	// merged here (UpsertMission is its writer).
	MissionID string
	// RunNumber is the sequential number of the run, from 1.
	RunNumber int
}

// errMissionNotInGraph reports that a mission-graph write found no :Mission
// node to attach to. The bootstrap writes the Mission node first, so this is
// an ordering defect, never a normal outcome.
var errMissionNotInGraph = errors.New("graph projector: the :Mission node does not exist")

// errMissionNodeNotInGraph reports that a DEPENDS_ON write found one of its two
// :MissionNode endpoints missing.
var errMissionNodeNotInGraph = errors.New("graph projector: a :MissionNode endpoint does not exist")

// upsertMissionRunCypher MERGEs a :MissionRun keyed by its run id and links it
// to its Mission. The run id is unique for each run, so a second write of the
// same run converges on the same node.
const upsertMissionRunCypher = `
MATCH (m:Mission {id: $mission_id})
MERGE (r:MissionRun {id: $run_id})
  ON CREATE SET r.status = 'running', r.created_at = datetime()
  SET r.mission_id = $mission_id, r.run_number = $run_number
MERGE (r)-[:BELONGS_TO]->(m)
RETURN r.id AS id`

// upsertMissionNodeCypher MERGEs a :MissionNode keyed by its derived id and
// links it to its Mission with PART_OF.
const upsertMissionNodeCypher = `
MATCH (m:Mission {id: $mission_id})
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
MERGE (n)-[:PART_OF]->(m)
RETURN n.id AS id`

// linkMissionNodesCypher MERGEs one DEPENDS_ON edge: from depends on to.
const linkMissionNodesCypher = `
MATCH (from:MissionNode {id: $from_id})
MATCH (to:MissionNode {id: $to_id})
MERGE (from)-[:DEPENDS_ON]->(to)
RETURN count(*) AS count`

// missionRunUpsertParams builds the parameter set for upsertMissionRunCypher.
func missionRunUpsertParams(r MissionRunProjection) map[string]any {
	return map[string]any{
		"run_id":     r.ID,
		"mission_id": r.MissionID,
		"run_number": r.RunNumber,
	}
}

// missionNodeUpsertParams builds the parameter set for upsertMissionNodeCypher.
// It validates the node and serializes its two JSON fields.
func missionNodeUpsertParams(node *schema.MissionNode) (map[string]any, error) {
	if node == nil {
		return nil, errors.New("graph projector: mission node is nil")
	}
	if err := node.Validate(); err != nil {
		return nil, fmt.Errorf("graph projector: invalid mission node: %w", err)
	}
	taskConfigJSON, err := node.TaskConfigJSON()
	if err != nil {
		return nil, fmt.Errorf("graph projector: marshal task config: %w", err)
	}
	retryPolicyJSON, err := node.RetryPolicyJSON()
	if err != nil {
		return nil, fmt.Errorf("graph projector: marshal retry policy: %w", err)
	}
	return map[string]any{
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
	}, nil
}

// UpsertMissionRun writes the :MissionRun of one run. It fails when the
// Mission node does not exist.
func (w *neo4jGraphWriter) UpsertMissionRun(ctx context.Context, tenant string, r MissionRunProjection) error {
	return w.execExpectingRow(ctx, tenant, upsertMissionRunCypher, missionRunUpsertParams(r),
		"mission_run", r.ID, errMissionNotInGraph)
}

// UpsertMissionNode writes one :MissionNode. It fails when the Mission node
// does not exist.
func (w *neo4jGraphWriter) UpsertMissionNode(ctx context.Context, tenant string, node *schema.MissionNode) error {
	params, err := missionNodeUpsertParams(node)
	if err != nil {
		return err
	}
	return w.execExpectingRow(ctx, tenant, upsertMissionNodeCypher, params,
		"mission_node", node.ID, errMissionNotInGraph)
}

// LinkMissionNodes writes one DEPENDS_ON edge from fromID to toID. It fails
// when one of the two nodes does not exist.
func (w *neo4jGraphWriter) LinkMissionNodes(ctx context.Context, tenant, fromID, toID string) error {
	return w.execExpectingRow(ctx, tenant, linkMissionNodesCypher,
		map[string]any{"from_id": fromID, "to_id": toID},
		"mission_node_dependency", fromID+"->"+toID, errMissionNodeNotInGraph)
}

// execExpectingRow runs one projection write that MATCHes an existing node
// and returns a row when it wrote. No row means the MATCH found nothing, and
// the write returns missing. A tenant with no Neo4j has nothing to project
// into, so the write is not an error, as in exec.
func (w *neo4jGraphWriter) execExpectingRow(
	ctx context.Context, tenant, cypher string, params map[string]any, kind string, id any, missing error,
) error {
	pool := w.poolGetter()
	if pool == nil {
		return errors.New("graph projector: pool not ready")
	}
	tid, err := auth.NewTenantID(tenant)
	if err != nil {
		return fmt.Errorf("graph projector: invalid tenant %q: %w", tenant, err)
	}
	conn, err := pool.For(ctx, tid)
	if err != nil {
		return fmt.Errorf("graph projector: pool.For(%s): %w", tenant, err)
	}
	defer conn.Release()
	if conn.Neo4j == nil {
		return nil
	}
	if err := w.ensureSchema(ctx, tenant, conn.Neo4j); err != nil {
		return err
	}
	wrote, err := conn.Neo4j.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, txErr := tx.Run(ctx, cypher, params)
		if txErr != nil {
			return nil, fmt.Errorf("run: %w", txErr)
		}
		hasRow := res.Next(ctx)
		if _, consumeErr := res.Consume(ctx); consumeErr != nil {
			return nil, fmt.Errorf("consume: %w", consumeErr)
		}
		return hasRow, nil
	})
	if err != nil {
		return fmt.Errorf("graph projector: upsert %s %v: %w", kind, id, err)
	}
	if ok, _ := wrote.(bool); !ok {
		return fmt.Errorf("graph projector: upsert %s %v: %w", kind, id, missing)
	}
	return nil
}
