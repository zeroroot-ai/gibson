package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/graphrag/graph"
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

// Checkpoint represents a saved mission state that can be restored later.
// Checkpoints capture the status and configuration of all mission nodes at a point in time.
type Checkpoint struct {
	// ID is the unique identifier for this checkpoint
	ID string `json:"id"`

	// MissionID is the ID of the parent mission
	MissionID string `json:"mission_id"`

	// Label is a human-readable description (user-provided or auto-generated)
	Label string `json:"label"`

	// CreatedAt is when the checkpoint was created
	CreatedAt time.Time `json:"created_at"`

	// NodeStates contains the state of each mission node at checkpoint time
	NodeStates map[string]NodeCheckpointState `json:"node_states"`

	// IsImplicit indicates if this was auto-created (true) or explicitly requested (false)
	IsImplicit bool `json:"is_implicit"`
}

// NodeCheckpointState captures the state of a single mission node at checkpoint time.
type NodeCheckpointState struct {
	// NodeID is the mission node identifier
	NodeID string `json:"node_id"`

	// Status is the node status at checkpoint time
	Status string `json:"status"`

	// TaskConfig is the node's task configuration
	TaskConfig map[string]interface{} `json:"task_config"`

	// Attempt is the current retry attempt number
	Attempt int `json:"attempt"`
}

// CheckpointManager defines the interface for managing mission checkpoints.
// Checkpoints enable rollback to previous states for error recovery and experimentation.
type CheckpointManager interface {
	// CreateCheckpoint captures the current mission state and returns the checkpoint ID.
	// The label can be user-provided or empty (auto-generated).
	CreateCheckpoint(ctx context.Context, missionID string, label string) (string, error)

	// RestoreCheckpoint reverts the mission to a previously captured state.
	// This resets node statuses and marks rolled-back executions as "rolled_back".
	RestoreCheckpoint(ctx context.Context, checkpointID string) error

	// GetCheckpoints retrieves all checkpoints for a mission, ordered by creation time.
	GetCheckpoints(ctx context.Context, missionID string) ([]Checkpoint, error)

	// CreateImplicitCheckpoint creates an automatic checkpoint before node execution.
	// This is called internally by the orchestrator to enable granular rollback.
	CreateImplicitCheckpoint(ctx context.Context, missionID, nodeID string) error
}

// Neo4jCheckpointManager implements CheckpointManager using Neo4j for storage.
type Neo4jCheckpointManager struct {
	client   graph.GraphClient
	eventBus EventBus
	logger   *slog.Logger
}

// NewNeo4jCheckpointManager creates a new Neo4jCheckpointManager.
// The client must be connected before using any methods.
// EventBus is optional - if nil, no events will be emitted.
func NewNeo4jCheckpointManager(client graph.GraphClient, eventBus EventBus) *Neo4jCheckpointManager {
	return &Neo4jCheckpointManager{
		client:   client,
		eventBus: eventBus,
		logger:   slog.Default(),
	}
}

// WithLogger sets the logger for checkpoint operations.
func (cm *Neo4jCheckpointManager) WithLogger(logger *slog.Logger) *Neo4jCheckpointManager {
	if logger != nil {
		cm.logger = logger
	}
	return cm
}

// CreateCheckpoint captures all MissionNode states as JSON.
func (cm *Neo4jCheckpointManager) CreateCheckpoint(ctx context.Context, missionID string, label string) (string, error) {
	// Validate mission ID
	mid, err := types.ParseID(missionID)
	if err != nil {
		return "", fmt.Errorf("invalid mission ID: %w", err)
	}

	// Generate auto label if not provided
	if label == "" {
		label = fmt.Sprintf("checkpoint_%s", time.Now().Format("20060102_150405"))
	}

	// Generate checkpoint ID
	checkpointID := types.NewID().String()
	now := time.Now()

	// Query all mission nodes for the mission
	cypher := `
		MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		RETURN n.id as node_id,
		       n.status as status,
		       n.task_config_json as task_config_json,
		       n.name as name
		ORDER BY n.created_at
	`

	params := map[string]any{
		"mission_id": mid.String(),
	}

	result, err := cm.client.Query(ctx, cypher, params)
	if err != nil {
		return "", fmt.Errorf("failed to query mission nodes: %w", err)
	}

	// Build node states map
	nodeStates := make(map[string]NodeCheckpointState)
	for _, record := range result.Records {
		nodeID, ok := record["node_id"].(string)
		if !ok {
			continue
		}

		status, _ := record["status"].(string)
		taskConfigJSON, _ := record["task_config_json"].(string)

		// Parse task config
		var taskConfig map[string]interface{}
		if taskConfigJSON != "" && taskConfigJSON != "{}" {
			if err := json.Unmarshal([]byte(taskConfigJSON), &taskConfig); err != nil {
				cm.logger.Warn("failed to parse task config for node",
					"node_id", nodeID,
					"error", err)
				taskConfig = make(map[string]interface{})
			}
		} else {
			taskConfig = make(map[string]interface{})
		}

		// Get attempt count from executions
		attempt := 1
		execCypher := `
			MATCH (e:AgentExecution)-[:EXECUTES]->(n:MissionNode {id: $node_id})
			RETURN e.attempt as attempt
			ORDER BY e.started_at DESC
			LIMIT 1
		`
		execParams := map[string]any{"node_id": nodeID}
		execResult, err := cm.client.Query(ctx, execCypher, execParams)
		if err == nil && len(execResult.Records) > 0 {
			if attemptVal, ok := execResult.Records[0]["attempt"]; ok {
				if attemptInt, ok := toInt64(attemptVal); ok {
					attempt = int(attemptInt)
				}
			}
		}

		nodeStates[nodeID] = NodeCheckpointState{
			NodeID:     nodeID,
			Status:     status,
			TaskConfig: taskConfig,
			Attempt:    attempt,
		}
	}

	// Serialize node states to JSON
	nodeStatesJSON, err := json.Marshal(nodeStates)
	if err != nil {
		return "", fmt.Errorf("failed to serialize node states: %w", err)
	}

	// Create checkpoint node in Neo4j
	createCypher := `
		CREATE (c:Checkpoint {
			id: $id,
			mission_id: $mission_id,
			label: $label,
			created_at: datetime($created_at),
			is_implicit: false,
			node_states_json: $node_states_json
		})
		WITH c
		MATCH (m:Mission {id: $mission_id})
		CREATE (c)-[:CHECKPOINT_OF]->(m)
		RETURN c.id as id
	`

	createParams := map[string]any{
		"id":               checkpointID,
		"mission_id":       mid.String(),
		"label":            label,
		"created_at":       now.UTC().Format(time.RFC3339Nano),
		"node_states_json": string(nodeStatesJSON),
	}

	createResult, err := cm.client.Query(ctx, createCypher, createParams)
	if err != nil {
		return "", fmt.Errorf("failed to create checkpoint node: %w", err)
	}

	if len(createResult.Records) == 0 {
		return "", fmt.Errorf("mission %s not found", missionID)
	}

	cm.logger.Info("checkpoint created",
		"checkpoint_id", checkpointID,
		"mission_id", missionID,
		"label", label,
		"node_count", len(nodeStates))

	// Emit checkpoint created event
	if cm.eventBus != nil {
		cm.eventBus.Publish(events.Event{
			Type:      events.EventCheckpointCreated,
			Timestamp: now,
			MissionID: mid,
			Payload: map[string]any{
				"checkpoint_id": checkpointID,
				"label":         label,
				"node_count":    len(nodeStates),
				"is_implicit":   false,
			},
		})
	}

	return checkpointID, nil
}

// RestoreCheckpoint updates node statuses and resets dependent nodes to PENDING.
// Rolled-back executions are marked as "rolled_back" to preserve history.
func (cm *Neo4jCheckpointManager) RestoreCheckpoint(ctx context.Context, checkpointID string) error {
	// Validate checkpoint ID
	if checkpointID == "" {
		return fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Retrieve checkpoint
	cypher := `
		MATCH (c:Checkpoint {id: $checkpoint_id})
		RETURN c.mission_id as mission_id,
		       c.label as label,
		       c.node_states_json as node_states_json
	`

	params := map[string]any{
		"checkpoint_id": checkpointID,
	}

	result, err := cm.client.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to query checkpoint: %w", err)
	}

	if len(result.Records) == 0 {
		return fmt.Errorf("checkpoint %s not found", checkpointID)
	}

	record := result.Records[0]
	missionID, _ := record["mission_id"].(string)
	label, _ := record["label"].(string)
	nodeStatesJSON, _ := record["node_states_json"].(string)

	// Parse node states
	var nodeStates map[string]NodeCheckpointState
	if err := json.Unmarshal([]byte(nodeStatesJSON), &nodeStates); err != nil {
		return fmt.Errorf("failed to parse node states: %w", err)
	}

	cm.logger.Info("restoring checkpoint",
		"checkpoint_id", checkpointID,
		"mission_id", missionID,
		"label", label,
		"node_count", len(nodeStates))

	// Execute restoration in a transaction for atomicity
	// We'll use multiple queries but ensure they all succeed or fail together
	// Note: Neo4j Go driver doesn't expose explicit transaction API in our interface,
	// so we'll do best-effort sequential updates with error handling

	// 1. Mark all executions after checkpoint as rolled_back
	markExecutionsCypher := `
		MATCH (e:AgentExecution)-[:EXECUTES]->(n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		WHERE e.status IN ['running', 'completed', 'failed']
		SET e.rolled_back = true,
		    e.updated_at = datetime($updated_at)
		RETURN count(e) as rolled_back_count
	`

	markParams := map[string]any{
		"mission_id": missionID,
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
	}

	markResult, err := cm.client.Query(ctx, markExecutionsCypher, markParams)
	if err != nil {
		return fmt.Errorf("failed to mark executions as rolled back: %w", err)
	}

	rolledBackCount := int64(0)
	if len(markResult.Records) > 0 {
		if count, ok := toInt64(markResult.Records[0]["rolled_back_count"]); ok {
			rolledBackCount = count
		}
	}

	// 2. Restore node statuses from checkpoint
	for nodeID, state := range nodeStates {
		// Update node status and task config
		updateNodeCypher := `
			MATCH (n:MissionNode {id: $node_id})
			SET n.status = $status,
			    n.task_config_json = $task_config_json,
			    n.updated_at = datetime($updated_at)
			RETURN n.id as id
		`

		taskConfigJSON, err := json.Marshal(state.TaskConfig)
		if err != nil {
			cm.logger.Warn("failed to serialize task config for node",
				"node_id", nodeID,
				"error", err)
			taskConfigJSON = []byte("{}")
		}

		updateNodeParams := map[string]any{
			"node_id":          nodeID,
			"status":           state.Status,
			"task_config_json": string(taskConfigJSON),
			"updated_at":       time.Now().UTC().Format(time.RFC3339Nano),
		}

		updateResult, err := cm.client.Query(ctx, updateNodeCypher, updateNodeParams)
		if err != nil {
			cm.logger.Error("failed to update node during restore",
				"node_id", nodeID,
				"error", err)
			continue
		}

		if len(updateResult.Records) == 0 {
			cm.logger.Warn("node not found during restore",
				"node_id", nodeID)
		}
	}

	// 3. Reset dependent nodes to PENDING if their dependencies changed
	// Find all nodes that were completed/failed and reset them if dependencies are no longer complete
	resetDependentsCypher := `
		MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		WHERE n.status IN ['completed', 'failed', 'running']
		AND EXISTS {
			MATCH (n)-[:DEPENDS_ON]->(dep:MissionNode)
			WHERE dep.status <> 'completed'
		}
		SET n.status = 'pending',
		    n.updated_at = datetime($updated_at)
		RETURN count(n) as reset_count
	`

	resetParams := map[string]any{
		"mission_id": missionID,
		"updated_at": time.Now().UTC().Format(time.RFC3339Nano),
	}

	resetResult, err := cm.client.Query(ctx, resetDependentsCypher, resetParams)
	if err != nil {
		cm.logger.Error("failed to reset dependent nodes",
			"error", err)
	}

	resetCount := int64(0)
	if len(resetResult.Records) > 0 {
		if count, ok := toInt64(resetResult.Records[0]["reset_count"]); ok {
			resetCount = count
		}
	}

	cm.logger.Info("checkpoint restored",
		"checkpoint_id", checkpointID,
		"mission_id", missionID,
		"nodes_restored", len(nodeStates),
		"executions_rolled_back", rolledBackCount,
		"dependent_nodes_reset", resetCount)

	// Emit rollback completed event
	if cm.eventBus != nil {
		mid, _ := types.ParseID(missionID)
		cm.eventBus.Publish(events.Event{
			Type:      events.EventRollbackCompleted,
			Timestamp: time.Now(),
			MissionID: mid,
			Payload: map[string]any{
				"checkpoint_id":          checkpointID,
				"label":                  label,
				"nodes_restored":         len(nodeStates),
				"executions_rolled_back": rolledBackCount,
				"dependent_nodes_reset":  resetCount,
			},
		})
	}

	return nil
}

// GetCheckpoints lists available checkpoints for a mission.
func (cm *Neo4jCheckpointManager) GetCheckpoints(ctx context.Context, missionID string) ([]Checkpoint, error) {
	// Validate mission ID
	mid, err := types.ParseID(missionID)
	if err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	cypher := `
		MATCH (c:Checkpoint)-[:CHECKPOINT_OF]->(m:Mission {id: $mission_id})
		RETURN c.id as id,
		       c.mission_id as mission_id,
		       c.label as label,
		       c.created_at as created_at,
		       c.is_implicit as is_implicit,
		       c.node_states_json as node_states_json
		ORDER BY c.created_at DESC
	`

	params := map[string]any{
		"mission_id": mid.String(),
	}

	result, err := cm.client.Query(ctx, cypher, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query checkpoints: %w", err)
	}

	checkpoints := make([]Checkpoint, 0, len(result.Records))
	for _, record := range result.Records {
		id, _ := record["id"].(string)
		missionID, _ := record["mission_id"].(string)
		label, _ := record["label"].(string)
		isImplicit, _ := record["is_implicit"].(bool)
		nodeStatesJSON, _ := record["node_states_json"].(string)

		// Parse created_at
		createdAt := time.Now()
		if createdAtStr, ok := record["created_at"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, createdAtStr); err == nil {
				createdAt = t
			}
		} else if createdAtTime, ok := record["created_at"].(time.Time); ok {
			createdAt = createdAtTime
		}

		// Parse node states
		var nodeStates map[string]NodeCheckpointState
		if err := json.Unmarshal([]byte(nodeStatesJSON), &nodeStates); err != nil {
			cm.logger.Warn("failed to parse node states for checkpoint",
				"checkpoint_id", id,
				"error", err)
			nodeStates = make(map[string]NodeCheckpointState)
		}

		checkpoints = append(checkpoints, Checkpoint{
			ID:         id,
			MissionID:  missionID,
			Label:      label,
			CreatedAt:  createdAt,
			NodeStates: nodeStates,
			IsImplicit: isImplicit,
		})
	}

	return checkpoints, nil
}

// CreateImplicitCheckpoint creates an automatic checkpoint before node execution.
func (cm *Neo4jCheckpointManager) CreateImplicitCheckpoint(ctx context.Context, missionID, nodeID string) error {
	// Validate IDs
	mid, err := types.ParseID(missionID)
	if err != nil {
		return fmt.Errorf("invalid mission ID: %w", err)
	}

	nid, err := types.ParseID(nodeID)
	if err != nil {
		return fmt.Errorf("invalid node ID: %w", err)
	}

	// Generate checkpoint ID and label
	checkpointID := types.NewID().String()
	label := fmt.Sprintf("before_node_%s", nodeID[:8])
	now := time.Now()

	// Query all mission nodes for the mission
	cypher := `
		MATCH (n:MissionNode)-[:PART_OF]->(m:Mission {id: $mission_id})
		RETURN n.id as node_id,
		       n.status as status,
		       n.task_config_json as task_config_json
		ORDER BY n.created_at
	`

	params := map[string]any{
		"mission_id": mid.String(),
	}

	result, err := cm.client.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to query mission nodes: %w", err)
	}

	// Build node states map (same as CreateCheckpoint)
	nodeStates := make(map[string]NodeCheckpointState)
	for _, record := range result.Records {
		nodeID, ok := record["node_id"].(string)
		if !ok {
			continue
		}

		status, _ := record["status"].(string)
		taskConfigJSON, _ := record["task_config_json"].(string)

		var taskConfig map[string]interface{}
		if taskConfigJSON != "" && taskConfigJSON != "{}" {
			if err := json.Unmarshal([]byte(taskConfigJSON), &taskConfig); err != nil {
				taskConfig = make(map[string]interface{})
			}
		} else {
			taskConfig = make(map[string]interface{})
		}

		// Get attempt count
		attempt := 1
		execCypher := `
			MATCH (e:AgentExecution)-[:EXECUTES]->(n:MissionNode {id: $node_id})
			RETURN e.attempt as attempt
			ORDER BY e.started_at DESC
			LIMIT 1
		`
		execParams := map[string]any{"node_id": nodeID}
		execResult, err := cm.client.Query(ctx, execCypher, execParams)
		if err == nil && len(execResult.Records) > 0 {
			if attemptVal, ok := execResult.Records[0]["attempt"]; ok {
				if attemptInt, ok := toInt64(attemptVal); ok {
					attempt = int(attemptInt)
				}
			}
		}

		nodeStates[nodeID] = NodeCheckpointState{
			NodeID:     nodeID,
			Status:     status,
			TaskConfig: taskConfig,
			Attempt:    attempt,
		}
	}

	// Serialize node states
	nodeStatesJSON, err := json.Marshal(nodeStates)
	if err != nil {
		return fmt.Errorf("failed to serialize node states: %w", err)
	}

	// Create implicit checkpoint with BEFORE_NODE relationship
	createCypher := `
		CREATE (c:Checkpoint {
			id: $id,
			mission_id: $mission_id,
			label: $label,
			created_at: datetime($created_at),
			is_implicit: true,
			node_states_json: $node_states_json
		})
		WITH c
		MATCH (m:Mission {id: $mission_id})
		CREATE (c)-[:CHECKPOINT_OF]->(m)
		WITH c
		MATCH (n:MissionNode {id: $node_id})
		CREATE (c)-[:BEFORE_NODE]->(n)
		RETURN c.id as id
	`

	createParams := map[string]any{
		"id":               checkpointID,
		"mission_id":       mid.String(),
		"node_id":          nid.String(),
		"label":            label,
		"created_at":       now.UTC().Format(time.RFC3339Nano),
		"node_states_json": string(nodeStatesJSON),
	}

	createResult, err := cm.client.Query(ctx, createCypher, createParams)
	if err != nil {
		return fmt.Errorf("failed to create implicit checkpoint: %w", err)
	}

	if len(createResult.Records) == 0 {
		return fmt.Errorf("mission or node not found")
	}

	cm.logger.Debug("implicit checkpoint created",
		"checkpoint_id", checkpointID,
		"mission_id", missionID,
		"node_id", nodeID,
		"node_count", len(nodeStates))

	// Emit checkpoint created event
	if cm.eventBus != nil {
		cm.eventBus.Publish(events.Event{
			Type:      events.EventCheckpointCreated,
			Timestamp: now,
			MissionID: mid,
			Payload: map[string]any{
				"checkpoint_id": checkpointID,
				"label":         label,
				"node_count":    len(nodeStates),
				"is_implicit":   true,
				"before_node":   nodeID,
			},
		})
	}

	return nil
}
