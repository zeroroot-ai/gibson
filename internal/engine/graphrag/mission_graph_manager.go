package graphrag

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/graph"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// MissionGraphManager handles Mission and MissionRun nodes in Neo4j.
// It manages the creation and lifecycle of mission-related graph nodes,
// ensuring proper relationships and provenance tracking for the GraphRAG system.
//
// Key responsibilities:
//   - Create or retrieve Mission nodes (deduplicated by name+target_id)
//   - Create new MissionRun nodes for each pipeline execution (always unique)
//   - Update MissionRun status throughout execution lifecycle
//   - Maintain BELONGS_TO relationships between MissionRun and Mission
type MissionGraphManager struct {
	graphClient graph.GraphClient
}

// NewMissionGraphManager creates a new MissionGraphManager with the given Neo4j client.
// The client must be connected before use; this function does not establish connections.
func NewMissionGraphManager(client graph.GraphClient) *MissionGraphManager {
	return &MissionGraphManager{
		graphClient: client,
	}
}

// EnsureMissionNode creates or retrieves a Mission node in Neo4j.
//
// Uses MERGE semantics because missions ARE intentionally deduplicated by name+target_id.
// Multiple runs of the same mission against the same target should share a Mission node,
// with each run creating a separate MissionRun node.
//
// Node structure:
//   - Label: :mission
//   - Properties: id (UUID), name, target_id, created_at (timestamp in ms)
//
// Returns the mission ID (existing or newly created).
func (m *MissionGraphManager) EnsureMissionNode(ctx context.Context, name, targetID string) (string, error) {
	if m.graphClient == nil {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "graph client is nil")
	}

	if name == "" {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "mission name cannot be empty")
	}

	if targetID == "" {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "target ID cannot be empty")
	}

	// Generate new ID for potential creation
	// MERGE will use this only if creating a new node
	newID := types.NewID()

	cypher := `
		MERGE (m:mission {name: $name, target_id: $target_id})
		ON CREATE SET m.id = $id, m.created_at = timestamp()
		RETURN m.id as mission_id
	`

	params := map[string]any{
		"name":      name,
		"target_id": targetID,
		"id":        newID.String(),
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return "", fmt.Errorf("failed to ensure mission node: %w", err)
	}

	if len(result.Records) == 0 {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "query returned no records")
	}

	missionID, ok := result.Records[0]["mission_id"].(string)
	if !ok {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "mission_id has invalid type")
	}

	return missionID, nil
}

// CreateMissionRunNode creates a new MissionRun node in Neo4j.
//
// Always uses CREATE (never MERGE) because each pipeline execution must be a unique node
// in the graph, even if running the same mission multiple times. This preserves full
// historical tracking and prevents data collisions across runs.
//
// Node structure:
//   - Label: :mission_run
//   - Properties: id (UUID), mission_id, run_number, created_at (timestamp in ms), status
//   - Relationships: Creates (mission_run)-[:BELONGS_TO]->(mission)
//
// Returns the mission run ID.
func (m *MissionGraphManager) CreateMissionRunNode(ctx context.Context, missionID string, runNumber int) (string, error) {
	if m.graphClient == nil {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "graph client is nil")
	}

	if missionID == "" {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "mission ID cannot be empty")
	}

	if runNumber < 0 {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "run number cannot be negative")
	}

	// Generate unique ID for this mission run
	runID := types.NewID()

	cypher := `
		MATCH (m:mission {id: $mission_id})
		CREATE (r:mission_run {
			id: $run_id,
			mission_id: $mission_id,
			run_number: $run_number,
			created_at: timestamp(),
			status: 'running'
		})
		CREATE (r)-[:BELONGS_TO]->(m)
		RETURN r.id as run_id
	`

	params := map[string]any{
		"mission_id": missionID,
		"run_id":     runID.String(),
		"run_number": runNumber,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return "", fmt.Errorf("failed to create mission run node: %w", err)
	}

	if len(result.Records) == 0 {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "query returned no records - mission may not exist")
	}

	returnedRunID, ok := result.Records[0]["run_id"].(string)
	if !ok {
		return "", types.NewError("GRAPHRAG_MISSION_MANAGER", "run_id has invalid type")
	}

	return returnedRunID, nil
}

// UpdateMissionRunStatus updates the status of a mission run node.
//
// Valid status values:
//   - "running" - Mission run is actively executing
//   - "completed" - Mission run finished successfully
//   - "failed" - Mission run encountered errors
//   - "cancelled" - Mission run was cancelled by user
//
// When status is set to "completed", "failed", or "cancelled", the completed_at timestamp
// is automatically set to the current time.
func (m *MissionGraphManager) UpdateMissionRunStatus(ctx context.Context, runID string, status string) error {
	if m.graphClient == nil {
		return types.NewError("GRAPHRAG_MISSION_MANAGER", "graph client is nil")
	}

	if runID == "" {
		return types.NewError("GRAPHRAG_MISSION_MANAGER", "run ID cannot be empty")
	}

	if status == "" {
		return types.NewError("GRAPHRAG_MISSION_MANAGER", "status cannot be empty")
	}

	// Build cypher based on status
	// For terminal states, set completed_at timestamp
	cypher := `
		MATCH (r:mission_run {id: $run_id})
		SET r.status = $status
	`

	if status == "completed" || status == "failed" || status == "cancelled" {
		cypher += `, r.completed_at = timestamp()`
	}

	cypher += `
		RETURN r.id as run_id
	`

	params := map[string]any{
		"run_id": runID,
		"status": status,
	}

	result, err := m.graphClient.Query(ctx, cypher, params)
	if err != nil {
		return fmt.Errorf("failed to update mission run status: %w", err)
	}

	if len(result.Records) == 0 {
		return types.NewError("GRAPHRAG_MISSION_MANAGER", "mission run not found")
	}

	return nil
}
