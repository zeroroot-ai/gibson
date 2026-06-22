package mission

import (
	"context"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// GraphRAGRunStore wraps MissionRunStore with GraphRAG persistence.
// It stores runs in both Redis (for fast queries) and Neo4j (for graph relationships).
type GraphRAGRunStore struct {
	runStore MissionRunStore
	graphRAG graphrag.GraphRAGStore
}

// NewGraphRAGRunStore creates a new GraphRAGRunStore.
func NewGraphRAGRunStore(runStore MissionRunStore, graphRAG graphrag.GraphRAGStore) *GraphRAGRunStore {
	return &GraphRAGRunStore{
		runStore: runStore,
		graphRAG: graphRAG,
	}
}

// Save persists a new mission run to both Redis and GraphRAG.
func (s *GraphRAGRunStore) Save(ctx context.Context, run *MissionRun) error {
	// Save to Redis first for atomicity
	if err := s.runStore.Save(ctx, run); err != nil {
		return fmt.Errorf("failed to save run to Redis: %w", err)
	}

	// Store in GraphRAG
	if err := s.storeRunNode(ctx, run, nil); err != nil {
		// Log error but don't fail - GraphRAG is supplementary
		// The run is still persisted in Redis
		return fmt.Errorf("failed to store run in GraphRAG (run saved to Redis): %w", err)
	}

	return nil
}

// Get retrieves a mission run by ID.
func (s *GraphRAGRunStore) Get(ctx context.Context, id types.ID) (*MissionRun, error) {
	return s.runStore.Get(ctx, id)
}

// GetByMissionAndNumber retrieves a run by mission ID and run number.
func (s *GraphRAGRunStore) GetByMissionAndNumber(ctx context.Context, missionID types.ID, runNumber int) (*MissionRun, error) {
	return s.runStore.GetByMissionAndNumber(ctx, missionID, runNumber)
}

// ListByMission retrieves all runs for a mission, ordered by run number descending.
func (s *GraphRAGRunStore) ListByMission(ctx context.Context, missionID types.ID) ([]*MissionRun, error) {
	return s.runStore.ListByMission(ctx, missionID)
}

// GetLatestByMission retrieves the most recent run for a mission.
func (s *GraphRAGRunStore) GetLatestByMission(ctx context.Context, missionID types.ID) (*MissionRun, error) {
	return s.runStore.GetLatestByMission(ctx, missionID)
}

// GetNextRunNumber returns the next run number for a mission.
func (s *GraphRAGRunStore) GetNextRunNumber(ctx context.Context, missionID types.ID) (int, error) {
	return s.runStore.GetNextRunNumber(ctx, missionID)
}

// Update modifies an existing mission run.
func (s *GraphRAGRunStore) Update(ctx context.Context, run *MissionRun) error {
	// Update Redis first
	if err := s.runStore.Update(ctx, run); err != nil {
		return fmt.Errorf("failed to update run in Redis: %w", err)
	}

	// Update GraphRAG (best effort)
	if err := s.updateRunNode(ctx, run); err != nil {
		// Log error but don't fail
		return fmt.Errorf("failed to update run in GraphRAG (run updated in Redis): %w", err)
	}

	return nil
}

// UpdateStatus updates only the status field.
func (s *GraphRAGRunStore) UpdateStatus(ctx context.Context, id types.ID, status MissionRunStatus) error {
	return s.runStore.UpdateStatus(ctx, id, status)
}

// UpdateProgress updates only the progress field.
func (s *GraphRAGRunStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	return s.runStore.UpdateProgress(ctx, id, progress)
}

// GetActive retrieves all active runs (running or paused).
func (s *GraphRAGRunStore) GetActive(ctx context.Context) ([]*MissionRun, error) {
	return s.runStore.GetActive(ctx)
}

// Delete removes a mission run (only terminal states).
func (s *GraphRAGRunStore) Delete(ctx context.Context, id types.ID) error {
	return s.runStore.Delete(ctx, id)
}

// CountByMission returns the number of runs for a mission.
func (s *GraphRAGRunStore) CountByMission(ctx context.Context, missionID types.ID) (int, error) {
	return s.runStore.CountByMission(ctx, missionID)
}

// storeRunNode stores a mission run as a node in GraphRAG with relationships.
func (s *GraphRAGRunStore) storeRunNode(ctx context.Context, run *MissionRun, previousRunID *types.ID) error {
	// Create MissionRun node
	node := graphrag.NewGraphNode(run.ID, graphrag.NodeType("MissionRun"))
	node.WithProperties(map[string]any{
		"mission_id":     run.MissionID.String(),
		"run_number":     run.RunNumber,
		"status":         string(run.Status),
		"progress":       run.Progress,
		"findings_count": run.FindingsCount,
		"error":          run.Error,
	})

	// Add timestamps
	node.Properties["created_at"] = run.CreatedAt.Format(time.RFC3339)
	node.Properties["updated_at"] = run.UpdatedAt.Format(time.RFC3339)
	if run.StartedAt != nil {
		node.Properties["started_at"] = run.StartedAt.Format(time.RFC3339)
	}
	if run.CompletedAt != nil {
		node.Properties["completed_at"] = run.CompletedAt.Format(time.RFC3339)
	}

	// Calculate duration if completed
	if run.StartedAt != nil && run.CompletedAt != nil {
		duration := run.CompletedAt.Sub(*run.StartedAt)
		node.Properties["duration_seconds"] = duration.Seconds()
	}

	// Create graph record with relationships
	record := graphrag.NewGraphRecord(*node)

	// Add EXECUTION_OF relationship to Mission
	executionRel := graphrag.Relationship{
		FromID:     run.ID,
		ToID:       run.MissionID,
		Type:       graphrag.RelationType("EXECUTION_OF"),
		Properties: map[string]any{},
	}
	record.WithRelationship(executionRel)

	// Add FOLLOWS relationship to previous run if exists
	if previousRunID != nil {
		followsRel := graphrag.Relationship{
			FromID: run.ID,
			ToID:   *previousRunID,
			Type:   graphrag.RelationType("FOLLOWS"),
			Properties: map[string]any{
				"run_number_diff": 1, // Sequential runs
			},
		}
		record.WithRelationship(followsRel)
	}

	// Store without embedding (MissionRun is structured data, not semantic content)
	if err := s.graphRAG.StoreWithoutEmbedding(ctx, record); err != nil {
		return fmt.Errorf("failed to store run node: %w", err)
	}

	return nil
}

// updateRunNode updates an existing mission run node in GraphRAG.
func (s *GraphRAGRunStore) updateRunNode(ctx context.Context, run *MissionRun) error {
	// Create updated node
	node := graphrag.NewGraphNode(run.ID, graphrag.NodeType("MissionRun"))
	node.WithProperties(map[string]any{
		"mission_id":     run.MissionID.String(),
		"run_number":     run.RunNumber,
		"status":         string(run.Status),
		"progress":       run.Progress,
		"findings_count": run.FindingsCount,
		"error":          run.Error,
		"updated_at":     run.UpdatedAt.Format(time.RFC3339),
	})

	if run.StartedAt != nil {
		node.Properties["started_at"] = run.StartedAt.Format(time.RFC3339)
	}
	if run.CompletedAt != nil {
		node.Properties["completed_at"] = run.CompletedAt.Format(time.RFC3339)
	}

	// Calculate duration if completed
	if run.StartedAt != nil && run.CompletedAt != nil {
		duration := run.CompletedAt.Sub(*run.StartedAt)
		node.Properties["duration_seconds"] = duration.Seconds()
	}

	// Store updated node (this will upsert)
	record := graphrag.NewGraphRecord(*node)
	if err := s.graphRAG.StoreWithoutEmbedding(ctx, record); err != nil {
		return fmt.Errorf("failed to update run node: %w", err)
	}

	return nil
}

// CreateRunWithGraphRAG creates a new run with GraphRAG integration.
// This is a convenience method that handles previous run lookup and GraphRAG storage.
func (s *GraphRAGRunStore) CreateRunWithGraphRAG(ctx context.Context, missionID types.ID) (*MissionRun, error) {
	// Get next run number
	runNumber, err := s.GetNextRunNumber(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get next run number: %w", err)
	}

	// Get previous run to link
	var previousRunID *types.ID
	if runNumber > 1 {
		prevRun, err := s.GetLatestByMission(ctx, missionID)
		if err == nil && prevRun != nil {
			previousRunID = &prevRun.ID
		}
		// Ignore error - no previous run is acceptable
	}

	// Create new run
	run := NewMissionRun(missionID, runNumber)

	// Save with GraphRAG relationships
	if err := s.runStore.Save(ctx, run); err != nil {
		return nil, fmt.Errorf("failed to save run to Redis: %w", err)
	}

	// Store in GraphRAG with relationships
	if err := s.storeRunNode(ctx, run, previousRunID); err != nil {
		// Log error but return the run - it's saved in Redis
		return run, fmt.Errorf("failed to store run in GraphRAG (run saved to Redis): %w", err)
	}

	return run, nil
}

// StoreFindingWithRun stores a finding with a DISCOVERED_IN relationship to a run.
// This extends the GraphRAG finding storage to include run tracking.
func (s *GraphRAGRunStore) StoreFindingWithRun(ctx context.Context, findingID, runID types.ID) error {
	// Create DISCOVERED_IN relationship
	rel := graphrag.Relationship{
		FromID: findingID,
		ToID:   runID,
		Type:   graphrag.RelationType("DISCOVERED_IN"),
		Properties: map[string]any{
			"discovered_at": time.Now().Format(time.RFC3339),
		},
	}

	// Store relationship only (finding node should already exist)
	if err := s.graphRAG.StoreRelationshipOnly(ctx, rel); err != nil {
		return fmt.Errorf("failed to create DISCOVERED_IN relationship: %w", err)
	}

	return nil
}

// Ensure GraphRAGRunStore implements MissionRunStore at compile time.
var _ MissionRunStore = (*GraphRAGRunStore)(nil)
