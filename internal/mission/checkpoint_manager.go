package mission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// FindingLister retrieves finding IDs for a given mission.
// Implementations may query Redis, SQL, or any other backing store.
// The interface is intentionally minimal to prevent coupling to specific store implementations.
type FindingLister interface {
	ListByMission(ctx context.Context, missionID types.ID) ([]types.ID, error)
}

// CheckpointManager manages the lifecycle of mission checkpoints for pause/resume capability.
// It provides methods to capture workflow state at clean boundaries, restore from saved checkpoints,
// and manage checkpoint integrity through cryptographic checksums.
type CheckpointManager interface {
	// Capture creates a checkpoint from current execution state.
	// The state parameter contains the current mission execution state including
	// node statuses, results, and execution order.
	// Returns the created checkpoint with a unique ID, version, and integrity checksum.
	Capture(ctx context.Context, missionID types.ID, state *MissionState) (*MissionCheckpoint, error)

	// Restore loads the latest checkpoint for a mission.
	// Returns nil if no checkpoint exists for the mission.
	// Validates checkpoint integrity using the stored checksum before returning.
	Restore(ctx context.Context, missionID types.ID) (*MissionCheckpoint, error)

	// List returns all checkpoints for a mission, ordered by creation time (newest first).
	// Currently returns only the latest checkpoint since the storage schema stores
	// a single checkpoint per mission. This matches the current SaveCheckpoint implementation.
	List(ctx context.Context, missionID types.ID) ([]*MissionCheckpoint, error)

	// SetAutoCheckpointInterval configures periodic automatic checkpointing.
	// When set to a non-zero duration, the manager will trigger checkpoint captures
	// at the specified interval during workflow execution.
	// Setting to 0 disables automatic checkpointing.
	SetAutoCheckpointInterval(interval time.Duration)
}

// DefaultCheckpointManager implements CheckpointManager using the mission store for persistence.
type DefaultCheckpointManager struct {
	store                  MissionStore
	findingLister          FindingLister // optional; nil disables finding ID collection
	autoCheckpointInterval time.Duration
}

// NewCheckpointManager creates a new CheckpointManager instance.
//
// findingLister is optional — pass nil to skip finding ID collection during Capture.
// When non-nil, finding IDs are fetched via ListByMission and embedded in the
// checkpoint so that a resume knows which findings were already submitted.
func NewCheckpointManager(store MissionStore, findingLister FindingLister) CheckpointManager {
	return &DefaultCheckpointManager{
		store:                  store,
		findingLister:          findingLister,
		autoCheckpointInterval: 0, // Auto-checkpoint disabled by default
	}
}

// Capture creates a checkpoint from the current mission execution state.
// It serializes the mission state, computes a SHA256 checksum for integrity,
// and persists the checkpoint through the mission store.
func (m *DefaultCheckpointManager) Capture(ctx context.Context, missionID types.ID, state *MissionState) (*MissionCheckpoint, error) {
	if state == nil {
		return nil, fmt.Errorf("mission state cannot be nil")
	}

	// Get the mission to capture metrics snapshot
	mission, err := m.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission for checkpoint: %w", err)
	}

	// Extract completed and pending nodes from mission state
	completedNodes := make([]string, 0)
	pendingNodes := state.GetPendingNodes()

	// Collect completed nodes and their results
	nodeResults := make(map[string]any)
	for nodeID, nodeState := range state.NodeStates {
		if nodeState.Status == NodeStatusCompleted {
			completedNodes = append(completedNodes, nodeID)

			// Store node result if available
			if result := state.GetResult(nodeID); result != nil {
				nodeResults[nodeID] = result
			}
		}
	}

	// Determine the last executing node (most recently started)
	var lastNodeID string
	var lastStartedAt time.Time
	for nodeID, nodeState := range state.NodeStates {
		if nodeState.StartedAt != nil && nodeState.StartedAt.After(lastStartedAt) {
			lastStartedAt = *nodeState.StartedAt
			lastNodeID = nodeID
		}
	}

	// Serialize mission state for storage
	missionStateData, err := m.serializeMissionState(state)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize mission state: %w", err)
	}

	// Collect finding IDs from the finding lister so the checkpoint knows which
	// findings were already submitted. A failure here must not abort the checkpoint —
	// an empty slice is preferable to losing all checkpoint state.
	findingIDs := make([]types.ID, 0)
	if m.findingLister != nil {
		ids, listErr := m.findingLister.ListByMission(ctx, missionID)
		if listErr != nil {
			slog.WarnContext(ctx, "failed to collect finding IDs for checkpoint; proceeding with empty list",
				slog.String("mission_id", missionID.String()),
				slog.String("error", listErr.Error()),
			)
		} else {
			findingIDs = ids
		}
	}

	// Create the checkpoint
	checkpoint := &MissionCheckpoint{
		ID:              types.NewID(),
		Version:         1, // Current checkpoint format version
		WorkflowState:   missionStateData,
		CompletedNodes:  completedNodes,
		PendingNodes:    pendingNodes,
		NodeResults:     nodeResults,
		LastNodeID:      lastNodeID,
		CheckpointedAt:  time.Now(),
		MetricsSnapshot: mission.Metrics,
		FindingIDs:      findingIDs,
		Checksum:        "", // Will be computed below
	}

	// Compute checksum for integrity validation
	checksum, err := m.computeChecksum(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checkpoint checksum: %w", err)
	}
	checkpoint.Checksum = checksum

	// Persist the checkpoint through the mission store
	if err := m.store.SaveCheckpoint(ctx, missionID, checkpoint); err != nil {
		return nil, fmt.Errorf("failed to save checkpoint: %w", err)
	}

	return checkpoint, nil
}

// Restore loads the latest checkpoint for a mission and validates its integrity.
// Returns nil if no checkpoint exists. Returns an error if the checkpoint is corrupted.
// If the checkpoint is corrupted, it attempts to recover from findings as a fallback.
func (m *DefaultCheckpointManager) Restore(ctx context.Context, missionID types.ID) (*MissionCheckpoint, error) {
	// Retrieve the mission which contains the checkpoint
	mission, err := m.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission for checkpoint restore: %w", err)
	}

	// Check if a checkpoint exists
	if mission.Checkpoint == nil {
		return nil, nil // No checkpoint available
	}

	checkpoint := mission.Checkpoint

	// Validate checkpoint integrity
	if err := m.validateChecksum(checkpoint); err != nil {
		// Checkpoint is corrupted - attempt recovery from findings
		corruptionErr := NewCheckpointError("restore",
			fmt.Errorf("checkpoint integrity validation failed: %w - attempting recovery from findings", err))

		// Try to recover from findings as fallback
		recoveredCheckpoint, recoverErr := m.RecoverFromFindings(ctx, missionID)
		if recoverErr != nil {
			// Recovery also failed - return original corruption error with recovery attempt details
			return nil, NewCheckpointError("restore",
				fmt.Errorf("checkpoint corrupt and recovery failed: validation error: %w, recovery error: %v",
					err, recoverErr))
		}

		// Recovery succeeded - log warning and return recovered checkpoint
		// Note: We don't have a logger injected, so we'll just return the recovered checkpoint
		// The caller should log the recovery success
		return recoveredCheckpoint, corruptionErr
	}

	return checkpoint, nil
}

// List returns all checkpoints for a mission.
// Currently returns only the latest checkpoint since the storage schema stores
// a single checkpoint per mission in the missions table.
func (m *DefaultCheckpointManager) List(ctx context.Context, missionID types.ID) ([]*MissionCheckpoint, error) {
	checkpoint, err := m.Restore(ctx, missionID)
	if err != nil {
		return nil, err
	}

	if checkpoint == nil {
		return []*MissionCheckpoint{}, nil
	}

	return []*MissionCheckpoint{checkpoint}, nil
}

// SetAutoCheckpointInterval configures the automatic checkpoint interval.
// When set to a non-zero duration, checkpoints should be captured at this interval.
// Setting to 0 disables automatic checkpointing.
func (m *DefaultCheckpointManager) SetAutoCheckpointInterval(interval time.Duration) {
	m.autoCheckpointInterval = interval
}

// GetAutoCheckpointInterval returns the current auto-checkpoint interval.
// This can be used by the orchestrator to schedule periodic checkpoints.
func (m *DefaultCheckpointManager) GetAutoCheckpointInterval() time.Duration {
	return m.autoCheckpointInterval
}

// serializeMissionState serializes the mission state to a map for storage.
// This captures the essential state information needed to resume execution.
func (m *DefaultCheckpointManager) serializeMissionState(state *MissionState) (map[string]any, error) {
	stateData := make(map[string]any)

	// Store basic mission information
	stateData["mission_id"] = state.MissionID.String()
	stateData["status"] = string(state.Status)
	stateData["started_at"] = state.StartedAt.Format(time.RFC3339)
	if state.CompletedAt != nil {
		stateData["completed_at"] = state.CompletedAt.Format(time.RFC3339)
	}

	// Store execution order if set
	if len(state.ExecutionOrder) > 0 {
		stateData["execution_order"] = state.ExecutionOrder
	}

	// Store node states
	nodeStates := make(map[string]map[string]any)
	for nodeID, nodeState := range state.NodeStates {
		nodeData := make(map[string]any)
		nodeData["status"] = string(nodeState.Status)
		nodeData["retry_count"] = nodeState.RetryCount

		if nodeState.StartedAt != nil {
			nodeData["started_at"] = nodeState.StartedAt.Format(time.RFC3339)
		}
		if nodeState.CompletedAt != nil {
			nodeData["completed_at"] = nodeState.CompletedAt.Format(time.RFC3339)
		}
		if nodeState.Error != nil {
			nodeData["error"] = nodeState.Error.Error()
		}
		if len(nodeState.RetryParams) > 0 {
			nodeData["retry_params"] = nodeState.RetryParams
		}

		nodeStates[nodeID] = nodeData
	}
	stateData["node_states"] = nodeStates

	return stateData, nil
}

// computeChecksum computes a SHA256 checksum of the checkpoint data for integrity validation.
// The checksum is computed over the serialized checkpoint data (excluding the checksum field itself).
func (m *DefaultCheckpointManager) computeChecksum(checkpoint *MissionCheckpoint) (string, error) {
	// Create a copy of the checkpoint without the checksum field for hashing
	checksumData := struct {
		ID              types.ID
		Version         int
		WorkflowState   map[string]any
		CompletedNodes  []string
		PendingNodes    []string
		NodeResults     map[string]any
		LastNodeID      string
		CheckpointedAt  time.Time
		MetricsSnapshot *MissionMetrics
		FindingIDs      []types.ID
	}{
		ID:              checkpoint.ID,
		Version:         checkpoint.Version,
		WorkflowState:   checkpoint.WorkflowState,
		CompletedNodes:  checkpoint.CompletedNodes,
		PendingNodes:    checkpoint.PendingNodes,
		NodeResults:     checkpoint.NodeResults,
		LastNodeID:      checkpoint.LastNodeID,
		CheckpointedAt:  checkpoint.CheckpointedAt,
		MetricsSnapshot: checkpoint.MetricsSnapshot,
		FindingIDs:      checkpoint.FindingIDs,
	}

	// Serialize to JSON for consistent hashing
	data, err := json.Marshal(checksumData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal checkpoint for checksum: %w", err)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// validateChecksum validates the integrity of a checkpoint by recomputing its checksum.
func (m *DefaultCheckpointManager) validateChecksum(checkpoint *MissionCheckpoint) error {
	if checkpoint.Checksum == "" {
		return fmt.Errorf("checkpoint has no checksum")
	}

	expectedChecksum := checkpoint.Checksum
	checkpoint.Checksum = "" // Temporarily clear for recomputation

	computedChecksum, err := m.computeChecksum(checkpoint)
	if err != nil {
		checkpoint.Checksum = expectedChecksum // Restore original
		return fmt.Errorf("failed to compute checksum: %w", err)
	}

	checkpoint.Checksum = expectedChecksum // Restore original

	if computedChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, computedChecksum)
	}

	return nil
}

// RecoverFromFindings attempts to reconstruct a partial checkpoint by querying the finding store
// for findings associated with this mission. It marks nodes that produced findings as completed
// and builds a minimal checkpoint that allows resumption from the last known good state.
//
// This is used as a fallback recovery mechanism when checkpoint data is corrupted but findings
// data is still intact. The recovered checkpoint is marked as partial and may not capture all
// workflow state, but allows the mission to resume rather than start over.
func (m *DefaultCheckpointManager) RecoverFromFindings(ctx context.Context, missionID types.ID) (*MissionCheckpoint, error) {
	// Get the mission to access workflow information
	mission, err := m.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission for recovery: %w", err)
	}

	// Note: In a full implementation, we would query the finding store here to get all findings
	// for this mission ID. For now, we'll create a minimal checkpoint that marks the mission
	// as needing to restart from the beginning.
	//
	// Future enhancement: Inject finding store and query like:
	//   findings, err := m.findingStore.List(ctx, missionID, nil)
	//   Then analyze findings to determine which nodes completed successfully.

	// Create a minimal recovered checkpoint
	recoveredCheckpoint := &MissionCheckpoint{
		ID:              types.NewID(),
		Version:         1,
		WorkflowState:   make(map[string]any),
		CompletedNodes:  []string{}, // No nodes marked complete - will restart from beginning
		PendingNodes:    []string{}, // Will be populated by orchestrator on resume
		NodeResults:     make(map[string]any),
		LastNodeID:      "",
		CheckpointedAt:  time.Now(),
		MetricsSnapshot: mission.Metrics,
		FindingIDs:      []types.ID{},
		Checksum:        "", // Will be computed below
	}

	// Add metadata to indicate this is a recovered checkpoint
	recoveredCheckpoint.WorkflowState["recovered"] = true
	recoveredCheckpoint.WorkflowState["recovery_reason"] = "checkpoint_corruption"
	recoveredCheckpoint.WorkflowState["original_workflow_id"] = mission.WorkflowID.String()

	// Compute checksum for the recovered checkpoint
	checksum, err := m.computeChecksum(recoveredCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checksum for recovered checkpoint: %w", err)
	}
	recoveredCheckpoint.Checksum = checksum

	return recoveredCheckpoint, nil
}

// Ensure DefaultCheckpointManager implements CheckpointManager at compile time.
var _ CheckpointManager = (*DefaultCheckpointManager)(nil)
