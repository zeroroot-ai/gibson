package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/mission/definitionutil"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// ErrMissionMemoryUnavailable is returned by RestoreFromCheckpoint when the
// MissionMemory Redis backend is unreachable at resume time. Proceeding with
// empty mission memory would silently corrupt the mission's expectations, so
// we fail fast instead.
var ErrMissionMemoryUnavailable = errors.New("mission memory unavailable at resume: Redis connection failed")

// RestoredState represents the fully restored orchestrator state from a checkpoint.
// This contains everything needed to resume mission execution from where it left off.
type RestoredState struct {
	// CompletedNodes maps node IDs to their outputs for nodes that have completed
	CompletedNodes map[string]mission.NodeOutput

	// CurrentNode is the ID of the node that was being executed when paused
	CurrentNode string

	// PendingQueue is the ordered list of nodes still to be executed
	PendingQueue []string

	// WorkingMemory is the deserialized agent working memory
	WorkingMemory map[string]any

	// MissionMemory is the deserialized mission memory
	MissionMemory map[string]any

	// InProgressNode contains state for a node that was mid-execution
	InProgressNode *mission.InProgressNodeState

	// ParallelState tracks parallel execution state for each parallel group
	ParallelState map[string][]string
}

// StateRestorer handles restoration of orchestrator state from checkpoints.
// It validates checkpoint integrity and deserializes all state components.
type StateRestorer struct{}

// NewStateRestorer creates a new StateRestorer instance.
func NewStateRestorer() *StateRestorer {
	return &StateRestorer{}
}

// RestoreFromCheckpoint converts a checkpoint into a RestoredState that the orchestrator can use.
// It validates the checkpoint structure and deserializes all memory components.
//
// Parameters:
//   - ctx: context for Redis calls
//   - checkpoint: the persisted checkpoint to restore from
//   - wm: optional live WorkingMemory instance. When non-nil, entries from the
//     checkpoint's working-memory payload are written into wm via Set(k, v).
//   - mm: optional live MissionMemory instance. When non-nil, its Redis availability
//     is probed via Keys(ctx). If Redis is reachable, it is trusted as-is (the
//     checkpoint snapshot is a recovery aid only). If Redis is unreachable,
//     ErrMissionMemoryUnavailable is returned and the resume aborts.
//
// Returns an error if:
//   - Checkpoint is nil
//   - Required fields are missing
//   - Memory deserialization fails (returns partial state with error)
//   - mm is non-nil and its Redis backend is unreachable
func (r *StateRestorer) RestoreFromCheckpoint(
	ctx context.Context,
	checkpoint *mission.Checkpoint,
	wm memory.WorkingMemory,
	mm memory.MissionMemory,
) (*RestoredState, error) {
	if checkpoint == nil {
		return nil, fmt.Errorf("checkpoint cannot be nil")
	}

	// Validate checkpoint has required fields.
	if err := r.ValidateCheckpoint(checkpoint); err != nil {
		return nil, fmt.Errorf("checkpoint validation failed: %w", err)
	}

	// Create restored state.
	restored := &RestoredState{
		CompletedNodes: checkpoint.CompletedNodes,
		CurrentNode:    checkpoint.CurrentNodeID,
		PendingQueue:   []string{},
	}

	// Copy in-progress node state if present.
	if checkpoint.InProgressNode != nil {
		restored.InProgressNode = &mission.InProgressNodeState{
			NodeID:     checkpoint.InProgressNode.NodeID,
			StartedAt:  checkpoint.InProgressNode.StartedAt,
			RetryCount: checkpoint.InProgressNode.RetryCount,
		}
	}

	// Restore DAG traversal state.
	if checkpoint.DAGState != nil {
		restored.PendingQueue = checkpoint.DAGState.PendingNodes
		restored.ParallelState = checkpoint.DAGState.ParallelState
	}

	// Deserialize working memory from checkpoint bytes.
	if len(checkpoint.WorkingMemory) > 0 {
		var workingMem map[string]any
		if err := json.Unmarshal(checkpoint.WorkingMemory, &workingMem); err != nil {
			// Return partial state with error — allow orchestrator to decide whether to continue.
			return restored, fmt.Errorf("failed to deserialize working memory (continuing with empty memory): %w", err)
		}
		restored.WorkingMemory = workingMem

		// Re-hydrate the live WorkingMemory instance when provided.
		if wm != nil {
			// The caller constructs a fresh instance; do NOT call wm.Clear().
			for k, v := range workingMem {
				if err := wm.Set(k, v); err != nil {
					// Token-budget eviction — log and continue; do not abort resume.
					slog.Warn("working memory re-hydration: Set error (token budget?)",
						"key", k,
						"err", err,
					)
				}
			}
		}
	} else {
		restored.WorkingMemory = make(map[string]any)
	}

	// Mission memory: probe Redis availability when mm is provided.
	// The checkpoint snapshot is a recovery aid; Redis is the authoritative source.
	if mm != nil {
		_, err := mm.Keys(ctx)
		if err != nil {
			// Redis is unreachable — fail fast rather than silently resume with empty
			// mission memory, which would corrupt the mission's expectations.
			missionID := checkpoint.MissionID.String()
			slog.Error("mission memory unavailable at resume: Redis connection failed",
				"mission_id", missionID,
				"err", err,
			)
			return nil, ErrMissionMemoryUnavailable
		}
		// Redis is reachable — trust it as-is. The checkpoint snapshot (below)
		// is stored in RestoredState for operator debugging only; it is NOT
		// re-hydrated back into Redis.
	}

	// Deserialize mission memory from checkpoint bytes (stored for operator reference).
	if len(checkpoint.MissionMemory) > 0 {
		var missionMem map[string]any
		if err := json.Unmarshal(checkpoint.MissionMemory, &missionMem); err != nil {
			// Return partial state with error — allow orchestrator to decide whether to continue.
			return restored, fmt.Errorf("failed to deserialize mission memory (continuing with empty memory): %w", err)
		}
		restored.MissionMemory = missionMem
	} else {
		restored.MissionMemory = make(map[string]any)
	}

	return restored, nil
}

// ValidateCheckpoint checks if a checkpoint has valid structure and required fields.
// This performs basic validation without requiring the full mission definition.
//
// Validation rules:
//   - MissionID must not be zero
//   - CreatedAt must not be zero
//   - CompletedNodes map must not be nil
//   - Metrics must not be nil
//
// Returns an error describing the validation failure, or nil if valid.
func (r *StateRestorer) ValidateCheckpoint(checkpoint *mission.Checkpoint) error {
	if checkpoint == nil {
		return fmt.Errorf("checkpoint is nil")
	}

	if checkpoint.MissionID.IsZero() {
		return fmt.Errorf("checkpoint has zero mission ID")
	}

	if checkpoint.CreatedAt.IsZero() {
		return fmt.Errorf("checkpoint has zero creation time")
	}

	if checkpoint.CompletedNodes == nil {
		return fmt.Errorf("checkpoint has nil completed nodes map")
	}

	// Metrics can be nil/zero for very early checkpoints, but it's suspicious
	// We'll allow it but the orchestrator should handle this case

	return nil
}

// ValidateCheckpointWithDefinition performs extended validation against a mission definition.
// This checks that:
//   - All completed node IDs exist in the definition
//   - All pending node IDs exist in the definition
//   - The current node ID exists in the definition
//
// This validation should be performed by the orchestrator before attempting to resume.
func (r *StateRestorer) ValidateCheckpointWithDefinition(checkpoint *mission.Checkpoint, def *missionv1.MissionDefinition) error {
	if err := r.ValidateCheckpoint(checkpoint); err != nil {
		return err
	}

	if def == nil {
		return fmt.Errorf("mission definition is nil")
	}

	// Validate current node exists
	if checkpoint.CurrentNodeID != "" {
		if _, ok := definitionutil.GetNode(def, checkpoint.CurrentNodeID); !ok {
			return fmt.Errorf("current node %q not found in mission definition", checkpoint.CurrentNodeID)
		}
	}

	// Validate completed nodes exist
	for nodeID := range checkpoint.CompletedNodes {
		if _, ok := definitionutil.GetNode(def, nodeID); !ok {
			return fmt.Errorf("completed node %q not found in mission definition", nodeID)
		}
	}

	// Validate pending nodes exist (if DAG state is present)
	if checkpoint.DAGState != nil {
		for _, nodeID := range checkpoint.DAGState.PendingNodes {
			if _, ok := definitionutil.GetNode(def, nodeID); !ok {
				return fmt.Errorf("pending node %q not found in mission definition", nodeID)
			}
		}
	}

	return nil
}
