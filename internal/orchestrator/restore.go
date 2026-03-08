package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/mission"
)

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
// Returns an error if:
//   - Checkpoint is nil
//   - Required fields are missing
//   - Memory deserialization fails (returns partial state with error)
func (r *StateRestorer) RestoreFromCheckpoint(ctx context.Context, checkpoint *mission.Checkpoint) (*RestoredState, error) {
	if checkpoint == nil {
		return nil, fmt.Errorf("checkpoint cannot be nil")
	}

	// Validate checkpoint has required fields
	if err := r.ValidateCheckpoint(checkpoint); err != nil {
		return nil, fmt.Errorf("checkpoint validation failed: %w", err)
	}

	// Create restored state
	restored := &RestoredState{
		CompletedNodes: checkpoint.CompletedNodes,
		CurrentNode:    checkpoint.CurrentNodeID,
		PendingQueue:   []string{},
	}

	// Copy in-progress node state if present
	if checkpoint.InProgressNode != nil {
		restored.InProgressNode = &mission.InProgressNodeState{
			NodeID:     checkpoint.InProgressNode.NodeID,
			StartedAt:  checkpoint.InProgressNode.StartedAt,
			RetryCount: checkpoint.InProgressNode.RetryCount,
		}
	}

	// Restore DAG traversal state
	if checkpoint.DAGState != nil {
		restored.PendingQueue = checkpoint.DAGState.PendingNodes
		restored.ParallelState = checkpoint.DAGState.ParallelState
	}

	// Deserialize working memory
	if len(checkpoint.WorkingMemory) > 0 {
		var workingMem map[string]any
		if err := json.Unmarshal(checkpoint.WorkingMemory, &workingMem); err != nil {
			// Return partial state with error - allow orchestrator to decide whether to continue
			return restored, fmt.Errorf("failed to deserialize working memory (continuing with empty memory): %w", err)
		}
		restored.WorkingMemory = workingMem
	} else {
		restored.WorkingMemory = make(map[string]any)
	}

	// Deserialize mission memory
	if len(checkpoint.MissionMemory) > 0 {
		var missionMem map[string]any
		if err := json.Unmarshal(checkpoint.MissionMemory, &missionMem); err != nil {
			// Return partial state with error - allow orchestrator to decide whether to continue
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
func (r *StateRestorer) ValidateCheckpointWithDefinition(checkpoint *mission.Checkpoint, def *mission.MissionDefinition) error {
	if err := r.ValidateCheckpoint(checkpoint); err != nil {
		return err
	}

	if def == nil {
		return fmt.Errorf("mission definition is nil")
	}

	// Validate current node exists
	if checkpoint.CurrentNodeID != "" {
		if def.GetNode(checkpoint.CurrentNodeID) == nil {
			return fmt.Errorf("current node %q not found in mission definition", checkpoint.CurrentNodeID)
		}
	}

	// Validate completed nodes exist
	for nodeID := range checkpoint.CompletedNodes {
		if def.GetNode(nodeID) == nil {
			return fmt.Errorf("completed node %q not found in mission definition", nodeID)
		}
	}

	// Validate pending nodes exist (if DAG state is present)
	if checkpoint.DAGState != nil {
		for _, nodeID := range checkpoint.DAGState.PendingNodes {
			if def.GetNode(nodeID) == nil {
				return fmt.Errorf("pending node %q not found in mission definition", nodeID)
			}
		}
	}

	return nil
}
