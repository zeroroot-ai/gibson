package mission

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// Checkpoint represents the complete execution state at a point in time.
// It captures all information needed to resume a mission from where it left off,
// including node states, outputs, memory, and DAG traversal position.
type Checkpoint struct {
	// MissionID is the unique identifier for the mission this checkpoint belongs to
	MissionID types.ID `json:"mission_id"`

	// CreatedAt is the timestamp when this checkpoint was created
	CreatedAt time.Time `json:"created_at"`

	// CurrentNodeID is the ID of the node being executed when the checkpoint was created
	CurrentNodeID string `json:"current_node_id"`

	// CompletedNodes is a map of node IDs to their outputs for nodes that have completed
	CompletedNodes map[string]NodeOutput `json:"completed_nodes"`

	// InProgressNode contains the state of a node that was mid-execution when paused
	InProgressNode *InProgressNodeState `json:"in_progress_node,omitempty"`

	// WorkingMemory is the serialized agent working memory state
	WorkingMemory []byte `json:"working_memory"`

	// MissionMemory is the serialized mission memory state
	MissionMemory []byte `json:"mission_memory"`

	// Findings contains the IDs of all findings discovered up to this checkpoint
	Findings []types.ID `json:"findings"`

	// Metrics contains the mission execution metrics at checkpoint time
	Metrics MissionMetrics `json:"metrics"`

	// DAGState captures the DAG traversal state for resumption
	DAGState *DAGTraversalState `json:"dag_state"`
}

// NodeOutput represents the output from a completed node execution.
// It contains the status, output data, and duration for a single node.
type NodeOutput struct {
	// NodeID is the unique identifier for this node
	NodeID string `json:"node_id"`

	// Status is the final status of the node execution
	Status string `json:"status"`

	// Output contains the node's output data as a generic map
	Output map[string]any `json:"output"`

	// Duration is how long the node took to execute
	Duration time.Duration `json:"duration"`
}

// InProgressNodeState captures the state of a node that was executing when paused.
// This allows the orchestrator to decide whether to retry the node or skip it.
type InProgressNodeState struct {
	// NodeID is the unique identifier for the node that was in progress
	NodeID string `json:"node_id"`

	// StartedAt is when the node execution began
	StartedAt time.Time `json:"started_at"`

	// RetryCount is the number of times this node has been retried
	RetryCount int `json:"retry_count"`
}

// DAGTraversalState captures the position in the mission DAG for resumption.
// It tracks which nodes are pending, the current branch being executed,
// and any parallel execution state.
type DAGTraversalState struct {
	// PendingNodes is the ordered list of nodes still to be executed
	PendingNodes []string `json:"pending_nodes"`

	// CurrentBranch identifies which conditional branch is being executed (if any)
	CurrentBranch string `json:"current_branch,omitempty"`

	// ParallelState tracks parallel execution state for each parallel group
	// Key is the parallel group ID, value is the list of completed node IDs in that group
	ParallelState map[string][]string `json:"parallel_state,omitempty"`
}

// CheckpointStore defines the interface for checkpoint persistence operations.
// Implementations of this interface handle the actual storage mechanism (Redis, file, etc.).
type CheckpointStore interface {
	// Save persists a checkpoint for the given mission
	Save(ctx context.Context, missionID types.ID, checkpoint *Checkpoint) error

	// Load retrieves the checkpoint for the given mission
	// Returns nil if no checkpoint exists
	Load(ctx context.Context, missionID types.ID) (*Checkpoint, error)

	// Delete removes the checkpoint for the given mission
	Delete(ctx context.Context, missionID types.ID) error

	// Exists checks if a checkpoint exists for the given mission
	Exists(ctx context.Context, missionID types.ID) (bool, error)
}

// SerializeMemory serializes a memory map to JSON bytes.
// This is used to persist memory state in checkpoints.
// Returns nil bytes for nil memory (not an error).
func SerializeMemory(memory map[string]any) ([]byte, error) {
	if memory == nil {
		return nil, nil
	}

	// Use json.Marshal for consistent serialization
	data, err := json.Marshal(memory)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize memory: %w", err)
	}

	return data, nil
}

// DeserializeMemory deserializes JSON bytes to a memory map.
// This is used to restore memory state from checkpoints.
// Returns an empty map for nil/empty bytes (not an error).
func DeserializeMemory(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return make(map[string]any), nil
	}

	var memory map[string]any
	if err := json.Unmarshal(data, &memory); err != nil {
		return nil, fmt.Errorf("failed to deserialize memory: %w", err)
	}

	return memory, nil
}
