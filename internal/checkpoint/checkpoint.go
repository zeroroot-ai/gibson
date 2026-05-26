package checkpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/vmihailenco/msgpack/v5"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// Checkpoint represents a complete snapshot of mission execution state at a point in time.
// Checkpoints enable mission pause/resume, recovery from failures, and thread branching
// for exploring alternative execution paths.
//
// Checkpoints are immutable once created. To modify state, create a new checkpoint
// with an updated state and reference the previous checkpoint via ParentID.
type Checkpoint struct {
	// ID is a unique ULID identifier for this checkpoint.
	// ULIDs provide time-ordering and are lexicographically sortable.
	ID string `json:"id" msgpack:"id"`

	// ThreadID identifies which execution thread this checkpoint belongs to.
	// Threads enable branching execution paths for parallel exploration.
	ThreadID string `json:"thread_id" msgpack:"thread_id"`

	// ParentID references the previous checkpoint in this thread.
	// This creates a linked chain of checkpoints for history tracking.
	// Empty for the first checkpoint in a thread.
	ParentID string `json:"parent_id,omitempty" msgpack:"parent_id,omitempty"`

	// Version indicates the checkpoint format version for migrations.
	// Increment when making breaking changes to the checkpoint structure.
	Version int `json:"version" msgpack:"version"`

	// CreatedAt is the timestamp when this checkpoint was created.
	CreatedAt time.Time `json:"created_at" msgpack:"created_at"`

	// MissionID is the mission this checkpoint belongs to.
	MissionID types.ID `json:"mission_id" msgpack:"mission_id"`

	// CurrentNodeID is the mission node being executed when this checkpoint was created.
	// This is where execution will resume from.
	CurrentNodeID string `json:"current_node_id" msgpack:"current_node_id"`

	// NodeStates maps node IDs to their current execution state.
	// Includes status, retry count, and timing information.
	NodeStates map[string]*NodeState `json:"node_states" msgpack:"node_states"`

	// CompletedNodes maps node IDs to their output for nodes that have finished.
	// This preserves node results for downstream nodes and final reporting.
	CompletedNodes map[string]*NodeOutput `json:"completed_nodes" msgpack:"completed_nodes"`

	// PendingNodes is the ordered list of node IDs still to be executed.
	// Order is determined by DAG dependencies and execution strategy.
	PendingNodes []string `json:"pending_nodes" msgpack:"pending_nodes"`

	// InProgressNode captures state of a node that was mid-execution when paused.
	// Used to decide whether to retry the node or skip on resume.
	InProgressNode *InProgressNodeState `json:"in_progress_node,omitempty" msgpack:"in_progress_node,omitempty"`

	// WorkingMemory is the serialized agent working memory state (ephemeral, task-scoped).
	// This is typically JSON-encoded map[string]any containing current task context.
	WorkingMemory []byte `json:"working_memory,omitempty" msgpack:"working_memory,omitempty"`

	// MissionMemory is the serialized mission memory state (persisted across nodes).
	// This is typically JSON-encoded map[string]any containing mission-wide state.
	MissionMemory []byte `json:"mission_memory,omitempty" msgpack:"mission_memory,omitempty"`

	// LargeObjectRefs maps logical keys to storage locations for large objects.
	// Used to store bulky artifacts (logs, binary data) separately from the checkpoint.
	// Format: {"key": "s3://bucket/path" or "redis://key"}
	LargeObjectRefs map[string]string `json:"large_object_refs,omitempty" msgpack:"large_object_refs,omitempty"`

	// DAGState captures the DAG traversal position for resumption.
	// Includes pending nodes, current branch, and parallel execution state.
	DAGState *DAGTraversalState `json:"dag_state,omitempty" msgpack:"dag_state,omitempty"`

	// Findings contains IDs of all findings discovered up to this checkpoint.
	// Full finding data is stored separately; this tracks which findings exist.
	Findings []types.ID `json:"findings,omitempty" msgpack:"findings,omitempty"`

	// ConversationHistory is the serialized LLM conversation history.
	// This is typically msgpack or JSON-encoded []llm.Message for context reconstruction.
	ConversationHistory []byte `json:"conversation_history,omitempty" msgpack:"conversation_history,omitempty"`

	// ApprovalState captures human-in-the-loop approval mission state.
	// Non-nil when execution is paused waiting for human approval.
	ApprovalState *ApprovalState `json:"approval_state,omitempty" msgpack:"approval_state,omitempty"`

	// Checksum is a SHA256 hash of critical checkpoint data for integrity verification.
	// Computed over all state fields before persistence.
	Checksum string `json:"checksum" msgpack:"checksum"`

	// SizeBytes is the total size of this checkpoint in bytes (including all serialized state).
	// Used for storage quotas and metrics.
	SizeBytes int64 `json:"size_bytes" msgpack:"size_bytes"`

	// Compressed indicates if the checkpoint data is gzip-compressed.
	// Large checkpoints should be compressed to reduce storage costs.
	Compressed bool `json:"compressed" msgpack:"compressed"`

	// Encrypted indicates if the checkpoint data is encrypted at rest.
	// When true, KeyID specifies which key was used.
	Encrypted bool `json:"encrypted" msgpack:"encrypted"`

	// KeyID identifies the encryption key used for this checkpoint.
	// Only set when Encrypted is true. Format depends on key management system.
	KeyID string `json:"key_id,omitempty" msgpack:"key_id,omitempty"`

	// Label is an optional human-readable label for this checkpoint.
	// Useful for marking important milestones (e.g., "pre_exploit", "post_pivot").
	Label string `json:"label,omitempty" msgpack:"label,omitempty"`

	// Metadata provides arbitrary key-value storage for checkpoint-specific information.
	// Can be used for tags, annotations, or integration-specific data.
	Metadata map[string]string `json:"metadata,omitempty" msgpack:"metadata,omitempty"`
}

// NodeState tracks the runtime state of a single mission node.
// This is distinct from NodeOutput which captures the final result.
type NodeState struct {
	// NodeID is the unique identifier for this node in the mission.
	NodeID string `json:"node_id" msgpack:"node_id"`

	// Status indicates the current execution state of this node.
	Status NodeStatus `json:"status" msgpack:"status"`

	// StartedAt is when this node began execution. Nil if not yet started.
	StartedAt *time.Time `json:"started_at,omitempty" msgpack:"started_at,omitempty"`

	// CompletedAt is when this node finished execution. Nil if not yet completed.
	CompletedAt *time.Time `json:"completed_at,omitempty" msgpack:"completed_at,omitempty"`

	// RetryCount tracks how many times this node has been retried after failure.
	RetryCount int `json:"retry_count" msgpack:"retry_count"`

	// RetryParams stores custom parameters for the next retry attempt.
	// Can override node configuration for adaptive retry strategies.
	RetryParams map[string]any `json:"retry_params,omitempty" msgpack:"retry_params,omitempty"`

	// Error contains the error message if the node failed.
	Error string `json:"error,omitempty" msgpack:"error,omitempty"`

	// Duration is the total execution time for this node.
	Duration time.Duration `json:"duration,omitempty" msgpack:"duration,omitempty"`
}

// NodeOutput captures the final output from a completed node execution.
// This represents the "result" of running a node, including its status and data.
type NodeOutput struct {
	// NodeID is the unique identifier for this node.
	NodeID string `json:"node_id" msgpack:"node_id"`

	// Status is the final execution status of the node.
	Status string `json:"status" msgpack:"status"`

	// Output contains the node's output data as a generic map.
	// Structure depends on the node type and agent implementation.
	Output map[string]any `json:"output,omitempty" msgpack:"output,omitempty"`

	// Duration is how long the node took to execute.
	Duration time.Duration `json:"duration" msgpack:"duration"`

	// Error contains error details if the node failed.
	Error string `json:"error,omitempty" msgpack:"error,omitempty"`

	// RetryCount indicates how many times this node was retried.
	RetryCount int `json:"retry_count,omitempty" msgpack:"retry_count,omitempty"`

	// CompletedAt is when this node finished execution.
	CompletedAt time.Time `json:"completed_at" msgpack:"completed_at"`
}

// InProgressNodeState captures state of a node that was executing when the
// checkpoint was created. This allows the orchestrator to decide on resume
// whether to retry the node or skip it.
type InProgressNodeState struct {
	// NodeID is the unique identifier for the node that was in progress.
	NodeID string `json:"node_id" msgpack:"node_id"`

	// StartedAt is when this node execution began.
	StartedAt time.Time `json:"started_at" msgpack:"started_at"`

	// RetryCount is the number of times this node has been retried so far.
	RetryCount int `json:"retry_count" msgpack:"retry_count"`

	// PartialOutput contains any partial results produced before the pause.
	// Can be used to avoid re-executing expensive operations on retry.
	PartialOutput map[string]any `json:"partial_output,omitempty" msgpack:"partial_output,omitempty"`

	// Elapsed is how long the node had been running when paused.
	Elapsed time.Duration `json:"elapsed" msgpack:"elapsed"`
}

// CurrentCheckpointVersion is the checkpoint schema version emitted by this
// binary. Increment when adding new required fields to Checkpoint or
// DAGTraversalState. Fail fast on load if the persisted version does not match.
const CurrentCheckpointVersion = 2

// ChildStatus tracks the execution status of a single child node within a
// parallel group.
type ChildStatus string

const (
	// ChildStatusPending means the child has been registered but not yet dispatched.
	ChildStatusPending ChildStatus = "pending"

	// ChildStatusInFlight means the child has been dispatched and is running.
	ChildStatusInFlight ChildStatus = "in_flight"

	// ChildStatusCompleted means the child finished successfully.
	ChildStatusCompleted ChildStatus = "completed"

	// ChildStatusFailed means the child finished with a failure.
	ChildStatusFailed ChildStatus = "failed"
)

// ParallelGroupState records the per-child execution status for one parallel
// group. It is embedded inside DAGTraversalState.ParallelGroupStates.
type ParallelGroupState struct {
	// GroupID is the identifier of the parallel group node in the mission DAG.
	GroupID string `json:"group_id" msgpack:"group_id"`

	// Children maps each child node ID to its current status.
	Children map[string]ChildStatus `json:"children" msgpack:"children"`

	// ChildOutputs maps completed child node IDs to their serialised output.
	// Only populated for ChildStatusCompleted children.
	ChildOutputs map[string]map[string]any `json:"child_outputs,omitempty" msgpack:"child_outputs,omitempty"`

	// FailFast records the group's failure semantics: when true, one child
	// failure transitions the group to Failed immediately.
	FailFast bool `json:"fail_fast" msgpack:"fail_fast"`
}

// DAGTraversalState captures the DAG execution position for resumption.
// This enables the orchestrator to continue from exactly where it left off.
type DAGTraversalState struct {
	// PendingNodes is the ordered list of nodes still to be executed.
	// Order respects dependency constraints and execution strategy.
	PendingNodes []string `json:"pending_nodes" msgpack:"pending_nodes"`

	// CurrentBranch identifies which conditional branch is being executed.
	// Empty if not in a conditional branch.
	CurrentBranch string `json:"current_branch,omitempty" msgpack:"current_branch,omitempty"`

	// ParallelState is DEPRECATED in schema version 2. It is retained here so
	// the struct compiles without breaking callers; it is excluded from
	// serialization. Use ParallelGroupStates instead.
	ParallelState map[string][]string `json:"-" msgpack:"-"`

	// ParallelGroupStates replaces the former ParallelState []string map.
	// It records full per-child status for every active parallel group.
	// Schema version 2 required.
	ParallelGroupStates map[string]ParallelGroupState `json:"parallel_group_states,omitempty" msgpack:"parallel_group_states,omitempty"`

	// VisitedNodes tracks all nodes that have been visited (started or completed).
	// Used to detect cycles and prevent infinite loops.
	VisitedNodes []string `json:"visited_nodes,omitempty" msgpack:"visited_nodes,omitempty"`

	// ExecutionOrder is the actual order nodes were executed in.
	// Useful for debugging and understanding execution flow.
	ExecutionOrder []string `json:"execution_order,omitempty" msgpack:"execution_order,omitempty"`
}

// NodeStatus represents the execution status of a mission node.
type NodeStatus string

const (
	// NodeStatusPending indicates the node has not yet started execution.
	NodeStatusPending NodeStatus = "pending"

	// NodeStatusRunning indicates the node is currently executing.
	NodeStatusRunning NodeStatus = "running"

	// NodeStatusCompleted indicates the node completed successfully.
	NodeStatusCompleted NodeStatus = "completed"

	// NodeStatusFailed indicates the node execution failed.
	NodeStatusFailed NodeStatus = "failed"

	// NodeStatusSkipped indicates the node was skipped (e.g., due to conditional logic).
	NodeStatusSkipped NodeStatus = "skipped"

	// NodeStatusCancelled indicates the node was cancelled during execution.
	NodeStatusCancelled NodeStatus = "cancelled"
)

// String returns the string representation of NodeStatus.
func (s NodeStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is terminal (completed, failed, skipped, cancelled).
func (s NodeStatus) IsTerminal() bool {
	return s == NodeStatusCompleted ||
		s == NodeStatusFailed ||
		s == NodeStatusSkipped ||
		s == NodeStatusCancelled
}

// NewCheckpoint creates a new checkpoint with generated ID and timestamp.
// The checkpoint format version is set to CurrentCheckpointVersion.
func NewCheckpoint(missionID types.ID, threadID string) *Checkpoint {
	return &Checkpoint{
		ID:             ulid.Make().String(),
		ThreadID:       threadID,
		Version:        CurrentCheckpointVersion,
		CreatedAt:      time.Now(),
		MissionID:      missionID,
		NodeStates:     make(map[string]*NodeState),
		CompletedNodes: make(map[string]*NodeOutput),
		PendingNodes:   []string{},
		Findings:       []types.ID{},
		Metadata:       make(map[string]string),
	}
}

// ComputeChecksum computes a SHA256 checksum of the critical checkpoint data.
// This is used for integrity verification when loading checkpoints.
func (c *Checkpoint) ComputeChecksum() (string, error) {
	// Create a copy with checksum zeroed out to avoid circular dependency
	temp := *c
	temp.Checksum = ""
	temp.SizeBytes = 0

	// Serialize to canonical form
	data, err := json.Marshal(temp)
	if err != nil {
		return "", fmt.Errorf("failed to marshal checkpoint for checksum: %w", err)
	}

	// Compute SHA256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// VerifyChecksum verifies that the checkpoint's checksum matches the computed checksum.
// Returns an error if the checksums don't match, indicating data corruption.
func (c *Checkpoint) VerifyChecksum() error {
	if c.Checksum == "" {
		return ErrChecksumMissing
	}

	computed, err := c.ComputeChecksum()
	if err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}

	if computed != c.Checksum {
		return ErrChecksumMismatch
	}

	return nil
}

// ComputeSize calculates the total size of the checkpoint in bytes.
// This includes all serialized state data.
func (c *Checkpoint) ComputeSize() (int64, error) {
	data, err := msgpack.Marshal(c)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal checkpoint for size: %w", err)
	}
	return int64(len(data)), nil
}

// Clone creates a deep copy of the checkpoint with a new ID and timestamp.
// This is useful for creating branched checkpoints on different threads.
func (c *Checkpoint) Clone() *Checkpoint {
	clone := &Checkpoint{
		ID:              ulid.Make().String(),
		ThreadID:        c.ThreadID,
		ParentID:        c.ID, // Reference the original as parent
		Version:         c.Version,
		CreatedAt:       time.Now(),
		MissionID:       c.MissionID,
		CurrentNodeID:   c.CurrentNodeID,
		NodeStates:      make(map[string]*NodeState),
		CompletedNodes:  make(map[string]*NodeOutput),
		PendingNodes:    make([]string, len(c.PendingNodes)),
		WorkingMemory:   make([]byte, len(c.WorkingMemory)),
		MissionMemory:   make([]byte, len(c.MissionMemory)),
		Findings:        make([]types.ID, len(c.Findings)),
		LargeObjectRefs: make(map[string]string),
		Compressed:      c.Compressed,
		Encrypted:       c.Encrypted,
		KeyID:           c.KeyID,
		Metadata:        make(map[string]string),
	}

	// Deep copy maps
	for k, v := range c.NodeStates {
		stateCopy := *v
		clone.NodeStates[k] = &stateCopy
	}
	for k, v := range c.CompletedNodes {
		outputCopy := *v
		clone.CompletedNodes[k] = &outputCopy
	}
	for k, v := range c.LargeObjectRefs {
		clone.LargeObjectRefs[k] = v
	}
	for k, v := range c.Metadata {
		clone.Metadata[k] = v
	}

	// Copy slices
	copy(clone.PendingNodes, c.PendingNodes)
	copy(clone.WorkingMemory, c.WorkingMemory)
	copy(clone.MissionMemory, c.MissionMemory)
	copy(clone.Findings, c.Findings)

	// Copy DAG state
	if c.DAGState != nil {
		clone.DAGState = &DAGTraversalState{
			PendingNodes:        make([]string, len(c.DAGState.PendingNodes)),
			CurrentBranch:       c.DAGState.CurrentBranch,
			ParallelGroupStates: make(map[string]ParallelGroupState),
			VisitedNodes:        make([]string, len(c.DAGState.VisitedNodes)),
			ExecutionOrder:      make([]string, len(c.DAGState.ExecutionOrder)),
		}
		copy(clone.DAGState.PendingNodes, c.DAGState.PendingNodes)
		copy(clone.DAGState.VisitedNodes, c.DAGState.VisitedNodes)
		copy(clone.DAGState.ExecutionOrder, c.DAGState.ExecutionOrder)
		// Deep-copy ParallelGroupStates: copy Children and ChildOutputs per group.
		for groupID, gs := range c.DAGState.ParallelGroupStates {
			childrenCopy := make(map[string]ChildStatus, len(gs.Children))
			for nodeID, status := range gs.Children {
				childrenCopy[nodeID] = status
			}
			outputsCopy := make(map[string]map[string]any, len(gs.ChildOutputs))
			for nodeID, out := range gs.ChildOutputs {
				outCopy := make(map[string]any, len(out))
				for k, v := range out {
					outCopy[k] = v
				}
				outputsCopy[nodeID] = outCopy
			}
			clone.DAGState.ParallelGroupStates[groupID] = ParallelGroupState{
				GroupID:      gs.GroupID,
				Children:     childrenCopy,
				ChildOutputs: outputsCopy,
				FailFast:     gs.FailFast,
			}
		}
	}

	// Copy in-progress node state
	if c.InProgressNode != nil {
		clone.InProgressNode = &InProgressNodeState{
			NodeID:        c.InProgressNode.NodeID,
			StartedAt:     c.InProgressNode.StartedAt,
			RetryCount:    c.InProgressNode.RetryCount,
			PartialOutput: make(map[string]any),
			Elapsed:       c.InProgressNode.Elapsed,
		}
		for k, v := range c.InProgressNode.PartialOutput {
			clone.InProgressNode.PartialOutput[k] = v
		}
	}

	// Copy approval state
	if c.ApprovalState != nil {
		clone.ApprovalState = c.ApprovalState.Clone()
	}

	return clone
}

// WithLabel sets a human-readable label on the checkpoint.
func (c *Checkpoint) WithLabel(label string) *Checkpoint {
	c.Label = label
	return c
}

// WithMetadata adds metadata to the checkpoint.
func (c *Checkpoint) WithMetadata(key, value string) *Checkpoint {
	if c.Metadata == nil {
		c.Metadata = make(map[string]string)
	}
	c.Metadata[key] = value
	return c
}
