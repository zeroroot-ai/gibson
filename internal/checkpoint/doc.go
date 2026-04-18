// Package checkpoint provides comprehensive mission state checkpointing and recovery
// capabilities for the Gibson AI agent platform.
//
// The checkpoint package enables Gibson missions to be paused, resumed, and recovered
// from failures by capturing complete execution state at strategic points during mission
// execution. This includes DAG traversal position, node states, memory contents, findings,
// and approval states.
//
// # Architecture
//
// The package is organized around several key concepts:
//
//   - Checkpoints: Immutable snapshots of complete mission state at a point in time
//   - Threads: Branching execution paths enabling parallel exploration and what-if scenarios
//   - ExecutionState: Serializable state representation for persistence and recovery
//   - ApprovalState: Human-in-the-loop approval mission state
//
// # Checkpoint Structure
//
// Each checkpoint captures:
//
//   - Mission and thread identifiers for tracking
//   - DAG traversal state (current node, pending nodes, completed nodes)
//   - Node execution states and outputs
//   - Working and mission memory snapshots
//   - Conversation history for LLM context reconstruction
//   - Findings discovered up to this point
//   - Approval mission state if waiting for human input
//   - Integrity checksums and encryption metadata
//
// # Threading Model
//
// Threads enable branching execution paths where missions can be forked at checkpoint
// boundaries to explore alternative execution strategies. This is particularly useful for:
//
//   - Trying different agent parameters or tools
//   - Exploring alternative decision paths
//   - Implementing approval rejection with retry
//   - A/B testing different mission strategies
//
// # Storage Optimization
//
// The package supports several optimizations for large checkpoints:
//
//   - Compression: Automatic gzip compression for large state data
//   - Encryption: Optional at-rest encryption using provided key IDs
//   - Large object references: Separate storage for bulky artifacts
//   - Incremental checkpoints: Delta-based storage for memory snapshots
//
// # Usage Example
//
//	// Create a checkpoint during mission execution
//	checkpoint := &checkpoint.Checkpoint{
//		ID:              ulid.Make().String(),
//		ThreadID:        "thread_main",
//		MissionID:       missionID,
//		CurrentNodeID:   "node_analyze",
//		NodeStates:      nodeStates,
//		CompletedNodes:  completedNodes,
//		PendingNodes:    []string{"node_report", "node_cleanup"},
//		WorkingMemory:   serializedMemory,
//		MissionMemory:   serializedMission,
//		DAGState:        dagState,
//		Findings:        findingIDs,
//		CreatedAt:       time.Now(),
//		Version:         1,
//	}
//
//	// Save checkpoint to storage
//	if err := store.Save(ctx, checkpoint); err != nil {
//		return fmt.Errorf("failed to save checkpoint: %w", err)
//	}
//
//	// Later, resume from checkpoint
//	loaded, err := store.Load(ctx, checkpoint.ID)
//	if err != nil {
//		return fmt.Errorf("failed to load checkpoint: %w", err)
//	}
//
//	// Restore execution state
//	state, err := loaded.ToExecutionState()
//	if err != nil {
//		return fmt.Errorf("failed to restore state: %w", err)
//	}
//
// # Thread Branching
//
//	// Create a branch from an existing checkpoint
//	branchThread := &checkpoint.Thread{
//		ID:           ulid.Make().String(),
//		MissionID:    missionID,
//		ParentThread: "thread_main",
//		CreatedAt:    time.Now(),
//		Metadata: map[string]string{
//			"branch_reason": "retry_with_different_params",
//			"parent_checkpoint": checkpoint.ID,
//		},
//	}
//
//	// Create new checkpoint on the branch
//	branchCheckpoint := checkpoint.Clone()
//	branchCheckpoint.ID = ulid.Make().String()
//	branchCheckpoint.ThreadID = branchThread.ID
//	branchCheckpoint.ParentID = checkpoint.ID
//
// # Error Handling
//
// The package defines specific error types for common failure scenarios:
//
//   - ErrCheckpointNotFound: Checkpoint ID does not exist in storage
//   - ErrChecksumMismatch: Checkpoint data corruption detected
//   - ErrDecryptionFailed: Unable to decrypt checkpoint data
//   - ErrSerializationFailed: Unable to serialize/deserialize state
//   - ErrThreadNotFound: Thread ID does not exist
//   - ErrApprovalTimeout: Approval request exceeded timeout
//
// # Concurrency
//
// Checkpoint operations are designed to be thread-safe. Multiple goroutines can
// safely create checkpoints on different threads. However, checkpoint storage
// backends must provide appropriate concurrency guarantees (e.g., Redis transactions,
// file locking, database ACID properties).
//
// # Version Compatibility
//
// Checkpoints include a version field to support format migrations. When loading
// checkpoints, the system can detect older versions and apply migration logic to
// upgrade the data structure to the current format.
package checkpoint
