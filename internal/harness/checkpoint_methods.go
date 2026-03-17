package harness

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/checkpoint"
	"github.com/zero-day-ai/gibson/internal/types"
)

// CheckpointAccess provides checkpoint operations for agents during execution.
// This interface enables agents to interact with the checkpointing system for
// state management, history tracking, and cross-run continuity.
//
// Checkpoint access is optional - if checkpointing is not configured for a mission,
// all methods will return ErrCheckpointingDisabled.
type CheckpointAccess interface {
	// GetCurrentCheckpoint retrieves the current/latest checkpoint for this execution.
	// This represents the most recent saved state for the current thread.
	//
	// Returns:
	//   - *checkpoint.Checkpoint: The latest checkpoint
	//   - error: Non-nil if checkpointing is disabled or retrieval fails
	//
	// Example:
	//   cp, err := harness.Checkpoint().GetCurrentCheckpoint()
	//   if err != nil {
	//       return fmt.Errorf("failed to get checkpoint: %w", err)
	//   }
	//   logger.Info("Current checkpoint", "id", cp.ID, "created", cp.CreatedAt)
	GetCurrentCheckpoint() (*checkpoint.Checkpoint, error)

	// CreateCheckpoint creates an explicit checkpoint with an optional label.
	// This allows agents to create named savepoints at important execution milestones.
	//
	// Parameters:
	//   - label: Optional human-readable label (e.g., "pre_exploit", "post_pivot")
	//
	// Returns:
	//   - *checkpoint.Checkpoint: The newly created checkpoint
	//   - error: Non-nil if checkpointing is disabled or creation fails
	//
	// The checkpoint captures the current execution state including:
	//   - Working memory (agent-local state)
	//   - Mission memory (shared mission state)
	//   - Conversation history
	//   - Node states and completion status
	//   - Findings discovered so far
	//
	// Example:
	//   cp, err := harness.Checkpoint().CreateCheckpoint("pre_exploit")
	//   if err != nil {
	//       return fmt.Errorf("failed to create checkpoint: %w", err)
	//   }
	//   logger.Info("Created checkpoint", "id", cp.ID, "label", cp.Label)
	CreateCheckpoint(label string) (*checkpoint.Checkpoint, error)

	// GetCheckpointHistory retrieves checkpoint history for the current thread.
	// Results are ordered by creation time descending (most recent first).
	//
	// Parameters:
	//   - limit: Maximum number of checkpoints to return (0 = no limit)
	//
	// Returns:
	//   - []*checkpoint.Checkpoint: List of checkpoints (newest first)
	//   - error: Non-nil if checkpointing is disabled or retrieval fails
	//
	// Use this to:
	//   - Review execution history
	//   - Find labeled checkpoints (e.g., find "pre_exploit" checkpoint)
	//   - Track execution progress over time
	//
	// Example:
	//   history, err := harness.Checkpoint().GetCheckpointHistory(10)
	//   if err != nil {
	//       return fmt.Errorf("failed to get history: %w", err)
	//   }
	//   for _, cp := range history {
	//       logger.Info("Checkpoint", "id", cp.ID, "label", cp.Label, "created", cp.CreatedAt)
	//   }
	GetCheckpointHistory(limit int) ([]*checkpoint.Checkpoint, error)

	// GetPreviousRunCheckpoint retrieves a checkpoint from a previous mission run.
	// This enables agents to access state from prior attempts at the same mission.
	//
	// Parameters:
	//   - runOffset: Run offset from current (1 = previous run, 2 = two runs ago, etc.)
	//
	// Returns:
	//   - *checkpoint.Checkpoint: The latest checkpoint from the specified run
	//   - error: Non-nil if checkpointing is disabled, run doesn't exist, or retrieval fails
	//
	// Use this to:
	//   - Compare current state with previous run
	//   - Resume from prior execution context
	//   - Learn from previous attempts
	//
	// Example:
	//   prevCP, err := harness.Checkpoint().GetPreviousRunCheckpoint(1)
	//   if err != nil {
	//       logger.Info("No previous run checkpoint available")
	//   } else {
	//       logger.Info("Previous run checkpoint", "id", prevCP.ID, "created", prevCP.CreatedAt)
	//       // Compare findings, node states, etc.
	//   }
	GetPreviousRunCheckpoint(runOffset int) (*checkpoint.Checkpoint, error)
}

// HarnessCheckpointMethods implements CheckpointAccess for the agent harness.
// It provides checkpoint operations scoped to the current thread and mission execution.
type HarnessCheckpointMethods struct {
	// checkpointer is the underlying checkpoint system
	checkpointer checkpoint.ThreadedCheckpointer

	// threadID identifies the current execution thread
	threadID string

	// missionID identifies the current mission
	missionID types.ID

	// runNumber is the current mission run number (1-indexed)
	runNumber int

	// enabled indicates if checkpointing is configured for this mission
	enabled bool
}

// NewHarnessCheckpointMethods creates a new checkpoint access implementation for the harness.
//
// Parameters:
//   - checkpointer: The threaded checkpointer instance (nil if checkpointing disabled)
//   - threadID: Current execution thread ID
//   - missionID: Current mission ID
//   - runNumber: Current run number (1-indexed)
//
// If checkpointer is nil, all methods will return ErrCheckpointingDisabled.
func NewHarnessCheckpointMethods(
	checkpointer checkpoint.ThreadedCheckpointer,
	threadID string,
	missionID types.ID,
	runNumber int,
) *HarnessCheckpointMethods {
	return &HarnessCheckpointMethods{
		checkpointer: checkpointer,
		threadID:     threadID,
		missionID:    missionID,
		runNumber:    runNumber,
		enabled:      checkpointer != nil,
	}
}

// GetCurrentCheckpoint retrieves the latest checkpoint for the current thread.
func (h *HarnessCheckpointMethods) GetCurrentCheckpoint() (*checkpoint.Checkpoint, error) {
	if !h.enabled {
		return nil, ErrCheckpointingDisabled
	}

	// Use a background context since we're just reading data
	// The harness would need to pass ctx through if cancellation is needed
	ctx := contextWithoutCancel()

	cp, err := h.checkpointer.GetLatestCheckpoint(ctx, h.threadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current checkpoint: %w", err)
	}

	return cp, nil
}

// CreateCheckpoint creates an explicit checkpoint with the current execution state.
func (h *HarnessCheckpointMethods) CreateCheckpoint(label string) (*checkpoint.Checkpoint, error) {
	if !h.enabled {
		return nil, ErrCheckpointingDisabled
	}

	// Creating a checkpoint requires access to current execution state
	// This would typically be called from within the harness where we have access to state
	// For now, we return an error indicating this needs orchestrator coordination
	return nil, fmt.Errorf("CreateCheckpoint must be called through orchestrator: agent-initiated checkpoints not yet implemented")
}

// GetCheckpointHistory retrieves checkpoint history for the current thread.
func (h *HarnessCheckpointMethods) GetCheckpointHistory(limit int) ([]*checkpoint.Checkpoint, error) {
	if !h.enabled {
		return nil, ErrCheckpointingDisabled
	}

	ctx := contextWithoutCancel()

	opts := checkpoint.HistoryOptions{
		Limit:     limit,
		Ascending: false, // Most recent first
	}

	checkpoints, err := h.checkpointer.GetCheckpointHistory(ctx, h.threadID, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get checkpoint history: %w", err)
	}

	return checkpoints, nil
}

// GetPreviousRunCheckpoint retrieves a checkpoint from a previous mission run.
func (h *HarnessCheckpointMethods) GetPreviousRunCheckpoint(runOffset int) (*checkpoint.Checkpoint, error) {
	if !h.enabled {
		return nil, ErrCheckpointingDisabled
	}

	if runOffset < 1 {
		return nil, fmt.Errorf("runOffset must be >= 1 (1 = previous run)")
	}

	// Calculate the target run number
	targetRunNumber := h.runNumber - runOffset
	if targetRunNumber < 1 {
		return nil, fmt.Errorf("no run exists at offset %d (current run: %d)", runOffset, h.runNumber)
	}

	ctx := contextWithoutCancel()

	// List all threads for this mission
	threads, err := h.checkpointer.ListThreads(ctx, h.missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list threads: %w", err)
	}

	// Find the primary thread for the target run
	// Convention: thread metadata contains "run_number" key
	var targetThreadID string
	for _, thread := range threads {
		if thread.Metadata != nil {
			if runNumStr, ok := thread.Metadata["run_number"]; ok {
				// Compare run number (stored as string in metadata)
				if fmt.Sprintf("%d", targetRunNumber) == runNumStr {
					targetThreadID = thread.ID
					break
				}
			}
		}
	}

	if targetThreadID == "" {
		return nil, fmt.Errorf("no thread found for run %d", targetRunNumber)
	}

	// Get the latest checkpoint from that thread
	cp, err := h.checkpointer.GetLatestCheckpoint(ctx, targetThreadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get checkpoint for run %d: %w", targetRunNumber, err)
	}

	return cp, nil
}

// contextWithoutCancel returns a background context for checkpoint operations.
// This is used when we need to perform read operations that shouldn't be cancelled
// by the agent's execution context (e.g., reading historical checkpoints).
func contextWithoutCancel() context.Context {
	return context.Background()
}
