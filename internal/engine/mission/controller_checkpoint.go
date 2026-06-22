package mission

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/engine/events"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ControllerCheckpointMethods provides checkpoint-aware mission control operations.
// This struct extends MissionController with pause/resume and recovery capabilities
// using the new checkpoint system for robust state management.
type ControllerCheckpointMethods struct {
	checkpointer  checkpoint.ThreadedCheckpointer
	restorer      checkpoint.StateRestorer
	store         MissionStore
	threadManager checkpoint.ThreadManager
	eventBus      events.EventBus // optional; nil means no-op event emission

	// locksMu protects access to the operationLocks map
	locksMu sync.Mutex
	// operationLocks provides per-mission mutexes to prevent concurrent checkpoint operations
	operationLocks map[types.ID]*sync.Mutex
}

// NewControllerCheckpointMethods creates a new checkpoint methods extension for MissionController.
//
// eventBus is optional — pass nil to disable lifecycle event emission.
func NewControllerCheckpointMethods(
	checkpointer checkpoint.ThreadedCheckpointer,
	restorer checkpoint.StateRestorer,
	store MissionStore,
	threadManager checkpoint.ThreadManager,
	eventBus events.EventBus,
) *ControllerCheckpointMethods {
	return &ControllerCheckpointMethods{
		checkpointer:   checkpointer,
		restorer:       restorer,
		store:          store,
		threadManager:  threadManager,
		eventBus:       eventBus,
		operationLocks: make(map[types.ID]*sync.Mutex),
	}
}

// ResumptionResult contains detailed information about resuming a mission from a checkpoint.
type ResumptionResult struct {
	// State is the restored execution state ready for use
	State *checkpoint.ExecutionState

	// Checkpoint is the checkpoint that was restored from
	Checkpoint *checkpoint.Checkpoint

	// Thread is the execution thread being resumed
	Thread *checkpoint.Thread

	// NodesSkipped is the list of node IDs that were already completed
	NodesSkipped []string

	// NodesToExecute is the list of node IDs remaining to execute
	NodesToExecute []string

	// ResumedAt is when the resumption occurred
	ResumedAt time.Time
}

// IncompleteMission represents a mission that was interrupted and can be recovered.
type IncompleteMission struct {
	// MissionID is the unique identifier for the incomplete mission
	MissionID types.ID

	// LastCheckpoint is the most recent checkpoint for the mission
	LastCheckpoint *checkpoint.Checkpoint

	// InterruptedAt is when the mission was last active
	InterruptedAt time.Time

	// RecoveryOptions lists the available recovery strategies
	RecoveryOptions []RecoveryOption
}

// RecoveryOption describes a possible recovery action for an incomplete mission.
type RecoveryOption struct {
	// Type indicates the recovery strategy (resume, replay, fail)
	Type RecoveryType

	// Description is a human-readable explanation of this recovery option
	Description string

	// CheckpointID is the checkpoint to use for this recovery (if applicable)
	CheckpointID string
}

// RecoveryType defines the type of recovery action to take.
type RecoveryType string

const (
	// RecoveryResume resumes execution from the last checkpoint
	RecoveryResume RecoveryType = "resume"

	// RecoveryReplay replays execution from a specific checkpoint
	RecoveryReplay RecoveryType = "replay"

	// RecoveryFail marks the mission as failed
	RecoveryFail RecoveryType = "fail"
)

// String returns the string representation of RecoveryType.
func (r RecoveryType) String() string {
	return string(r)
}

// PauseWithCheckpoint pauses a mission and creates a checkpoint of its current state.
// This enables resuming the mission later from exactly where it left off.
func (c *ControllerCheckpointMethods) PauseWithCheckpoint(
	ctx context.Context,
	missionID types.ID,
	state *checkpoint.ExecutionState,
) (*checkpoint.Checkpoint, error) {
	// Acquire lock to prevent concurrent pause/resume operations
	unlock, err := c.AcquireLock(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer unlock()

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate inputs
	if state == nil {
		return nil, fmt.Errorf("execution state cannot be nil")
	}
	if state.MissionID != missionID {
		return nil, fmt.Errorf("state mission ID mismatch: expected %s, got %s", missionID, state.MissionID)
	}

	// Get mission to verify it exists and is pausable
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	// Verify mission status allows pausing
	if !mission.Status.CanTransitionTo(MissionStatusPaused) {
		return nil, NewInvalidStateError(mission.Status, MissionStatusPaused)
	}

	// Get or create thread for this mission
	threadID := state.ThreadID
	if threadID == "" {
		// Create a new thread if none exists
		thread, err := c.threadManager.CreateThread(ctx, missionID)
		if err != nil {
			return nil, fmt.Errorf("failed to create thread: %w", err)
		}
		threadID = thread.ID
		state.ThreadID = threadID
	}

	// Create checkpoint
	chkpt, err := c.checkpointer.Checkpoint(ctx, threadID, state)
	if err != nil {
		return nil, fmt.Errorf("failed to create checkpoint: %w", err)
	}

	// Update mission status to paused
	mission.Status = MissionStatusPaused
	mission.CheckpointAt = NewUnixTimePtr(&chkpt.CreatedAt)
	mission.UpdatedAt = NewUnixTimeNow()

	if err := c.store.Update(ctx, mission); err != nil {
		return nil, fmt.Errorf("failed to update mission status: %w", err)
	}

	// Emit paused event
	c.EmitPausedEvent(ctx, missionID, chkpt.ID)

	return chkpt, nil
}

// ResumeFromCheckpoint resumes a mission from its latest checkpoint.
// This is the primary resumption method for paused missions.
func (c *ControllerCheckpointMethods) ResumeFromCheckpoint(
	ctx context.Context,
	missionID types.ID,
) (*ResumptionResult, error) {
	// Acquire lock to prevent concurrent pause/resume operations
	unlock, err := c.AcquireLock(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer unlock()

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Get mission
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	// Verify mission status allows resumption
	if !mission.Status.CanTransitionTo(MissionStatusRunning) {
		return nil, NewInvalidStateError(mission.Status, MissionStatusRunning)
	}

	// List threads for the mission
	threads, err := c.threadManager.ListThreads(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list threads: %w", err)
	}
	if len(threads) == 0 {
		return nil, fmt.Errorf("no threads found for mission %s", missionID)
	}

	// Use the most recently updated thread
	var activeThread *checkpoint.Thread
	for _, thread := range threads {
		if activeThread == nil || thread.UpdatedAt.After(activeThread.UpdatedAt) {
			activeThread = thread
		}
	}

	// Get latest checkpoint for the thread
	chkpt, err := c.checkpointer.GetLatestCheckpoint(ctx, activeThread.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get latest checkpoint: %w", err)
	}
	if chkpt == nil {
		return nil, fmt.Errorf("no checkpoint found for thread %s", activeThread.ID)
	}

	// Restore execution state from checkpoint
	state, err := c.restorer.Restore(ctx, chkpt)
	if err != nil {
		return nil, fmt.Errorf("failed to restore state: %w", err)
	}

	// Build resumption result
	result := &ResumptionResult{
		State:          state,
		Checkpoint:     chkpt,
		Thread:         activeThread,
		NodesSkipped:   checkpoint.IdentifySkippedNodes(chkpt),
		NodesToExecute: checkpoint.BuildPendingQueue(chkpt),
		ResumedAt:      time.Now(),
	}

	// Update mission status to running
	mission.Status = MissionStatusRunning
	mission.StartedAt = NewUnixTimePtrNow()
	mission.UpdatedAt = NewUnixTimeNow()

	if err := c.store.Update(ctx, mission); err != nil {
		return nil, fmt.Errorf("failed to update mission status: %w", err)
	}

	// Emit resumed event
	c.EmitResumedEvent(ctx, missionID, chkpt.ID)

	return result, nil
}

// ResumeFromSpecificCheckpoint resumes a mission from a specific checkpoint ID.
// This is useful for replaying execution from a particular point in time.
func (c *ControllerCheckpointMethods) ResumeFromSpecificCheckpoint(
	ctx context.Context,
	missionID types.ID,
	checkpointID string,
) (*ResumptionResult, error) {
	// Acquire lock to prevent concurrent pause/resume operations
	unlock, err := c.AcquireLock(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer unlock()

	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// Validate checkpoint ID
	if checkpointID == "" {
		return nil, fmt.Errorf("checkpoint ID cannot be empty")
	}

	// Get mission
	mission, err := c.store.Get(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get mission: %w", err)
	}

	// Verify mission status allows resumption
	if !mission.Status.CanTransitionTo(MissionStatusRunning) {
		return nil, NewInvalidStateError(mission.Status, MissionStatusRunning)
	}

	// Get the checkpoint to find its thread
	chkpt, err := c.checkpointer.GetLatestCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to get checkpoint: %w", err)
	}
	if chkpt == nil {
		return nil, fmt.Errorf("checkpoint %s not found", checkpointID)
	}

	// Verify checkpoint belongs to this mission
	if chkpt.MissionID != missionID {
		return nil, fmt.Errorf("checkpoint %s does not belong to mission %s", checkpointID, missionID)
	}

	// Get the thread
	thread, err := c.threadManager.GetThread(ctx, chkpt.ThreadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get thread: %w", err)
	}

	// Restore execution state from the specific checkpoint
	state, err := c.restorer.RestoreFromID(ctx, chkpt.ThreadID, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to restore state: %w", err)
	}

	// Build resumption result
	result := &ResumptionResult{
		State:          state,
		Checkpoint:     chkpt,
		Thread:         thread,
		NodesSkipped:   checkpoint.IdentifySkippedNodes(chkpt),
		NodesToExecute: checkpoint.BuildPendingQueue(chkpt),
		ResumedAt:      time.Now(),
	}

	// Update mission status to running
	mission.Status = MissionStatusRunning
	mission.StartedAt = NewUnixTimePtrNow()
	mission.UpdatedAt = NewUnixTimeNow()

	if err := c.store.Update(ctx, mission); err != nil {
		return nil, fmt.Errorf("failed to update mission status: %w", err)
	}

	// Emit resumed event
	c.EmitResumedEvent(ctx, missionID, checkpointID)

	return result, nil
}

// DiscoverIncompleteMissions finds missions that were interrupted and can be recovered.
// This is typically called at startup to detect missions that need recovery.
func (c *ControllerCheckpointMethods) DiscoverIncompleteMissions(
	ctx context.Context,
) ([]*IncompleteMission, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	// List all non-terminal missions
	filter := &MissionFilter{
		// Exclude terminal states
		ExcludeStatus: []MissionStatus{
			MissionStatusCompleted,
			MissionStatusFailed,
			MissionStatusCancelled,
		},
	}

	missions, err := c.store.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list missions: %w", err)
	}

	incomplete := make([]*IncompleteMission, 0)

	for _, mission := range missions {
		// Get threads for this mission
		threads, err := c.threadManager.ListThreads(ctx, mission.ID)
		if err != nil {
			// Log error but continue processing other missions
			continue
		}

		if len(threads) == 0 {
			// No threads means no checkpoints, skip
			continue
		}

		// Find the most recent thread
		var activeThread *checkpoint.Thread
		for _, thread := range threads {
			if activeThread == nil || thread.UpdatedAt.After(activeThread.UpdatedAt) {
				activeThread = thread
			}
		}

		// Get latest checkpoint for the thread
		chkpt, err := c.checkpointer.GetLatestCheckpoint(ctx, activeThread.ID)
		if err != nil || chkpt == nil {
			// No checkpoint available, skip
			continue
		}

		// Build recovery options
		options := []RecoveryOption{
			{
				Type:         RecoveryResume,
				Description:  "Resume execution from the last checkpoint",
				CheckpointID: chkpt.ID,
			},
			{
				Type:         RecoveryReplay,
				Description:  "Replay execution from a specific checkpoint",
				CheckpointID: chkpt.ID,
			},
			{
				Type:        RecoveryFail,
				Description: "Mark the mission as failed",
			},
		}

		incomplete = append(incomplete, &IncompleteMission{
			MissionID:       mission.ID,
			LastCheckpoint:  chkpt,
			InterruptedAt:   mission.UpdatedAt.Time,
			RecoveryOptions: options,
		})
	}

	return incomplete, nil
}

// ExecuteRecovery performs the selected recovery option for an incomplete mission.
func (c *ControllerCheckpointMethods) ExecuteRecovery(
	ctx context.Context,
	missionID types.ID,
	option RecoveryOption,
) (*ResumptionResult, error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	switch option.Type {
	case RecoveryResume:
		// Resume from last checkpoint
		return c.ResumeFromCheckpoint(ctx, missionID)

	case RecoveryReplay:
		// Replay from specific checkpoint
		if option.CheckpointID == "" {
			return nil, fmt.Errorf("checkpoint ID required for replay recovery")
		}
		return c.ResumeFromSpecificCheckpoint(ctx, missionID, option.CheckpointID)

	case RecoveryFail:
		// Mark mission as failed
		mission, err := c.store.Get(ctx, missionID)
		if err != nil {
			return nil, fmt.Errorf("failed to get mission: %w", err)
		}

		mission.Status = MissionStatusFailed
		mission.Error = "Mission marked as failed during recovery"
		mission.CompletedAt = NewUnixTimePtrNow()
		mission.UpdatedAt = NewUnixTimeNow()

		if err := c.store.Update(ctx, mission); err != nil {
			return nil, fmt.Errorf("failed to update mission: %w", err)
		}

		return nil, nil

	default:
		return nil, fmt.Errorf("unknown recovery type: %s", option.Type)
	}
}

// AcquireLock acquires a lock for checkpoint operations on a mission.
// Returns an unlock function that must be called to release the lock.
// This prevents concurrent pause/resume operations on the same mission.
func (c *ControllerCheckpointMethods) AcquireLock(
	ctx context.Context,
	missionID types.ID,
) (func(), error) {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	c.locksMu.Lock()
	mu, exists := c.operationLocks[missionID]
	if !exists {
		mu = &sync.Mutex{}
		c.operationLocks[missionID] = mu
	}
	c.locksMu.Unlock()

	// Try to acquire the lock (blocking)
	// Note: In a production system, you might want a timeout here
	mu.Lock()

	// Return unlock function
	return func() {
		mu.Unlock()
	}, nil
}

// EmitPausedEvent emits a mission.paused event to the event bus.
// Callers should invoke this after a checkpoint has been successfully saved.
// If the event bus is nil or Publish returns an error, the error is logged as
// a WARN and the method returns — it must never block mission control flow.
func (c *ControllerCheckpointMethods) EmitPausedEvent(
	ctx context.Context,
	missionID types.ID,
	checkpointID string,
) {
	if c.eventBus == nil {
		return
	}
	evt := events.Event{
		Type:      events.EventMissionPaused,
		MissionID: missionID,
		Timestamp: time.Now(),
		Payload:   map[string]any{"checkpoint_id": checkpointID},
	}
	if err := c.eventBus.Publish(ctx, evt); err != nil {
		slog.WarnContext(ctx, "failed to publish mission.paused event",
			slog.String("mission_id", missionID.String()),
			slog.String("checkpoint_id", checkpointID),
			slog.String("error", err.Error()),
		)
	}
}

// EmitResumedEvent emits a mission.resumed event to the event bus.
// Callers should invoke this after a mission has been successfully resumed from
// a checkpoint. Errors from Publish are logged as WARN and do not propagate.
func (c *ControllerCheckpointMethods) EmitResumedEvent(
	ctx context.Context,
	missionID types.ID,
	checkpointID string,
) {
	if c.eventBus == nil {
		return
	}
	evt := events.Event{
		Type:      events.EventMissionResumed,
		MissionID: missionID,
		Timestamp: time.Now(),
		Payload:   map[string]any{"checkpoint_id": checkpointID},
	}
	if err := c.eventBus.Publish(ctx, evt); err != nil {
		slog.WarnContext(ctx, "failed to publish mission.resumed event",
			slog.String("mission_id", missionID.String()),
			slog.String("checkpoint_id", checkpointID),
			slog.String("error", err.Error()),
		)
	}
}
