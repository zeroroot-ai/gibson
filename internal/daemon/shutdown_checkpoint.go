package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/types"
	"golang.org/x/sync/errgroup"
)

// ShutdownCheckpointer coordinates checkpointing of active missions during graceful shutdown.
// It ensures that mission state is preserved to Redis before the daemon terminates,
// enabling mission resumption after restart.
type ShutdownCheckpointer struct {
	checkpointer   checkpoint.ThreadedCheckpointer
	missionTracker MissionTracker
	timeout        time.Duration
	logger         *slog.Logger
}

// MissionTracker provides access to active mission state during shutdown.
// This interface allows the checkpointer to query which missions are running
// and retrieve their current execution state for persistence.
type MissionTracker interface {
	// GetActiveMissions returns all currently running missions
	GetActiveMissions() []*ActiveMission

	// GetMissionState returns current execution state for a mission
	GetMissionState(missionID types.ID) (*checkpoint.ExecutionState, error)
}

// ActiveMission represents a mission currently being executed.
// This captures the minimum information needed to checkpoint a mission during shutdown.
type ActiveMission struct {
	MissionID types.ID  // Unique identifier for the mission
	ThreadID  string    // Checkpoint thread ID for this mission
	StartedAt time.Time // When mission execution began
	NodeID    string    // Current node being executed (optional)
}

// NewShutdownCheckpointer creates a new shutdown checkpointer with the given configuration.
// The timeout parameter determines the maximum time allowed to checkpoint all missions
// during shutdown. This should be less than the Kubernetes preStop hook timeout (typically 30s).
func NewShutdownCheckpointer(
	checkpointer checkpoint.ThreadedCheckpointer,
	tracker MissionTracker,
	timeout time.Duration,
) *ShutdownCheckpointer {
	return &ShutdownCheckpointer{
		checkpointer:   checkpointer,
		missionTracker: tracker,
		timeout:        timeout,
		logger:         slog.Default().With("component", "shutdown-checkpointer"),
	}
}

// SetLogger sets a custom logger for the checkpointer.
func (s *ShutdownCheckpointer) SetLogger(logger *slog.Logger) {
	s.logger = logger.With("component", "shutdown-checkpointer")
}

// ShutdownResult captures the results of shutdown checkpointing.
// It provides statistics and error details for observability and debugging.
type ShutdownResult struct {
	TotalMissions     int               // Total number of missions that needed checkpointing
	CheckpointedCount int               // Number of successfully checkpointed missions
	FailedCount       int               // Number of failed checkpoint attempts
	Failures          []ShutdownFailure // Details of failed checkpoint attempts
	Duration          time.Duration     // Total time spent checkpointing
}

// ShutdownFailure captures details of a failed checkpoint attempt.
type ShutdownFailure struct {
	MissionID types.ID // Mission that failed to checkpoint
	ThreadID  string   // Thread ID for the mission
	Error     error    // Error that occurred during checkpointing
}

// OnShutdown checkpoints all active missions within the configured timeout.
// This method is called from the daemon's shutdown handler on SIGTERM/SIGINT.
// It executes checkpoints in parallel for efficiency and returns detailed results.
func (s *ShutdownCheckpointer) OnShutdown(ctx context.Context) *ShutdownResult {
	startTime := time.Now()

	// Query active missions from tracker
	activeMissions := s.missionTracker.GetActiveMissions()
	totalMissions := len(activeMissions)

	s.logCheckpointStart(totalMissions)

	// Handle no active missions case
	if totalMissions == 0 {
		s.logger.Info("no active missions to checkpoint during shutdown")
		return &ShutdownResult{
			TotalMissions:     0,
			CheckpointedCount: 0,
			FailedCount:       0,
			Failures:          []ShutdownFailure{},
			Duration:          time.Since(startTime),
		}
	}

	// Create context with configured timeout
	shutdownCtx, cancel := s.WithTimeout(ctx)
	defer cancel()

	// Checkpoint all missions in parallel
	result := s.checkpointAll(shutdownCtx, activeMissions)
	result.Duration = time.Since(startTime)

	// Log completion summary
	s.logCheckpointComplete(result)

	return result
}

// checkpointAll checkpoints all missions in parallel with timeout.
// Uses errgroup for coordinated parallel execution with error collection.
func (s *ShutdownCheckpointer) checkpointAll(ctx context.Context, missions []*ActiveMission) *ShutdownResult {
	result := &ShutdownResult{
		TotalMissions:     len(missions),
		CheckpointedCount: 0,
		FailedCount:       0,
		Failures:          make([]ShutdownFailure, 0),
	}

	// Use errgroup for parallel execution with context
	g, gctx := errgroup.WithContext(ctx)

	// Mutex to protect result updates
	var mu sync.Mutex

	// Launch checkpoint goroutines for each mission
	for _, mission := range missions {
		// Capture loop variable for goroutine
		m := mission

		g.Go(func() error {
			// Checkpoint the mission
			err := s.checkpointMission(gctx, m)

			// Update result (thread-safe)
			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				result.FailedCount++
				result.Failures = append(result.Failures, ShutdownFailure{
					MissionID: m.MissionID,
					ThreadID:  m.ThreadID,
					Error:     err,
				})
				s.logCheckpointFailure(m, err)
				// Continue with other missions - don't fail fast
				return nil
			}

			result.CheckpointedCount++
			return nil
		})
	}

	// Wait for all checkpoint operations to complete
	// Note: errgroup.Wait() returns the first non-nil error, but we're
	// returning nil from goroutines to ensure all complete
	if err := g.Wait(); err != nil {
		s.logger.Error("unexpected error during parallel checkpointing", "error", err)
	}

	return result
}

// checkpointMission checkpoints a single mission (internal).
// This retrieves the mission's current execution state and persists it
// to the checkpoint store for later resumption.
func (s *ShutdownCheckpointer) checkpointMission(ctx context.Context, mission *ActiveMission) error {
	// Check for context cancellation
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled before checkpoint: %w", err)
	}

	s.logger.Debug("checkpointing mission during shutdown",
		"mission_id", mission.MissionID,
		"thread_id", mission.ThreadID,
		"current_node", mission.NodeID,
	)

	// Get current execution state from mission tracker
	state, err := s.missionTracker.GetMissionState(mission.MissionID)
	if err != nil {
		return fmt.Errorf("failed to get mission state: %w", err)
	}

	if state == nil {
		return fmt.Errorf("mission state is nil")
	}

	// Validate thread ID matches
	if state.ThreadID != mission.ThreadID {
		s.logger.Warn("thread ID mismatch during checkpoint",
			"expected", mission.ThreadID,
			"actual", state.ThreadID,
			"mission_id", mission.MissionID,
		)
		// Use the state's thread ID as it's the source of truth
	}

	// Create checkpoint via threaded checkpointer
	cp, err := s.checkpointer.Checkpoint(ctx, state.ThreadID, state)
	if err != nil {
		return fmt.Errorf("failed to create checkpoint: %w", err)
	}

	s.logger.Info("mission checkpointed successfully during shutdown",
		"mission_id", mission.MissionID,
		"thread_id", mission.ThreadID,
		"checkpoint_id", cp.ID,
		"checkpoint_size", cp.SizeBytes,
	)

	return nil
}

// WithTimeout wraps checkpoint operation with configured timeout.
// Returns a context with timeout and its cancel function.
func (s *ShutdownCheckpointer) WithTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, s.timeout)
}

// RegisterShutdownHandler registers the checkpoint handler with the daemon's shutdown manager.
// This should be called during daemon initialization to ensure checkpoints are
// created before the daemon terminates.
//
// The checkpointer is registered with a priority that ensures it runs after
// the health check is set to unhealthy but before agent disconnection.
func (s *ShutdownCheckpointer) RegisterShutdownHandler(shutdownManager ShutdownManager) {
	shutdownManager.OnShutdown(10, "checkpoint_missions", func(ctx context.Context) error {
		result := s.OnShutdown(ctx)

		// Return error if any checkpoints failed
		if result.FailedCount > 0 {
			return fmt.Errorf("failed to checkpoint %d of %d missions",
				result.FailedCount, result.TotalMissions)
		}

		return nil
	})
}

// ShutdownManager defines the interface for registering shutdown handlers.
// This allows the checkpointer to integrate with the daemon's shutdown coordination.
type ShutdownManager interface {
	// OnShutdown registers a shutdown handler with a priority.
	// Lower priority values execute first. The name is used for logging.
	OnShutdown(priority int, name string, handler func(context.Context) error)
}

// logCheckpointStart logs the start of shutdown checkpointing.
func (s *ShutdownCheckpointer) logCheckpointStart(count int) {
	s.logger.Info("starting shutdown checkpoint of active missions",
		"mission_count", count,
		"timeout", s.timeout,
	)
}

// logCheckpointComplete logs completion of shutdown checkpointing.
func (s *ShutdownCheckpointer) logCheckpointComplete(result *ShutdownResult) {
	if result.FailedCount > 0 {
		s.logger.Warn("shutdown checkpoint completed with failures",
			"total_missions", result.TotalMissions,
			"checkpointed", result.CheckpointedCount,
			"failed", result.FailedCount,
			"duration", result.Duration,
		)

		// Log individual failures for debugging
		for _, failure := range result.Failures {
			s.logger.Error("mission checkpoint failure",
				"mission_id", failure.MissionID,
				"thread_id", failure.ThreadID,
				"error", failure.Error,
			)
		}
	} else {
		s.logger.Info("shutdown checkpoint completed successfully",
			"total_missions", result.TotalMissions,
			"checkpointed", result.CheckpointedCount,
			"duration", result.Duration,
		)
	}
}

// logCheckpointFailure logs a failed checkpoint attempt.
func (s *ShutdownCheckpointer) logCheckpointFailure(mission *ActiveMission, err error) {
	s.logger.Error("failed to checkpoint mission during shutdown",
		"mission_id", mission.MissionID,
		"thread_id", mission.ThreadID,
		"current_node", mission.NodeID,
		"error", err,
	)
}
