package mission

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// MissionStatusInfo provides detailed status information about a mission.
// This is a client-side representation suitable for returning to agents.
type MissionStatusInfo struct {
	// Status is the current execution state.
	Status MissionStatus

	// Progress is the completion percentage (0.0 to 1.0).
	Progress float64

	// Phase is the current mission phase or step name.
	Phase string

	// FindingCounts maps finding severity levels to counts.
	FindingCounts map[string]int

	// TokenUsage is the cumulative number of LLM tokens consumed.
	TokenUsage int64

	// Duration is the elapsed execution time.
	Duration time.Duration

	// Error contains error details if the mission failed.
	Error string
}

// Run queues a mission for execution via the orchestrator.
// This method is non-blocking - it starts the mission in a goroutine and returns immediately.
// Use GetStatus or WaitForCompletion to monitor progress.
//
// The mission must be in pending status to be run. The orchestrator is invoked
// in a separate goroutine to avoid blocking the caller.
func (c *MissionClient) Run(ctx context.Context, missionID string) error {
	// Start tracing span
	ctx, span := c.tracer.Start(ctx, "mission.client.Run")
	defer span.End()

	// Parse mission ID
	id, err := types.ParseID(missionID)
	if err != nil {
		c.logger.ErrorContext(ctx, "invalid mission ID",
			slog.String("mission_id", missionID),
			slog.String("error", err.Error()))
		return fmt.Errorf("invalid mission ID: %w", err)
	}

	// Load mission from store
	mission, err := c.store.Get(ctx, id)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to load mission",
			slog.String("mission_id", missionID),
			slog.String("error", err.Error()))
		return fmt.Errorf("failed to load mission: %w", err)
	}

	// Validate mission can be run
	if !mission.Status.CanTransitionTo(MissionStatusRunning) {
		c.logger.WarnContext(ctx, "mission cannot transition to running state",
			slog.String("mission_id", missionID),
			slog.String("current_status", string(mission.Status)))
		return NewInvalidStateError(mission.Status, MissionStatusRunning)
	}

	// Start mission execution in background goroutine
	// We detach from the parent context to allow the mission to continue
	// even if the caller's context is cancelled
	go func() {
		// Create a new context for mission execution
		// This ensures the mission continues even if the caller cancels
		execCtx := context.Background()

		c.logger.InfoContext(execCtx, "starting mission execution",
			slog.String("mission_id", missionID),
			slog.String("mission_name", mission.Name))

		// Execute the mission via the orchestrator
		result, err := c.orchestrator.Execute(execCtx, mission)
		if err != nil {
			c.logger.ErrorContext(execCtx, "mission execution failed",
				slog.String("mission_id", missionID),
				slog.String("error", err.Error()))
			// The orchestrator should have updated the mission status to failed
			return
		}

		c.logger.InfoContext(execCtx, "mission execution completed",
			slog.String("mission_id", missionID),
			slog.String("status", string(result.Status)),
			slog.Int("findings_count", len(result.FindingIDs)))
	}()

	c.logger.InfoContext(ctx, "mission queued for execution",
		slog.String("mission_id", missionID))

	return nil
}

// GetStatus returns the current status and progress information for a mission.
// This method loads the mission from the store and converts it to a status info structure.
func (c *MissionClient) GetStatus(ctx context.Context, missionID string) (*MissionStatusInfo, error) {
	// Start tracing span
	ctx, span := c.tracer.Start(ctx, "mission.client.GetStatus")
	defer span.End()

	// Parse mission ID
	id, err := types.ParseID(missionID)
	if err != nil {
		c.logger.ErrorContext(ctx, "invalid mission ID",
			slog.String("mission_id", missionID),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	// Load mission from store
	mission, err := c.store.Get(ctx, id)
	if err != nil {
		c.logger.ErrorContext(ctx, "failed to load mission",
			slog.String("mission_id", missionID),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("failed to load mission: %w", err)
	}

	// Build status info from mission
	statusInfo := &MissionStatusInfo{
		Status:        mission.Status,
		Progress:      mission.Progress,
		Error:         mission.Error,
		FindingCounts: make(map[string]int),
		TokenUsage:    0,
		Duration:      0,
	}

	// Extract phase from checkpoint if available
	if mission.Checkpoint != nil && len(mission.Checkpoint.PendingNodes) > 0 {
		// Use the first pending node as the current phase
		statusInfo.Phase = mission.Checkpoint.PendingNodes[0]
	}

	// Extract metrics if available
	if mission.Metrics != nil {
		statusInfo.TokenUsage = mission.Metrics.TotalTokens
		statusInfo.FindingCounts = mission.Metrics.FindingsBySeverity

		// Calculate duration
		if !mission.StartedAt.IsNil() {
			if !mission.CompletedAt.IsNil() {
				statusInfo.Duration = mission.CompletedAt.Time.Sub(*mission.StartedAt.Time)
			} else {
				// Mission is still running, calculate elapsed time
				statusInfo.Duration = time.Since(*mission.StartedAt.Time)
			}
		}
	}

	c.logger.DebugContext(ctx, "retrieved mission status",
		slog.String("mission_id", missionID),
		slog.String("status", string(statusInfo.Status)),
		slog.Float64("progress", statusInfo.Progress))

	return statusInfo, nil
}

// WaitForCompletion blocks until the mission reaches a terminal state or the timeout expires.
// This method polls the mission status periodically until completion.
//
// Returns the mission result if completed successfully, or an error if:
// - The timeout expires before completion
// - The mission fails during execution
// - There's an error checking the mission status
//
// The timeout duration specifies how long to wait. A zero timeout means wait indefinitely.
func (c *MissionClient) WaitForCompletion(ctx context.Context, missionID string, timeout time.Duration) (*MissionResult, error) {
	// Start tracing span
	ctx, span := c.tracer.Start(ctx, "mission.client.WaitForCompletion")
	defer span.End()

	// Parse mission ID
	id, err := types.ParseID(missionID)
	if err != nil {
		c.logger.ErrorContext(ctx, "invalid mission ID",
			slog.String("mission_id", missionID),
			slog.String("error", err.Error()))
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	c.logger.InfoContext(ctx, "waiting for mission completion",
		slog.String("mission_id", missionID),
		slog.Duration("timeout", timeout))

	// Create a context with timeout if specified
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Poll interval for checking mission status
	pollInterval := 1 * time.Second
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	// Poll until mission completes or context is cancelled
	for {
		select {
		case <-ctx.Done():
			// Context cancelled or timeout expired
			c.logger.WarnContext(ctx, "wait for completion cancelled or timed out",
				slog.String("mission_id", missionID),
				slog.String("error", ctx.Err().Error()))
			return nil, fmt.Errorf("wait for completion: %w", ctx.Err())

		case <-ticker.C:
			// Check mission status
			mission, err := c.store.Get(ctx, id)
			if err != nil {
				c.logger.ErrorContext(ctx, "failed to load mission while waiting",
					slog.String("mission_id", missionID),
					slog.String("error", err.Error()))
				return nil, fmt.Errorf("failed to check mission status: %w", err)
			}

			// Check if mission reached a terminal state
			if mission.Status.IsTerminal() {
				c.logger.InfoContext(ctx, "mission reached terminal state",
					slog.String("mission_id", missionID),
					slog.String("status", string(mission.Status)))

				// Build and return mission result
				result := &MissionResult{
					MissionID:     mission.ID,
					Status:        mission.Status,
					Metrics:       mission.Metrics,
					FindingIDs:    []types.ID{}, // Would need to query finding store for full list
					MissionResult: map[string]any{},
					Error:         mission.Error,
				}

				if !mission.CompletedAt.IsNil() {
					result.CompletedAt = *mission.CompletedAt.Time
				} else {
					result.CompletedAt = time.Now()
				}

				// Add checkpoint results if available
				if mission.Checkpoint != nil && mission.Checkpoint.NodeResults != nil {
					result.MissionResult = mission.Checkpoint.NodeResults
				}

				return result, nil
			}

			// Log progress periodically
			c.logger.DebugContext(ctx, "mission still running",
				slog.String("mission_id", missionID),
				slog.String("status", string(mission.Status)),
				slog.Float64("progress", mission.Progress))
		}
	}
}
