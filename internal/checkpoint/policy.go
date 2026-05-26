package checkpoint

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// CheckpointPolicy defines the interface for checkpoint retention and creation policies.
// Policies control when checkpoints are created and how long they are retained based
// on mission status, checkpoint type, and configuration.
type CheckpointPolicy interface {
	// ShouldCheckpoint determines if a checkpoint should be created for this event.
	// Returns true if a checkpoint should be created based on the policy configuration.
	ShouldCheckpoint(ctx context.Context, event CheckpointEvent) bool

	// GetRetentionConfig returns the retention configuration based on mission status.
	// Different retention rules can be applied for running, completed, or failed missions.
	GetRetentionConfig(missionStatus MissionStatus) RetentionConfig

	// ApplyRetention applies the retention policy to a thread's checkpoints.
	// This removes checkpoints that should be deleted based on the retention rules.
	// Returns an error if the cleanup fails.
	ApplyRetention(ctx context.Context, threadID string, status MissionStatus) error
}

// CheckpointEvent represents an event that may trigger checkpoint creation.
// Events can be super-steps (LLM interactions), explicit checkpoint requests,
// approval requests, or system shutdowns.
type CheckpointEvent struct {
	// Type indicates the kind of event triggering checkpoint consideration.
	Type CheckpointEventType

	// NodeID is the mission node associated with this event.
	NodeID string

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Metadata provides additional context for the event.
	Metadata map[string]string
}

// CheckpointEventType categorizes different checkpoint trigger events.
type CheckpointEventType string

const (
	// CheckpointEventSuperStep is triggered after each LLM interaction/super-step.
	// This is the primary checkpoint frequency for mission execution.
	CheckpointEventSuperStep CheckpointEventType = "super_step"

	// CheckpointEventExplicit is triggered by an explicit checkpoint request.
	// Agents or operators can request checkpoints at important milestones.
	CheckpointEventExplicit CheckpointEventType = "explicit"

	// CheckpointEventApproval is triggered when requesting human approval.
	// Always creates a checkpoint to enable resumption after approval.
	CheckpointEventApproval CheckpointEventType = "approval"

	// CheckpointEventShutdown is triggered during graceful shutdown.
	// Creates a checkpoint to enable resumption after restart.
	CheckpointEventShutdown CheckpointEventType = "shutdown"

	// CheckpointEventError is triggered when an error occurs.
	// Creates a checkpoint before failure for debugging and recovery.
	CheckpointEventError CheckpointEventType = "error"

	// CheckpointEventBranch is triggered when creating a thread branch.
	// Creates a checkpoint at the branch point for alternate path exploration.
	CheckpointEventBranch CheckpointEventType = "branch"
)

// String returns the string representation of CheckpointEventType.
func (t CheckpointEventType) String() string {
	return string(t)
}

// RetentionMode defines how checkpoints are retained for a mission.
type RetentionMode string

const (
	// RetentionFinalOnly keeps only the final checkpoint and deletes all intermediate ones.
	// Useful for completed missions where only the final state matters.
	RetentionFinalOnly RetentionMode = "final_only"

	// RetentionAll keeps all checkpoints indefinitely (subject to TTL).
	// Useful for missions requiring full audit trails or debugging.
	RetentionAll RetentionMode = "all"

	// RetentionErrorOnly keeps all checkpoints for failed missions, final only for successful.
	// Balances storage costs with debugging needs.
	RetentionErrorOnly RetentionMode = "error_only"

	// RetentionNone deletes all checkpoints immediately after mission completion.
	// Useful for ephemeral missions where state persistence is not needed.
	RetentionNone RetentionMode = "none"

	// RetentionLabeled keeps only explicitly labeled checkpoints and the final one.
	// Useful for milestone-based retention (e.g., "pre_exploit", "post_pivot").
	RetentionLabeled RetentionMode = "labeled"
)

// String returns the string representation of RetentionMode.
func (m RetentionMode) String() string {
	return string(m)
}

// RetentionConfig defines the retention parameters for checkpoints.
// Configuration can vary based on mission status (running, completed, failed).
type RetentionConfig struct {
	// Mode specifies the retention strategy to apply.
	Mode RetentionMode

	// TTL is the time-to-live for checkpoints. After this duration,
	// checkpoints are eligible for deletion regardless of mode.
	// Zero means no TTL (keep indefinitely).
	TTL time.Duration

	// MaxCount limits the maximum number of checkpoints per thread.
	// When exceeded, oldest checkpoints are deleted (subject to mode rules).
	// Zero means unlimited.
	MaxCount int

	// MinInterval is the minimum time between auto-checkpoints.
	// Prevents excessive checkpoint creation during rapid execution.
	// Zero means no minimum interval.
	MinInterval time.Duration
}

// MissionStatus represents the current state of a mission.
// This determines which retention policy to apply.
type MissionStatus string

const (
	// MissionStatusRunning indicates the mission is actively executing.
	// Checkpoints are never deleted for running missions.
	MissionStatusRunning MissionStatus = "running"

	// MissionStatusCompleted indicates the mission finished successfully.
	// Retention policy determines which checkpoints to keep.
	MissionStatusCompleted MissionStatus = "completed"

	// MissionStatusFailed indicates the mission failed during execution.
	// Typically retains more checkpoints for debugging.
	MissionStatusFailed MissionStatus = "failed"

	// MissionStatusCancelled indicates the mission was cancelled by user.
	// May apply different retention rules than failed missions.
	MissionStatusCancelled MissionStatus = "cancelled"

	// MissionStatusPaused indicates the mission is paused (e.g., waiting for approval).
	// Treated similarly to running for retention purposes.
	MissionStatusPaused MissionStatus = "paused"
)

// String returns the string representation of MissionStatus.
func (s MissionStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the mission status is terminal (won't execute further).
func (s MissionStatus) IsTerminal() bool {
	return s == MissionStatusCompleted ||
		s == MissionStatusFailed ||
		s == MissionStatusCancelled
}

// PolicyConfig configures the checkpoint policy behavior.
// Provides defaults and per-status overrides for fine-grained control.
type PolicyConfig struct {
	// AutoCheckpoint enables automatic checkpoint creation at super-steps.
	// When false, only explicit checkpoint requests create checkpoints.
	AutoCheckpoint bool

	// DefaultMode is the default retention mode for missions.
	DefaultMode RetentionMode

	// DefaultTTL is the default time-to-live for checkpoints (7 days default).
	DefaultTTL time.Duration

	// MaxCheckpoints is the default maximum checkpoints per thread (100 default).
	MaxCheckpoints int

	// MinCheckpointInterval is the minimum time between auto-checkpoints (30s default).
	MinCheckpointInterval time.Duration

	// CompletedRetention specifies retention for successfully completed missions.
	// Overrides default configuration when mission completes successfully.
	CompletedRetention RetentionConfig

	// FailedRetention specifies retention for failed missions.
	// Typically more generous to enable debugging.
	FailedRetention RetentionConfig

	// CancelledRetention specifies retention for cancelled missions.
	// Can differ from failed missions if user cancellation is intentional.
	CancelledRetention RetentionConfig

	// PausedRetention specifies retention for paused missions.
	// Usually the same as running missions.
	PausedRetention RetentionConfig

	// PerMissionOverrides allows overriding policy on a per-mission basis.
	// Maps mission ID to custom retention config.
	PerMissionOverrides map[types.ID]RetentionConfig
}

// DefaultPolicyConfig returns a sensible default policy configuration.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		AutoCheckpoint:        true,
		DefaultMode:           RetentionErrorOnly,
		DefaultTTL:            7 * 24 * time.Hour, // 7 days
		MaxCheckpoints:        100,
		MinCheckpointInterval: 30 * time.Second,
		CompletedRetention: RetentionConfig{
			Mode:        RetentionFinalOnly,
			TTL:         7 * 24 * time.Hour,
			MaxCount:    10,
			MinInterval: 30 * time.Second,
		},
		FailedRetention: RetentionConfig{
			Mode:        RetentionAll,
			TTL:         30 * 24 * time.Hour, // 30 days for debugging
			MaxCount:    0,                   // Unlimited
			MinInterval: 30 * time.Second,
		},
		CancelledRetention: RetentionConfig{
			Mode:        RetentionFinalOnly,
			TTL:         3 * 24 * time.Hour, // 3 days
			MaxCount:    5,
			MinInterval: 30 * time.Second,
		},
		PausedRetention: RetentionConfig{
			Mode:        RetentionAll,
			TTL:         0, // No TTL while paused
			MaxCount:    0, // Unlimited
			MinInterval: 30 * time.Second,
		},
		PerMissionOverrides: make(map[types.ID]RetentionConfig),
	}
}

// Note: CheckpointStore interface is defined in threaded_checkpointer.go
// This policy adapts to use the existing CheckpointStore interface methods:
// - SaveCheckpoint (instead of Save)
// - GetCheckpoint (instead of Load)
// - ListCheckpoints (instead of ListByThread)
// - GetLatestCheckpoint (instead of GetLatest)
// - DeleteCheckpoint (instead of Delete)
// - DeleteThreadCheckpoints (batch delete)

// DefaultCheckpointPolicy implements the CheckpointPolicy interface with
// configurable retention rules and automatic cleanup.
type DefaultCheckpointPolicy struct {
	// store is the checkpoint storage backend.
	store CheckpointStore

	// config contains the policy configuration.
	config PolicyConfig

	// lastCheckpointTime tracks the last checkpoint time per thread for rate limiting.
	lastCheckpointTime map[string]time.Time
}

// NewCheckpointPolicy creates a new checkpoint policy with the given configuration.
func NewCheckpointPolicy(store CheckpointStore, config PolicyConfig) *DefaultCheckpointPolicy {
	return &DefaultCheckpointPolicy{
		store:              store,
		config:             config,
		lastCheckpointTime: make(map[string]time.Time),
	}
}

// ShouldCheckpoint determines if a checkpoint should be created for the given event.
func (p *DefaultCheckpointPolicy) ShouldCheckpoint(ctx context.Context, event CheckpointEvent) bool {
	switch event.Type {
	case CheckpointEventApproval, CheckpointEventShutdown, CheckpointEventError, CheckpointEventBranch:
		// Always checkpoint for critical events
		return true

	case CheckpointEventExplicit:
		// Always honor explicit checkpoint requests
		return true

	case CheckpointEventSuperStep:
		// Check if auto-checkpoint is enabled
		if !p.config.AutoCheckpoint {
			return false
		}

		// Check minimum interval rate limiting
		if p.config.MinCheckpointInterval > 0 {
			// Extract thread ID from metadata if available
			threadID := event.Metadata["thread_id"]
			if threadID != "" {
				lastTime, exists := p.lastCheckpointTime[threadID]
				if exists && time.Since(lastTime) < p.config.MinCheckpointInterval {
					return false
				}
			}
		}

		return true

	default:
		// Unknown event type, don't checkpoint
		return false
	}
}

// GetRetentionConfig returns the retention configuration for a given mission status.
func (p *DefaultCheckpointPolicy) GetRetentionConfig(missionStatus MissionStatus) RetentionConfig {
	switch missionStatus {
	case MissionStatusCompleted:
		return p.config.CompletedRetention

	case MissionStatusFailed:
		return p.config.FailedRetention

	case MissionStatusCancelled:
		return p.config.CancelledRetention

	case MissionStatusPaused:
		return p.config.PausedRetention

	case MissionStatusRunning:
		// For running missions, use default with no TTL
		return RetentionConfig{
			Mode:        p.config.DefaultMode,
			TTL:         0, // Never delete checkpoints for running missions
			MaxCount:    p.config.MaxCheckpoints,
			MinInterval: p.config.MinCheckpointInterval,
		}

	default:
		// Fallback to default
		return RetentionConfig{
			Mode:        p.config.DefaultMode,
			TTL:         p.config.DefaultTTL,
			MaxCount:    p.config.MaxCheckpoints,
			MinInterval: p.config.MinCheckpointInterval,
		}
	}
}

// ApplyRetention applies the retention policy to a thread's checkpoints.
// This performs the actual cleanup based on the retention rules.
func (p *DefaultCheckpointPolicy) ApplyRetention(ctx context.Context, threadID string, status MissionStatus) error {
	// Never delete checkpoints for running or paused missions
	if status == MissionStatusRunning || status == MissionStatusPaused {
		return nil
	}

	// Get the retention configuration for this mission status
	config := p.GetRetentionConfig(status)

	// List all checkpoints for the thread
	checkpoints, err := p.store.ListCheckpoints(ctx, threadID, HistoryOptions{})
	if err != nil {
		return fmt.Errorf("failed to list checkpoints for thread %s: %w", threadID, err)
	}

	if len(checkpoints) == 0 {
		return nil
	}

	// Sort checkpoints by creation time (oldest first)
	sort.Slice(checkpoints, func(i, j int) bool {
		return checkpoints[i].CreatedAt.Before(checkpoints[j].CreatedAt)
	})

	// Apply retention mode
	toDelete := p.selectCheckpointsToDelete(checkpoints, config)

	// Delete selected checkpoints
	if len(toDelete) > 0 {
		for _, checkpointID := range toDelete {
			if err := p.store.DeleteCheckpoint(ctx, checkpointID); err != nil {
				return fmt.Errorf("failed to delete checkpoint %s: %w", checkpointID, err)
			}
		}
	}

	return nil
}

// selectCheckpointsToDelete determines which checkpoints to delete based on retention config.
func (p *DefaultCheckpointPolicy) selectCheckpointsToDelete(checkpoints []*Checkpoint, config RetentionConfig) []string {
	if len(checkpoints) == 0 {
		return nil
	}

	now := time.Now()
	toDelete := []string{}

	// First pass: collect checkpoints to delete based on mode
	switch config.Mode {
	case RetentionNone:
		// Delete all checkpoints
		for _, cp := range checkpoints {
			toDelete = append(toDelete, cp.ID)
		}
		return toDelete

	case RetentionFinalOnly:
		// Keep only the last checkpoint, delete all others
		for i := 0; i < len(checkpoints)-1; i++ {
			toDelete = append(toDelete, checkpoints[i].ID)
		}

	case RetentionLabeled:
		// Keep only labeled checkpoints and the final one
		for i := 0; i < len(checkpoints)-1; i++ {
			if checkpoints[i].Label == "" {
				toDelete = append(toDelete, checkpoints[i].ID)
			}
		}

	case RetentionErrorOnly:
		// This is handled at the mission level, not checkpoint level
		// If we're here, it means we should apply final_only logic
		for i := 0; i < len(checkpoints)-1; i++ {
			toDelete = append(toDelete, checkpoints[i].ID)
		}

	case RetentionAll:
		// Don't delete based on mode, but may delete based on TTL/MaxCount below
	}

	// Second pass: apply TTL if configured
	if config.TTL > 0 {
		expiry := now.Add(-config.TTL)
		for _, cp := range checkpoints {
			if cp.CreatedAt.Before(expiry) && !contains(toDelete, cp.ID) {
				// Don't delete the last checkpoint due to TTL
				if cp.ID != checkpoints[len(checkpoints)-1].ID {
					toDelete = append(toDelete, cp.ID)
				}
			}
		}
	}

	// Third pass: apply MaxCount if configured
	if config.MaxCount > 0 && len(checkpoints) > config.MaxCount {
		// Calculate how many to delete to get under MaxCount
		excessCount := len(checkpoints) - config.MaxCount

		// Delete oldest checkpoints that aren't already marked for deletion
		deleted := 0
		for i := 0; i < len(checkpoints) && deleted < excessCount; i++ {
			if !contains(toDelete, checkpoints[i].ID) {
				// Don't delete the last checkpoint due to MaxCount
				if checkpoints[i].ID != checkpoints[len(checkpoints)-1].ID {
					toDelete = append(toDelete, checkpoints[i].ID)
					deleted++
				}
			}
		}
	}

	return toDelete
}

// RecordCheckpoint updates internal tracking when a checkpoint is created.
// This enables rate limiting based on MinCheckpointInterval.
func (p *DefaultCheckpointPolicy) RecordCheckpoint(threadID string, timestamp time.Time) {
	p.lastCheckpointTime[threadID] = timestamp
}

// GetMissionOverride returns the per-mission retention override if configured.
func (p *DefaultCheckpointPolicy) GetMissionOverride(missionID types.ID) (RetentionConfig, bool) {
	config, exists := p.config.PerMissionOverrides[missionID]
	return config, exists
}

// SetMissionOverride sets a per-mission retention override.
func (p *DefaultCheckpointPolicy) SetMissionOverride(missionID types.ID, config RetentionConfig) {
	if p.config.PerMissionOverrides == nil {
		p.config.PerMissionOverrides = make(map[types.ID]RetentionConfig)
	}
	p.config.PerMissionOverrides[missionID] = config
}

// ClearMissionOverride removes a per-mission retention override.
func (p *DefaultCheckpointPolicy) ClearMissionOverride(missionID types.ID) {
	delete(p.config.PerMissionOverrides, missionID)
}

// contains checks if a string slice contains a given string.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// NewCheckpointEvent creates a new checkpoint event.
func NewCheckpointEvent(eventType CheckpointEventType, nodeID string) CheckpointEvent {
	return CheckpointEvent{
		Type:      eventType,
		NodeID:    nodeID,
		Timestamp: time.Now(),
		Metadata:  make(map[string]string),
	}
}

// WithMetadata adds metadata to a checkpoint event.
func (e CheckpointEvent) WithMetadata(key, value string) CheckpointEvent {
	if e.Metadata == nil {
		e.Metadata = make(map[string]string)
	}
	e.Metadata[key] = value
	return e
}
