package mission

import (
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MissionRunStatus represents the execution status of a mission run
type MissionRunStatus string

const (
	MissionRunStatusPending   MissionRunStatus = "pending"
	MissionRunStatusRunning   MissionRunStatus = "running"
	MissionRunStatusCompleted MissionRunStatus = "completed"
	MissionRunStatusFailed    MissionRunStatus = "failed"
	MissionRunStatusCancelled MissionRunStatus = "cancelled"
	MissionRunStatusPaused    MissionRunStatus = "paused"
)

// IsTerminal returns true if the status is a terminal state (no further transitions)
func (s MissionRunStatus) IsTerminal() bool {
	switch s {
	case MissionRunStatusCompleted, MissionRunStatusFailed, MissionRunStatusCancelled:
		return true
	default:
		return false
	}
}

// String returns the string representation of MissionRunStatus
func (s MissionRunStatus) String() string {
	return string(s)
}

// MissionRun represents a single execution instance of a mission.
// Multiple runs can exist for the same mission, each tracked with a unique ID.
// This aligns with Neo4j's MissionRun node structure for consistent ID-based queries.
type MissionRun struct {
	// ID is the unique identifier for this run (UUID).
	// This ID is shared between SQLite and Neo4j for consistent lookups.
	ID types.ID `json:"id"`

	// MissionID references the parent mission.
	MissionID types.ID `json:"mission_id"`

	// RunNumber is the sequential run number (1, 2, 3...).
	RunNumber int `json:"run_number"`

	// Status is the current execution status of this run.
	Status MissionRunStatus `json:"status"`

	// Progress represents completion from 0.0 to 1.0.
	Progress float64 `json:"progress"`

	// FindingsCount is the number of findings discovered in this run.
	FindingsCount int `json:"findings_count"`

	// Checkpoint stores state for resume capability.
	Checkpoint *MissionCheckpoint `json:"checkpoint,omitempty"`

	// Error contains error message if the run failed.
	Error string `json:"error,omitempty"`

	// CreatedAt is when the run was created.
	CreatedAt time.Time `json:"created_at"`

	// StartedAt is when execution started.
	StartedAt *time.Time `json:"started_at,omitempty"`

	// CompletedAt is when execution finished.
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// UpdatedAt is when the run was last updated.
	UpdatedAt time.Time `json:"updated_at"`
}

// NewMissionRun creates a new MissionRun with the given mission ID and run number.
func NewMissionRun(missionID types.ID, runNumber int) *MissionRun {
	now := time.Now()
	return &MissionRun{
		ID:        types.NewID(),
		MissionID: missionID,
		RunNumber: runNumber,
		Status:    MissionRunStatusPending,
		Progress:  0.0,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// Validate checks that all required fields are set correctly.
func (r *MissionRun) Validate() error {
	if err := r.ID.Validate(); err != nil {
		return fmt.Errorf("invalid run ID: %w", err)
	}
	if err := r.MissionID.Validate(); err != nil {
		return fmt.Errorf("invalid mission ID: %w", err)
	}
	if r.RunNumber < 1 {
		return fmt.Errorf("run_number must be >= 1, got %d", r.RunNumber)
	}
	if r.Progress < 0 || r.Progress > 1 {
		return fmt.Errorf("progress must be between 0.0 and 1.0, got %f", r.Progress)
	}
	return nil
}

// MarkStarted sets status to running and records the start time.
func (r *MissionRun) MarkStarted() {
	now := time.Now()
	r.Status = MissionRunStatusRunning
	r.StartedAt = &now
	r.UpdatedAt = now
}

// MarkCompleted sets status to completed and records the completion time.
func (r *MissionRun) MarkCompleted() {
	now := time.Now()
	r.Status = MissionRunStatusCompleted
	r.CompletedAt = &now
	r.UpdatedAt = now
}

// MarkFailed sets status to failed with an error message.
func (r *MissionRun) MarkFailed(errMsg string) {
	now := time.Now()
	r.Status = MissionRunStatusFailed
	r.Error = errMsg
	r.CompletedAt = &now
	r.UpdatedAt = now
}

// MarkCancelled sets status to cancelled.
func (r *MissionRun) MarkCancelled() {
	now := time.Now()
	r.Status = MissionRunStatusCancelled
	r.CompletedAt = &now
	r.UpdatedAt = now
}

// MarkPaused sets status to paused.
func (r *MissionRun) MarkPaused() {
	now := time.Now()
	r.Status = MissionRunStatusPaused
	r.UpdatedAt = now
}

// UpdateProgress updates the progress value.
func (r *MissionRun) UpdateProgress(progress float64) {
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	r.Progress = progress
	r.UpdatedAt = time.Now()
}

// IncrementFindings increments the findings count.
func (r *MissionRun) IncrementFindings(count int) {
	r.FindingsCount += count
	r.UpdatedAt = time.Now()
}
