package checkpoint

import (
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Thread represents a branching execution path in mission execution.
// Threads enable parallel exploration of different execution strategies,
// parameter sets, or decision paths from a common checkpoint.
//
// The threading model supports:
//   - Primary thread: The main execution path (typically named "main" or "primary")
//   - Branch threads: Alternative paths forked from a checkpoint
//   - Merge points: Where branches can be evaluated and the best selected
//
// Thread branching is useful for:
//   - Trying different agent parameters or tool selections
//   - Exploring alternative decision paths (e.g., different exploit strategies)
//   - A/B testing different mission approaches
//   - Parallel hypothesis exploration
type Thread struct {
	// ID is a unique ULID identifier for this thread.
	// ULIDs provide time-ordering and are lexicographically sortable.
	ID string `json:"id" msgpack:"id"`

	// MissionID is the mission this thread belongs to.
	// All threads for a mission share the same mission ID.
	MissionID types.ID `json:"mission_id" msgpack:"mission_id"`

	// ParentThread is the thread ID this thread was branched from.
	// Empty for the primary thread. Creates a thread hierarchy.
	ParentThread string `json:"parent_thread,omitempty" msgpack:"parent_thread,omitempty"`

	// BranchCheckpointID identifies the checkpoint where this thread branched off.
	// This is the "fork point" in the execution history.
	BranchCheckpointID string `json:"branch_checkpoint_id,omitempty" msgpack:"branch_checkpoint_id,omitempty"`

	// CreatedAt is the timestamp when this thread was created.
	CreatedAt time.Time `json:"created_at" msgpack:"created_at"`

	// UpdatedAt is the timestamp of the last update to this thread.
	UpdatedAt time.Time `json:"updated_at" msgpack:"updated_at"`

	// Status indicates the current state of this thread.
	Status ThreadStatus `json:"status" msgpack:"status"`

	// Label is an optional human-readable label for this thread.
	// Useful for describing the purpose of the branch (e.g., "retry_with_nmap", "stealth_mode").
	Label string `json:"label,omitempty" msgpack:"label,omitempty"`

	// Strategy describes the execution strategy for this thread.
	// Can indicate different parameter sets, tool choices, or approaches.
	Strategy string `json:"strategy,omitempty" msgpack:"strategy,omitempty"`

	// Priority indicates the relative priority of this thread (higher = more important).
	// Can be used for scheduling when multiple threads are active.
	Priority int `json:"priority" msgpack:"priority"`

	// Metadata provides arbitrary key-value storage for thread-specific information.
	// Can store branch reasons, parameter overrides, or custom tracking data.
	Metadata map[string]string `json:"metadata,omitempty" msgpack:"metadata,omitempty"`

	// CheckpointCount is the number of checkpoints created on this thread.
	// Useful for metrics and understanding execution depth.
	CheckpointCount int `json:"checkpoint_count" msgpack:"checkpoint_count"`

	// LastCheckpointID is the ID of the most recent checkpoint on this thread.
	// Quick access to the current state without scanning all checkpoints.
	LastCheckpointID string `json:"last_checkpoint_id,omitempty" msgpack:"last_checkpoint_id,omitempty"`

	// LastCheckpointAt is the timestamp of the most recent checkpoint.
	LastCheckpointAt *time.Time `json:"last_checkpoint_at,omitempty" msgpack:"last_checkpoint_at,omitempty"`

	// CompletedAt is set when the thread completes (success or failure).
	CompletedAt *time.Time `json:"completed_at,omitempty" msgpack:"completed_at,omitempty"`

	// Result summarizes the outcome of this thread.
	// Can be used to compare results across branches.
	Result *ThreadResult `json:"result,omitempty" msgpack:"result,omitempty"`
}

// ThreadStatus represents the current state of a thread.
type ThreadStatus string

const (
	// ThreadStatusActive indicates the thread is actively executing.
	ThreadStatusActive ThreadStatus = "active"

	// ThreadStatusPaused indicates the thread is paused (e.g., during graceful shutdown).
	ThreadStatusPaused ThreadStatus = "paused"

	// ThreadStatusCompleted indicates the thread completed successfully.
	ThreadStatusCompleted ThreadStatus = "completed"

	// ThreadStatusFailed indicates the thread failed during execution.
	ThreadStatusFailed ThreadStatus = "failed"

	// ThreadStatusCancelled indicates the thread was cancelled.
	ThreadStatusCancelled ThreadStatus = "cancelled"

	// ThreadStatusMerged indicates the thread was merged back into another thread.
	ThreadStatusMerged ThreadStatus = "merged"
)

// String returns the string representation of ThreadStatus.
func (s ThreadStatus) String() string {
	return string(s)
}

// IsTerminal returns true if the status is terminal (cannot transition further).
func (s ThreadStatus) IsTerminal() bool {
	return s == ThreadStatusCompleted ||
		s == ThreadStatusFailed ||
		s == ThreadStatusCancelled ||
		s == ThreadStatusMerged
}

// ThreadResult summarizes the outcome of thread execution.
// Used for comparing results across branches to select the best path.
type ThreadResult struct {
	// Status is the final status of the thread.
	Status ThreadStatus `json:"status" msgpack:"status"`

	// FindingsCount is the number of findings discovered on this thread.
	FindingsCount int `json:"findings_count" msgpack:"findings_count"`

	// NodesCompleted is the number of nodes successfully completed.
	NodesCompleted int `json:"nodes_completed" msgpack:"nodes_completed"`

	// NodesFailed is the number of nodes that failed.
	NodesFailed int `json:"nodes_failed" msgpack:"nodes_failed"`

	// Duration is the total execution time for this thread.
	Duration time.Duration `json:"duration" msgpack:"duration"`

	// TokensUsed is the total LLM tokens consumed on this thread.
	TokensUsed int64 `json:"tokens_used" msgpack:"tokens_used"`

	// Cost is the total cost in dollars for this thread.
	Cost float64 `json:"cost" msgpack:"cost"`

	// Score is an optional numeric score for ranking threads.
	// Can be computed based on findings, cost, duration, etc.
	Score float64 `json:"score,omitempty" msgpack:"score,omitempty"`

	// Error contains the error message if the thread failed.
	Error string `json:"error,omitempty" msgpack:"error,omitempty"`

	// Metadata provides additional result information.
	Metadata map[string]any `json:"metadata,omitempty" msgpack:"metadata,omitempty"`
}

// NewThread creates a new primary thread for a mission.
func NewThread(missionID types.ID) *Thread {
	now := time.Now()
	return &Thread{
		ID:              ulid.Make().String(),
		MissionID:       missionID,
		CreatedAt:       now,
		UpdatedAt:       now,
		Status:          ThreadStatusActive,
		Priority:        0,
		CheckpointCount: 0,
		Metadata:        make(map[string]string),
	}
}

// NewBranchThread creates a new thread branched from a parent thread at a checkpoint.
func NewBranchThread(missionID types.ID, parentThreadID, checkpointID string) *Thread {
	now := time.Now()
	return &Thread{
		ID:                 ulid.Make().String(),
		MissionID:          missionID,
		ParentThread:       parentThreadID,
		BranchCheckpointID: checkpointID,
		CreatedAt:          now,
		UpdatedAt:          now,
		Status:             ThreadStatusActive,
		Priority:           0,
		CheckpointCount:    0,
		Metadata:           make(map[string]string),
	}
}

// WithLabel sets a human-readable label on the thread.
func (t *Thread) WithLabel(label string) *Thread {
	t.Label = label
	t.UpdatedAt = time.Now()
	return t
}

// WithStrategy sets the execution strategy for the thread.
func (t *Thread) WithStrategy(strategy string) *Thread {
	t.Strategy = strategy
	t.UpdatedAt = time.Now()
	return t
}

// WithPriority sets the priority for the thread.
func (t *Thread) WithPriority(priority int) *Thread {
	t.Priority = priority
	t.UpdatedAt = time.Now()
	return t
}

// WithMetadata adds metadata to the thread.
func (t *Thread) WithMetadata(key, value string) *Thread {
	if t.Metadata == nil {
		t.Metadata = make(map[string]string)
	}
	t.Metadata[key] = value
	t.UpdatedAt = time.Now()
	return t
}

// AddCheckpoint updates thread state when a new checkpoint is created.
func (t *Thread) AddCheckpoint(checkpointID string) {
	t.CheckpointCount++
	t.LastCheckpointID = checkpointID
	now := time.Now()
	t.LastCheckpointAt = &now
	t.UpdatedAt = now
}

// Complete marks the thread as completed with a result.
func (t *Thread) Complete(result *ThreadResult) {
	t.Status = ThreadStatusCompleted
	t.Result = result
	now := time.Now()
	t.CompletedAt = &now
	t.UpdatedAt = now
}

// Fail marks the thread as failed with an error.
func (t *Thread) Fail(err error) {
	t.Status = ThreadStatusFailed
	t.Result = &ThreadResult{
		Status: ThreadStatusFailed,
		Error:  err.Error(),
	}
	now := time.Now()
	t.CompletedAt = &now
	t.UpdatedAt = now
}

// Cancel marks the thread as cancelled.
func (t *Thread) Cancel() {
	t.Status = ThreadStatusCancelled
	now := time.Now()
	t.CompletedAt = &now
	t.UpdatedAt = now
}

// Pause marks the thread as paused.
func (t *Thread) Pause() {
	t.Status = ThreadStatusPaused
	t.UpdatedAt = time.Now()
}

// Resume marks the thread as active again.
func (t *Thread) Resume() {
	t.Status = ThreadStatusActive
	t.UpdatedAt = time.Now()
}

// Merge marks the thread as merged into another thread.
func (t *Thread) Merge() {
	t.Status = ThreadStatusMerged
	now := time.Now()
	t.CompletedAt = &now
	t.UpdatedAt = now
}

// IsPrimary returns true if this is a primary thread (no parent).
func (t *Thread) IsPrimary() bool {
	return t.ParentThread == ""
}

// IsBranch returns true if this is a branch thread (has a parent).
func (t *Thread) IsBranch() bool {
	return t.ParentThread != ""
}
