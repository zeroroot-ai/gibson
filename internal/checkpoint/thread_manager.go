package checkpoint

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ThreadStore defines the interface for storing and retrieving thread metadata.
type ThreadStore interface {
	// SaveThread persists a thread to storage.
	SaveThread(ctx context.Context, thread *Thread) error

	// GetThread retrieves a thread by ID.
	GetThread(ctx context.Context, threadID string) (*Thread, error)

	// ListThreads lists all threads for a mission.
	ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error)

	// UpdateThread updates an existing thread's state.
	UpdateThread(ctx context.Context, thread *Thread) error

	// DeleteThread removes a thread from storage.
	DeleteThread(ctx context.Context, threadID string) error
}

// ThreadManager provides high-level thread management operations.
// It handles thread creation, branching, status updates, and lifecycle management.
// This interface wraps the lower-level ThreadStore to provide a simplified API.
type ThreadManager interface {
	// CreateThread creates a new primary thread for a mission.
	// Options can customize the thread's label, strategy, priority, and metadata.
	CreateThread(ctx context.Context, missionID types.ID, opts ...ThreadOption) (*Thread, error)

	// CreateBranchThread creates a new thread branched from a parent thread at a checkpoint.
	// The new thread inherits state from the branch checkpoint and can explore alternative paths.
	CreateBranchThread(ctx context.Context, parentThreadID string, branchCheckpointID string, opts ...ThreadOption) (*Thread, error)

	// GetThread retrieves a thread by its ID.
	GetThread(ctx context.Context, threadID string) (*Thread, error)

	// ListThreads retrieves all threads for a mission.
	// Threads are returned in creation order.
	ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error)

	// UpdateThreadStatus updates the status of a thread.
	// Returns an error if attempting an invalid status transition.
	UpdateThreadStatus(ctx context.Context, threadID string, status ThreadStatus) error

	// DeleteThread removes a thread and all its associated checkpoints.
	// This operation is irreversible and should be used with caution.
	DeleteThread(ctx context.Context, threadID string) error

	// GenerateSubgraphThreadID generates a hierarchical thread ID for subgraph execution.
	// Format: {parent_thread}:{node_id}:{uuid}
	// This enables tracking execution across nested mission graphs.
	GenerateSubgraphThreadID(parentThread string, nodeID string) string
}

// ThreadOption is a functional option for thread creation and modification.
type ThreadOption func(*Thread)

// WithThreadID sets a deterministic thread ID for testing purposes.
// This should not be used in production code.
func WithThreadID(id string) ThreadOption {
	return func(t *Thread) {
		t.ID = id
	}
}

// WithMetadata adds multiple metadata key-value pairs to the thread.
// This is a convenience function that wraps multiple WithThreadMetadata calls.
func WithMetadata(meta map[string]string) ThreadOption {
	return func(t *Thread) {
		if t.Metadata == nil {
			t.Metadata = make(map[string]string)
		}
		for k, v := range meta {
			t.Metadata[k] = v
		}
	}
}

// DefaultThreadManager is the default implementation of ThreadManager.
// It uses separate stores for thread metadata and checkpoint data,
// allowing different persistence strategies for each.
type DefaultThreadManager struct {
	threadStore     ThreadStore
	checkpointStore CheckpointStore
}

// NewThreadManager creates a new thread manager with the provided stores.
// The threadStore handles thread metadata persistence, while checkpointStore
// handles checkpoint data persistence. These can be the same underlying store
// or different stores depending on your architecture.
func NewThreadManager(threadStore ThreadStore, checkpointStore CheckpointStore) *DefaultThreadManager {
	return &DefaultThreadManager{
		threadStore:     threadStore,
		checkpointStore: checkpointStore,
	}
}

// CreateThread creates a new primary thread for a mission.
func (tm *DefaultThreadManager) CreateThread(ctx context.Context, missionID types.ID, opts ...ThreadOption) (*Thread, error) {
	// Validate mission ID
	if missionID.IsZero() {
		return nil, ErrInvalidMissionID
	}

	// Create thread
	thread := NewThread(missionID)

	// Apply options
	for _, opt := range opts {
		opt(thread)
	}

	// Persist thread
	if err := tm.threadStore.SaveThread(ctx, thread); err != nil {
		return nil, fmt.Errorf("failed to save thread: %w", err)
	}

	return thread, nil
}

// CreateBranchThread creates a new thread branched from a parent thread at a checkpoint.
func (tm *DefaultThreadManager) CreateBranchThread(ctx context.Context, parentThreadID string, branchCheckpointID string, opts ...ThreadOption) (*Thread, error) {
	// Validate inputs
	if parentThreadID == "" {
		return nil, ErrInvalidThreadID
	}
	if branchCheckpointID == "" {
		return nil, ErrInvalidCheckpointID
	}

	// Retrieve parent thread to get mission ID
	parentThread, err := tm.threadStore.GetThread(ctx, parentThreadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get parent thread: %w", err)
	}

	// Verify checkpoint exists and belongs to parent thread
	checkpoint, err := tm.checkpointStore.GetCheckpoint(ctx, branchCheckpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to get branch checkpoint: %w", err)
	}
	if checkpoint.ThreadID != parentThreadID {
		return nil, fmt.Errorf("checkpoint %s does not belong to parent thread %s", branchCheckpointID, parentThreadID)
	}

	// Create branch thread
	thread := NewBranchThread(parentThread.MissionID, parentThreadID, branchCheckpointID)

	// Apply options
	for _, opt := range opts {
		opt(thread)
	}

	// Persist thread
	if err := tm.threadStore.SaveThread(ctx, thread); err != nil {
		return nil, fmt.Errorf("failed to save branch thread: %w", err)
	}

	return thread, nil
}

// GetThread retrieves a thread by its ID.
func (tm *DefaultThreadManager) GetThread(ctx context.Context, threadID string) (*Thread, error) {
	if threadID == "" {
		return nil, ErrInvalidThreadID
	}

	thread, err := tm.threadStore.GetThread(ctx, threadID)
	if err != nil {
		return nil, fmt.Errorf("failed to get thread: %w", err)
	}

	return thread, nil
}

// ListThreads retrieves all threads for a mission.
func (tm *DefaultThreadManager) ListThreads(ctx context.Context, missionID types.ID) ([]*Thread, error) {
	if missionID.IsZero() {
		return nil, ErrInvalidMissionID
	}

	threads, err := tm.threadStore.ListThreads(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to list threads: %w", err)
	}

	return threads, nil
}

// UpdateThreadStatus updates the status of a thread.
func (tm *DefaultThreadManager) UpdateThreadStatus(ctx context.Context, threadID string, status ThreadStatus) error {
	if threadID == "" {
		return ErrInvalidThreadID
	}

	// Retrieve current thread
	thread, err := tm.threadStore.GetThread(ctx, threadID)
	if err != nil {
		return fmt.Errorf("failed to get thread: %w", err)
	}

	// Validate status transition
	if thread.Status.IsTerminal() {
		return fmt.Errorf("cannot update status of terminal thread (current: %s)", thread.Status)
	}

	// Update thread status using the status transition methods
	switch status {
	case ThreadStatusActive:
		thread.Resume()
	case ThreadStatusPaused:
		thread.Pause()
	case ThreadStatusCompleted:
		thread.Complete(nil) // Result will be set separately
	case ThreadStatusFailed:
		// Note: Normally Fail() takes an error, but we don't have one here
		// The caller should use thread.Fail(err) directly if they have an error
		thread.Status = ThreadStatusFailed
		thread.UpdatedAt = time.Now()
	case ThreadStatusCancelled:
		thread.Cancel()
	case ThreadStatusMerged:
		thread.Merge()
	default:
		return fmt.Errorf("invalid thread status: %s", status)
	}

	// Persist updated thread
	if err := tm.threadStore.UpdateThread(ctx, thread); err != nil {
		return fmt.Errorf("failed to update thread status: %w", err)
	}

	return nil
}

// DeleteThread removes a thread and all its associated checkpoints.
func (tm *DefaultThreadManager) DeleteThread(ctx context.Context, threadID string) error {
	if threadID == "" {
		return ErrInvalidThreadID
	}

	// Verify thread exists
	if _, err := tm.threadStore.GetThread(ctx, threadID); err != nil {
		return fmt.Errorf("failed to get thread: %w", err)
	}

	// Delete all checkpoints for this thread first
	if err := tm.checkpointStore.DeleteThreadCheckpoints(ctx, threadID); err != nil {
		return fmt.Errorf("failed to delete thread checkpoints: %w", err)
	}

	// Delete thread
	if err := tm.threadStore.DeleteThread(ctx, threadID); err != nil {
		return fmt.Errorf("failed to delete thread: %w", err)
	}

	return nil
}

// GenerateSubgraphThreadID generates a hierarchical thread ID for subgraph execution.
// Format: {parent_thread}:{node_id}:{uuid}
func (tm *DefaultThreadManager) GenerateSubgraphThreadID(parentThread string, nodeID string) string {
	return fmt.Sprintf("%s:%s:%s", parentThread, nodeID, uuid.New().String())
}

// ParseThreadID parses a thread ID into its components.
// For hierarchical thread IDs, it returns the parent thread, node ID, and UUID.
// For non-hierarchical thread IDs, it returns empty strings for parent and node.
func ParseThreadID(threadID string) (parentThread, nodeID, uuidPart string, err error) {
	if threadID == "" {
		return "", "", "", ErrInvalidThreadID
	}

	// Check if it's a hierarchical thread ID
	parts := strings.Split(threadID, ":")
	if len(parts) == 3 {
		// Hierarchical format: parent:node:uuid
		return parts[0], parts[1], parts[2], nil
	} else if len(parts) == 1 {
		// Simple thread ID (primary thread)
		return "", "", threadID, nil
	}

	// Invalid format
	return "", "", "", fmt.Errorf("invalid thread ID format: %s", threadID)
}

// IsSubgraphThread checks if a thread ID is hierarchical (subgraph thread).
// Subgraph threads have the format: {parent_thread}:{node_id}:{uuid}
func IsSubgraphThread(threadID string) bool {
	parts := strings.Split(threadID, ":")
	return len(parts) == 3
}
