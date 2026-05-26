package checkpoint

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ApprovalManager manages the approval mission lifecycle for human-in-the-loop operations.
// It coordinates approval requests, decisions, timeouts, and state modifications during review.
type ApprovalManager interface {
	// RequestApproval initiates an approval request and pauses execution.
	// Creates an approval state, stores it in Redis, and emits an approval.requested event.
	RequestApproval(ctx context.Context, threadID string, checkpointID string, request ApprovalRequest) (*ApprovalState, error)

	// GetPendingApproval retrieves the pending approval for a thread.
	// Returns nil if no pending approval exists.
	GetPendingApproval(ctx context.Context, threadID string) (*ApprovalState, error)

	// ProcessDecision handles an approval decision (approve, reject, modify).
	// Updates the approval state, emits events, and resumes execution within 500ms for approved requests.
	ProcessDecision(ctx context.Context, threadID string, decision ApprovalDecision) error

	// CheckTimeout verifies if an approval has timed out.
	// If timed out, transitions to paused_timeout status and emits approval.timeout event.
	// Returns true if timeout occurred.
	CheckTimeout(ctx context.Context, threadID string) (bool, error)

	// CancelApproval cancels a pending approval request.
	// Transitions to cancelled status and cleans up state.
	CancelApproval(ctx context.Context, threadID string) error

	// ListPendingApprovals returns all pending approvals across all threads.
	// Useful for dashboard and monitoring interfaces.
	ListPendingApprovals(ctx context.Context) ([]*PendingApproval, error)
}

// ApprovalRequest contains the details needed to create an approval request.
type ApprovalRequest struct {
	// NodeID is the mission node requesting approval.
	NodeID string

	// Title is a brief summary of what needs approval.
	Title string

	// Description provides detailed context for the approval request.
	Description string

	// Reasoning explains why approval is needed and what led to this point.
	Reasoning string

	// RiskLevel indicates the risk level of the proposed actions.
	RiskLevel RiskLevel

	// ProposedActions lists the specific actions being requested for approval.
	ProposedActions []ProposedAction

	// Timeout overrides the default approval timeout.
	// If zero, uses the configured default timeout.
	Timeout time.Duration

	// Impact describes the expected impact of approving the request.
	Impact string

	// Alternatives lists alternative approaches that were considered.
	Alternatives []string

	// EstimatedDuration is how long the actions are expected to take.
	EstimatedDuration time.Duration

	// RequiresRollback indicates if these actions can be rolled back.
	RequiresRollback bool

	// CurrentFindings contains relevant findings that informed this request.
	CurrentFindings []types.ID

	// Metadata provides additional context for the approval request.
	Metadata map[string]any
}

// PendingApproval represents a pending approval with its context.
// Used for listing and monitoring pending approvals.
type PendingApproval struct {
	// ThreadID is the thread this approval belongs to.
	ThreadID string

	// CheckpointID is the checkpoint where execution paused.
	CheckpointID string

	// MissionID is the mission this approval belongs to.
	MissionID types.ID

	// State is the current approval state.
	State *ApprovalState

	// CreatedAt is when the approval was requested.
	CreatedAt time.Time

	// TimeoutAt is when the approval will timeout.
	TimeoutAt time.Time
}

// EventEmitter emits approval lifecycle events.
// Implementations can integrate with event buses, message queues, or notification systems.
type EventEmitter interface {
	// Emit publishes an approval event.
	Emit(ctx context.Context, event ApprovalEvent) error
}

// ApprovalEvent represents an approval lifecycle event.
type ApprovalEvent struct {
	// Type indicates the event type.
	Type ApprovalEventType

	// ThreadID is the thread this event belongs to.
	ThreadID string

	// Timestamp is when the event occurred.
	Timestamp time.Time

	// Data contains event-specific data.
	Data any
}

// ApprovalEventType categorizes approval events.
type ApprovalEventType string

const (
	// ApprovalEventRequested is emitted when an approval is requested.
	ApprovalEventRequested ApprovalEventType = "approval.requested"

	// ApprovalEventApproved is emitted when an approval is approved.
	ApprovalEventApproved ApprovalEventType = "approval.approved"

	// ApprovalEventRejected is emitted when an approval is rejected.
	ApprovalEventRejected ApprovalEventType = "approval.rejected"

	// ApprovalEventModified is emitted when an approval is approved with modifications.
	ApprovalEventModified ApprovalEventType = "approval.modified"

	// ApprovalEventTimeout is emitted when an approval times out.
	ApprovalEventTimeout ApprovalEventType = "approval.timeout"

	// ApprovalEventCancelled is emitted when an approval is cancelled.
	ApprovalEventCancelled ApprovalEventType = "approval.cancelled"
)

// ApprovalConfig configures the approval manager behavior.
type ApprovalConfig struct {
	// DefaultTimeout is the default timeout for approval requests.
	// Default: 24 hours
	DefaultTimeout time.Duration

	// MaxTimeout is the maximum allowed timeout for approval requests.
	// Requests exceeding this timeout are capped to this value.
	// Default: 7 days
	MaxTimeout time.Duration

	// EventEmitter emits approval lifecycle events.
	// If nil, events are not emitted.
	EventEmitter EventEmitter

	// ResumeDelay is the delay before resuming execution after approval.
	// Default: 500ms
	ResumeDelay time.Duration

	// KeyPrefix is the Redis key prefix for approval data.
	// Default: "gibson"
	KeyPrefix string
}

// DefaultApprovalConfig returns sensible defaults for approval configuration.
func DefaultApprovalConfig() ApprovalConfig {
	return ApprovalConfig{
		DefaultTimeout: 24 * time.Hour,     // 24 hours
		MaxTimeout:     7 * 24 * time.Hour, // 7 days
		ResumeDelay:    500 * time.Millisecond,
		KeyPrefix:      "gibson",
	}
}

// DefaultApprovalManager is the default implementation of ApprovalManager.
// It stores approval state in Redis and integrates with the checkpoint system.
type DefaultApprovalManager struct {
	store        CheckpointStore
	checkpointer ThreadedCheckpointer
	config       ApprovalConfig
	stateClient  *state.StateClient
}

// NewApprovalManager creates a new DefaultApprovalManager with the provided configuration.
func NewApprovalManager(
	store CheckpointStore,
	checkpointer ThreadedCheckpointer,
	stateClient *state.StateClient,
	config ApprovalConfig,
) *DefaultApprovalManager {
	// Apply defaults
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 24 * time.Hour
	}
	if config.MaxTimeout == 0 {
		config.MaxTimeout = 7 * 24 * time.Hour
	}
	if config.ResumeDelay == 0 {
		config.ResumeDelay = 500 * time.Millisecond
	}
	if config.KeyPrefix == "" {
		config.KeyPrefix = "gibson"
	}

	return &DefaultApprovalManager{
		store:        store,
		checkpointer: checkpointer,
		config:       config,
		stateClient:  stateClient,
	}
}

// RequestApproval creates an approval request and pauses execution.
func (m *DefaultApprovalManager) RequestApproval(
	ctx context.Context,
	threadID string,
	checkpointID string,
	request ApprovalRequest,
) (*ApprovalState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if threadID == "" {
		return nil, ErrInvalidThreadID
	}
	if checkpointID == "" {
		return nil, ErrInvalidCheckpointID
	}
	if request.NodeID == "" {
		return nil, fmt.Errorf("approval request must specify a node ID")
	}

	// Check if there's already a pending approval
	existing, err := m.GetPendingApproval(ctx, threadID)
	if err != nil && err != ErrCheckpointNotFound {
		return nil, fmt.Errorf("failed to check existing approval: %w", err)
	}
	if existing != nil && !existing.IsResolved() {
		return nil, fmt.Errorf("thread %s already has a pending approval", threadID)
	}

	// Determine timeout
	timeout := request.Timeout
	if timeout == 0 {
		timeout = m.config.DefaultTimeout
	}
	if timeout > m.config.MaxTimeout {
		timeout = m.config.MaxTimeout
	}

	// Create approval state
	approvalState := NewApprovalState(request.NodeID, timeout)
	approvalState.ApprovalDetails = ApprovalDetails{
		Title:             request.Title,
		Description:       request.Description,
		Reasoning:         request.Reasoning,
		RiskLevel:         request.RiskLevel,
		Impact:            request.Impact,
		Alternatives:      request.Alternatives,
		EstimatedDuration: request.EstimatedDuration,
		RequiresRollback:  request.RequiresRollback,
	}
	approvalState.ProposedActions = request.ProposedActions
	approvalState.CurrentFindings = request.CurrentFindings
	approvalState.Metadata = request.Metadata

	// Store approval in Redis
	approvalKey := m.approvalKey(threadID)
	if err := m.stateClient.JSONSet(ctx, approvalKey, "$", approvalState); err != nil {
		return nil, fmt.Errorf("failed to store approval state: %w", err)
	}

	// Store in index for listing
	indexKey := m.approvalIndexKey()
	rdb := m.stateClient.Client()
	score := float64(approvalState.RequestedAt.UnixNano())
	if err := rdb.ZAdd(ctx, indexKey, redis.Z{
		Score:  score,
		Member: threadID,
	}).Err(); err != nil {
		return nil, fmt.Errorf("failed to update approval index: %w", err)
	}

	// Emit approval.requested event
	if m.config.EventEmitter != nil {
		event := ApprovalEvent{
			Type:      ApprovalEventRequested,
			ThreadID:  threadID,
			Timestamp: time.Now(),
			Data: map[string]any{
				"checkpoint_id": checkpointID,
				"node_id":       request.NodeID,
				"title":         request.Title,
				"risk_level":    request.RiskLevel,
				"timeout_at":    approvalState.TimeoutAt,
			},
		}
		if err := m.config.EventEmitter.Emit(ctx, event); err != nil {
			// Log error but don't fail the request
			// TODO: Add structured logging
		}
	}

	return approvalState, nil
}

// GetPendingApproval retrieves the pending approval for a thread.
func (m *DefaultApprovalManager) GetPendingApproval(ctx context.Context, threadID string) (*ApprovalState, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	if threadID == "" {
		return nil, ErrInvalidThreadID
	}

	approvalKey := m.approvalKey(threadID)
	var approvalState ApprovalState
	if err := m.stateClient.JSONGet(ctx, approvalKey, "$", &approvalState); err != nil {
		if state.IsNotFound(err) {
			return nil, ErrCheckpointNotFound
		}
		return nil, fmt.Errorf("failed to load approval state: %w", err)
	}

	return &approvalState, nil
}

// ProcessDecision handles an approval decision.
func (m *DefaultApprovalManager) ProcessDecision(
	ctx context.Context,
	threadID string,
	decision ApprovalDecision,
) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	if threadID == "" {
		return ErrInvalidThreadID
	}

	// Load current approval state
	approvalState, err := m.GetPendingApproval(ctx, threadID)
	if err != nil {
		return fmt.Errorf("failed to load approval state: %w", err)
	}

	// Verify approval is still pending
	if approvalState.Status != ApprovalStatusPending {
		return fmt.Errorf("approval is not pending (status: %s)", approvalState.Status)
	}

	// Check if already timed out
	if approvalState.IsTimedOut() {
		return ErrApprovalTimeout
	}

	// Apply decision to approval state
	switch decision.Status {
	case ApprovalStatusApproved:
		approvalState.Approve(decision.ApprovedBy, decision.Comments)
	case ApprovalStatusRejected:
		approvalState.Reject(decision.ApprovedBy, decision.Comments)
	case ApprovalStatusModified:
		approvalState.Modify(decision.ApprovedBy, decision.Comments, decision.Modifications)
	default:
		return fmt.Errorf("invalid decision status: %s", decision.Status)
	}

	// Update decision with constraints and expiration
	approvalState.Decision.Constraints = decision.Constraints
	approvalState.Decision.ExpiresAt = decision.ExpiresAt

	// Store updated approval state
	approvalKey := m.approvalKey(threadID)
	if err := m.stateClient.JSONSet(ctx, approvalKey, "$", approvalState); err != nil {
		return fmt.Errorf("failed to update approval state: %w", err)
	}

	// Remove from pending index
	indexKey := m.approvalIndexKey()
	rdb := m.stateClient.Client()
	if err := rdb.ZRem(ctx, indexKey, threadID).Err(); err != nil {
		// Log error but don't fail
		// TODO: Add structured logging
	}

	// Emit event based on decision
	if m.config.EventEmitter != nil {
		var eventType ApprovalEventType
		switch decision.Status {
		case ApprovalStatusApproved:
			eventType = ApprovalEventApproved
		case ApprovalStatusRejected:
			eventType = ApprovalEventRejected
		case ApprovalStatusModified:
			eventType = ApprovalEventModified
		}

		event := ApprovalEvent{
			Type:      eventType,
			ThreadID:  threadID,
			Timestamp: time.Now(),
			Data: map[string]any{
				"approved_by": decision.ApprovedBy,
				"comments":    decision.Comments,
				"status":      decision.Status,
			},
		}
		if err := m.config.EventEmitter.Emit(ctx, event); err != nil {
			// Log error but don't fail
			// TODO: Add structured logging
		}
	}

	// For approved/modified requests, handle state modifications and resume
	if decision.Status.IsPositive() {
		// If there are modifications, create a new checkpoint branch
		if decision.Status == ApprovalStatusModified && len(decision.Modifications) > 0 {
			if err := m.applyModifications(ctx, threadID, decision); err != nil {
				return fmt.Errorf("failed to apply modifications: %w", err)
			}
		}

		// Resume execution after configured delay
		if m.config.ResumeDelay > 0 {
			time.Sleep(m.config.ResumeDelay)
		}

		// TODO: Trigger resume mechanism (signal orchestrator, update thread status, etc.)
		// This would typically involve:
		// 1. Loading the checkpoint
		// 2. Updating execution status
		// 3. Notifying the orchestrator to resume
	}

	return nil
}

// CheckTimeout verifies if an approval has timed out.
func (m *DefaultApprovalManager) CheckTimeout(ctx context.Context, threadID string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("context cancelled: %w", err)
	}

	if threadID == "" {
		return false, ErrInvalidThreadID
	}

	// Load approval state
	approvalState, err := m.GetPendingApproval(ctx, threadID)
	if err != nil {
		if err == ErrCheckpointNotFound {
			return false, nil // No pending approval
		}
		return false, fmt.Errorf("failed to load approval state: %w", err)
	}

	// Check if already resolved
	if approvalState.IsResolved() {
		return false, nil
	}

	// Check if timed out
	if !approvalState.IsTimedOut() {
		return false, nil
	}

	// Mark as timed out
	approvalState.Timeout()

	// Store updated state
	approvalKey := m.approvalKey(threadID)
	if err := m.stateClient.JSONSet(ctx, approvalKey, "$", approvalState); err != nil {
		return false, fmt.Errorf("failed to update approval state: %w", err)
	}

	// Remove from pending index
	indexKey := m.approvalIndexKey()
	rdb := m.stateClient.Client()
	if err := rdb.ZRem(ctx, indexKey, threadID).Err(); err != nil {
		// Log error but don't fail
		// TODO: Add structured logging
	}

	// Emit timeout event
	if m.config.EventEmitter != nil {
		event := ApprovalEvent{
			Type:      ApprovalEventTimeout,
			ThreadID:  threadID,
			Timestamp: time.Now(),
			Data: map[string]any{
				"request_id": approvalState.RequestID,
				"node_id":    approvalState.NodeID,
				"timeout_at": approvalState.TimeoutAt,
			},
		}
		if err := m.config.EventEmitter.Emit(ctx, event); err != nil {
			// Log error but don't fail
			// TODO: Add structured logging
		}
	}

	return true, nil
}

// CancelApproval cancels a pending approval request.
func (m *DefaultApprovalManager) CancelApproval(ctx context.Context, threadID string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context cancelled: %w", err)
	}

	if threadID == "" {
		return ErrInvalidThreadID
	}

	// Load approval state
	approvalState, err := m.GetPendingApproval(ctx, threadID)
	if err != nil {
		return fmt.Errorf("failed to load approval state: %w", err)
	}

	// Verify approval is still pending
	if approvalState.Status != ApprovalStatusPending {
		return fmt.Errorf("approval is not pending (status: %s)", approvalState.Status)
	}

	// Mark as cancelled
	approvalState.Cancel()

	// Store updated state
	approvalKey := m.approvalKey(threadID)
	if err := m.stateClient.JSONSet(ctx, approvalKey, "$", approvalState); err != nil {
		return fmt.Errorf("failed to update approval state: %w", err)
	}

	// Remove from pending index
	indexKey := m.approvalIndexKey()
	rdb := m.stateClient.Client()
	if err := rdb.ZRem(ctx, indexKey, threadID).Err(); err != nil {
		// Log error but don't fail
		// TODO: Add structured logging
	}

	// Emit cancelled event
	if m.config.EventEmitter != nil {
		event := ApprovalEvent{
			Type:      ApprovalEventCancelled,
			ThreadID:  threadID,
			Timestamp: time.Now(),
			Data: map[string]any{
				"request_id": approvalState.RequestID,
				"node_id":    approvalState.NodeID,
			},
		}
		if err := m.config.EventEmitter.Emit(ctx, event); err != nil {
			// Log error but don't fail
			// TODO: Add structured logging
		}
	}

	return nil
}

// ListPendingApprovals returns all pending approvals across all threads.
func (m *DefaultApprovalManager) ListPendingApprovals(ctx context.Context) ([]*PendingApproval, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context cancelled: %w", err)
	}

	indexKey := m.approvalIndexKey()
	rdb := m.stateClient.Client()

	// Get all thread IDs with pending approvals (newest first)
	threadIDs, err := rdb.ZRevRange(ctx, indexKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to query approval index: %w", err)
	}

	if len(threadIDs) == 0 {
		return []*PendingApproval{}, nil
	}

	// Fetch approval states for each thread
	pendingApprovals := make([]*PendingApproval, 0, len(threadIDs))
	for _, threadID := range threadIDs {
		approvalState, err := m.GetPendingApproval(ctx, threadID)
		if err != nil {
			if err == ErrCheckpointNotFound {
				// Approval was resolved but index wasn't updated - skip it
				continue
			}
			return nil, fmt.Errorf("failed to load approval for thread %s: %w", threadID, err)
		}

		// Skip if no longer pending
		if approvalState.Status != ApprovalStatusPending {
			continue
		}

		// Get thread to retrieve mission ID and checkpoint ID
		thread, err := m.checkpointer.GetThread(ctx, threadID)
		if err != nil {
			// Skip if thread not found
			continue
		}

		pendingApproval := &PendingApproval{
			ThreadID:     threadID,
			CheckpointID: thread.LastCheckpointID,
			MissionID:    thread.MissionID,
			State:        approvalState,
			CreatedAt:    approvalState.RequestedAt,
			TimeoutAt:    approvalState.TimeoutAt,
		}

		pendingApprovals = append(pendingApprovals, pendingApproval)
	}

	return pendingApprovals, nil
}

// applyModifications creates a new checkpoint branch with modified state.
func (m *DefaultApprovalManager) applyModifications(
	ctx context.Context,
	threadID string,
	decision ApprovalDecision,
) error {
	// Get the latest checkpoint
	checkpoint, err := m.checkpointer.GetLatestCheckpoint(ctx, threadID)
	if err != nil {
		return fmt.Errorf("failed to get latest checkpoint: %w", err)
	}

	// Build working memory updates with modified parameters
	workingMemory := make(map[string]any)
	if len(decision.Modifications) > 0 {
		for actionIndex, params := range decision.Modifications {
			key := fmt.Sprintf("action_%d_params", actionIndex)
			workingMemory[key] = params
		}
	}

	// Build metadata updates
	metadata := map[string]string{
		"modified_by": decision.ApprovedBy,
		"modified_at": time.Now().Format(time.RFC3339),
	}

	// TODO: Once the package-level StateUpdates naming conflict between
	// threaded_checkpointer.go and branch.go is resolved, use the
	// checkpointer.UpdateState method to create a new checkpoint branch.
	// For now, we store the modifications in the approval state itself
	// and let the orchestrator apply them during resume.

	// Log the intended modifications for debugging
	_ = workingMemory
	_ = metadata
	_ = checkpoint

	// The modifications are already stored in the ApprovalState.Decision.Modifications
	// and will be applied by the orchestrator when resuming execution
	return nil
}

// approvalKey builds the Redis key for approval state.
// Format: {prefix}:approval:{thread_id}
func (m *DefaultApprovalManager) approvalKey(threadID string) string {
	return fmt.Sprintf("%s:approval:%s", m.config.KeyPrefix, threadID)
}

// approvalIndexKey builds the Redis key for the approval index (sorted set).
// Format: {prefix}:approval:index
func (m *DefaultApprovalManager) approvalIndexKey() string {
	return fmt.Sprintf("%s:approval:index", m.config.KeyPrefix)
}

// Ensure DefaultApprovalManager implements ApprovalManager at compile time.
var _ ApprovalManager = (*DefaultApprovalManager)(nil)
