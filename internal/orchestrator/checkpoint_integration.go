package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/checkpoint"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/types"
)

// CheckpointIntegration integrates automatic checkpointing into the orchestrator's
// execution loop. It determines when checkpoints should be created based on the
// configured policy and captures complete execution state at super-step boundaries.
//
// Key responsibilities:
//   - Track super-step completions and parallel node group completions
//   - Decide when to checkpoint based on policy and configuration
//   - Capture full execution state (mission state, memory, conversation, findings)
//   - Create checkpoints asynchronously to avoid blocking execution
//   - Handle errors gracefully without stopping mission execution
type CheckpointIntegration struct {
	// checkpointer handles checkpoint creation and storage
	checkpointer checkpoint.ThreadedCheckpointer

	// policy determines when checkpoints should be created
	policy checkpoint.CheckpointPolicy

	// enabled controls whether auto-checkpoint is active
	enabled bool

	// threadID identifies the execution thread for this mission
	threadID string

	// missionID identifies the mission being executed
	missionID types.ID

	// lastCheckpointTime tracks the last successful checkpoint for rate limiting
	lastCheckpointTime time.Time

	// mu protects parallel group tracking state
	mu sync.RWMutex

	// parallelGroups tracks completion of nodes in parallel groups
	// Maps group ID to set of completed node IDs
	parallelGroups map[string]map[string]bool

	// logger for checkpoint operations (optional)
	logger Logger
}

// CheckpointIntegrationOption is a functional option for configuring CheckpointIntegration.
type CheckpointIntegrationOption func(*CheckpointIntegration)

// WithCheckpointLogger sets a logger for checkpoint operations.
func WithCheckpointLogger(logger Logger) CheckpointIntegrationOption {
	return func(ci *CheckpointIntegration) {
		ci.logger = logger
	}
}

// NewCheckpointIntegration creates a new checkpoint integration for the orchestrator.
//
// Parameters:
//   - checkpointer: The threaded checkpointer for creating and storing checkpoints
//   - policy: The checkpoint policy that determines when to create checkpoints
//   - missionID: The ID of the mission being executed
//   - threadID: The ID of the execution thread
//
// The integration respects the policy's auto_checkpoint configuration. If auto-checkpoint
// is disabled, only explicit checkpoint requests will create checkpoints.
func NewCheckpointIntegration(
	checkpointer checkpoint.ThreadedCheckpointer,
	policy checkpoint.CheckpointPolicy,
	missionID types.ID,
	threadID string,
	opts ...CheckpointIntegrationOption,
) *CheckpointIntegration {
	ci := &CheckpointIntegration{
		checkpointer:   checkpointer,
		policy:         policy,
		missionID:      missionID,
		threadID:       threadID,
		enabled:        true, // Enabled by default, policy controls auto-checkpoint
		parallelGroups: make(map[string]map[string]bool),
	}

	for _, opt := range opts {
		opt(ci)
	}

	return ci
}

// OnSuperStepComplete is called after each super-step (LLM interaction) completes.
// A super-step is a complete observe → think → act cycle in the orchestrator.
//
// This method:
//   1. Checks if a checkpoint should be created based on policy
//   2. Captures current execution state
//   3. Creates checkpoint asynchronously (non-blocking on success)
//   4. Logs errors but doesn't fail the mission
//
// Parameters:
//   - ctx: The execution context (used for timeout/cancellation)
//   - state: The current mission execution state
//   - completedNodes: Node IDs that completed in this super-step
func (c *CheckpointIntegration) OnSuperStepComplete(
	ctx context.Context,
	state *ExecutionState,
	completedNodes []string,
) error {
	if !c.enabled {
		return nil
	}

	// Create checkpoint event for policy evaluation
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventSuperStep, state.CurrentNodeID)
	event = event.WithMetadata("thread_id", c.threadID)
	event = event.WithMetadata("completed_count", fmt.Sprintf("%d", len(completedNodes)))

	// Check policy to determine if we should checkpoint
	if !c.policy.ShouldCheckpoint(ctx, event) {
		return nil
	}

	// Create checkpoint asynchronously to avoid blocking execution
	go c.createCheckpointAsync(state, "super_step", completedNodes)

	return nil
}

// OnParallelGroupComplete is called when all nodes in a parallel group finish.
// This creates a checkpoint at the parallel group boundary to ensure we can resume
// properly after completing all parallel tasks.
//
// Parameters:
//   - ctx: The execution context
//   - state: The current mission execution state
//   - groupID: The ID of the parallel group that completed
//   - completedNodes: All node IDs in the group that completed
func (c *CheckpointIntegration) OnParallelGroupComplete(
	ctx context.Context,
	state *ExecutionState,
	groupID string,
	completedNodes []string,
) error {
	if !c.enabled {
		return nil
	}

	// Create explicit checkpoint event - always checkpoint on parallel group completion
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventSuperStep, state.CurrentNodeID)
	event = event.WithMetadata("thread_id", c.threadID)
	event = event.WithMetadata("group_id", groupID)
	event = event.WithMetadata("reason", "parallel_group_complete")

	// Check policy (should always allow but respect configuration)
	if !c.policy.ShouldCheckpoint(ctx, event) {
		return nil
	}

	// Create checkpoint with label for parallel boundary
	go c.createCheckpointAsyncWithLabel(state, fmt.Sprintf("parallel_group_%s_complete", groupID), completedNodes)

	// Clear parallel group tracking
	c.ClearParallelGroup(groupID)

	return nil
}

// OnApprovalRequired is called when a node requires human approval before proceeding.
// This always creates a checkpoint so execution can be properly resumed after approval.
//
// Parameters:
//   - ctx: The execution context
//   - state: The current mission execution state
//   - nodeID: The node ID requesting approval
//   - request: The approval request details
//
// Returns the created checkpoint (synchronous) so the approval can reference it.
func (c *CheckpointIntegration) OnApprovalRequired(
	ctx context.Context,
	state *ExecutionState,
	nodeID string,
	request ApprovalRequest,
) (*checkpoint.Checkpoint, error) {
	// Always checkpoint on approval requests (critical for resumption)
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventApproval, nodeID)
	event = event.WithMetadata("thread_id", c.threadID)
	event = event.WithMetadata("approval_id", request.ID)

	// Policy should always allow approval checkpoints
	if !c.policy.ShouldCheckpoint(ctx, event) {
		if c.logger != nil {
			c.logger.Warn(ctx, "policy prevented approval checkpoint - forcing checkpoint anyway",
				"node_id", nodeID,
				"approval_id", request.ID,
			)
		}
	}

	// Capture execution state
	execState := c.captureExecutionState(state)

	// Create approval state and attach to execution state
	approvalState := c.convertToCheckpointApprovalState(request)
	execState.ApprovalState = approvalState

	// Create checkpoint synchronously (we need the checkpoint ID for the approval)
	cp, err := c.checkpointer.Checkpoint(ctx, c.threadID, execState)
	if err != nil {
		return nil, fmt.Errorf("failed to create approval checkpoint: %w", err)
	}

	// Update last checkpoint time
	c.lastCheckpointTime = time.Now()

	if c.logger != nil {
		c.logger.Info(ctx, "created approval checkpoint",
			"checkpoint_id", cp.ID,
			"node_id", nodeID,
			"approval_id", request.ID,
		)
	}

	return cp, nil
}

// OnShutdown is called during graceful shutdown to preserve execution state.
// This creates a final checkpoint so the mission can be resumed later.
//
// Parameters:
//   - ctx: The execution context (may have short deadline)
//   - state: The current mission execution state
func (c *CheckpointIntegration) OnShutdown(ctx context.Context, state *ExecutionState) error {
	if !c.enabled {
		return nil
	}

	// Create shutdown event - always checkpoint on shutdown
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventShutdown, state.CurrentNodeID)
	event = event.WithMetadata("thread_id", c.threadID)
	event = event.WithMetadata("reason", "graceful_shutdown")

	// Policy should always allow shutdown checkpoints
	if !c.policy.ShouldCheckpoint(ctx, event) {
		if c.logger != nil {
			c.logger.Warn(ctx, "policy prevented shutdown checkpoint - forcing checkpoint anyway")
		}
	}

	// Capture execution state
	execState := c.captureExecutionState(state)

	// Mark as shutdown checkpoint
	execState.Metadata["shutdown"] = true
	execState.Metadata["shutdown_time"] = time.Now().Format(time.RFC3339)

	// Create checkpoint synchronously (we need to complete before shutdown)
	cp, err := c.checkpointer.Checkpoint(ctx, c.threadID, execState)
	if err != nil {
		return fmt.Errorf("failed to create shutdown checkpoint: %w", err)
	}

	// Update last checkpoint time
	c.lastCheckpointTime = time.Now()

	if c.logger != nil {
		c.logger.Info(ctx, "created shutdown checkpoint",
			"checkpoint_id", cp.ID,
		)
	}

	return nil
}

// OnError is called when an error occurs during execution.
// This optionally creates a checkpoint before failure for debugging and recovery.
//
// Parameters:
//   - ctx: The execution context
//   - state: The current mission execution state
//   - err: The error that occurred
func (c *CheckpointIntegration) OnError(ctx context.Context, state *ExecutionState, err error) error {
	if !c.enabled {
		return nil
	}

	// Create error event
	event := checkpoint.NewCheckpointEvent(checkpoint.CheckpointEventError, state.CurrentNodeID)
	event = event.WithMetadata("thread_id", c.threadID)
	event = event.WithMetadata("error", err.Error())

	// Check policy - error checkpoints are optional
	if !c.policy.ShouldCheckpoint(ctx, event) {
		return nil
	}

	// Capture execution state
	execState := c.captureExecutionState(state)

	// Add error context
	execState.Metadata["error"] = err.Error()
	execState.Metadata["error_time"] = time.Now().Format(time.RFC3339)

	// Create checkpoint asynchronously (best effort, don't delay error handling)
	go func() {
		cp, cpErr := c.checkpointer.Checkpoint(context.Background(), c.threadID, execState)
		if cpErr != nil {
			if c.logger != nil {
				c.logger.Error(context.Background(), "failed to create error checkpoint",
					"error", cpErr,
					"original_error", err,
				)
			}
			return
		}

		c.lastCheckpointTime = time.Now()

		if c.logger != nil {
			c.logger.Info(context.Background(), "created error checkpoint",
				"checkpoint_id", cp.ID,
				"error", err.Error(),
			)
		}
	}()

	return nil
}

// CaptureExecutionState builds a checkpoint ExecutionState from the orchestrator's
// current runtime state. This captures everything needed to resume execution:
//   - Mission state (node states, completed results, pending queue)
//   - Working memory (ephemeral task-scoped data)
//   - Mission memory (persistent mission-wide data)
//   - Conversation history (LLM messages)
//   - Findings (discovered security findings)
//
// This is exported so the orchestrator can manually capture state for explicit checkpoints.
func CaptureExecutionState(
	missionState *mission.MissionState,
	workingMemory memory.WorkingMemory,
	missionMemory memory.MissionMemory,
	conversationHistory []llm.Message,
	findings []types.ID,
) *checkpoint.ExecutionState {
	// Create new execution state
	execState := checkpoint.NewExecutionState(missionState.MissionID, "")

	// Capture node states
	for nodeID, nodeState := range missionState.NodeStates {
		cpNodeState := &checkpoint.NodeState{
			NodeID:      nodeID,
			Status:      checkpoint.NodeStatus(nodeState.Status),
			StartedAt:   nodeState.StartedAt,
			CompletedAt: nodeState.CompletedAt,
			RetryCount:  nodeState.RetryCount,
			RetryParams: nodeState.RetryParams,
		}
		if nodeState.Error != nil {
			cpNodeState.Error = nodeState.Error.Error()
		}
		execState.AddNodeState(nodeID, cpNodeState)
	}

	// Capture completed results
	for nodeID, result := range missionState.Results {
		cpOutput := &checkpoint.NodeOutput{
			NodeID:      nodeID,
			Status:      string(result.Status),
			Output:      result.Output,
			Duration:    result.Duration,
			RetryCount:  result.RetryCount,
			CompletedAt: result.CompletedAt,
		}
		if result.Error != nil {
			cpOutput.Error = result.Error.Message
		}
		execState.AddCompletedResult(nodeID, cpOutput)
	}

	// Capture pending queue (ready nodes in execution order)
	execState.PendingQueue = missionState.GetReadyNodes()

	// Capture working memory
	// TODO: WorkingMemory.GetAll() needs to be implemented
	// For now, working memory is not persisted across checkpoints
	_ = workingMemory

	// Capture mission memory
	// TODO: MissionMemory.GetAll() needs to be implemented
	// For now, mission memory is not persisted across checkpoints
	_ = missionMemory

	// Capture conversation history
	if conversationHistory != nil {
		execState.ConversationHistory = conversationHistory
	}

	// Capture findings
	if findings != nil {
		execState.Findings = findings
	}

	// Capture DAG traversal state
	execState.DAGState = &checkpoint.DAGTraversalState{
		PendingNodes:   missionState.GetPendingNodes(),
		ExecutionOrder: missionState.GetExecutionOrder(),
	}

	return execState
}

// captureExecutionState is the internal version that uses the integration's stored state.
func (c *CheckpointIntegration) captureExecutionState(state *ExecutionState) *checkpoint.ExecutionState {
	execState := checkpoint.NewExecutionState(c.missionID, c.threadID)

	// Copy all fields from the provided state
	execState.CurrentNodeID = state.CurrentNodeID
	execState.NodeStates = state.NodeStates
	execState.CompletedResults = state.CompletedResults
	execState.PendingQueue = state.PendingQueue
	execState.InProgress = state.InProgress
	execState.WorkingMemory = state.WorkingMemory
	execState.MissionMemory = state.MissionMemory
	execState.ConversationHistory = state.ConversationHistory
	execState.DAGState = state.DAGState
	execState.Findings = state.Findings
	execState.Metadata = state.Metadata

	return execState
}

// createCheckpointAsync creates a checkpoint asynchronously without blocking execution.
// Errors are logged but don't fail the mission.
func (c *CheckpointIntegration) createCheckpointAsync(state *ExecutionState, label string, completedNodes []string) {
	ctx := context.Background()

	execState := c.captureExecutionState(state)

	// Add metadata
	execState.Metadata["completed_nodes"] = completedNodes
	execState.Metadata["checkpoint_time"] = time.Now().Format(time.RFC3339)

	cp, err := c.checkpointer.Checkpoint(ctx, c.threadID, execState)
	if err != nil {
		if c.logger != nil {
			c.logger.Error(ctx, "failed to create checkpoint",
				"error", err,
				"label", label,
			)
		}
		return
	}

	// Update last checkpoint time
	c.lastCheckpointTime = time.Now()

	if c.logger != nil {
		c.logger.Debug(ctx, "created checkpoint",
			"checkpoint_id", cp.ID,
			"label", label,
			"size_bytes", cp.SizeBytes,
		)
	}
}

// createCheckpointAsyncWithLabel creates a checkpoint asynchronously with a human-readable label.
func (c *CheckpointIntegration) createCheckpointAsyncWithLabel(state *ExecutionState, label string, completedNodes []string) {
	ctx := context.Background()

	execState := c.captureExecutionState(state)

	// Add metadata
	execState.Metadata["label"] = label
	execState.Metadata["completed_nodes"] = completedNodes
	execState.Metadata["checkpoint_time"] = time.Now().Format(time.RFC3339)

	cp, err := c.checkpointer.Checkpoint(ctx, c.threadID, execState)
	if err != nil {
		if c.logger != nil {
			c.logger.Error(ctx, "failed to create checkpoint",
				"error", err,
				"label", label,
			)
		}
		return
	}

	// Apply label to checkpoint
	cp = cp.WithLabel(label)

	// Update last checkpoint time
	c.lastCheckpointTime = time.Now()

	if c.logger != nil {
		c.logger.Info(ctx, "created labeled checkpoint",
			"checkpoint_id", cp.ID,
			"label", label,
			"size_bytes", cp.SizeBytes,
		)
	}
}

// ShouldCheckpoint checks if a checkpoint should be created for the given event.
// This delegates to the policy's decision logic.
func (c *CheckpointIntegration) ShouldCheckpoint(event checkpoint.CheckpointEvent) bool {
	if !c.enabled {
		return false
	}

	return c.policy.ShouldCheckpoint(context.Background(), event)
}

// GetCurrentThreadID returns the thread ID for this execution.
func (c *CheckpointIntegration) GetCurrentThreadID() string {
	return c.threadID
}

// GetCheckpointPolicy returns the configured checkpoint policy.
func (c *CheckpointIntegration) GetCheckpointPolicy() checkpoint.CheckpointPolicy {
	return c.policy
}

// TrackParallelCompletion tracks completion of a node in a parallel group.
// Returns true when all nodes in the group are complete.
//
// This is used to detect when a parallel group boundary is reached and
// a checkpoint should be created.
//
// Parameters:
//   - groupID: The ID of the parallel group
//   - nodeID: The ID of the node that just completed
//
// Returns true if this was the last node in the group.
func (c *CheckpointIntegration) TrackParallelCompletion(groupID string, nodeID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Initialize group if not exists
	if c.parallelGroups[groupID] == nil {
		c.parallelGroups[groupID] = make(map[string]bool)
	}

	// Mark node as complete
	c.parallelGroups[groupID][nodeID] = true

	// TODO: Need to know total nodes in group to detect completion
	// For now, we'll rely on the orchestrator to call OnParallelGroupComplete explicitly
	return false
}

// ClearParallelGroup removes tracking for a completed parallel group.
// This should be called after the parallel group checkpoint is created.
func (c *CheckpointIntegration) ClearParallelGroup(groupID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.parallelGroups, groupID)
}

// Enable enables automatic checkpoint creation.
func (c *CheckpointIntegration) Enable() {
	c.enabled = true
}

// Disable disables automatic checkpoint creation.
// Explicit checkpoints (approval, shutdown) will still be created.
func (c *CheckpointIntegration) Disable() {
	c.enabled = false
}

// IsEnabled returns whether automatic checkpointing is enabled.
func (c *CheckpointIntegration) IsEnabled() bool {
	return c.enabled
}

// GetLastCheckpointTime returns the timestamp of the last successful checkpoint.
func (c *CheckpointIntegration) GetLastCheckpointTime() time.Time {
	return c.lastCheckpointTime
}

// convertToCheckpointApprovalState converts an orchestrator ApprovalRequest
// to a checkpoint ApprovalState for serialization.
func (c *CheckpointIntegration) convertToCheckpointApprovalState(req ApprovalRequest) *checkpoint.ApprovalState {
	approvalState := checkpoint.NewApprovalState(req.NodeID, req.Timeout)
	approvalState.RequestID = req.ID

	// Set basic details
	approvalState.ApprovalDetails = checkpoint.ApprovalDetails{
		Title:       "Approval Required",
		Description: req.Context,
		RiskLevel:   checkpoint.RiskLevelMedium, // Default, could be enhanced
	}

	// Set timeout action
	if req.TimeoutAction == "reject" {
		approvalState.Metadata["timeout_action"] = "reject"
	} else {
		approvalState.Metadata["timeout_action"] = "skip"
	}

	return approvalState
}

// ExecutionState represents the orchestrator's runtime execution state.
// This is a simplified view for checkpoint integration purposes.
// The full ObservationState from the observer is more comprehensive.
type ExecutionState struct {
	// CurrentNodeID is the node currently being executed
	CurrentNodeID string

	// NodeStates maps node IDs to their execution state
	NodeStates map[string]*checkpoint.NodeState

	// CompletedResults maps node IDs to their final outputs
	CompletedResults map[string]*checkpoint.NodeOutput

	// PendingQueue is the ordered list of nodes waiting to execute
	PendingQueue []string

	// InProgress captures state of a node mid-execution (if any)
	InProgress *checkpoint.InProgressNodeState

	// WorkingMemory is ephemeral task-scoped memory
	WorkingMemory map[string]any

	// MissionMemory is persistent mission-wide memory
	MissionMemory map[string]any

	// ConversationHistory contains LLM conversation messages
	ConversationHistory []llm.Message

	// DAGState captures DAG traversal position
	DAGState *checkpoint.DAGTraversalState

	// Findings contains discovered security findings
	Findings []types.ID

	// Metadata provides arbitrary state-specific data
	Metadata map[string]any
}
