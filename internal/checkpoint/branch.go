//go:build ignore
// +build ignore

package checkpoint

import (
	"context"
	"fmt"
	"time"
)

// BranchManager manages state branching and time-travel operations
type BranchManager interface {
	// CreateBranch creates a branch from a checkpoint with optional state modifications
	CreateBranch(ctx context.Context, sourceCheckpointID string, updates *StateUpdates) (*BranchResult, error)

	// GetBranchHistory returns all checkpoints in branch lineage
	GetBranchHistory(ctx context.Context, checkpointID string) ([]*Checkpoint, error)

	// FindCommonAncestor finds the common ancestor of two branches
	FindCommonAncestor(ctx context.Context, checkpointID1, checkpointID2 string) (*Checkpoint, error)

	// PrepareReplay creates a replay plan from a checkpoint
	PrepareReplay(ctx context.Context, checkpointID string) (*ReplayPlan, error)

	// MergeBranch merges branch results back to parent thread
	MergeBranch(ctx context.Context, branchThreadID string, targetThreadID string) error
}

// BranchResult represents the result of creating a branch
type BranchResult struct {
	NewThread        *Thread
	NewCheckpoint    *Checkpoint
	SourceCheckpoint *Checkpoint
	BranchPoint      time.Time
}

// ReplayPlan describes how to replay execution from a checkpoint
type ReplayPlan struct {
	SourceCheckpoint *Checkpoint
	ExecutionState   *ExecutionState
	NodesToReplay    []string // Nodes that will be re-executed
	NodesSkipped     []string // Nodes completed before checkpoint
	StartNode        string   // First node to execute
}

// StateUpdates for branching - defined in threaded_checkpointer.go
// type StateUpdates struct {
// 	// Variables to update or add
// 	Variables map[string]interface{}
//
// 	// Tool results to override
// 	ToolResults map[string]*ToolResult
//
// 	// Memory updates
// 	Memory map[string]interface{}
//
// 	// Node states to modify
// 	NodeStates map[string]NodeState
//
// 	// Custom metadata
// 	Metadata map[string]interface{}
// }

// ToolResult represents a tool execution result (placeholder for now)
type ToolResult struct {
	ToolName string
	Output   interface{}
	Error    string
}

// DefaultBranchManager is the standard implementation of BranchManager
type DefaultBranchManager struct {
	store         CheckpointStore
	threadManager ThreadManager
	restorer      StateRestorer
}

// NewBranchManager creates a new branch manager
func NewBranchManager(
	store CheckpointStore,
	threadManager ThreadManager,
	restorer StateRestorer,
) *DefaultBranchManager {
	return &DefaultBranchManager{
		store:         store,
		threadManager: threadManager,
		restorer:      restorer,
	}
}

// CreateBranch creates a new branch from a checkpoint with optional state modifications
func (bm *DefaultBranchManager) CreateBranch(ctx context.Context, sourceCheckpointID string, updates *StateUpdates) (*BranchResult, error) {
	// Retrieve source checkpoint
	sourceCheckpoint, err := bm.store.GetCheckpoint(ctx, sourceCheckpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve source checkpoint: %w", err)
	}

	// Restore execution state from checkpoint
	executionState, err := bm.restorer.Restore(ctx, sourceCheckpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to restore execution state: %w", err)
	}

	// Apply state modifications if provided
	if updates != nil {
		executionState = ApplyUpdates(executionState, updates)
	}

	// Create new thread for the branch
	branchThread, err := bm.threadManager.CreateBranchThread(ctx, sourceCheckpoint.ThreadID, sourceCheckpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to create branch thread: %w", err)
	}

	// Create new checkpoint in the branched thread
	branchPoint := time.Now()
	newCheckpoint := &Checkpoint{
		ID:              generateCheckpointID(),
		ThreadID:        branchThread.ID,
		ParentID:        sourceCheckpointID,
		Timestamp:       branchPoint,
		ExecutionState:  executionState,
		MissionSnapshot: sourceCheckpoint.MissionSnapshot, // Copy mission definition
		Metadata: map[string]interface{}{
			"branch_source":    sourceCheckpointID,
			"branch_timestamp": branchPoint,
			"is_branch":        true,
		},
	}

	// Store the new checkpoint
	if err := bm.store.SaveCheckpoint(ctx, newCheckpoint); err != nil {
		return nil, fmt.Errorf("failed to save branch checkpoint: %w", err)
	}

	return &BranchResult{
		NewThread:        branchThread,
		NewCheckpoint:    newCheckpoint,
		SourceCheckpoint: sourceCheckpoint,
		BranchPoint:      branchPoint,
	}, nil
}

// GetBranchHistory retrieves the complete lineage of checkpoints leading to the given checkpoint
func (bm *DefaultBranchManager) GetBranchHistory(ctx context.Context, checkpointID string) ([]*Checkpoint, error) {
	var history []*Checkpoint
	currentID := checkpointID

	// Traverse the parent_id chain
	for currentID != "" {
		checkpoint, err := bm.store.GetCheckpoint(ctx, currentID)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve checkpoint %s: %w", currentID, err)
		}

		history = append(history, checkpoint)
		currentID = checkpoint.ParentID
	}

	// Reverse to get chronological order (oldest first)
	for i, j := 0, len(history)-1; i < j; i, j = i+1, j-1 {
		history[i], history[j] = history[j], history[i]
	}

	return history, nil
}

// FindCommonAncestor finds the most recent common ancestor checkpoint of two branches
func (bm *DefaultBranchManager) FindCommonAncestor(ctx context.Context, checkpointID1, checkpointID2 string) (*Checkpoint, error) {
	// Get complete history for both branches
	history1, err := bm.GetBranchHistory(ctx, checkpointID1)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for checkpoint1: %w", err)
	}

	history2, err := bm.GetBranchHistory(ctx, checkpointID2)
	if err != nil {
		return nil, fmt.Errorf("failed to get history for checkpoint2: %w", err)
	}

	// Create a set of checkpoint IDs from history1
	checkpointSet := make(map[string]*Checkpoint)
	for _, cp := range history1 {
		checkpointSet[cp.ID] = cp
	}

	// Find first checkpoint in history2 that exists in history1 (most recent common ancestor)
	// Iterate backwards through history2 for most recent ancestor
	for i := len(history2) - 1; i >= 0; i-- {
		if ancestorCP, exists := checkpointSet[history2[i].ID]; exists {
			return ancestorCP, nil
		}
	}

	return nil, fmt.Errorf("no common ancestor found between checkpoints")
}

// PrepareReplay creates a replay plan showing what needs to be re-executed from a checkpoint
func (bm *DefaultBranchManager) PrepareReplay(ctx context.Context, checkpointID string) (*ReplayPlan, error) {
	// Retrieve checkpoint
	checkpoint, err := bm.store.GetCheckpoint(ctx, checkpointID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve checkpoint: %w", err)
	}

	// Restore execution state
	executionState, err := bm.restorer.RestoreState(ctx, checkpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to restore execution state: %w", err)
	}

	// Analyze mission to determine replay nodes
	var nodesSkipped []string
	var nodesToReplay []string
	var startNode string

	// Get current node from execution state
	currentNode := executionState.CurrentNode

	// Categorize nodes based on completion status
	for nodeID, nodeState := range executionState.NodeStates {
		switch nodeState.Status {
		case NodeStatusCompleted:
			nodesSkipped = append(nodesSkipped, nodeID)
		case NodeStatusPending, NodeStatusFailed:
			nodesToReplay = append(nodesToReplay, nodeID)
		case NodeStatusRunning:
			// Running node should be restarted
			nodesToReplay = append(nodesToReplay, nodeID)
			if startNode == "" || nodeID == currentNode {
				startNode = nodeID
			}
		}
	}

	// If no start node determined, use current node or first pending node
	if startNode == "" {
		if currentNode != "" {
			startNode = currentNode
		} else if len(nodesToReplay) > 0 {
			startNode = nodesToReplay[0]
		}
	}

	return &ReplayPlan{
		SourceCheckpoint: checkpoint,
		ExecutionState:   executionState,
		NodesToReplay:    nodesToReplay,
		NodesSkipped:     nodesSkipped,
		StartNode:        startNode,
	}, nil
}

// MergeBranch merges the final state from a branch thread back to the target thread
func (bm *DefaultBranchManager) MergeBranch(ctx context.Context, branchThreadID string, targetThreadID string) error {
	// Get the most recent checkpoint from the branch thread
	branchCheckpoints, err := bm.store.ListCheckpoints(ctx, branchThreadID)
	if err != nil {
		return fmt.Errorf("failed to list branch checkpoints: %w", err)
	}

	if len(branchCheckpoints) == 0 {
		return fmt.Errorf("no checkpoints found in branch thread")
	}

	// Get the latest checkpoint (assuming they're sorted by timestamp)
	latestBranchCheckpoint := branchCheckpoints[len(branchCheckpoints)-1]

	// Restore the branch's final execution state
	branchState, err := bm.restorer.RestoreState(ctx, latestBranchCheckpoint)
	if err != nil {
		return fmt.Errorf("failed to restore branch state: %w", err)
	}

	// Get the latest checkpoint from target thread
	targetCheckpoints, err := bm.store.ListCheckpoints(ctx, targetThreadID)
	if err != nil {
		return fmt.Errorf("failed to list target checkpoints: %w", err)
	}

	if len(targetCheckpoints) == 0 {
		return fmt.Errorf("no checkpoints found in target thread")
	}

	latestTargetCheckpoint := targetCheckpoints[len(targetCheckpoints)-1]

	// Create a merged checkpoint in the target thread
	mergedCheckpoint := &Checkpoint{
		ID:              generateCheckpointID(),
		ThreadID:        targetThreadID,
		ParentID:        latestTargetCheckpoint.ID,
		Timestamp:       time.Now(),
		ExecutionState:  branchState, // Use branch's final state
		MissionSnapshot: latestTargetCheckpoint.MissionSnapshot,
		Metadata: map[string]interface{}{
			"merged_from_branch": branchThreadID,
			"merge_timestamp":    time.Now(),
			"branch_checkpoint":  latestBranchCheckpoint.ID,
		},
	}

	// Save the merged checkpoint
	if err := bm.store.SaveCheckpoint(ctx, mergedCheckpoint); err != nil {
		return fmt.Errorf("failed to save merged checkpoint: %w", err)
	}

	return nil
}

// ApplyUpdates merges StateUpdates into ExecutionState, creating a new modified state
func ApplyUpdates(state *ExecutionState, updates *StateUpdates) *ExecutionState {
	// Create a deep copy of the state to maintain immutability
	newState := &ExecutionState{
		ThreadID:            state.ThreadID,
		MissionDefinitionID: state.MissionDefinitionID,
		CurrentNode:         state.CurrentNode,
		Status:              state.Status,
		Variables:           copyMap(state.Variables),
		ToolResults:         copyToolResults(state.ToolResults),
		Memory:              copyMap(state.Memory),
		NodeStates:          copyNodeStates(state.NodeStates),
		StartTime:           state.StartTime,
		EndTime:             state.EndTime,
		Error:               state.Error,
	}

	// Apply variable updates
	if updates.Variables != nil {
		for key, value := range updates.Variables {
			newState.Variables[key] = value
		}
	}

	// Apply tool result updates
	if updates.ToolResults != nil {
		for key, result := range updates.ToolResults {
			newState.ToolResults[key] = result
		}
	}

	// Apply memory updates
	if updates.Memory != nil {
		for key, value := range updates.Memory {
			newState.Memory[key] = value
		}
	}

	// Apply node state updates
	if updates.NodeStates != nil {
		for nodeID, nodeState := range updates.NodeStates {
			newState.NodeStates[nodeID] = nodeState
		}
	}

	return newState
}

// Helper functions for deep copying

func copyMap(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return make(map[string]interface{})
	}
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyToolResults(m map[string]*ToolResult) map[string]*ToolResult {
	if m == nil {
		return make(map[string]*ToolResult)
	}
	result := make(map[string]*ToolResult, len(m))
	for k, v := range m {
		if v != nil {
			result[k] = &ToolResult{
				ToolName:  v.ToolName,
				Output:    v.Output,
				Error:     v.Error,
				Timestamp: v.Timestamp,
				Duration:  v.Duration,
			}
		}
	}
	return result
}

func copyNodeStates(m map[string]NodeState) map[string]NodeState {
	if m == nil {
		return make(map[string]NodeState)
	}
	result := make(map[string]NodeState, len(m))
	for k, v := range m {
		result[k] = NodeState{
			NodeID:    v.NodeID,
			Status:    v.Status,
			StartTime: v.StartTime,
			EndTime:   v.EndTime,
			Attempts:  v.Attempts,
			Error:     v.Error,
			Output:    v.Output,
			Metadata:  copyMap(v.Metadata),
		}
	}
	return result
}

// generateCheckpointID generates a unique checkpoint ID
func generateCheckpointID() string {
	return fmt.Sprintf("ckpt_%d", time.Now().UnixNano())
}
