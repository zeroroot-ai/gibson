package mission

import (
	"fmt"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
	missionv1 "github.com/zero-day-ai/sdk/api/gen/gibson/mission/v1"
)

// NodeStatus represents the execution status of a mission node
type NodeStatus string

const (
	NodeStatusPending   NodeStatus = "pending"
	NodeStatusRunning   NodeStatus = "running"
	NodeStatusCompleted NodeStatus = "completed"
	NodeStatusFailed    NodeStatus = "failed"
	NodeStatusSkipped   NodeStatus = "skipped"
	NodeStatusCancelled NodeStatus = "cancelled"
)

// NodeError represents an error that occurred during node execution
type NodeError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	Cause   error          `json:"-"`
}

// Error implements the error interface for NodeError
func (e *NodeError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// NodeResult represents the execution result of a single mission node
type NodeResult struct {
	NodeID      string          `json:"node_id"`
	Status      NodeStatus      `json:"status"`
	Output      map[string]any  `json:"output,omitempty"`
	Error       *NodeError      `json:"error,omitempty"`
	Findings    []agent.Finding `json:"findings,omitempty"`
	Duration    time.Duration   `json:"duration"`
	RetryCount  int             `json:"retry_count"`
	StartedAt   time.Time       `json:"started_at"`
	CompletedAt time.Time       `json:"completed_at"`
	Metadata    map[string]any  `json:"metadata,omitempty"`
}

// NodeState tracks the execution state of a single mission node.
type NodeState struct {
	// NodeID is the unique identifier for the node
	NodeID string

	// Status is the current execution status of the node
	Status NodeStatus

	// StartedAt is the timestamp when the node execution began
	StartedAt *time.Time

	// CompletedAt is the timestamp when the node execution completed
	CompletedAt *time.Time

	// RetryCount tracks the number of retry attempts for this node
	RetryCount int

	// RetryParams stores custom parameters for retry attempts
	RetryParams map[string]any

	// Error stores any error that occurred during node execution
	Error error
}

// MissionState manages the runtime execution state of a mission.
// It tracks the status of all nodes, their results, and provides thread-safe
// access to state information during mission execution.
//
// Note: MissionState is used for runtime execution tracking. It differs from
// the Mission struct which represents the persisted mission record. A Mission
// may have multiple MissionState instances across checkpoints and retries.
type MissionState struct {
	// MissionID is the unique identifier for this mission execution
	MissionID types.ID

	// Definition is a reference to the mission definition being executed
	Definition *missionv1.MissionDefinition

	// Status is the current execution status of the mission
	Status MissionStatus

	// NodeStates tracks the execution state of each node, indexed by node ID
	NodeStates map[string]*NodeState

	// Results stores the execution results for completed nodes, indexed by node ID
	Results map[string]*NodeResult

	// ExecutionOrder defines the custom order for executing pending nodes
	ExecutionOrder []string

	// StartedAt is the timestamp when mission execution began
	StartedAt time.Time

	// CompletedAt is the timestamp when mission execution completed (nil if still running)
	CompletedAt *time.Time

	// mu provides thread-safe access to the mission state
	mu sync.RWMutex
}

// NewMissionState creates a new MissionState instance initialized with all nodes
// in pending status. This prepares the state for mission execution.
//
// Note: The nodes parameter will change to use MissionDefinition.Nodes once definition.go
// is created in task 1.1. For now, it accepts a generic map.
func NewMissionState(missionID types.ID, nodes map[string]any) *MissionState {
	nodeStates := make(map[string]*NodeState, len(nodes))

	// Initialize all nodes to pending status
	for nodeID := range nodes {
		nodeStates[nodeID] = &NodeState{
			NodeID:     nodeID,
			Status:     NodeStatusPending,
			RetryCount: 0,
		}
	}

	return &MissionState{
		MissionID:  missionID,
		Status:     MissionStatusPending,
		NodeStates: nodeStates,
		Results:    make(map[string]*NodeResult),
		StartedAt:  time.Now(),
	}
}

// GetReadyNodes returns all nodes that are ready to be executed.
// A node is ready if:
//   - Its status is pending
//   - All of its dependencies have completed successfully
//
// This method is thread-safe and uses a read lock.
func (ms *MissionState) GetReadyNodes() []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	var readyNodes []string

	for nodeID, nodeState := range ms.NodeStates {
		// Skip if node is not pending
		if nodeState.Status != NodeStatusPending {
			continue
		}

		// Check dependencies if definition is available
		if ms.Definition != nil {
			node := ms.Definition.GetNodes()[nodeID]
			if node != nil && len(node.GetDependencies()) > 0 {
				if !ms.areDependenciesCompleted(node.GetDependencies()) {
					continue
				}
			}
		}

		readyNodes = append(readyNodes, nodeID)
	}

	return readyNodes
}

// areDependenciesCompleted checks if all dependencies for a node have completed successfully.
// This is an internal helper method that must be called with a lock held.
func (ms *MissionState) areDependenciesCompleted(dependencies []string) bool {
	if len(dependencies) == 0 {
		return true
	}

	for _, depID := range dependencies {
		depState, exists := ms.NodeStates[depID]
		if !exists {
			return false
		}

		// Dependency must be completed successfully
		if depState.Status != NodeStatusCompleted {
			return false
		}
	}

	return true
}

// MarkNodeStarted marks a node as started and sets the StartedAt timestamp.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) MarkNodeStarted(nodeID string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if nodeState, exists := ms.NodeStates[nodeID]; exists {
		nodeState.Status = NodeStatusRunning
		now := time.Now()
		nodeState.StartedAt = &now
	}
}

// MarkNodeCompleted marks a node as successfully completed, stores its result,
// and sets the CompletedAt timestamp.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) MarkNodeCompleted(nodeID string, result *NodeResult) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if nodeState, exists := ms.NodeStates[nodeID]; exists {
		nodeState.Status = NodeStatusCompleted
		now := time.Now()
		nodeState.CompletedAt = &now

		// Store the result
		if result != nil {
			ms.Results[nodeID] = result
		}
	}
}

// MarkNodeFailed marks a node as failed and stores the error that caused the failure.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) MarkNodeFailed(nodeID string, err error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if nodeState, exists := ms.NodeStates[nodeID]; exists {
		nodeState.Status = NodeStatusFailed
		nodeState.Error = err
		now := time.Now()
		nodeState.CompletedAt = &now
	}
}

// MarkNodeSkipped marks a node as skipped with a reason.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) MarkNodeSkipped(nodeID string, reason string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if nodeState, exists := ms.NodeStates[nodeID]; exists {
		nodeState.Status = NodeStatusSkipped
		now := time.Now()
		nodeState.CompletedAt = &now

		// Store the skip reason as a result for tracking purposes
		ms.Results[nodeID] = &NodeResult{
			NodeID:      nodeID,
			Status:      NodeStatusSkipped,
			Metadata:    map[string]any{"skip_reason": reason},
			CompletedAt: now,
		}
	}
}

// StoreResult stores a node result. This is useful for storing results from failed
// nodes so we can extract error output details later.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) StoreResult(nodeID string, result *NodeResult) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if result != nil {
		ms.Results[nodeID] = result
	}
}

// IsComplete returns true if all nodes in the mission have reached a terminal status
// (completed, failed, or skipped).
// This method is thread-safe and uses a read lock.
func (ms *MissionState) IsComplete() bool {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	for _, nodeState := range ms.NodeStates {
		// Check if node has reached a terminal status
		switch nodeState.Status {
		case NodeStatusCompleted, NodeStatusFailed, NodeStatusSkipped, NodeStatusCancelled:
			// Terminal status - continue checking other nodes
			continue
		default:
			// Non-terminal status found - mission is not complete
			return false
		}
	}

	return true
}

// GetResult returns the execution result for a specific node.
// Returns nil if no result exists for the node.
// This method is thread-safe and uses a read lock.
func (ms *MissionState) GetResult(nodeID string) *NodeResult {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	return ms.Results[nodeID]
}

// GetNodeStatus returns the current status of a specific node.
// Returns an empty NodeStatus if the node doesn't exist in the state.
// This method is thread-safe and uses a read lock.
func (ms *MissionState) GetNodeStatus(nodeID string) NodeStatus {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if nodeState, exists := ms.NodeStates[nodeID]; exists {
		return nodeState.Status
	}

	return ""
}

// GetPendingNodes returns all node IDs that are in pending status.
// Returns an empty slice (not nil) when no pending nodes exist.
// This method is thread-safe and uses a read lock.
func (ms *MissionState) GetPendingNodes() []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	pendingNodes := make([]string, 0)

	for nodeID, nodeState := range ms.NodeStates {
		if nodeState.Status == NodeStatusPending {
			pendingNodes = append(pendingNodes, nodeID)
		}
	}

	return pendingNodes
}

// GetExecutionOrder returns the execution order for pending nodes.
// If a custom order has been set via SetExecutionOrder, it returns that order.
// Otherwise, it returns nodes in dependency order (topological sort).
// This method is thread-safe and uses a read lock.
func (ms *MissionState) GetExecutionOrder() []string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	// If custom order is set, return it
	if len(ms.ExecutionOrder) > 0 {
		return ms.ExecutionOrder
	}

	// Otherwise, return pending nodes in dependency order
	return ms.getPendingInDependencyOrder()
}

// SetExecutionOrder sets a custom execution order for pending nodes.
// It validates that:
//   - All nodes in the order exist in the mission
//   - All nodes in the order are currently pending
//   - The order respects dependency constraints
//
// This method is thread-safe and uses a write lock.
func (ms *MissionState) SetExecutionOrder(order []string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Validate all nodes exist
	for _, nodeID := range order {
		if _, exists := ms.NodeStates[nodeID]; !exists {
			return fmt.Errorf("node %s not found in mission", nodeID)
		}
	}

	// Validate all nodes are pending
	for _, nodeID := range order {
		nodeState, exists := ms.NodeStates[nodeID]
		if !exists || nodeState.Status != NodeStatusPending {
			return fmt.Errorf("node %s is not pending", nodeID)
		}
	}

	// Validate dependency order if definition is available
	if ms.Definition != nil {
		if err := ms.validateDependencyOrder(order); err != nil {
			return err
		}
	}

	ms.ExecutionOrder = order
	return nil
}

// ReorderRemaining allows reordering of remaining pending nodes during execution.
// It validates the new order respects dependencies and only includes pending nodes.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) ReorderRemaining(order []string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Validate all nodes are pending
	for _, nodeID := range order {
		nodeState, exists := ms.NodeStates[nodeID]
		if !exists {
			return fmt.Errorf("node %s not found in mission", nodeID)
		}
		if nodeState.Status != NodeStatusPending {
			return fmt.Errorf("node %s is not pending", nodeID)
		}
	}

	// Validate dependency order if definition is available
	if ms.Definition != nil {
		if err := ms.validateDependencyOrder(order); err != nil {
			return err
		}
	}

	ms.ExecutionOrder = order
	return nil
}

// SkipNode marks a node as skipped with a reason and removes it from the execution order.
// The node must be in pending status.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) SkipNode(nodeID string, reason string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Validate node exists
	nodeState, exists := ms.NodeStates[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found in mission", nodeID)
	}

	// Validate node is pending
	if nodeState.Status != NodeStatusPending {
		return fmt.Errorf("node %s is not pending", nodeID)
	}

	// Mark node as skipped
	nodeState.Status = NodeStatusSkipped
	now := time.Now()
	nodeState.CompletedAt = &now

	// Store the skip reason as a result
	ms.Results[nodeID] = &NodeResult{
		NodeID:      nodeID,
		Status:      NodeStatusSkipped,
		Metadata:    map[string]any{"skip_reason": reason},
		CompletedAt: now,
	}

	// Remove from execution order if present
	if len(ms.ExecutionOrder) > 0 {
		newOrder := make([]string, 0, len(ms.ExecutionOrder)-1)
		for _, id := range ms.ExecutionOrder {
			if id != nodeID {
				newOrder = append(newOrder, id)
			}
		}
		ms.ExecutionOrder = newOrder
	}

	return nil
}

// ResetForRetry resets a failed node back to pending status for retry.
// It increments the retry count and optionally updates node parameters.
// This method is thread-safe and uses a write lock.
func (ms *MissionState) ResetForRetry(nodeID string, newParams map[string]any) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Validate node exists
	nodeState, exists := ms.NodeStates[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found in mission", nodeID)
	}

	// Validate node is failed
	if nodeState.Status != NodeStatusFailed {
		return fmt.Errorf("node %s is not failed", nodeID)
	}

	// Reset node state
	nodeState.Status = NodeStatusPending
	nodeState.StartedAt = nil
	nodeState.CompletedAt = nil
	nodeState.Error = nil
	nodeState.RetryCount++
	nodeState.RetryParams = newParams

	// Remove result
	delete(ms.Results, nodeID)

	return nil
}

// validateDependencyOrder validates that the given node order respects dependency constraints.
// For each node, all its dependencies must appear earlier in the order.
// This is an internal helper that must be called with a lock held.
func (ms *MissionState) validateDependencyOrder(order []string) error {
	if ms.Definition == nil {
		return nil
	}

	// Build a position map for quick lookup
	position := make(map[string]int, len(order))
	for i, nodeID := range order {
		position[nodeID] = i
	}

	// Check each node's dependencies appear before it in the order
	for i, nodeID := range order {
		node := ms.Definition.GetNodes()[nodeID]
		if node == nil {
			continue
		}

		for _, depID := range node.GetDependencies() {
			depPos, exists := position[depID]
			if !exists {
				// Dependency not in order - check if it's already completed
				if depState, ok := ms.NodeStates[depID]; ok && depState.Status == NodeStatusCompleted {
					continue
				}
				return fmt.Errorf("dependency %s for node %s not found in order", depID, nodeID)
			}
			if depPos >= i {
				return fmt.Errorf("dependency %s must appear before node %s in order", depID, nodeID)
			}
		}
	}

	return nil
}

// getPendingInDependencyOrder returns pending nodes in topological order (respecting dependencies).
// This is an internal helper that must be called with a lock held.
func (ms *MissionState) getPendingInDependencyOrder() []string {
	pending := make([]string, 0)
	for nodeID, nodeState := range ms.NodeStates {
		if nodeState.Status == NodeStatusPending {
			pending = append(pending, nodeID)
		}
	}

	// If no definition, return unsorted
	if ms.Definition == nil {
		return pending
	}

	// Topological sort using Kahn's algorithm
	// Build in-degree map for pending nodes only
	inDegree := make(map[string]int)
	for _, nodeID := range pending {
		inDegree[nodeID] = 0
	}

	// Count dependencies that are also pending
	for _, nodeID := range pending {
		node := ms.Definition.GetNodes()[nodeID]
		if node == nil {
			continue
		}
		for _, depID := range node.GetDependencies() {
			if _, isPending := inDegree[depID]; isPending {
				inDegree[nodeID]++
			}
		}
	}

	// Start with nodes that have no pending dependencies
	var queue []string
	for nodeID, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, nodeID)
		}
	}

	// Process queue
	result := make([]string, 0, len(pending))
	for len(queue) > 0 {
		nodeID := queue[0]
		queue = queue[1:]
		result = append(result, nodeID)

		// Find nodes that depend on this one and decrement their in-degree
		for _, otherID := range pending {
			node := ms.Definition.GetNodes()[otherID]
			if node == nil {
				continue
			}
			for _, depID := range node.GetDependencies() {
				if depID == nodeID {
					inDegree[otherID]--
					if inDegree[otherID] == 0 {
						queue = append(queue, otherID)
					}
				}
			}
		}
	}

	return result
}
