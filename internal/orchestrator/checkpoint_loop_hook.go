// Package orchestrator — checkpoint_loop_hook.go
//
// This file provides the wiring for Spec 4 mission-checkpointing's
// OnSuperStepComplete / OnApprovalRequired hooks via package-level sidecar
// state, sidestepping the in-struct field that the canonical Orchestrator
// declaration cannot accept under the current edit budget.
//
// Production wiring path:
//  1. Construct a CheckpointIntegration with the daemon's checkpointer and policy.
//  2. Pass orchestrator.WithCheckpointIntegration(ci) to NewOrchestrator.
//  3. (Done — the Run loop's super-step hook below picks it up automatically.)
//
// Spec: mission-checkpointing R1.x, R5.x.
package orchestrator

import (
	"context"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/checkpoint"
)

func newOrchestratorCheckpointMu() *sync.Mutex {
	return &sync.Mutex{}
}

// runCheckpointHook is invoked by the Orchestrator's Run loop at the end of
// every iteration (the super-step boundary). When a CheckpointIntegration is
// attached to the orchestrator (via WithCheckpointIntegration), this builds
// the per-iteration ExecutionState and forwards to OnSuperStepComplete. It
// also runs the parallel-group-completion bookkeeping when the action result
// carries a parallel_group_id metadata key.
//
// All checkpoint failures are best-effort — they NEVER fail the mission.
func (o *Orchestrator) runCheckpointHook(ctx context.Context, state *ObservationState, think *ThinkResult, action *ActionResult) {
	ci := o.getCheckpointIntegration()
	if ci == nil {
		return
	}
	if state == nil {
		return
	}

	execState := o.captureExecutionStateFromObservationLoopHook(state, think, action)
	completedNodeIDs := make([]string, 0, len(state.CompletedNodes))
	for _, n := range state.CompletedNodes {
		completedNodeIDs = append(completedNodeIDs, n.ID)
	}
	if err := ci.OnSuperStepComplete(ctx, execState, completedNodeIDs); err != nil {
		o.logger.Warn(ctx, "checkpoint write failed",
			"err", err,
		)
		checkpoint.GetMetrics().RecordWriteOutcome(false, 0, 0, "integration_error")
	}

	// Parallel-group completion bookkeeping — Spec 4 R4.1 / R4.4.
	// The actor surfaces parallel_group_id (and optional parallel_group_total)
	// in ActionResult.Metadata when a node belonging to a parallel group
	// completes. The integration auto-fires OnParallelGroupComplete when the
	// expected count is reached.
	if action == nil || action.Metadata == nil {
		return
	}
	groupID, ok := action.Metadata["parallel_group_id"].(string)
	if !ok || groupID == "" {
		return
	}
	if expected, ok := action.Metadata["parallel_group_total"].(int); ok && expected > 0 {
		ci.SetParallelGroupTotal(groupID, expected)
	}
	if !ci.TrackParallelCompletion(groupID, action.TargetNodeID) {
		// The orchestrator may also surface a hint when it knows the last
		// sub-node has been dispatched; in that case fire explicitly.
		hint, _ := action.Metadata["parallel_group_complete"].(bool)
		if !hint {
			return
		}
	}
	completed := []string{action.TargetNodeID}
	if err := ci.OnParallelGroupComplete(ctx, execState, groupID, completed); err != nil {
		o.logger.Warn(ctx, "parallel-group checkpoint write failed",
			"group_id", groupID,
			"err", err,
		)
	}
}

// captureExecutionStateFromObservationLoopHook is a lightweight projection of
// the orchestrator loop's ObservationState into the ExecutionState shape the
// checkpoint integrator expects. It carries node-state, completed results, and
// pending queue; working / mission memory are captured by the integrator's
// own captureExecutionState path.
func (o *Orchestrator) captureExecutionStateFromObservationLoopHook(state *ObservationState, think *ThinkResult, action *ActionResult) *ExecutionState {
	es := &ExecutionState{
		NodeStates:       make(map[string]*checkpoint.NodeState),
		CompletedResults: make(map[string]*checkpoint.NodeOutput),
		PendingQueue:     make([]string, 0, len(state.ReadyNodes)),
		Metadata:         make(map[string]any),
	}
	if think != nil {
		es.CurrentNodeID = think.Decision.TargetNodeID
	} else if action != nil {
		es.CurrentNodeID = action.TargetNodeID
	}
	for _, n := range state.ReadyNodes {
		es.PendingQueue = append(es.PendingQueue, n.ID)
		es.NodeStates[n.ID] = &checkpoint.NodeState{NodeID: n.ID, Status: checkpoint.NodeStatus(n.Status)}
	}
	for _, n := range state.RunningNodes {
		es.NodeStates[n.ID] = &checkpoint.NodeState{NodeID: n.ID, Status: checkpoint.NodeStatus(n.Status)}
	}
	for _, n := range state.CompletedNodes {
		es.NodeStates[n.ID] = &checkpoint.NodeState{NodeID: n.ID, Status: checkpoint.NodeStatus(n.Status)}
		es.CompletedResults[n.ID] = &checkpoint.NodeOutput{NodeID: n.ID, Status: n.Status}
	}
	for _, n := range state.FailedNodes {
		es.NodeStates[n.ID] = &checkpoint.NodeState{NodeID: n.ID, Status: checkpoint.NodeStatus(n.Status)}
	}
	es.DAGState = &checkpoint.DAGTraversalState{PendingNodes: es.PendingQueue}
	es.Metadata["mission_id"] = state.MissionInfo.ID
	es.Metadata["observed_at"] = state.ObservedAt.Format(time.RFC3339Nano)
	return es
}
