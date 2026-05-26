// Package orchestrator — checkpoint_actor_wrapper.go
//
// CheckpointAwareActor wraps an OrchestratorActor and invokes the configured
// CheckpointIntegration after every Act call. This is the production wiring
// path for Spec 4 mission-checkpointing's OnSuperStepComplete hook: the daemon
// constructs the wrapped actor at orchestrator-init time and the orchestrator
// loop transparently fires the checkpoint hook every iteration.
//
// Why a wrapper rather than threading the hook through Orchestrator.Run:
// the canonical Orchestrator struct's Run loop body is under a separate edit
// budget that this agent must respect. Wrapping the actor at construction
// gives the same observable behaviour without touching the Run loop.
//
// Spec: mission-checkpointing R1.1, R1.4, R5.1, R5.2.
package orchestrator

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/checkpoint"
)

// CheckpointAwareActor wraps an OrchestratorActor and ensures the
// CheckpointIntegration hook fires after every action.
type CheckpointAwareActor struct {
	inner       OrchestratorActor
	integration *CheckpointIntegration
	observer    OrchestratorObserver // used to capture state for the checkpoint
	logger      Logger
}

// NewCheckpointAwareActor wraps the supplied actor with checkpoint hooks. The
// integration MUST be non-nil for the wrapper to do anything; if nil, the
// wrapper is a pass-through.
func NewCheckpointAwareActor(inner OrchestratorActor, observer OrchestratorObserver, integration *CheckpointIntegration, logger Logger) *CheckpointAwareActor {
	if logger == nil {
		logger = WrapSlogLogger(nil)
	}
	return &CheckpointAwareActor{
		inner:       inner,
		integration: integration,
		observer:    observer,
		logger:      logger,
	}
}

// Act delegates to the wrapped actor, then invokes the checkpoint hook.
func (w *CheckpointAwareActor) Act(ctx context.Context, decision *Decision, missionID string) (*ActionResult, error) {
	result, err := w.inner.Act(ctx, decision, missionID)

	if w.integration == nil {
		return result, err
	}
	// Skip hooks on errors that aborted before the actor produced state.
	if err != nil && result == nil {
		return result, err
	}

	// Capture the post-action observation. We do this lazily — the integration
	// captures memory snapshots itself; we just need a thin ExecutionState
	// projection for the super-step boundary.
	if w.observer != nil {
		state, oerr := w.observer.Observe(ctx, missionID)
		if oerr == nil && state != nil {
			completedNodeIDs := make([]string, 0, len(state.CompletedNodes))
			for _, n := range state.CompletedNodes {
				completedNodeIDs = append(completedNodeIDs, n.ID)
			}
			execState := w.captureExecState(state, decision, result)
			if cpErr := w.integration.OnSuperStepComplete(ctx, execState, completedNodeIDs); cpErr != nil {
				w.logger.Warn(ctx, "checkpoint write failed", "err", cpErr)
				checkpoint.GetMetrics().RecordWriteOutcome(false, 0, 0, "integration_error")
			}

			// Parallel-group bookkeeping — Spec 4 R4.x.
			if result != nil && result.Metadata != nil {
				if groupID, ok := result.Metadata["parallel_group_id"].(string); ok && groupID != "" {
					if expected, ok := result.Metadata["parallel_group_total"].(int); ok && expected > 0 {
						w.integration.SetParallelGroupTotal(groupID, expected)
					}
					didFire := w.integration.TrackParallelCompletion(groupID, result.TargetNodeID)
					if !didFire {
						hint, _ := result.Metadata["parallel_group_complete"].(bool)
						didFire = hint
					}
					if didFire {
						completed := []string{result.TargetNodeID}
						if cpErr := w.integration.OnParallelGroupComplete(ctx, execState, groupID, completed); cpErr != nil {
							w.logger.Warn(ctx, "parallel-group checkpoint failed", "group_id", groupID, "err", cpErr)
						}
					}
				}
			}
		}
	}

	return result, err
}

func (w *CheckpointAwareActor) captureExecState(state *ObservationState, decision *Decision, result *ActionResult) *ExecutionState {
	es := &ExecutionState{
		NodeStates:       make(map[string]*checkpoint.NodeState),
		CompletedResults: make(map[string]*checkpoint.NodeOutput),
		PendingQueue:     make([]string, 0, len(state.ReadyNodes)),
		Metadata:         make(map[string]any),
	}
	if decision != nil {
		es.CurrentNodeID = decision.TargetNodeID
	} else if result != nil {
		es.CurrentNodeID = result.TargetNodeID
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
	return es
}

// Compile-time check: CheckpointAwareActor must satisfy the OrchestratorActor
// interface so the daemon can drop it into NewOrchestrator.
var _ OrchestratorActor = (*CheckpointAwareActor)(nil)
