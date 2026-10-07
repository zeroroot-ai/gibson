// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// checkpointSnapshotKey is the result metadata key of the snapshot that a
// node of the sandbox checkpoint mode left (ADR-0170). The brain writes it
// on the Timeline event of the node end.
const checkpointSnapshotKey = "checkpoint_snapshot"

// CheckpointSnapshot returns the snapshot that a node left, or "".
func CheckpointSnapshot(res agent.Result) string {
	meta, _ := res.Output["metadata"].(map[string]any)
	snap, _ := meta[checkpointSnapshotKey].(string)
	return snap
}

// checkpointSnapshot takes the snapshot of a parked checkpoint node. A
// failed snapshot does not fail the node: its checkpoint then has no
// snapshot, and a rewind to it starts a fresh sandbox (ADR-0170).
func (h *DefaultAgentHarness) checkpointSnapshot(ctx context.Context, tenant string, task agent.Task, sandboxID string) map[string]any {
	snap, err := h.agentLauncher.SnapshotSandbox(ctx, tenant, sandboxID, SnapshotLife)
	if err != nil {
		h.logger.Warn("checkpoint snapshot not taken; a rewind to this node starts a fresh sandbox",
			"node", task.NodeID, "sandbox_id", sandboxID, "error", err)
		return nil
	}
	if h.forks != nil && h.forks.Ledger != nil {
		if grantID == "" {
			h.logger.Warn("checkpoint snapshot dropped: the grant of the node has no id",
				"node", task.NodeID, "sandbox_id", sandboxID)
			return nil
		}
		if err := h.forks.Ledger.BeginFork(ctx, grantID, sandboxID, forkRecordTTL); err != nil {
			h.logger.Warn("checkpoint snapshot dropped: the grant of the node was not marked as forked",
				"node", task.NodeID, "sandbox_id", sandboxID, "error", err)
			return nil
		}
	}
	return map[string]any{checkpointSnapshotKey: snap}
}

// delegateToAgentViaRestore starts the node of a rewind from the snapshot of
// its checkpoint (ADR-0170). The sandbox gets the tenant and the network of
// the node. The process in it is the parked agent of the earlier run, and it
// claims the dispatch of this node with its verified identity (D80), so the
// daemon records that dispatch for the new sandbox before it can call.
func (h *DefaultAgentHarness) delegateToAgentViaRestore(
	ctx context.Context,
	name string,
	task agent.Task,
	spec sandboxed.AgentLaunchSpec,
	dispatch sandboxed.AgentDispatch,
) (agent.Result, error) {
	if h.forks == nil || h.forks.Ledger == nil {
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			"node "+task.NodeID+" starts from a snapshot, and this daemon has no fork ledger")
	}
	restoreSpec := sandboxed.AgentForkSpec{
		SandboxClass: spec.SandboxClass,
		NetworkMode:  spec.NetworkMode,
		Egress:       spec.Egress,
	}
	onStarted := func(sandboxID string) error {
		return h.forks.Ledger.RecordStart(ctx, ForkDispatch{
			SandboxID:    sandboxID,
			Tenant:       dispatch.Tenant,
			AgentName:    name,
			MissionID:    dispatch.MissionID,
			MissionRunID: dispatch.MissionRunID,
			AgentRunID:   dispatch.AgentRunID,
			NodeID:       task.NodeID,
			Model:        spec.Model,
			TaskB64:      dispatch.TaskB64,
		}, forkRecordTTL)
	}
	h.logger.Info("dispatching agent from a checkpoint snapshot",
		"agent", name, "tenant", dispatch.Tenant, "node", task.NodeID, "snapshot", task.FromSnapshot)
	outcome, err := h.agentLauncher.LaunchFromSnapshot(ctx, task.FromSnapshot, restoreSpec, dispatch, onStarted)
	if errors.Is(err, sandboxed.ErrSnapshotGone) {
		return agent.Result{}, sandboxed.ErrSnapshotGone
	}
	if err != nil {
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed, "agent restore failed: "+name, err)
	}
	return h.sandboxOutcome(name, dispatch.Tenant, task, outcome, map[string]any{
		"restored_from_snapshot": task.FromSnapshot,
	})
}
