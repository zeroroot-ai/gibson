// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package sandboxed

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// SnapshotSandbox takes a snapshot of a running sandbox of the tenant that
// lives for ttl (ADR-0170, setec#242). The sandbox keeps running.
func (l *AgentLauncher) SnapshotSandbox(ctx context.Context, tenant, sandboxID string, ttl time.Duration) (string, error) {
	if tenant == "" || sandboxID == "" {
		return "", types.NewError(types.SANDBOX_POLICY_DENIED, "snapshot: the tenant and the sandbox are required")
	}
	snap, err := l.client.Snapshot(ctx, tenant, sandboxID, ttl)
	if err != nil {
		return "", types.WrapError(types.SANDBOX_LAUNCH_FAILED, "snapshot sandbox "+sandboxID, err)
	}
	return snap, nil
}

// LaunchFromSnapshot starts a sandbox from a snapshot that SnapshotSandbox
// took, with the network of spec, and follows it to its end (ADR-0170). The
// process in the snapshot is a parked agent: it claims the dispatch of its
// new node with its verified identity (D80). onStarted runs after setec
// started the sandbox and before the agent can claim, so the caller records
// the dispatch there. An error of onStarted kills the sandbox.
//
// A snapshot that no longer exists returns ErrSnapshotGone, and the caller
// starts a fresh sandbox.
func (l *AgentLauncher) LaunchFromSnapshot(ctx context.Context, snapshot string, spec AgentForkSpec, dispatch AgentDispatch, onStarted func(sandboxID string) error) (AgentRunResult, error) {
	ctx, span := l.tracer.Start(ctx, "harness.sandboxed.launch_from_snapshot")
	defer span.End()
	if snapshot == "" {
		return AgentRunResult{}, types.NewError(types.SANDBOX_POLICY_DENIED, "restore: no snapshot")
	}
	tenant := dispatch.Tenant
	if tenant == "" {
		return AgentRunResult{}, types.NewError(types.SANDBOX_POLICY_DENIED, "restore: the dispatch names no tenant")
	}
	class := spec.SandboxClass
	if class == "" {
		class = l.sandboxClass
	}
	span.SetAttributes(attribute.String("setec.tenant", tenant), attribute.String("setec.snapshot", snapshot))

	runTimeout := l.runTimeout
	if dispatch.RunTimeout > 0 {
		runTimeout = dispatch.RunTimeout
	}
	resp, err := l.client.Launch(ctx, LaunchRequest{
		Tenant:       tenant,
		FromSnapshot: snapshot,
		Timeout:      runTimeout + killGrace,
		Egress:       spec.Egress,
		NetworkMode:  spec.NetworkMode,
	})
	if errors.Is(err, ErrSnapshotGone) {
		return AgentRunResult{}, ErrSnapshotGone
	}
	if err != nil {
		return AgentRunResult{}, types.WrapError(types.SANDBOX_LAUNCH_FAILED, "launch from snapshot "+snapshot, err)
	}
	if err := onStarted(resp.SandboxID); err != nil {
		l.kill(ctx, tenant, resp.SandboxID)
		return AgentRunResult{}, types.WrapError(types.SANDBOX_LAUNCH_FAILED,
			"record the start of "+resp.SandboxID, err)
	}
	return l.followFork(ctx, tenant, resp.SandboxID, class, dispatch)
}
