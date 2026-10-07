// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An agent forks at run time when it originates a child mission that starts
// from its own state (ADR-0169, gibson#803). CreateMission forks the sandbox
// of the caller at the call, with the network scope of the first node of the
// child, because setec gives a fork its network at the Fork call. The fork
// claims its dispatch at once (sdk#248) and waits in ClaimFork. When the
// brain dispatches the first node of the child, the harness records the
// dispatch for the waiting fork and follows it, in place of a fresh launch.

// ChildFirstNodeSource returns the first node of a child mission, as the run
// of that mission will project it. The mission operator of the daemon
// implements it.
type ChildFirstNodeSource interface {
	ChildFirstNode(ctx context.Context, missionID types.ID) (brain.WorkNode, error)
}

// CallerFork is the fork of a caller for the first node of its child.
type CallerFork struct {
	// CallerSandboxID is the sandbox of the caller, as setec verified it.
	CallerSandboxID string
	// CallerJTI is the id of the grant of the caller.
	CallerJTI string
	// AgentName is the agent of the caller.
	AgentName string
	// ChildMissionID is the child mission, and Node is its first node.
	ChildMissionID types.ID
	Node           brain.WorkNode
}

// CallerForker forks the sandbox of a caller for the first node of its
// child mission. DefaultAgentHarness implements it.
type CallerForker interface {
	ForkCaller(ctx context.Context, req CallerFork) (string, error)
}

var _ CallerForker = (*DefaultAgentHarness)(nil)

// ForkCaller forks the sandbox of the caller once, with the network scope of
// the first node of the child, and records the fork as the seat of that node.
// From the fork on, the grant of the caller works only in the caller sandbox
// (D74). It returns the id of the fork.
func (h *DefaultAgentHarness) ForkCaller(ctx context.Context, req CallerFork) (string, error) {
	if h.forks == nil || h.forks.Ledger == nil || h.agentLauncher == nil || h.agentLaunchSpecResolver == nil {
		return "", types.NewError(ErrHarnessDelegationFailed, "this daemon cannot fork a caller sandbox")
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return "", types.NewError(types.SANDBOX_POLICY_DENIED, "fork of the caller: no tenant in context")
	}
	if req.CallerSandboxID == "" || req.CallerJTI == "" {
		return "", types.NewError(types.SANDBOX_POLICY_DENIED, "fork of the caller: the caller sandbox and its grant are required")
	}
	// A fork continues the process of the caller, so only the agent of the
	// caller can run the node that the fork serves.
	if req.Node.Target != req.AgentName {
		return "", types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("fork of the caller: the first node %q of the child runs %q, not the caller %q", req.Node.ID, req.Node.Target, req.AgentName))
	}
	spec, err := h.agentLaunchSpecResolver.ResolveAgentLaunchSpec(ctx, AgentLaunchRequest{AgentName: req.AgentName})
	if err != nil {
		return "", types.WrapError(types.SANDBOX_POLICY_DENIED, "fork of the caller: resolve launch spec", err)
	}
	// The network scope of the first node of the child, built as a dispatch
	// of that node builds it. Never the scope of the caller.
	mode, egress := spec.NetworkMode, spec.Egress
	if req.Node.Network != nil {
		mode, egress = nodeNetworkScope(req.Node.Network, h.agentCallbackEndpoint)
	}
	if err := h.forks.Ledger.BeginFork(ctx, req.CallerJTI, req.CallerSandboxID, forkRecordTTL); err != nil {
		return "", types.WrapError(ErrHarnessDelegationFailed, "record the fork of the caller", err)
	}
	forkSpec := sandboxed.AgentForkSpec{
		SandboxClass: spec.SandboxClass,
		NetworkMode:  mode,
		Egress:       egress,
		OnForked: func(resp sandboxed.ForkResponse) error {
			return h.forks.Ledger.ReserveForkSeat(ctx, ForkSeat{
				MissionID:       req.ChildMissionID.String(),
				NodeID:          req.Node.ID,
				Tenant:          tenant,
				AgentName:       req.AgentName,
				SandboxID:       resp.SandboxIDs[0],
				SandboxClass:    spec.SandboxClass,
				SourceSandboxID: req.CallerSandboxID,
				SourceJTI:       req.CallerJTI,
			}, forkRecordTTL)
		},
	}
	id, err := h.agentLauncher.ForkSandbox(ctx, tenant, req.CallerSandboxID, forkSpec)
	if err != nil {
		return "", types.WrapError(ErrHarnessDelegationFailed, "fork the caller sandbox", err)
	}
	h.logger.Info("forked the caller for the first node of its child mission",
		"agent", req.AgentName, "tenant", tenant, "child_mission_id", req.ChildMissionID.String(),
		"node", req.Node.ID, "source_sandbox_id", req.CallerSandboxID, "fork_sandbox_id", id)
	return id, nil
}

// takeForkSeat returns the waiting fork of the node of this dispatch.
func (h *DefaultAgentHarness) takeForkSeat(ctx context.Context, task agent.Task) (ForkSeat, bool, error) {
	if h.forks == nil || h.forks.Ledger == nil || task.NodeID == "" {
		return ForkSeat{}, false, nil
	}
	seat, ok, err := h.forks.Ledger.TakeForkSeat(ctx, h.missionCtx.ID.String(), task.NodeID)
	if err != nil {
		return ForkSeat{}, false, types.WrapError(ErrHarnessDelegationFailed, "read the fork seat of node "+task.NodeID, err)
	}
	return seat, ok, nil
}

// delegateToAgentViaSeat runs a node in the fork of a caller that waits for
// it. It records the dispatch of the node for the fork, so the ClaimFork of
// the fork returns, and follows the fork to its end.
func (h *DefaultAgentHarness) delegateToAgentViaSeat(
	ctx context.Context,
	name string,
	task agent.Task,
	spec sandboxed.AgentLaunchSpec,
	dispatch sandboxed.AgentDispatch,
	seat ForkSeat,
) (agent.Result, error) {
	if seat.Tenant != dispatch.Tenant {
		return agent.Result{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("node %q: the waiting fork belongs to another tenant", task.NodeID))
	}
	if seat.AgentName != name {
		return agent.Result{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("node %q runs %q, and the waiting fork continues %q", task.NodeID, name, seat.AgentName))
	}
	err := h.forks.Ledger.RecordForks(ctx, seat.SourceJTI, seat.SourceSandboxID, []ForkDispatch{{
		SandboxID:    seat.SandboxID,
		Tenant:       dispatch.Tenant,
		AgentName:    name,
		MissionID:    dispatch.MissionID,
		MissionRunID: dispatch.MissionRunID,
		AgentRunID:   dispatch.AgentRunID,
		NodeID:       task.NodeID,
		Model:        spec.Model,
		TaskB64:      dispatch.TaskB64,
	}}, forkRecordTTL)
	if err != nil {
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed, "record the dispatch of the waiting fork", err)
	}
	h.logger.Info("dispatching agent to the waiting fork of its caller",
		"agent", name, "tenant", dispatch.Tenant, "node", task.NodeID,
		"fork_sandbox_id", seat.SandboxID, "source_sandbox_id", seat.SourceSandboxID)
	outcome, err := h.agentLauncher.FollowAgent(ctx, seat.SandboxID, seat.SandboxClass, dispatch)
	if err != nil {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "fork",
		})
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed, "agent fork run failed: "+name, err)
	}
	return h.sandboxOutcome(name, dispatch.Tenant, task, outcome, map[string]any{
		"forked_from_sandbox": seat.SourceSandboxID,
	})
}

// callerForkPlan is what CreateMission checked before it creates a child
// that starts from the state of the caller.
type callerForkPlan struct {
	forker    CallerForker
	nodes     ChildFirstNodeSource
	sandboxID string
	jti       string
	agentName string
}

// planCallerFork checks that the caller can be forked: a daemon with fork
// support, a task grant, and a caller sandbox that setec verifies from the
// identity token of the caller (setec#235). The callback interceptor already
// refused a grant that was forked before, outside its source sandbox. The
// result is a gRPC status.
func (s *HarnessCallbackService) planCallerFork(ctx context.Context, parent AgentHarness, req *harnesspb.CreateMissionRequest) (*callerForkPlan, error) {
	forker, ok := parent.(CallerForker)
	if !ok || s.forkLedger == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon cannot fork the caller")
	}
	nodes, ok := s.missionManager.(ChildFirstNodeSource)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "this daemon cannot find the first node of a child mission")
	}
	claims, ok := TaskGrantClaimsFromContext(ctx)
	if !ok || claims.JTI == "" {
		return nil, status.Error(codes.Unauthenticated, "a fork of the caller needs the task grant of the caller")
	}
	sandboxID, err := verifiedSandbox(ctx, s.sandboxIdentity, claims.Tenant.String())
	if err != nil {
		return nil, err
	}
	return &callerForkPlan{
		forker: forker, nodes: nodes, sandboxID: sandboxID, jti: claims.JTI,
		agentName: req.GetContext().GetAgentName(),
	}, nil
}

// forkCallerForChild forks the caller for the first node of the child. The
// result is a gRPC status.
func (s *HarnessCallbackService) forkCallerForChild(ctx context.Context, plan *callerForkPlan, childID types.ID) error {
	node, err := plan.nodes.ChildFirstNode(ctx, childID)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition, "the child mission cannot start from the caller: %v", err)
	}
	if _, err := plan.forker.ForkCaller(ctx, CallerFork{
		CallerSandboxID: plan.sandboxID,
		CallerJTI:       plan.jti,
		AgentName:       plan.agentName,
		ChildMissionID:  childID,
		Node:            node,
	}); err != nil {
		return status.Errorf(codes.FailedPrecondition, "fork the caller: %v", err)
	}
	return nil
}
