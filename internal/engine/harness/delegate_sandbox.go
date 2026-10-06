// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// AgentSandboxLauncher launches an untrusted/sandboxed agent as an ephemeral
// Setec sandbox for one mission run and waits for its terminal outcome
// (ADR-0116 / gibson#1596). *sandboxed.AgentLauncher satisfies it. The harness
// depends on this interface rather than the concrete launcher so a build
// without setec_integration wires nil and tests can supply a stub.
//
// Nil means no sandboxed agent dispatch: DelegateToAgent denies an untrusted
// agent fail-closed.
type AgentSandboxLauncher interface {
	LaunchAgent(ctx context.Context, spec sandboxed.AgentLaunchSpec, dispatch sandboxed.AgentDispatch) (sandboxed.AgentRunResult, error)
	// ForkAgent starts the dispatches in forks of a running source sandbox
	// (ADR-0169).
	ForkAgent(ctx context.Context, sourceSandboxID string, spec sandboxed.AgentForkSpec, dispatches []sandboxed.AgentDispatch) (sandboxed.ForkRun, error)
}

// AgentLaunchSpecResolver resolves the per-agent launch spec — image, sandbox
// class, egress envelope and resolved model — for a sandboxed agent. This slice
// (gibson#1596) treats it as a typed seam: tests supply a resolver and S5
// (gibson#1597) wires the real signed-catalog-manifest resolver that also
// resolves the newest tenant model at dispatch (ADR-0116).
//
// Nil means no spec source, so a sandboxed dispatch cannot proceed and the
// harness denies fail-closed rather than launching with an empty image.
type AgentLaunchSpecResolver interface {
	ResolveAgentLaunchSpec(ctx context.Context, req AgentLaunchRequest) (sandboxed.AgentLaunchSpec, error)
}

// AgentLaunchRequest is what the dispatch knows about the launch it is asking
// for. It is a struct rather than a parameter list because the shape grows: a
// bank launch adds the login shape today (gibson#1714) and more later, and a
// resolver that took positional arguments would break every caller each time.
// The tenant is NOT a field. It comes from the caller identity on the context,
// the way every other tenant-scoped decision in the daemon reads it
// (Requirement 8.7): a launch that could name its own tenant would resolve
// another tenant's provider credentials.
type AgentLaunchRequest struct {
	// AgentName is the catalog id of the agent to launch. Required.
	AgentName string
	// LoginShape is how the agent authenticates to its model vendor
	// (ADR-0119). Empty means the API-key shape: a one-shot
	// dispatch has no person present to sign in.
	LoginShape string
	// Mode is which of the two shapes one image runs as (ADR-0119): a one-shot
	// process that serves one dispatch and ends, or a member that serves many
	// over its life. Empty means one-shot, which is what a mission dispatch is.
	Mode string
}

// Instance modes. One image carries both shapes, so the difference is the
// command the launch runs and the variable the process reads to know which it
// is.
const (
	// ModeOneShot runs one dispatch and ends. It is the default.
	ModeOneShot = "oneshot"
	// ModeMember is a long-lived member of a bank.
	ModeMember = "member"
)

// IsInstanceMode reports whether m names an instance mode. The empty string is
// a mode: it means one-shot.
func IsInstanceMode(m string) bool {
	return m == "" || m == ModeOneShot || m == ModeMember
}

// delegateToAgentViaSandbox launches an untrusted/sandboxed agent as an
// ephemeral Setec sandbox for one mission run, injecting the per-dispatch grant
// and the tenant egress envelope, and waits for the terminal outcome
// (ADR-0116). The tenant-enablement gate has already run in DelegateToAgent, so
// this is authorized before the sandbox starts.
//
// It returns the structured result of the agent in Result.Output. The agent
// writes that result as the last result line on its stdout, and the launcher
// reads it (sandboxed.AgentTerminalResult). A sandbox that exits with no
// result line is an error, and so is a result that reports a failure.
// Teardown is left to setec's finished-TTL reaper.
func (h *DefaultAgentHarness) delegateToAgentViaSandbox(
	ctx context.Context,
	name string,
	task agent.Task,
	_ componentpb.ContentTrust,
) (agent.Result, error) {
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return agent.Result{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent %q: no tenant in context; refusing sandboxed dispatch", name))
	}
	if h.agentLaunchSpecResolver == nil {
		return agent.Result{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent %q: sandboxed dispatch needs a launch-spec source (catalog manifest, gibson#1597) which is not wired", name))
	}

	spec, err := h.agentLaunchSpecResolver.ResolveAgentLaunchSpec(ctx, AgentLaunchRequest{AgentName: name})
	if err != nil {
		return agent.Result{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent %q: resolve launch spec", name), err)
	}

	// The network scope of the node (S6, gibson#865). The sandbox reaches the
	// targets of the node, the model provider and the callback endpoint of
	// the daemon. A research node is unrestricted.
	if task.Network != nil {
		spec.NetworkMode, spec.Egress = nodeNetworkScope(task.Network, h.agentCallbackEndpoint)
	}

	// The sandboxed agent calls back over HarnessCallbackService with
	// (mission, agent) in its context. Those calls resolve through the
	// callback registry to a harness, so the child harness of this agent is
	// registered for the run, as on the work queue path (gibson#1633). Its
	// mission context carries the scope of the node, so each tool that the
	// agent starts gets the network of the node.
	if h.callbackManager != nil && h.factory != nil {
		childMissionCtx := h.missionCtx
		childMissionCtx.CurrentAgent = name
		childMissionCtx.DelegationDepth = h.missionCtx.DelegationDepth + 1
		childMissionCtx.NodeSlotOverrides = task.SlotOverrides
		childMissionCtx.NodeNetwork = task.Network
		childMissionCtx.NodeID = task.NodeID
		childHarness, cerr := h.factory(ctx, childMissionCtx, h.targetInfo)
		if cerr != nil {
			return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed,
				"failed to create child harness for the sandboxed agent: "+name, cerr)
		}
		if key := h.callbackManager.RegisterHarnessForMission(h.missionCtx.ID.String(), name, childHarness); key != "" {
			defer h.callbackManager.UnregisterHarness(key)
		}
	}

	// Per-dispatch grant: a tenant+run-scoped CG-JWT with a short TTL, nothing
	// standing (ADR-0116). Reuses the work-item minter with recipient
	// class "agent", so the sandboxed agent's callback subject matches the
	// in-process delegation subject exactly.
	grant := h.mintCGForWork(name, "agent")

	taskPayload, marshalErr := protojson.Marshal(agent.TaskToProto(task))
	if marshalErr != nil {
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed,
			"marshal agent task for sandbox: "+name, marshalErr)
	}

	dispatch := sandboxed.AgentDispatch{
		Grant:            grant,
		CallbackEndpoint: h.agentCallbackEndpoint,
		MissionID:        h.missionCtx.ID.String(),
		MissionRunID:     h.missionCtx.MissionRunID,
		AgentRunID:       h.missionCtx.AgentRunID,
		TaskB64:          base64.StdEncoding.EncodeToString(taskPayload),
		// Live-console scope (ADR-0116 S11): the customer tenant that owns this
		// mission run and the agent name, so the running instance is enumerable
		// and keyed to the caller's tenant, never the setec infra tenant.
		Tenant:    tenant,
		AgentName: name,
		// The node's declared timeout bounds the sandbox too, or the launcher's
		// thirty-minute default would cap a live session that declared eight
		// hours (gibson#1602).
		RunTimeout: capRunTimeout(task.Timeout, spec.MaxRuntime),
	}

	if task.StartsFrom != "" {
		return h.delegateToAgentViaFork(ctx, name, task, spec, dispatch)
	}
	if task.Forkable && h.forks != nil {
		dispatch.Forkable = true
	}

	h.logger.Info("dispatching agent to ephemeral sandbox",
		"agent", name,
		"tenant", tenant,
		"mission_run_id", h.missionCtx.MissionRunID,
		"sandbox_class", spec.SandboxClass,
		"egress_rules", len(spec.Egress))

	outcome, launchErr := h.agentLauncher.LaunchAgent(ctx, spec, dispatch)
	if launchErr != nil {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "sandbox",
		})
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed,
			"agent sandbox launch failed: "+name, launchErr)
	}
	if outcome.Parked {
		h.forks.Parked.Park(h.missionCtx.MissionRunID, task.NodeID, ParkedSource{
			Tenant:    tenant,
			SandboxID: outcome.SandboxID,
			GrantJTI:  grantJTI(grant),
		})
	}
	return h.sandboxOutcome(name, tenant, task, outcome, nil)
}

// sandboxOutcome turns the outcome of a sandboxed agent run into the result
// of the node. extra adds keys to the metadata of the result.
func (h *DefaultAgentHarness) sandboxOutcome(name, tenant string, task agent.Task, outcome sandboxed.AgentRunResult, extra map[string]any) (agent.Result, error) {
	if outcome.ExitCode != 0 {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "sandbox",
		})
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("agent %q sandbox %s exited %d (%s): %s",
				name, outcome.SandboxID, outcome.ExitCode, outcome.Reason, outcome.LogTail))
	}

	if outcome.Result == nil {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "sandbox",
		})
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("agent %q sandbox %s exited 0 and wrote no result line", name, outcome.SandboxID))
	}
	if !outcome.Result.Success {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "sandbox",
		})
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("agent %q sandbox %s reported a failure: %s", name, outcome.SandboxID, outcome.Result.Output))
	}

	h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
		"agent": name, "status": "success", "transport": "sandbox",
	})
	h.logger.Info("agent sandbox delegation completed",
		"agent", name, "tenant", tenant, "sandbox_id", outcome.SandboxID)

	out := sandboxResultOutput(outcome.Result)
	if len(extra) > 0 {
		meta, _ := out["metadata"].(map[string]any)
		if meta == nil {
			meta = make(map[string]any, len(extra))
		}
		for k, v := range extra {
			meta[k] = v
		}
		out["metadata"] = meta
	}
	result := agent.NewResult(task.ID)
	result.Complete(out)
	return result, nil
}

// sandboxResultOutput maps the terminal result of a sandboxed agent to the
// output of the mission node.
func sandboxResultOutput(r *sandboxed.AgentTerminalResult) map[string]any {
	out := map[string]any{"output": r.Output}
	if len(r.FindingIDs) > 0 {
		ids := make([]any, len(r.FindingIDs))
		for i, id := range r.FindingIDs {
			ids[i] = id
		}
		out["finding_ids"] = ids
	}
	if len(r.Metadata) > 0 {
		out["metadata"] = r.Metadata
	}
	return out
}

// capRunTimeout bounds a dispatch's run timeout by the enrollment cap
// (gibson#597): the cap wins when the node asked for nothing or for more
// than the cap allows, and a zero cap changes nothing.
func capRunTimeout(requested, limit time.Duration) time.Duration {
	if limit <= 0 {
		return requested
	}
	if requested <= 0 || requested > limit {
		return limit
	}
	return requested
}
