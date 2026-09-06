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
// (ADR-0016 / gibson#1596). *sandboxed.AgentLauncher satisfies it. The harness
// depends on this interface rather than the concrete launcher so a build
// without setec_integration wires nil and tests can supply a stub.
//
// Nil means no sandboxed agent dispatch: DelegateToAgent denies an untrusted
// agent fail-closed under setec-only.
type AgentSandboxLauncher interface {
	LaunchAgent(ctx context.Context, spec sandboxed.AgentLaunchSpec, dispatch sandboxed.AgentDispatch) (sandboxed.AgentRunResult, error)
}

// AgentLaunchSpecResolver resolves the per-agent launch spec — image, sandbox
// class, egress envelope and resolved model — for a sandboxed agent. This slice
// (gibson#1596) treats it as a typed seam: tests supply a resolver and S5
// (gibson#1597) wires the real signed-catalog-manifest resolver that also
// resolves the newest tenant model at dispatch (ADR-0016 decision 7).
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
	// (ADR-0019 decision 4). Empty means the API-key shape: a one-shot
	// dispatch has no person present to sign in.
	LoginShape string
	// Mode is which of the two shapes one image runs as (ADR-0019): a one-shot
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
// (ADR-0016). The tenant-enablement gate has already run in DelegateToAgent, so
// this is authorized before the sandbox starts.
//
// It returns a terminal Result on a clean exit. The agent's STRUCTURED mission
// result returns over the agent's own callback seam to the daemon, not through
// setec, which reports only exit status and streamed stdout. Correlating that
// payload back into Result.Output is the next slice; this slice reports the
// terminal run outcome and leaves teardown to setec's finished-TTL reaper.
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

	// Per-dispatch grant: a tenant+run-scoped CG-JWT with a short TTL, nothing
	// standing (ADR-0016 decision 2). Reuses the work-item minter with recipient
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
		// Live-console scope (ADR-0016 S11): the customer tenant that owns this
		// mission run and the agent name, so the running instance is enumerable
		// and keyed to the caller's tenant, never the setec infra tenant.
		Tenant:    tenant,
		AgentName: name,
		// The node's declared timeout bounds the sandbox too, or the launcher's
		// thirty-minute default would cap a live session that declared eight
		// hours (gibson#1602).
		RunTimeout: task.Timeout,
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
	if outcome.ExitCode != 0 {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "sandbox",
		})
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("agent %q sandbox %s exited %d (%s): %s",
				name, outcome.SandboxID, outcome.ExitCode, outcome.Reason, outcome.LogTail))
	}

	h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
		"agent": name, "status": "success", "transport": "sandbox",
	})
	h.logger.Info("agent sandbox delegation completed",
		"agent", name, "tenant", tenant, "sandbox_id", outcome.SandboxID)

	result := agent.NewResult(task.ID)
	result.Status = agent.ResultStatusCompleted
	result.CompletedAt = time.Now()
	return result, nil
}
