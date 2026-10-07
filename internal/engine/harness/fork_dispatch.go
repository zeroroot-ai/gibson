// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// forkRecordTTL bounds the fork record of a source grant. It outlives the
// snapshot (one hour) and the park timeout of a source (ten minutes).
const forkRecordTTL = 2 * time.Hour

// ForkSupport is the fork state of the daemon (ADR-0169, D74).
type ForkSupport struct {
	// Parked holds the sources that wait for a later node.
	Parked *ParkedSources
	// Ledger records the forks of each source grant for the callback
	// service.
	Ledger ForkLedger
}

// ParkedSource is a sandbox whose node ended and whose process waits for a
// fork.
type ParkedSource struct {
	Tenant string
	// AgentName is the agent that ran the node. A fork continues its
	// process, so only the same agent can run a node that starts from it.
	AgentName string
	SandboxID string
	// GrantJTI is the id of the grant of the source. The callback service
	// refuses that grant in a fork.
	GrantJTI string
}

// ParkedSources maps a node of a mission run to its parked source. A mission
// run executes in one daemon process, so the map lives in that process.
type ParkedSources struct {
	mu      sync.Mutex
	sources map[string]ParkedSource
}

// NewParkedSources returns an empty registry.
func NewParkedSources() *ParkedSources {
	return &ParkedSources{sources: make(map[string]ParkedSource)}
}

func parkedKey(missionRunID, nodeID string) string { return missionRunID + "\x00" + nodeID }

// Park records the parked source of a node.
func (p *ParkedSources) Park(missionRunID, nodeID string, src ParkedSource) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sources[parkedKey(missionRunID, nodeID)] = src
}

// Lookup returns the parked source of a node.
func (p *ParkedSources) Lookup(missionRunID, nodeID string) (ParkedSource, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	src, ok := p.sources[parkedKey(missionRunID, nodeID)]
	return src, ok
}

// delegateToAgentViaFork starts a node in a fork of the parked sandbox of
// the node that it names in starts_from (ADR-0169, gibson#802). The fork
// gets the network scope of its own node. The snapshot id goes into the
// metadata of the result, so the brain records it as a Timeline event.
func (h *DefaultAgentHarness) delegateToAgentViaFork(
	ctx context.Context,
	name string,
	task agent.Task,
	spec sandboxed.AgentLaunchSpec,
	dispatch sandboxed.AgentDispatch,
) (agent.Result, error) {
	if h.forks == nil || h.forks.Parked == nil || h.forks.Ledger == nil {
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("node %q starts from %q, and this daemon has no fork support", task.NodeID, task.StartsFrom))
	}
	src, ok := h.forks.Parked.Lookup(h.missionCtx.MissionRunID, task.StartsFrom)
	if !ok {
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("node %q starts from %q, and no parked sandbox of %q exists in this mission run", task.NodeID, task.StartsFrom, task.StartsFrom))
	}
	if src.Tenant != dispatch.Tenant {
		return agent.Result{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("node %q starts from a sandbox of another tenant", task.NodeID))
	}
	if src.AgentName == "" || src.AgentName != name {
		return agent.Result{}, types.NewError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("node %q starts from a sandbox of another agent", task.NodeID))
	}
	if src.GrantJTI == "" {
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("node %q starts from %q, whose grant has no id", task.NodeID, task.StartsFrom))
	}
	if err := h.forks.Ledger.BeginFork(ctx, src.GrantJTI, src.SandboxID, forkRecordTTL); err != nil {
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed, "record the fork of "+task.StartsFrom, err)
	}

	forkSpec := sandboxed.AgentForkSpec{
		SandboxClass: spec.SandboxClass,
		NetworkMode:  spec.NetworkMode,
		Egress:       spec.Egress,
		OnForked: func(resp sandboxed.ForkResponse) error {
			forks := make([]ForkDispatch, len(resp.SandboxIDs))
			for i, id := range resp.SandboxIDs {
				forks[i] = ForkDispatch{
					SandboxID:    id,
					Tenant:       dispatch.Tenant,
					AgentName:    name,
					MissionID:    dispatch.MissionID,
					MissionRunID: dispatch.MissionRunID,
					AgentRunID:   dispatch.AgentRunID,
					NodeID:       task.NodeID,
					Model:        spec.Model,
					TaskB64:      dispatch.TaskB64,
				}
			}
			return h.forks.Ledger.RecordForks(ctx, src.GrantJTI, src.SandboxID, forks, forkRecordTTL)
		},
	}
	h.logger.Info("dispatching agent to a fork",
		"agent", name, "tenant", dispatch.Tenant, "node", task.NodeID,
		"starts_from", task.StartsFrom, "source_sandbox_id", src.SandboxID)

	run, err := h.agentLauncher.ForkAgent(ctx, src.SandboxID, forkSpec, []sandboxed.AgentDispatch{dispatch})
	if err != nil {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "fork",
		})
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed, "agent fork failed: "+name, err)
	}
	if run.Errs[0] != nil {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "fork",
		})
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed, "agent fork run failed: "+name, run.Errs[0])
	}
	return h.sandboxOutcome(name, dispatch.Tenant, task, run.Results[0], map[string]any{
		"snapshot":    run.Snapshot,
		"starts_from": task.StartsFrom,
	})
}

// grantJTI reads the jti claim of a grant that this daemon minted. It does
// not verify the grant: the daemon signed it a moment ago. An empty or
// unreadable grant has no id.
func grantJTI(grant string) string {
	parts := strings.Split(grant, ".")
	if len(parts) != 3 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		JTI string `json:"jti"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return ""
	}
	return c.JTI
}
