// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package daemon — brain_execution.go
//
// brainExecutor is the daemon-side concrete binding that makes the ECS brain the
// live mission engine (gibson#851). The brain engine is per-tenant but the agent
// harness + LLM are per-mission, so the executor routes brain.Dispatch /
// brain.Decide calls to the right mission's binding by MissionID.
//
//   - As a brain.Dispatcher it launches the node's work via the mission's harness
//     off the tick — DelegateToAgent for agent nodes, CallToolProto for tool nodes
//     (which reaches remote components over the work queue) — and reports
//     WorkCompleted back.
//   - As a brain.DeciderLLM it serializes the MissionContext into a prompt, calls
//     the mission's slot LLM with structured output, and parses the next action.
//
// executeMission registers a binding before projecting the mission and removes it
// when the mission reaches a terminal state.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// deciderSlot is the LLM slot the Decider runs on. The mission-level decider_slot
// (gibson#850) selects the provider/model; this is the harness slot name.
const deciderSlot = "primary"

// missionBinding ties a live mission to the harness + engine the executor needs.
type missionBinding struct {
	ctx context.Context
	// tenant owns this mission. Component discovery for the mission is scoped to
	// it; without it the mission has no catalog rather than a shared one.
	tenant  string
	eng     *brain.Engine
	harness gibsonharness.AgentHarness
	slot    string
}

// brainExecutor implements brain.Dispatcher and brain.DeciderLLM by routing to
// per-mission bindings.
type brainExecutor struct {
	registry component.ComponentDiscovery
	logger   *slog.Logger
	// jobs is where a job node's jobs live (ADR-0019, gibson#1713). Read per
	// dispatch because the data-plane pool is built after the executor.
	jobs func() (job.Store, error)

	mu       sync.RWMutex
	bindings map[string]*missionBinding
}

func newBrainExecutor(registry component.ComponentDiscovery, logger *slog.Logger) *brainExecutor {
	return &brainExecutor{
		registry: registry,
		logger:   logger,
		bindings: map[string]*missionBinding{},
	}
}

func (b *brainExecutor) register(missionID string, bind *missionBinding) {
	b.mu.Lock()
	b.bindings[missionID] = bind
	b.mu.Unlock()
}

func (b *brainExecutor) unregister(missionID string) {
	b.mu.Lock()
	delete(b.bindings, missionID)
	b.mu.Unlock()
}

// IsMissionLive reports whether this mission is executing right now. A binding
// exists for exactly the window between the mission's launch and its return, so
// it is the daemon's own answer to "is this run still going" — and it is what
// bounds capability-grant renewal to the life of the run (gibson#1602).
func (b *brainExecutor) IsMissionLive(missionID string) bool {
	_, ok := b.get(missionID)
	return ok
}

func (b *brainExecutor) get(missionID string) (*missionBinding, bool) {
	b.mu.RLock()
	bind, ok := b.bindings[missionID]
	b.mu.RUnlock()
	return bind, ok
}

// Dispatch (brain.Dispatcher) launches the work off the tick and reports back via
// WorkCompleted. Agent nodes go through the mission harness's delegation path;
// tool nodes go through its tool path, which reaches remote components over the
// component work queue.
func (b *brainExecutor) Dispatch(req brain.DispatchRequest) {
	bind, ok := b.get(req.MissionID)
	if !ok {
		b.logger.Warn("brain dispatch for unknown mission", "mission_id", req.MissionID, "work_id", req.WorkID)
		return
	}
	go func() {
		switch req.Kind {
		case "agent":
			// The node's declared timeout is the agent's bound. Zero stays zero:
			// DelegateToAgent reads that as "run until the agent returns a result
			// or its worker stops heartbeating", which is what a live session
			// node needs (gibson#1602).
			res, err := bind.harness.DelegateToAgent(bind.ctx, req.Target, agent.Task{
				Goal:    req.Input,
				Timeout: req.Timeout,
			})
			if err != nil {
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Result: resultSummary(res)})

		case "tool":
			// A tool node is a mission node in its own right: it names a tool and
			// its input, and nothing else in the mission has to exist for it to
			// run. Refusing to dispatch it left such missions bootstrapped and
			// then silent — the run neither progressed nor failed (gibson#1196).
			//
			// CallToolProto carries the tool contract (ExecuteRequest.input_json →
			// ExecuteResponse.output_json) and already routes to a remote component
			// over the work queue when the tool is registered but has no in-process
			// implementation, which is how an off-cluster component serves a
			// mission node.
			out, err := b.dispatchTool(bind, req)
			if err != nil {
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Result: out})

		case "job":
			// A job node drives a bank (ADR-0019 decisions 10, 12 and 15): open
			// a job, let the verifier judge each turn, close with a verdict.
			out, err := b.dispatchJob(bind, req)
			if err != nil {
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, Result: out})
		default:
			// Plugin dispatch still needs method routing from the projected node;
			// name what is unsupported rather than letting the mission hang.
			bind.eng.Submit(brain.WorkCompleted{
				ID:  req.WorkID,
				Err: "direct " + req.Kind + " dispatch not supported (agent, tool and job nodes are)",
			})
		}
	}()
}

// dispatchTool invokes a tool node through the mission harness.
//
// req.Input is the node's tool input as JSON (see nodeKindTargetInput). It is
// passed through verbatim as ExecuteRequest.input_json: the tool owns its own
// schema, and re-shaping the caller's parameters here would silently change what
// the mission asked for. An empty input is legitimate — plenty of tools take no
// parameters.
func (b *brainExecutor) dispatchTool(bind *missionBinding, req brain.DispatchRequest) (string, error) {
	if req.Target == "" {
		return "", fmt.Errorf("tool node has no tool name")
	}
	toolReq := &toolpb.ExecuteRequest{InputJson: req.Input}
	toolResp := &toolpb.ExecuteResponse{}
	if err := bind.harness.CallToolProto(bind.ctx, req.Target, toolReq, toolResp); err != nil {
		return "", fmt.Errorf("tool %q: %w", req.Target, err)
	}
	if e := toolResp.GetError(); e != nil && e.GetMessage() != "" {
		return "", fmt.Errorf("tool %q reported: %s", req.Target, e.GetMessage())
	}
	return toolResp.GetOutputJson(), nil
}

// Decide (brain.DeciderLLM) asks the mission's slot LLM for the next action over
// the serialized own-mission World slice + capability catalog.
func (b *brainExecutor) Decide(ctx context.Context, mc brain.MissionContext) (brain.DeciderOutput, error) {
	bind, ok := b.get(mc.MissionID)
	if !ok {
		return brain.DeciderOutput{}, fmt.Errorf("brain decide: no binding for mission %s", mc.MissionID)
	}
	slot := bind.slot
	if slot == "" {
		slot = deciderSlot
	}
	messages := buildDeciderPrompt(mc)
	raw, err := bind.harness.CompleteStructuredAny(ctx, slot, messages, deciderDecision{})
	if err != nil {
		return brain.DeciderOutput{}, fmt.Errorf("brain decide: llm: %w", err)
	}
	return parseDecision(raw), nil
}

// catalog lists the mission tenant's enrolled components as brain capabilities.
//
// The tenant comes from the mission's binding, bound onto the context here.
// This used to run on context.Background(), which named no tenant at all — the
// registry adapter then fell back to the daemon-wide "default" namespace, so
// the doc comment's "the tenant's enrolled components" described something the
// code did not do. The Decider was offered a catalog assembled in a shared
// pseudo-tenant and could dispatch against it.
//
// A mission with no live binding gets no capabilities rather than a catalog
// from somewhere else: the Decider then has nothing to dispatch, which is the
// correct outcome for a mission that is no longer running.
func (b *brainExecutor) catalog(missionID string) []brain.Capability {
	bind, ok := b.get(missionID)
	if !ok {
		b.logger.Warn("brain catalog for unknown mission", "mission_id", missionID)
		return nil
	}
	if bind.tenant == "" {
		b.logger.Warn("brain catalog for mission with no tenant", "mission_id", missionID)
		return nil
	}
	// bind.ctx is the mission's execution context; the tenant is bound onto it
	// explicitly rather than assumed to be there, because the mission manager
	// knows the tenant and the context it hands over may not carry it.
	ctx := auth.ContextWithTenantString(bind.ctx, bind.tenant)

	var caps []brain.Capability
	if agents, err := b.registry.ListAgents(ctx); err == nil {
		for _, a := range agents {
			caps = append(caps, brain.Capability{Kind: "agent", Name: a.Name, Description: a.Description})
		}
	}
	if tools, err := b.registry.ListTools(ctx); err == nil {
		for _, t := range tools {
			caps = append(caps, brain.Capability{Kind: "tool", Name: t.Name, Description: t.Description})
		}
	}
	if plugins, err := b.registry.ListPlugins(ctx); err == nil {
		for _, p := range plugins {
			desc := p.Description
			if len(p.Methods) > 0 {
				desc = strings.TrimSpace(desc + " methods: " + strings.Join(p.Methods, ","))
			}
			caps = append(caps, brain.Capability{Kind: "plugin", Name: p.Name, Description: desc})
		}
	}
	return caps
}

// deciderDecision is the structured-output schema for one single-shot decision
// (CONTEXT.md: single-shot per decision). action ∈ {dispatch, complete, wait}.
type deciderDecision struct {
	Action  string `json:"action" jsonschema:"description=One of: dispatch (run a capability), complete (end the mission), wait (await in-flight work)"`
	Kind    string `json:"kind" jsonschema:"description=When action=dispatch: agent, tool, or plugin"`
	Target  string `json:"target" jsonschema:"description=When action=dispatch: the capability name from the catalog"`
	Input   string `json:"input" jsonschema:"description=When action=dispatch: an agent task goal (natural language) or structured JSON for a tool/plugin"`
	Outcome string `json:"outcome" jsonschema:"description=When action=complete: success or failed"`
	Reason  string `json:"reason" jsonschema:"description=A short rationale for the decision (recorded for audit)"`
}

func parseDecision(raw any) brain.DeciderOutput {
	d, ok := raw.(*deciderDecision)
	if !ok || d == nil {
		return brain.DeciderOutput{} // treat as wait
	}
	switch strings.ToLower(strings.TrimSpace(d.Action)) {
	case "dispatch":
		if d.Target == "" {
			return brain.DeciderOutput{}
		}
		kind := d.Kind
		if kind == "" {
			kind = "agent"
		}
		return brain.DeciderOutput{Dispatches: []brain.DeciderDispatch{{Kind: kind, Target: d.Target, Input: d.Input}}}
	case "complete":
		return brain.DeciderOutput{Complete: &brain.DeciderComplete{Outcome: d.Outcome, Reason: d.Reason}}
	default:
		return brain.DeciderOutput{} // wait
	}
}

// buildDeciderPrompt renders the own-mission slice + catalog into the Decider's
// messages. The Decider reasons over structured World state, not a transcript
// (CONTEXT.md / ADR-0001).
func buildDeciderPrompt(mc brain.MissionContext) []llm.Message {
	system := "You are the orchestration Decider for an autonomous offensive-security mission. " +
		"Reason over the current world state and choose the single next action that best advances the goal. " +
		"You re-invoke existing capabilities with new inputs; you never author the knowledge graph. " +
		"Respond with one decision: dispatch a capability, complete the mission when the goal is met or unreachable, or wait if work is still in flight."

	var b strings.Builder
	fmt.Fprintf(&b, "GOAL: %s\n\n", mc.Goal)

	b.WriteString("CAPABILITY CATALOG (only these may be dispatched):\n")
	if len(mc.Capabilities) == 0 {
		b.WriteString("  (none enrolled)\n")
	}
	for _, c := range mc.Capabilities {
		fmt.Fprintf(&b, "  - [%s] %s: %s\n", c.Kind, c.Name, c.Description)
	}

	b.WriteString("\nWORK SO FAR:\n")
	if len(mc.Work) == 0 {
		b.WriteString("  (nothing dispatched yet)\n")
	}
	for _, w := range mc.Work {
		line := fmt.Sprintf("  - %s [%s/%s] %s", w.ID, w.Kind, w.Target, w.State)
		if w.Result != "" {
			line += " → " + truncate(w.Result, 200)
		}
		if w.Err != "" {
			line += " ERR: " + truncate(w.Err, 200)
		}
		b.WriteString(line + "\n")
	}

	if len(mc.Findings) > 0 {
		b.WriteString("\nFINDINGS:\n")
		for _, f := range mc.Findings {
			fmt.Fprintf(&b, "  - [%s] %s\n", f.Severity, f.Title)
		}
	}
	if len(mc.Hosts) > 0 {
		b.WriteString("\nHOSTS DISCOVERED:\n")
		for _, h := range mc.Hosts {
			fmt.Fprintf(&b, "  - %s (ports: %v)\n", h.Address, h.OpenPorts)
		}
		if mc.OmittedHosts > 0 {
			fmt.Fprintf(&b, "  …and %d more lower-relevance hosts omitted (ambient projection)\n", mc.OmittedHosts)
		}
	}

	return []llm.Message{
		{Role: llm.RoleSystem, Content: system},
		{Role: llm.RoleUser, Content: b.String()},
	}
}

func resultSummary(res agent.Result) string {
	if len(res.Output) > 0 {
		return truncate(fmt.Sprintf("%v", res.Output), 1000)
	}
	return string(res.Status)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
