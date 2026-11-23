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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"

	"github.com/google/uuid"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/agentwire"
	"github.com/zeroroot-ai/gibson/internal/engine/brain"
	gibsonharness "github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/engine/jobnode"
	"github.com/zeroroot-ai/gibson/internal/engine/metatool"
	"github.com/zeroroot-ai/gibson/internal/engine/modelclient"
	"github.com/zeroroot-ai/gibson/internal/engine/taxonomy"
	"github.com/zeroroot-ai/gibson/internal/engine/toolid"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/job"
	"github.com/zeroroot-ai/gibson/internal/platform/modelgate"
	"github.com/zeroroot-ai/gibson/internal/platform/principal"
	toolpb "github.com/zeroroot-ai/sdk/api/gen/gibson/tool/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// deciderSlot is the LLM slot the Decider runs on. The mission-level decider_slot
// (gibson#850) selects the provider/model; this is the harness slot name.
// withDeciderSlotPin puts that pin on this slot of the mission harness.
const deciderSlot = "primary"

// missionBinding ties a live mission to the harness + engine the executor needs.
type missionBinding struct {
	ctx context.Context
	// runID is the run of the mission that this binding serves. The mission ID
	// is the same for every run of a record, so the binding of run 2 replaces
	// the binding of run 1 under one key. A dispatch of another run is refused
	// (gibson#1217).
	runID string
	// tenant owns this mission. Component discovery for the mission is scoped to
	// it; without it the mission has no catalog rather than a shared one.
	tenant  string
	eng     *brain.Engine
	harness gibsonharness.AgentHarness
	slot    string
	// deciderPin is the decider_slot of the mission. newMissionHarness puts
	// the same value on the harness, so one value decides both the slot and
	// how Decide treats a resolution failure (gibson#1210).
	deciderPin brain.DeciderSlot
	// initiator is the person who created the mission, as an FGA user
	// ("user:<id>"), or empty. It is the subject of the model access check of
	// each Decider call.
	initiator string
	// taskData is the typed, untrusted task data that an outside caller sent with
	// the message that started the mission, by key (for example "webhook"). The
	// agent task carries it as data in its Context, and never in its Goal.
	taskData map[string]any
}

// taskContext returns the Context of an agent task for this mission: the task data
// and its trust mark. It returns nil when the mission has no task data. The mark
// is always "untrusted", because the data comes from an outside caller.
func (b *missionBinding) taskContext() map[string]any {
	if len(b.taskData) == 0 {
		return nil
	}
	return map[string]any{
		MetadataTaskData:      b.taskData,
		MetadataTaskDataTrust: TaskDataUntrusted,
	}
}

// taskDataOf reads the task data from the metadata of a mission record. The
// metadata may come from JSON, so the value is a map of any.
func taskDataOf(meta map[string]any) map[string]any {
	data, _ := meta[MetadataTaskData].(map[string]any)
	return data
}

// deciderModels is the part of the model client that the Decider uses.
type deciderModels interface {
	Respond(ctx context.Context, caller modelclient.Caller, target modelclient.Target,
		req modelclient.Request) (*modelclient.Response, error)
}

// brainExecutor implements brain.Dispatcher and brain.DeciderLLM by routing to
// per-mission bindings.
type brainExecutor struct {
	registry component.ComponentDiscovery
	logger   *slog.Logger
	// gate returns the mission gate of a tenant. A tenant with no gate gets
	// noMissionGate.
	// Dispatch waits on it before it starts a work item, so the gate tuple that
	// ext-authz reads is confirmed before the work item gets a task grant.
	gate func(tenant string) MissionGateAwaiter
	// cancels holds the cancel function of each running A2A work item, by work
	// id. CancelWork calls it. A mission node has no entry, because only an A2A
	// CancelTask cancels a single item.
	cancelMu sync.Mutex
	cancels  map[string]context.CancelFunc
	// jobs is where a job node's jobs live (ADR-0119, gibson#1713). Read per
	// dispatch because the data-plane pool is built after the executor.
	jobs func() (job.Store, error)
	// jobClosed links a closed job's deliverables into the graph
	// (gibson#477). dispatchJob hands it to jobnode, which refuses a nil.
	jobClosed jobnode.CloseObserver
	// jobFindings resolves a job node's {{findings.open}} to the open findings on
	// the run's target (gibson#497). A mission definition cannot name finding
	// ids, because the run is what produces them.
	jobFindings jobnode.FindingsResolver
	// jobClaims holds the findings of a fix job while it runs (gibson#1454).
	jobClaims jobnode.FixClaims
	// connectors makes the connector call of a TOOL node (gibson#1469). It is
	// read per dispatch, because the daemon builds the callback manager after
	// the executor. nil means a tool node cannot name a connector tool.
	connectors func() missionConnectorCaller
	// approvalPoll is how long a TOOL node waits between two asks for an
	// approval. Zero means approvalPollInterval. A test sets it.
	approvalPoll time.Duration
	// models sends the model call of the Decider to the model gateway
	// (gibson#1392). The gateway trace is the one source of the llm_call.observed
	// and token.used events of that call, so the executor emits neither.
	models deciderModels

	mu       sync.RWMutex
	bindings map[string]*missionBinding
}

func newBrainExecutor(registry component.ComponentDiscovery, logger *slog.Logger) *brainExecutor {
	return &brainExecutor{
		registry: registry,
		logger:   logger,
		bindings: map[string]*missionBinding{},
		gate:     func(string) MissionGateAwaiter { return noMissionGate{} },
	}
}

func (b *brainExecutor) register(missionID string, bind *missionBinding) {
	b.mu.Lock()
	b.bindings[missionID] = bind
	b.mu.Unlock()
}

// unregister removes the binding bind of a mission. It removes the entry only
// when the entry is bind: the next run of the mission may have registered its
// own binding, and that one must stay (gibson#1217).
func (b *brainExecutor) unregister(missionID string, bind *missionBinding) {
	b.mu.Lock()
	if b.bindings[missionID] == bind {
		delete(b.bindings, missionID)
	}
	b.mu.Unlock()
}

// IsMissionRunLive reports whether this run of the mission is executing right
// now. A binding exists for exactly the window between the launch of a run and
// its return, so it is the daemon's own answer to "is this run still going", and
// it is what bounds capability-grant renewal to the life of the run
// (gibson#1602). The mission ID is the same for every run of a record, so the
// binding must be the binding of this run: a grant of run 1 does not renew
// while run 2 is live. A call with no run is never live.
func (b *brainExecutor) IsMissionRunLive(missionID, runID string) bool {
	bind, ok := b.get(missionID)
	return ok && runID != "" && bind.runID == runID
}

func (b *brainExecutor) get(missionID string) (*missionBinding, bool) {
	b.mu.RLock()
	bind, ok := b.bindings[missionID]
	b.mu.RUnlock()
	return bind, ok
}

// awaitMissionGate waits until the gate tuple of the mission is confirmed. A work
// item of a mission gets a task grant when it starts, and its agent then calls a
// gateway at once. ext-authz refuses the call of a mission whose gate is not
// open, so the gate comes first. The error says why the work item cannot start.
func (b *brainExecutor) awaitMissionGate(ctx context.Context, eng *brain.Engine, req brain.DispatchRequest) error {
	if req.MissionID == "" {
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, missionGateAwaitTimeout)
	defer cancel()
	if err := b.gate(eng.World.Tenant).AwaitOpen(waitCtx, req.MissionID); err != nil {
		return fmt.Errorf("wait for the mission gate: %w", err)
	}
	return nil
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
	if bind.runID != req.RunID {
		// A dispatch that was queued by run 1 reaches the binding of run 2.
		// It must not run against the target under run 2.
		b.logger.Warn("brain dispatch of another run; refused",
			"mission_id", req.MissionID, "work_id", req.WorkID, "run_id", req.RunID, "binding_run_id", bind.runID)
		return
	}
	go func() {
		if err := b.awaitMissionGate(bind.ctx, bind.eng, req); err != nil {
			b.logger.Error("work item not started: the mission gate is not open",
				"mission_id", req.MissionID, "work_id", req.WorkID, "error", err)
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Err: err.Error()})
			return
		}
		switch req.Kind {
		case "agent":
			// The node's declared timeout is the agent's bound. Zero stays zero:
			// DelegateToAgent reads that as "run until the agent returns a result
			// or its worker stops heartbeating", which is what a live session
			// node needs (gibson#1602).
			// The network scope of the node decides the egress of the agent
			// sandbox (owner decision S6, gibson#865).
			agentCtx, release := b.trackWork(bind.ctx, req)
			defer release()
			res, err := bind.harness.DelegateToAgent(agentCtx, req.Target, agent.Task{
				ID:   a2aTaskID(req),
				Goal: req.Input,
				// The task data of an outside caller is data, in the Context. It is
				// never part of the Goal (ADR-0094).
				Context: bind.taskContext(),
				Timeout: req.Timeout,
				Network: req.Network,
				// The LLM slot pins of the node (gibson#539, gibson#1203).
				SlotOverrides: taskSlotOverrides(req.SlotPins),
				// The token cap of one model call of the node.
				MaxTokensPerCall: req.MaxTokensPerCall,
				// The fork fields of the node (ADR-0169, gibson#802).
				NodeID:     nodeIDOf(req.WorkID, req.MissionID),
				StartsFrom: req.StartsFrom,
				Forkable:   req.Forkable,
				// The checkpoint fields of the node (ADR-0170).
				Checkpoint:   req.Checkpoint,
				FromSnapshot: req.FromSnapshot,
			})
			if err != nil {
				bind.eng.Submit(agentWorkFailure(req.WorkID, req.RunID, err))
				return
			}
			// The snapshot id of the node end is part of the Timeline event,
			// so a replay names the same checkpoint state (ADR-0170).
			bind.eng.Submit(brain.WorkCompleted{
				ID: req.WorkID, RunID: req.RunID, Result: resultSummary(res),
				Snapshot: gibsonharness.CheckpointSnapshot(res),
			})

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
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Result: out})

		case workKindBank, workKindJobTurn:
			// An A2A message aimed at a bank, or at a job of a bank. The
			// daemon opens the job, or sends the next turn, and waits for the
			// turn (gibson#1400).
			jobCtx, release := b.trackWork(bind.ctx, req)
			defer release()
			out, err := b.dispatchBankTurn(jobCtx, bind, req)
			if err != nil {
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Result: out})

		case "job":
			// A job node drives a bank (ADR-0119): open
			// a job, let the verifier judge each turn, close with a verdict.
			out, err := b.dispatchJob(bind, req)
			if err != nil {
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Result: out})
		case "plugin":
			// A plugin node names a plugin, a method and its params; the harness
			// routes the call over the component work queue the same way an
			// agent's QueryPlugin does (gibson#556). Before this the kind fell
			// through to the refusal below and a mission with a plugin node
			// failed that node by name.
			out, err := b.dispatchPlugin(bind, req)
			if err != nil {
				bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Err: err.Error()})
				return
			}
			bind.eng.Submit(brain.WorkCompleted{ID: req.WorkID, RunID: req.RunID, Result: out})

		default:
			// Name what is unsupported rather than letting the mission hang.
			bind.eng.Submit(brain.WorkCompleted{
				ID:    req.WorkID,
				RunID: req.RunID,
				Err:   "direct " + req.Kind + " dispatch not supported (agent, tool, plugin and job nodes are)",
			})
		}
	}()
}

// dispatchPlugin invokes a plugin node through the mission harness.
//
// req.Input is the node's method and params as JSON (see pluginInputJSON). The
// method is required; params may be absent. The result the plugin returns is
// re-encoded as JSON so the work record carries what the plugin said.
func (b *brainExecutor) dispatchPlugin(bind *missionBinding, req brain.DispatchRequest) (string, error) {
	if req.Target == "" {
		return "", errors.New("plugin node has no plugin name")
	}
	var in pluginInput
	if err := json.Unmarshal([]byte(req.Input), &in); err != nil {
		return "", fmt.Errorf("plugin %q: decode node input: %w", req.Target, err)
	}
	if in.Method == "" {
		return "", fmt.Errorf("plugin %q: node input names no method", req.Target)
	}
	var params map[string]any
	if len(in.Params) > 0 {
		if err := json.Unmarshal(in.Params, &params); err != nil {
			return "", fmt.Errorf("plugin %q: params are not an object: %w", req.Target, err)
		}
	}
	// Same per-instance target switch as dispatchTool, for the same reason.
	h := bind.harness
	if instTarget := instanceTargetID(req.WorkID); instTarget != "" {
		h = h.ForTarget(instTarget)
	}
	result, err := h.QueryPlugin(bind.ctx, req.Target, in.Method, params)
	if err != nil {
		return "", fmt.Errorf("plugin %q.%s: %w", req.Target, in.Method, err)
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("plugin %q.%s: encode result: %w", req.Target, in.Method, err)
	}
	return string(out), nil
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
	// A tool node that names mcp:<connector>:<tool> calls a connector of the
	// tenant on the one governed path of a connector call, the path of
	// invoke_tool (gibson#1469). Any other name takes the paths below.
	if tid, err := toolid.Parse(req.Target); err == nil && tid.Source == toolid.SourceMCP {
		return b.dispatchConnectorTool(bind, req, tid)
	}
	// A for_each instance runs against its OWN target, so the harness it gets
	// must report that target: every scope reader — observationAttribution,
	// SubmitProof, the destructive-authz callback — resolves the finding's scope
	// from h.Target().ID. Without this, instance B's findings would carry the
	// mission's primary target and several hosts would merge onto one coordinate,
	// which is the exact failure observationAttribution refuses an empty scope to
	// prevent (gibson#526).
	//
	// The target is DERIVED from the work id rather than carried beside it: the
	// id already states it, and a second copy threaded through WorkNode,
	// WorkItem, WorkDispatched and DispatchRequest is four places that can
	// disagree about which host a finding belongs to.
	//
	// Guarded rather than relying on ForTarget("") being identity. A harness that
	// embeds the AgentHarness interface to inherit its method set — which the
	// test stubs here do, and a wrapper elsewhere may — has a nil embedded
	// interface, so calling ANY method it does not implement panics. Calling the
	// new method only when there is a target to switch to means an ordinary
	// dispatch never touches it, and the fan-out path is the only one that
	// requires a real implementation.
	h := bind.harness
	if instTarget := instanceTargetID(req.WorkID); instTarget != "" {
		h = h.ForTarget(instTarget)
	}
	// The sandbox of the tool gets the network of its node, as an agent node's
	// sandbox does (owner decision S6, gibson#865).
	ctx := gibsonharness.WithNodeNetwork(bind.ctx, req.Network)
	toolReq := &toolpb.ExecuteRequest{InputJson: req.Input}
	toolResp := &toolpb.ExecuteResponse{}
	if err := h.CallToolProto(ctx, req.Target, toolReq, toolResp); err != nil {
		return "", fmt.Errorf("tool %q: %w", req.Target, err)
	}
	if e := toolResp.GetError(); e != nil && e.GetMessage() != "" {
		return "", fmt.Errorf("tool %q reported: %s", req.Target, e.GetMessage())
	}
	return toolResp.GetOutputJson(), nil
}

// Decide (brain.DeciderLLM) asks the mission's slot LLM for the next action over
// the serialized own-mission World slice + capability catalog.
//
// The Decider sends its call to the model gateway (gibson#1392). The gateway
// trace is the one source of the llm_call.observed and token.used events of the
// call, so Decide emits neither. The transcript of the Decider still reaches the
// mission Timeline (ADR-0120, gibson#271), through the receiver of the trace.
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
	if b.models == nil {
		return brain.DeciderOutput{}, errors.New("brain decide: no model gateway client is configured")
	}
	resolver, ok := bind.harness.(gibsonharness.SlotModelResolver)
	if !ok {
		return brain.DeciderOutput{}, fmt.Errorf("brain decide: the harness %T cannot resolve a slot to a model", bind.harness)
	}
	// One slot resolves to one exact model name before the call. The gateway
	// never sees a slot.
	picked, err := resolver.ResolveSlotModel(ctx, slot)
	if err != nil {
		return b.deciderFailure(bind, err)
	}
	schemaName, schema, err := gibsonharness.StructuredSchema(deciderDecision{})
	if err != nil {
		return brain.DeciderOutput{}, fmt.Errorf("brain decide: schema: %w", err)
	}
	resp, err := b.models.Respond(ctx,
		modelclient.Caller{
			Tenant: bind.tenant, Mission: mc.MissionID, Task: "decide-" + uuid.NewString(),
			Initiator: bind.initiator, Purpose: "brain-decider",
		},
		modelclient.Target{Tenant: bind.tenant, Provider: picked.Provider, Model: picked.Model},
		modelclient.Request{Input: deciderInput(messages), Text: modelclient.JSONSchemaFormat(schemaName, schema)},
	)
	if err != nil {
		var refused *modelclient.APIError
		if errors.As(err, &refused) && refused.Refused() {
			// ext-authz refused the call: the model is not allowed, or the mission
			// is not running. A pin that is refused cannot be served.
			return b.deciderFailure(bind, types.WrapError(gibsonharness.ErrNoMatchingProvider,
				fmt.Sprintf("model_access_denied: the gateway refused the model %q on provider %q", picked.Model, picked.Provider), err))
		}
		return brain.DeciderOutput{}, fmt.Errorf("brain decide: llm: %w", err)
	}
	var decision deciderDecision
	if err := json.Unmarshal([]byte(resp.OutputText()), &decision); err != nil {
		return brain.DeciderOutput{}, fmt.Errorf("brain decide: the model did not return the decision schema: %w", err)
	}
	return parseDecision(&decision), nil
}

// deciderFailure turns a slot or gateway failure into the answer of Decide. A
// pin that cannot be served ends the mission with the reason (gibson#1210).
// Other failures go back to the brain, which retries on the next evidence
// change.
func (b *brainExecutor) deciderFailure(bind *missionBinding, err error) (brain.DeciderOutput, error) {
	if pinnedDeciderUnservable(bind.deciderPin, err) {
		// The brain retries a failed decision on the next evidence change,
		// and the budget System bounds a persistent failure. A pin that
		// cannot be served spends no tokens, and a retry cannot serve it.
		return brain.DeciderOutput{Complete: &brain.DeciderComplete{
			Outcome: "failed",
			Reason:  fmt.Sprintf("the decider_slot of the mission cannot be served: %v", err),
		}}, nil
	}
	return brain.DeciderOutput{}, fmt.Errorf("brain decide: llm: %w", err)
}

// deciderMessage is one message of the prompt of the Decider.
type deciderMessage struct {
	Role    string
	Content string
}

// The roles of a Decider prompt message.
const (
	deciderRoleSystem    = "system"
	deciderRoleAssistant = "assistant"
	deciderRoleUser      = "user"
)

// deciderInput maps the prompt messages to Open Responses items.
func deciderInput(messages []deciderMessage) []modelclient.Item {
	out := make([]modelclient.Item, 0, len(messages))
	for _, m := range messages {
		switch m.Role {
		case deciderRoleSystem:
			out = append(out, modelclient.SystemMessage(m.Content))
		case deciderRoleAssistant:
			out = append(out, modelclient.AssistantMessage(m.Content))
		default:
			out = append(out, modelclient.UserMessage(m.Content))
		}
	}
	return out
}

// pinnedDeciderUnservable reports whether err is a slot resolution failure of a
// mission that pins its Decider. Without a pin the brain keeps its retry. A
// gate that could not decide (modelgate.ErrUnavailable) and a canceled or
// timed out call also keep the retry, because a later call can succeed.
func pinnedDeciderUnservable(pin brain.DeciderSlot, err error) bool {
	if pin.Provider == "" && pin.Model == "" {
		return false
	}
	if errors.Is(err, modelgate.ErrUnavailable) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// A pin that names a provider that the tenant does not have cannot be
	// served either. The wait for a later call does not help.
	return errors.Is(err, types.NewError(gibsonharness.ErrNoMatchingProvider, "")) ||
		errors.Is(err, types.NewError(gibsonharness.ErrProviderNotFound, ""))
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
			caps = append(caps, brain.Capability{
				Kind:        "agent",
				Name:        a.Name,
				Description: a.Description,
				Coverage:    b.agentCoverage(a),
			})
		}
	}
	if tools, err := b.registry.ListTools(ctx); err == nil {
		for _, t := range tools {
			caps = append(caps, brain.Capability{
				Kind: "tool", Name: t.Name, Description: t.Description,
				Coverage: b.coverage("tool", t.Name, nil),
			})
		}
	}
	if plugins, err := b.registry.ListPlugins(ctx); err == nil {
		for _, p := range plugins {
			desc := p.Description
			if len(p.Methods) > 0 {
				desc = strings.TrimSpace(desc + " methods: " + strings.Join(p.Methods, ","))
			}
			caps = append(caps, brain.Capability{
				Kind: "plugin", Name: p.Name, Description: desc,
				Coverage: b.coverage("plugin", p.Name, nil),
			})
		}
	}
	return caps
}

// agentCoverage is the coverage of an enrolled agent: the technique types it
// declares when it registers (component.AgentInfo.TechniqueTypes, raw
// registry-metadata strings), plus the categories and techniques of its
// catalog entry (ADR-0135, gibson#716).
func (b *brainExecutor) agentCoverage(a component.AgentInfo) taxonomy.Coverage {
	return b.coverage("agent", a.Name, a.TechniqueTypes)
}

// coverage builds the validated coverage of one capability: the extra
// categories, and the coverage block of its catalog entry when it has one
// (ADR-0135, gibson#716).
//
// Each id is checked on its own against the technique hierarchy. An id
// outside it is dropped with a warning, and the rest stays: one stale id must
// not hide what a capability does cover. A technique comes from a Domain Pack
// (ADR-0133), so a technique that no pack of the hierarchy defines is
// dropped the same way.
func (b *brainExecutor) coverage(kind, name string, extraCategories []string) taxonomy.Coverage {
	categories := append([]string(nil), extraCategories...)
	var techniques []string
	if decl, ok := componentcatalog.LookupCoverage(kind, name); ok {
		categories = append(categories, decl.Categories...)
		techniques = decl.Techniques
	}
	if len(categories) == 0 && len(techniques) == 0 {
		return taxonomy.EmptyCoverage()
	}
	h := taxonomy.GlobalTechniques
	var cats []taxonomy.CategoryID
	for _, c := range categories {
		if !h.HasCategory(taxonomy.CategoryID(c)) {
			b.logger.Warn("capability declares a category outside the taxonomy", "kind", kind, "name", name, "category", c)
			continue
		}
		cats = append(cats, taxonomy.CategoryID(c))
	}
	var techs []taxonomy.TechniqueID
	for _, t := range techniques {
		if !h.HasTechnique(taxonomy.TechniqueID(t)) {
			b.logger.Warn("capability declares a technique outside the taxonomy", "kind", kind, "name", name, "technique", t)
			continue
		}
		techs = append(techs, taxonomy.TechniqueID(t))
	}
	coverage, err := taxonomy.NewCoverage(h, cats, techs)
	if err != nil {
		// Each id was checked above, so this is a fault of the hierarchy.
		b.logger.Warn("capability coverage could not be built", "kind", kind, "name", name, "error", err)
		return taxonomy.EmptyCoverage()
	}
	return coverage
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
// (CONTEXT.md / ADR-0101).
func buildDeciderPrompt(mc brain.MissionContext) []deciderMessage {
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

	return []deciderMessage{
		{Role: deciderRoleSystem, Content: system},
		{Role: deciderRoleUser, Content: b.String()},
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

// taskSlotOverrides converts the slot pins of a node to the per-slot overrides
// of an agent task. Nil pins give nil overrides.
func taskSlotOverrides(pins map[string]agent.SlotConfig) map[string]*agent.SlotConfig {
	if len(pins) == 0 {
		return nil
	}
	out := make(map[string]*agent.SlotConfig, len(pins))
	for slot, cfg := range pins {
		out[slot] = &cfg
	}
	return out
}

// missionInitiatorOf names the person who created a mission as an FGA user. A
// mission that no person created has none. It is the subject of the model
// access check of ext-authz.
func missionInitiatorOf(createdBy principal.Principal) string {
	if createdBy.Kind != principal.User || createdBy.ID == "" {
		return ""
	}
	return "user:" + createdBy.ID
}

// agentWorkFailure builds the WorkCompleted of an agent node that did not
// finish. A run that ended in the A2A state canceled, input-required or
// auth-required keeps that state on the work item. Any other error fails the
// item.
func agentWorkFailure(workID, runID string, err error) brain.WorkCompleted {
	var se *agentwire.StateError
	if errors.As(err, &se) {
		switch state := brain.WorkStateFromTask(se.State); state {
		case brain.WorkCanceled, brain.WorkInputRequired:
			return brain.WorkCompleted{ID: workID, RunID: runID, State: state, Err: se.Message}
		case brain.WorkPending, brain.WorkRunning, brain.WorkDone, brain.WorkFailed, brain.WorkSkipped:
			// These states fail the item below.
		}
	}
	return brain.WorkCompleted{ID: workID, RunID: runID, Err: err.Error()}
}

// missionConnectorCaller makes the connector call of a TOOL node.
// harness.CallbackManager satisfies it.
type missionConnectorCaller interface {
	CallConnectorForMission(ctx context.Context, tenant, missionID, runID, workID, connector, tool string, args map[string]any) (any, error)
}

// approvalPollInterval is how long a TOOL node waits before it asks again for
// the approval of a marked tool.
const approvalPollInterval = 5 * time.Second

// dispatchConnectorTool runs a TOOL node that names a connector tool. The input
// of the node is the JSON object of the arguments. The result is the JSON of the
// tool result, which is the output of the node.
//
// A tool with an approval mark waits for a person. The node then moves to
// input_required and shows the reason, and the same call is made again until the
// approval is decided: the gate answers the same arguments with the state of the
// request, as it does for an agent. A denial fails the node. A mission that is
// canceled ends the wait.
func (b *brainExecutor) dispatchConnectorTool(bind *missionBinding, req brain.DispatchRequest, tid toolid.ID) (string, error) {
	if b.connectors == nil || b.connectors() == nil {
		return "", fmt.Errorf("tool %q: this daemon has no connector caller", tid.Canonical())
	}
	args := map[string]any{}
	if in := strings.TrimSpace(req.Input); in != "" && in != "null" {
		if err := json.Unmarshal([]byte(in), &args); err != nil {
			return "", fmt.Errorf("tool %q: the input of the node is not a JSON object: %w", tid.Canonical(), err)
		}
	}
	poll := b.approvalPoll
	if poll <= 0 {
		poll = approvalPollInterval
	}
	reported := false
	for {
		res, err := b.connectors().CallConnectorForMission(bind.ctx, bind.tenant, req.MissionID, bind.runID, req.WorkID,
			tid.Connector, tid.Tool, args)
		if err == nil {
			if res == nil {
				// A call that returns nothing is not a result. The node must not
				// succeed with "null".
				return "", fmt.Errorf("tool %q: the connector returned no result", tid.Canonical())
			}
			out, merr := json.Marshal(res)
			if merr != nil {
				return "", fmt.Errorf("tool %q: encode the result: %w", tid.Canonical(), merr)
			}
			return string(out), nil
		}
		if !errors.Is(err, metatool.ErrApprovalPending) {
			return "", fmt.Errorf("tool %q: %w", tid.Canonical(), err)
		}
		if !reported && bind.eng != nil {
			reported = true
			bind.eng.Submit(brain.WorkCompleted{
				ID: req.WorkID, RunID: req.RunID, State: brain.WorkInputRequired,
				Err: fmt.Sprintf("waiting for the approval of %s: %v", tid.Canonical(), err),
			})
		}
		select {
		case <-bind.ctx.Done():
			return "", fmt.Errorf("tool %q: the wait for the approval ended: %w", tid.Canonical(), bind.ctx.Err())
		case <-time.After(poll):
		}
	}
}
