// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	harnesspb "github.com/zeroroot-ai/sdk/api/gen/gibson/harness/v1"

	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/engine/emitbounds"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/engine/mission/targetbind"
	"github.com/zeroroot-ai/gibson/internal/infra/contextkeys"
	sdkqueue "github.com/zeroroot-ai/gibson/internal/infra/queue"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/authz"
	"github.com/zeroroot-ai/gibson/internal/platform/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/internal/platform/componentcatalog"
	agentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/agent/v1"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/protoresolver"
	"github.com/zeroroot-ai/sdk/secretenv"
	sdktypes "github.com/zeroroot-ai/sdk/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// defaultMaxDelegationDepth is the default cap on the number of nested DelegateToAgent
// hops allowed before returning delegation_depth_exceeded. Override per-harness via
// maxDelegationDepth if needed (e.g. via daemon config). Zero means "use this default."
const defaultMaxDelegationDepth = 8

// DefaultAgentHarness is the production implementation of the AgentHarness interface.
// It provides agents with access to all framework capabilities including LLM operations,
// tool execution, plugin queries, sub-agent delegation, finding management, memory storage,
// and observability primitives.
//
// The harness orchestrates interactions between agents and the Gibson platform,
// handling:
//   - LLM provider management and slot-based model selection
//   - Tool registration, validation, and execution
//   - Plugin lifecycle and communication
//   - Sub-agent discovery and delegation
//   - Finding storage and querying
//   - Memory tier coordination (working, mission, long-term)
//   - Distributed tracing and structured logging
//   - Metrics collection and token usage tracking
//
// All methods are safe for concurrent use. The harness ensures thread-safety
// for shared resources and coordinates access across multiple agents.
type DefaultAgentHarness struct {
	// LLM components
	slotManager llm.SlotManager
	llmRegistry llm.LLMRegistry

	// Registry adapter for unified component discovery via the component registry
	// Used for agent delegation operations (DelegateToAgent, ListAgents)
	registryAdapter component.ComponentDiscovery

	// Memory and storage
	findingStore FindingStore

	// Factory for creating child harnesses during delegation
	factory HarnessFactory

	// Context information
	missionCtx      MissionContext
	targetInfo      TargetInfo
	contextProvider MissionContextProvider

	// Observability
	tracer     trace.Tracer
	logger     *slog.Logger
	metrics    MetricsRecorder
	tokenUsage llm.TokenTracker

	// delegationSink folds agent-delegation run-provenance into the World (ADR-0107).
	delegationSink DelegationSink

	// Mission management (optional, nil = mission methods return error)
	missionClient MissionOperator
	spawnLimits   SpawnLimits

	// Event logging for structured observability
	eventLogger EventLogger

	// resolver provides dynamic proto type resolution for tool execution
	resolver protoresolver.ProtoResolver

	// workspaceManager provides access to Git repository workspaces (nil if not configured)
	workspaceManager workspace.WorkspaceManager

	// categoryClassifier provides semantic category normalization (nil if disabled)
	categoryClassifier CategoryClassifier

	// taxonomyRegistry provides read-only access to the taxonomy registry for querying
	// available node types, relationships, and extensions in the knowledge graph.
	taxonomyRegistry sdkgraphrag.TaxonomyIntrospector

	// componentRegistry provides Redis-backed component discovery scoped by tenant.
	// When non-nil, CallToolProto and QueryPlugin consult this registry first before
	// falling back to the registryAdapter. Nil means use the registryAdapter path only.
	componentRegistry component.ComponentRegistry

	// targetFacts resolves the dispatched unit of work's target at dispatch, so
	// a sandboxed tool is told what it acts against. nil when the daemon wires
	// no target store, and a tool then receives no GIBSON_TARGET_* at all —
	// absent rather than guessed, because the alternative is a tool scanning a
	// host the mission did not name.
	targetFacts TargetFactsLookup

	// missionSecrets resolves a declared secret's value at dispatch. nil when
	// the daemon wires no credential store, and a component then receives no
	// GIBSON_SECRET_* — a mission that declared one gets a refusal rather than
	// a silent dispatch without it.
	missionSecrets CredentialStore

	// graphrag serves the knowledge-graph reads. The SAME querier the daemon
	// hands to ComponentService — one implementation reached two ways, which is
	// what ADR-0161 promised and could not deliver until this field existed.
	// Nil means the reads report ErrKnowledgeUnavailable.
	graphrag component.GraphRAGQuerier

	// workQueue provides pull-based work dispatch over Redis Streams.
	// When non-nil, remote components discovered via componentRegistry (those without
	// an address of their own) receive work items via this queue
	// rather than a direct gRPC call. Nil means use the existing path.
	workQueue component.WorkQueue
	// callbackManager registers the child harness for a queue-dispatched agent
	// so its callbacks resolve (nil: no registration, gibson#1633).
	callbackManager CallbackRegistrar

	// cgMinter mints capability-grant JWTs that flow with each
	// dispatched work item. Agents present the CG-JWT on harness
	// callbacks; ext-authz validates it and short-circuits FGA when
	// the requested method is in allowed_rpcs. Nil disables CG-JWT
	// dispatch — useful for tests; production should always wire it.
	// Spec: unified-identity-and-authorization Requirement 13.1.
	cgMinter *capabilitygrant.Minter

	// workQueueTimeout is the maximum duration to wait for a remote component to
	// deliver a WorkResult after enqueuing. Defaults to 5 minutes when zero.
	workQueueTimeout time.Duration

	// livenessProbeEvery overrides how often an unbounded agent wait re-checks
	// that its worker is still registered (gibson#1602). It is a test seam:
	// zero, the production value, uses livenessProbeInterval.
	livenessProbeEvery time.Duration

	// componentAccess enforces per-tenant opt-in control for platform (_system) plugins.
	// When non-nil and a QueryPlugin call finds no tenant-scoped instances, the harness
	// checks that the tenant has explicitly enabled the plugin and has a stored config
	// before dispatching to the _system instance. Nil disables access enforcement
	// (backward-compatible for deployments that have not yet wired this store).
	componentAccess component.ComponentAccessStore

	// componentAuthorizer gates AGENT dispatch on can_execute against the
	// canonical component:agent/<name> object (gibson#1595). A mission may
	// dispatch to an agent only when the calling tenant has that agent enabled;
	// can_execute composes direct_execute AND in_tenant_catalog (from
	// tenant_enabled) AND NOT disabled in model.fga, so a Check that returns
	// false is exactly "not enabled for this tenant". This is the SAME FGA
	// authorizer the callback service uses for tool invocation, so the
	// dispatch-time subject matches the invocation-time subject. Nil is
	// fail-closed: an unwired authorizer denies every agent dispatch.
	componentAuthorizer authz.Authorizer

	// maxDelegationDepth is the maximum allowed DelegateToAgent nesting depth.
	// When zero, defaultMaxDelegationDepth (8) is used. The daemon config flag
	// "harness.max_delegation_depth" can override this per deployment.
	maxDelegationDepth int

	// sandboxedExecutor dispatches tool calls into Setec microVM sandboxes
	// via gRPC. Consulted BEFORE any local/component-registry path in
	// CallToolProto; nil disables sandboxed dispatch entirely.
	sandboxedExecutor *sandboxed.Executor

	// agentLauncher launches an untrusted/sandboxed agent as an ephemeral Setec
	// sandbox for one mission run (ADR-0116 / gibson#1596). When wired,
	// DelegateToAgent routes an untrusted agent to it instead of denying.
	// Nil means no sandboxed agent dispatch, so an untrusted agent is denied
	// fail-closed. See delegate_sandbox.go.
	agentLauncher AgentSandboxLauncher

	// agentLaunchSpecResolver resolves the launch spec (image, sandbox class,
	// egress envelope, model) for a sandboxed agent from the signed catalog
	// manifest. It is the typed seam for gibson#1597 (S5): nil means no spec
	// source, so a sandboxed dispatch cannot proceed and the harness denies
	// fail-closed rather than launching with an empty image.
	agentLaunchSpecResolver AgentLaunchSpecResolver

	// forks holds the parked sources and the fork ledger of ADR-0169. Nil
	// means no fork support: a node with starts_from fails, and a forkable
	// node runs as a normal node.
	forks *ForkSupport

	// agentCallbackEndpoint is the HarnessCallbackService address the daemon
	// advertises. It is injected into an ephemeral agent sandbox so the agent
	// dials the daemon back for LLM/tools/findings and to return its result.
	// Empty leaves the sandbox without a callback address (dev/test).
	agentCallbackEndpoint string

	// agentDispatchMode reports the catalog dispatch mode for an agent name and
	// whether that agent is listed in the component catalog. It is the injectable
	// seam over componentcatalog.LookupAgent (gibson#1598 / ADR-0116): a catalog
	// agent whose manifest declares dispatchMode==sandboxed must route to the
	// sandbox regardless of registry content trust, because a platform agent is
	// launched-on-dispatch, not a registered polling worker. Nil means "not
	// sandboxed" — DelegateToAgent then falls back to registry trust, which is
	// safe. A test injects a stub so the routing is exercised without shipping a
	// manifest into the embedded catalog.
	agentDispatchMode func(name string) (mode string, listed bool)

	// quotaCounter maintains the per-tenant concurrent_agents Redis
	// counter on agent idle→busy / busy→idle transitions, gated by
	// inFlightTasks bookkeeping below. nil disables agent-quota
	// counting. Spec plans-and-quotas-simplification.
	quotaCounter QuotaCounter

	// inFlightTasks tracks per-(parent → child agent) outstanding
	// DelegateToAgent calls. The child agent transitions idle→busy on
	// the 0→1 increment of its entry, and busy→idle on the 1→0
	// decrement. quotaCounter callbacks fire only on those transitions.
	// Sibling siblings of a parent harness DO NOT share state (each
	// DefaultAgentHarness instance owns its own map); the daemon's
	// missionManager owns one parent harness per mission, and that
	// parent's map is the authoritative source.
	inFlightTasksMu sync.Mutex
	inFlightTasks   map[string]int

	// currentNode is the mission node being executed by this harness instance.
	// When set, EffectivePerCallCap reads per-noun max_tokens_per_call from
	// the node config and uses it to clamp LLM requests. nil disables the
	// per-node override (mission-level cap still applies if missionConstraints
	// is set).
	// Spec: mission-author-experience M4 (gibson#133).
	currentNode *missionv1.MissionNode

	// missionConstraints carries the mission-level token budget constraints
	// for this execution. EffectivePerCallCap falls back to
	// missionConstraints.MaxTokensPerCall when no per-node override is
	// present. nil means no mission-level cap from this mechanism.
	// Spec: mission-author-experience M4 (gibson#133).
	missionConstraints *missionv1.MissionConstraints

	// nodeSlotOverrides carries per-slot LLM provider/model bindings for the
	// agent node executing through this harness instance. Keyed by slot name;
	// a nil value for a key means no override for that slot (fall through to
	// tenant default). Populated from MissionContext.NodeSlotOverrides by
	// DefaultHarnessFactory.Create.
	//
	// Every ResolveSlot call passes nodeSlotOverrides[slot] as the override
	// argument (nil when absent), so the slot manager's precedence chain is:
	//   explicit node binding > tenant default > deterministic constraint scan.
	//
	// Spec: per-node-slot-override (gibson#539).
	nodeSlotOverrides map[string]*agent.SlotConfig

	// emitCount bounds how many observations this task may emit
	// (emitbounds.MaxObservationsPerTask, ADR-0112 "Write contract"). A
	// harness instance is created per agent execution and unregistered when
	// that execution ends, so the counter's lifetime is the task's — no
	// keyed map, and therefore no unbounded bookkeeping introduced by the
	// bound itself. Zero value ready to use.
	emitCount emitbounds.Counter
}

// Ensure DefaultAgentHarness implements AgentHarness
var _ AgentHarness = (*DefaultAgentHarness)(nil)

// Ensure DefaultAgentHarness implements agent.AgentHarness (the minimal interface)
var _ agent.AgentHarness = (*DefaultAgentHarness)(nil)

// slotOverride returns the per-node SlotConfig override for the named slot, or nil
// when no override is configured. The nil return preserves the existing fall-through
// behavior (tenant default → deterministic constraint scan) inside the slot manager.
//
// Spec: per-node-slot-override (gibson#539).
func (h *DefaultAgentHarness) slotOverride(slot string) *agent.SlotConfig {
	if h.nodeSlotOverrides == nil {
		return nil
	}
	return h.nodeSlotOverrides[slot]
}

// WithPerCallCapContext wires the per-call token cap into the harness.
//
// node is the mission node being executed by this harness (may be nil when
// no per-node override applies). constraints carries the mission-level
// MissionConstraints (may be nil when no mission-level cap is configured).
//
// When both are set, EffectivePerCallCap applies the cascade documented in
// per_call_cap.go: per-noun MaxTokensPerCall → mission-level MaxTokensPerCall
// → 0 (no cap). The effective cap is applied before every LLM provider call
// in Complete, CompleteWithTools, and Stream.
//
// This method returns the receiver so it can be chained at construction time.
// Spec: mission-author-experience M4 (gibson#133).
func (h *DefaultAgentHarness) WithPerCallCapContext(node *missionv1.MissionNode, constraints *missionv1.MissionConstraints) *DefaultAgentHarness {
	h.currentNode = node
	h.missionConstraints = constraints
	return h
}

// applyPerCallCap clamps req.MaxTokens to the effective per-call cap.
//
// If no cap applies (EffectivePerCallCap returns 0), req.MaxTokens is left
// unchanged. If the caller already set a lower MaxTokens, that lower value
// is preserved (the cap is a ceiling, not a floor).
//
// Called immediately before each provider call in Complete, CompleteWithTools,
// and Stream.
func (h *DefaultAgentHarness) applyPerCallCap(req *llm.CompletionRequest) {
	cap := EffectivePerCallCap(h.currentNode, h.missionConstraints)
	if cap <= 0 {
		return
	}
	capInt := int(cap)
	if req.MaxTokens == 0 || req.MaxTokens > capInt {
		req.MaxTokens = capInt
	}
}

// ────────────────────────────────────────────────────────────────────────────
// LLM Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Complete performs a synchronous LLM completion using the specified slot.
func (h *DefaultAgentHarness) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.Complete")
	defer span.End()

	// Apply completion options
	options := applyOptions(opts...)

	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot", true)

	// Resolve slot to provider and model; honor any per-node binding (gibson#539).
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, h.slotOverride(slot))
	if err != nil {
		h.logger.Error("failed to resolve LLM slot",
			"slot", slot,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			fmt.Sprintf("failed to resolve slot %s", slot),
			err,
		)
	}

	// Build completion request
	req := llm.CompletionRequest{
		Model:    modelInfo.Name,
		Messages: messages,
	}

	// Apply options to request
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		// Prepend system message if provided
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Apply per-call token cap (per-node override → mission-level → no cap).
	// Must be called after all caller-provided options are applied so it
	// acts as a ceiling, never a floor.
	// Spec: mission-author-experience M4 (gibson#133).
	h.applyPerCallCap(&req)

	// Emit LLM request event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMRequest, "llm request", LLMRequestEventData{
			Model:        modelInfo.Name,
			MessageCount: len(req.Messages),
			Slot:         slot,
		})
	}

	// Execute completion
	resp, err := provider.Complete(ctx, req)
	if err != nil {
		h.logger.Error("LLM completion failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			"LLM completion failed",
			err,
		)
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	err = h.tokenUsage.RecordUsage(scope, provider.Name(), resp.Model, tokenUsage)
	if err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
		// Don't fail the request if tracking fails
	}

	// Record metrics
	h.metrics.RecordCounter("llm.completions", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
		"status":   "success",
	})
	h.metrics.RecordCounter("llm.tokens.input", int64(resp.Usage.PromptTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})
	h.metrics.RecordCounter("llm.tokens.output", int64(resp.Usage.CompletionTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})

	h.logger.Debug("LLM completion successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", resp.Model,
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	// Emit LLM response event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMResponse, "llm response", LLMResponseEventData{
			Model:            resp.Model,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.PromptTokens + resp.Usage.CompletionTokens,
			Slot:             slot,
		})
	}

	return resp, nil
}

// CompleteWithTools performs a completion with tool-calling capabilities.
func (h *DefaultAgentHarness) CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CompleteWithTools")
	defer span.End()

	// Apply completion options
	options := applyOptions(opts...)

	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot", true)

	// Resolve slot to provider and model; honor any per-node binding (gibson#539).
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, h.slotOverride(slot))
	if err != nil {
		h.logger.Error("failed to resolve LLM slot",
			"slot", slot,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			fmt.Sprintf("failed to resolve slot %s", slot),
			err,
		)
	}

	// Build completion request
	req := llm.CompletionRequest{
		Model:    modelInfo.Name,
		Messages: messages,
	}

	// Apply options to request
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Apply per-call token cap (per-node override → mission-level → no cap).
	// Spec: mission-author-experience M4 (gibson#133).
	h.applyPerCallCap(&req)

	// Emit LLM request event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMRequest, "llm request with tools", LLMRequestEventData{
			Model:        modelInfo.Name,
			MessageCount: len(req.Messages),
			Slot:         slot,
		})
	}

	// Execute completion with tools
	resp, err := provider.CompleteWithTools(ctx, req, tools)
	if err != nil {
		h.logger.Error("LLM completion with tools failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			"LLM completion with tools failed",
			err,
		)
	}

	// Track token usage
	scope := llm.UsageScope{
		MissionID: h.missionCtx.ID,
		AgentName: h.missionCtx.CurrentAgent,
		SlotName:  slot,
	}
	tokenUsage := llm.TokenUsage{
		InputTokens:  resp.Usage.PromptTokens,
		OutputTokens: resp.Usage.CompletionTokens,
	}
	err = h.tokenUsage.RecordUsage(scope, provider.Name(), resp.Model, tokenUsage)
	if err != nil {
		h.logger.Warn("failed to record token usage",
			"error", err)
	}

	// Record metrics
	h.metrics.RecordCounter("llm.completions.with_tools", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
		"status":   "success",
	})
	h.metrics.RecordCounter("llm.tokens.input", int64(resp.Usage.PromptTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})
	h.metrics.RecordCounter("llm.tokens.output", int64(resp.Usage.CompletionTokens), map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    resp.Model,
	})

	h.logger.Debug("LLM completion with tools successful",
		"slot", slot,
		"provider", provider.Name(),
		"model", resp.Model,
		"tool_calls", len(resp.Message.ToolCalls),
		"input_tokens", resp.Usage.PromptTokens,
		"output_tokens", resp.Usage.CompletionTokens)

	// Emit LLM response event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventLLMResponse, "llm response with tools", LLMResponseEventData{
			Model:            resp.Model,
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.PromptTokens + resp.Usage.CompletionTokens,
			Slot:             slot,
		})
	}

	return resp, nil
}

// Stream performs a streaming LLM completion, returning chunks as they arrive.
func (h *DefaultAgentHarness) Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.Stream")
	defer span.End()

	// Apply completion options
	options := applyOptions(opts...)

	// Create slot definition for the named slot
	slotDef := agent.NewSlotDefinition(slot, "LLM slot", true)

	// Resolve slot to provider and model; honor any per-node binding (gibson#539).
	provider, modelInfo, err := h.slotManager.ResolveSlot(ctx, slotDef, h.slotOverride(slot))
	if err != nil {
		h.logger.Error("failed to resolve LLM slot",
			"slot", slot,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			fmt.Sprintf("failed to resolve slot %s", slot),
			err,
		)
	}

	// Build completion request
	req := llm.CompletionRequest{
		Model:    modelInfo.Name,
		Messages: messages,
	}

	// Apply options to request
	if options.Temperature != nil {
		req.Temperature = *options.Temperature
	}
	if options.MaxTokens != nil {
		req.MaxTokens = *options.MaxTokens
	}
	if options.TopP != nil {
		req.TopP = *options.TopP
	}
	if options.StopSequences != nil {
		req.StopSequences = options.StopSequences
	}
	if options.SystemPrompt != nil && *options.SystemPrompt != "" {
		req.Messages = append([]llm.Message{
			llm.NewSystemMessage(*options.SystemPrompt),
		}, req.Messages...)
	}

	// Apply per-call token cap (per-node override → mission-level → no cap).
	// Spec: mission-author-experience M4 (gibson#133).
	h.applyPerCallCap(&req)

	// Execute streaming completion
	chunks, err := provider.Stream(ctx, req)
	if err != nil {
		h.logger.Error("LLM stream failed",
			"slot", slot,
			"provider", provider.Name(),
			"model", modelInfo.Name,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessCompletionFailed,
			"LLM stream failed",
			err,
		)
	}

	// Record metrics
	h.metrics.RecordCounter("llm.streams", 1, map[string]string{
		"slot":     slot,
		"provider": provider.Name(),
		"model":    modelInfo.Name,
		"status":   "started",
	})

	h.logger.Debug("LLM stream started",
		"slot", slot,
		"provider", provider.Name(),
		"model", modelInfo.Name)

	// Wrap channel to record stream completion and aggregate response
	wrappedChan := make(chan llm.StreamChunk)
	go func() {
		defer close(wrappedChan)

		for chunk := range chunks {
			wrappedChan <- chunk

			// If this is the final chunk, record completion metrics
			// Note: Token usage tracking for streaming requires provider-specific support
			// and is typically only available after the stream completes
			if chunk.FinishReason != "" {
				// Record completion metrics
				h.metrics.RecordCounter("llm.streams.completed", 1, map[string]string{
					"slot":     slot,
					"provider": provider.Name(),
					"model":    modelInfo.Name,
				})

				h.logger.Debug("LLM stream completed",
					"slot", slot,
					"provider", provider.Name(),
					"model", modelInfo.Name,
					"finish_reason", string(chunk.FinishReason))
			}
		}
	}()

	return wrappedChan, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Tool Execution Methods
// ────────────────────────────────────────────────────────────────────────────

// CallToolProto executes a tool using proto message input/output.
//
// A tool has two dispatch paths (ADR-0110):
//  1. The sandbox: a tool with a kind:tool catalog manifest runs in a setec
//     sandbox (ADR-0117).
//  2. The work queue: a tool that registered through ComponentService pulls
//     its work.
//
// A tool with neither gets ErrHarnessToolNotFound. Tools are never compiled
// into the Gibson daemon, and the daemon dials no address that a tool reports.
func (h *DefaultAgentHarness) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	ctx, span := h.tracer.Start(ctx, "harness.CallToolProto")
	defer span.End()

	inputSize := proto.Size(request)
	span.SetAttributes(
		attribute.String("tool.name", name),
		attribute.Int("tool.input_size", inputSize),
	)

	h.logger.Debug("calling tool with proto messages",
		"tool", name,
		"input_type", string(request.ProtoReflect().Descriptor().FullName()),
		"output_type", string(response.ProtoReflect().Descriptor().FullName()))

	// ── The execute gate ──────────────────────────────────────────────────
	// One decision before every dispatch path: may the caller execute
	// component:tool/<name>? can_execute needs the tenant to have the tool
	// enabled, so a tool that is in no catalog of the tenant is refused here,
	// whatever registry it is found in. The gate is fail-closed, and it runs
	// before any lookup, so a refusal starts nothing.
	if err := h.authorizeToolDispatch(ctx, name); err != nil {
		return err
	}

	// ── Manifest-sourced sandboxed tool (ADR-0117) ────────────────────────
	// A kind:tool catalog manifest is the source of truth for a tool's runtime
	// shape. A sandboxed manifest tool is dispatched to the sandbox.
	if spec, ok := h.sandboxedToolSpecFromManifest(name); ok {
		if h.sandboxedExecutor == nil {
			return types.WrapError(types.SANDBOX_TOOL_NOT_REGISTERED,
				fmt.Sprintf("tool %q is a sandboxed manifest tool but no sandboxed executor is wired", name), nil)
		}
		spec.Live = h.liveScope(ctx)
		h.addTargetFacts(ctx, &spec)
		if err := h.addDeclaredSecrets(ctx, name, &spec); err != nil {
			return err
		}
		//nolint:wrapcheck // ExecuteWithSpec already returns a typed gibson error; re-wrapping would double-wrap it (same as the registry path below).
		return h.sandboxedExecutor.ExecuteWithSpec(ctx, name, spec, request, response)
	}

	// ── Path 2: the work queue ───────────────────────────────────────────────
	// A tool that a developer or a customer runs registered through
	// ComponentService. It pulls its work from the work queue. The daemon
	// dials no address that a tool reports, and no third path exists
	// (ADR-0110).
	notFound := types.NewError(ErrHarnessToolNotFound,
		fmt.Sprintf("tool %q has no sandbox manifest and no work queue instance", name))
	if h.componentRegistry == nil {
		return notFound
	}
	// authorizeToolDispatch refused a call with no tenant before this point.
	tenant := auth.TenantStringFromContext(ctx)
	instances, discErr := h.componentRegistry.Discover(ctx, tenant, "tool", name)
	if discErr != nil {
		return types.WrapError(ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool %q: component registry discovery failed", name), discErr)
	}
	if len(instances) == 0 {
		return notFound
	}
	info := instances[0] // Use first live instance; load-balancing is a future concern.

	// Dispatch gate (ADR-0110). We reach here only when the tool has no
	// sandbox manifest, so there is no sandboxed dispatch available. The gate
	// reads where the instance runs and, for code in the platform's cluster,
	// the trust the catalog states. What the instance reported about itself
	// is not an input.
	placement, trust := component.DispatchStanding(info.Attested, authz.KindTool, name)
	if dispatchpolicy.Decide(placement, trust, false) == dispatchpolicy.Deny {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q runs in the cluster, the catalog does not state it as trusted, and it has no sandboxed dispatch", name), nil)
	}

	if h.workQueue == nil {
		return notFound
	}

	h.logger.Debug("routing tool call via work queue",
		"tool", name,
		"tenant", tenant,
		"instance_id", info.InstanceID)
	return h.callToolViaWorkQueue(ctx, tenant, name, request, response, info)
}

// workQueueWaitTimeout returns the configured wait timeout or the 5-minute default.
func (h *DefaultAgentHarness) workQueueWaitTimeout() time.Duration {
	if h.workQueueTimeout > 0 {
		return h.workQueueTimeout
	}
	return 5 * time.Minute
}

// callToolViaWorkQueue enqueues a proto tool call to a remote component registered
// via ComponentService and waits synchronously for the result. The result JSON is
// unmarshalled back into response using protojson.
//
// This path is taken when:
//   - A component is found in the ComponentRegistry (Redis), AND
//   - A WorkQueue is configured on the harness.
//
// remoteAgentInstance resolves a live kind=agent component for this tenant.
// The work queue drives it. The daemon dials no address that an instance
// reports, so the metadata of the instance selects nothing.
func (h *DefaultAgentHarness) remoteAgentInstance(ctx context.Context, tenant, name string) (component.ComponentInfo, bool) {
	if h.componentRegistry == nil || h.workQueue == nil || tenant == "" {
		return component.ComponentInfo{}, false
	}
	instances, err := h.componentRegistry.Discover(ctx, tenant, "agent", name)
	if err != nil {
		h.logger.Warn("component registry agent discovery failed",
			"agent", name, "tenant", tenant, "error", err)
		return component.ComponentInfo{}, false
	}
	if len(instances) == 0 {
		return component.ComponentInfo{}, false
	}
	return instances[0], true // First live instance; load-balancing is a future concern.
}

// delegateToAgentViaWorkQueue runs a mission node's agent on a remote component
// registered through ComponentService, and waits for its result.
//
// Without this, a component registered as kind=agent enrolled, heartbeated and
// polled correctly and was never handed anything: work was enqueued for tools
// and plugins only, so the platform could be called BY an external agent but
// could not run one (gibson#1197). The wire contract is the same one the
// in-cluster gRPC agent client uses — ExecuteRequest/ExecuteResponse — so an
// agent serving either transport implements one thing.
//
// The remote agent reaches harness operations (LLM, tools, findings) back over
// HarnessCallbackService using the task-scoped capability grant that
// dispatchWorkAndWait puts in the work item's context; it does not get a child
// harness object, because it is not in this process.
func (h *DefaultAgentHarness) delegateToAgentViaWorkQueue(
	ctx context.Context,
	tenant, name string,
	task agent.Task,
	info component.ComponentInfo,
) (agent.Result, error) {
	req := &agentpb.ExecuteRequest{
		Task:      agent.TaskToProto(task),
		TimeoutMs: task.Timeout.Milliseconds(),
	}
	if spanCtx := trace.SpanFromContext(ctx).SpanContext(); spanCtx.IsValid() {
		req.TraceId = spanCtx.TraceID().String()
		req.ParentSpanId = spanCtx.SpanID().String()
	}
	payload, err := protojson.Marshal(req)
	if err != nil {
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed,
			"failed to marshal agent request for work queue: "+name, err)
	}

	// The remote agent calls back over HarnessCallbackService with
	// (mission, agent) in its context; those calls resolve through the
	// callback registry to a harness. The queue path registers the child
	// harness for the agent, or every Observe/SubmitFinding from an
	// off-cluster agent answers "no active harness" (gibson#1633).
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
				"failed to create child harness for the queue-dispatched agent: "+name, cerr)
		}
		key := h.callbackManager.RegisterHarnessForMission(h.missionCtx.ID.String(), name, childHarness)
		if key != "" {
			defer h.callbackManager.UnregisterHarness(key)
		}
		h.observeDelegation(ctx, name, childHarness)
	}
	// An agent node is the one dispatch that may legitimately outlive any clock
	// the harness would pick: a live coding-agent session runs for hours. Its
	// own declared timeout bounds it, and when it declares none the worker's
	// heartbeat does (gibson#1602).
	resultBytes, err := h.dispatchWorkAndWait(ctx, tenant, "agent", name, component.WorkTypeAgentExecute, payload, nil, info,
		waitPolicy{bound: task.Timeout, livenessBounded: true})
	if err != nil {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "work_queue",
		})
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed,
			"agent work queue call failed: "+name, err)
	}

	resp := &agentpb.ExecuteResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(resultBytes, resp); err != nil {
		return agent.Result{}, types.WrapError(ErrHarnessDelegationFailed,
			"failed to unmarshal agent work result: "+name, err)
	}
	if e := resp.GetError(); e != nil && (e.GetMessage() != "" || e.GetCode() != "") {
		// A remote agent that reports a failure fails the node with its own
		// reason; swallowing it would leave the mission looking successful.
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent": name, "status": "failed", "transport": "work_queue",
		})
		return agent.Result{}, types.NewError(ErrHarnessDelegationFailed,
			fmt.Sprintf("remote agent %q returned error [%s]: %s", name, e.GetCode(), e.GetMessage()))
	}

	result := agent.ProtoToResult(resp.GetResult())
	result.TaskID = task.ID

	h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
		"agent": name, "status": "success", "transport": "work_queue",
	})
	h.logger.Debug("agent work queue delegation succeeded",
		"agent", name, "tenant", tenant, "instance_id", info.InstanceID)
	return result, nil
}

// observeDelegation records that this run delegated to a child run. It does
// NOT write the graph: the fact is folded into the tenant World through the
// DelegationSink, and the graph projector, the sole writer (ADR-0107),
// materializes the :AgentRun nodes and the DELEGATED_TO edge.
func (h *DefaultAgentHarness) observeDelegation(ctx context.Context, name string, childHarness AgentHarness) {
	parentRunID := h.missionCtx.AgentRunID
	var childRunID string
	if dah, ok := childHarness.(*DefaultAgentHarness); ok {
		childRunID = dah.missionCtx.AgentRunID
	}
	if h.delegationSink != nil && parentRunID != "" && childRunID != "" {
		h.delegationSink(ctx, DelegationObserved{
			Tenant:      h.missionCtx.TenantID,
			Scope:       h.missionCtx.ID.String(),
			ParentRunID: parentRunID,
			ParentAgent: h.missionCtx.CurrentAgent,
			ChildRunID:  childRunID,
			ChildAgent:  name,
		})
	}
}

// trackInFlightAgent does the concurrent_agents quota bookkeeping for one
// delegation and returns the release function. Shared by the sandbox and
// work-queue paths so each agent counts against the tenant's quota.
func (h *DefaultAgentHarness) trackInFlightAgent(ctx context.Context, name string) func() {
	if h.quotaCounter == nil {
		return func() {}
	}
	h.inFlightTasksMu.Lock()
	if h.inFlightTasks == nil {
		h.inFlightTasks = make(map[string]int)
	}
	prev := h.inFlightTasks[name]
	h.inFlightTasks[name] = prev + 1
	h.inFlightTasksMu.Unlock()
	if prev == 0 {
		if incErr := h.quotaCounter.IncrementAgentCount(ctx); incErr != nil {
			h.logger.Warn("harness: increment concurrent_agents failed (non-fatal)",
				"agent", name, "error", incErr.Error())
		}
	}
	return func() {
		h.inFlightTasksMu.Lock()
		h.inFlightTasks[name]--
		now := h.inFlightTasks[name]
		if now <= 0 {
			delete(h.inFlightTasks, name)
		}
		h.inFlightTasksMu.Unlock()
		if now == 0 {
			if decErr := h.quotaCounter.DecrementAgentCount(ctx); decErr != nil {
				h.logger.Warn("harness: decrement concurrent_agents failed (non-fatal)",
					"agent", name, "error", decErr.Error())
			}
		}
	}
}

func (h *DefaultAgentHarness) callToolViaWorkQueue(
	ctx context.Context,
	tenant, name string,
	request proto.Message,
	response proto.Message,
	info component.ComponentInfo,
) error {
	// Serialize the proto request to JSON for the work item payload.
	inputJSON, err := protojson.Marshal(request)
	if err != nil {
		h.logger.Error("failed to marshal tool request for work queue",
			"tool", name,
			"tenant", tenant,
			"error", err)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("failed to marshal tool request for work queue: %s", name),
			err,
		)
	}

	// Kind-uniform work-queue dispatch (gibson#663): the work-queue mechanics
	// (workCtx, AuthzContext, task CG-JWT, _system config injection, enqueue,
	// wait) are shared across agent/tool/plugin via dispatchWorkAndWait; this
	// wrapper only owns the tool-specific proto marshal/unmarshal + metrics.
	resultBytes, err := h.dispatchWorkAndWait(ctx, tenant, "tool", name, "execute_proto", inputJSON, nil, info, waitPolicy{})
	if err != nil {
		h.logger.Error("tool work queue dispatch failed",
			"tool", name, "tenant", tenant, "instance_id", info.InstanceID, "error", err)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool work queue call failed: %s", name),
			err,
		)
	}

	// Unmarshal the JSON result back into the response proto message.
	unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshaler.Unmarshal(resultBytes, response); err != nil {
		h.logger.Error("failed to unmarshal tool work result",
			"tool", name,
			"tenant", tenant,
			"error", err)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("failed to unmarshal tool work result: %s", name),
			err,
		)
	}

	h.logger.Debug("tool work queue call succeeded",
		"tool", name,
		"tenant", tenant,
		"discovery", "component_registry_work_queue")

	h.metrics.RecordCounter("tools.executions", 1, map[string]string{
		"tool":      name,
		"remote":    "true",
		"status":    "success",
		"mode":      "proto",
		"transport": "work_queue",
	})

	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventToolResult, "tool result", ToolResultEventData{
			ToolName: name,
			Success:  true,
		})
	}

	return nil
}

// callPluginViaWorkQueue enqueues a plugin query to a remote component registered
// via ComponentService and waits synchronously for the result.
//
// The result JSON is deserialised into a map[string]any and returned as-is,
// matching the return type of QueryPlugin.
func (h *DefaultAgentHarness) callPluginViaWorkQueue(
	ctx context.Context,
	tenant, name, method string,
	params map[string]any,
	info component.ComponentInfo,
) (any, error) {
	// Serialize params + method as the work item payload.
	payload, err := json.Marshal(map[string]any{
		"method": method,
		"params": params,
	})
	if err != nil {
		h.logger.Error("failed to marshal plugin query payload for work queue",
			"plugin", name,
			"method", method,
			"tenant", tenant,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("failed to marshal plugin query payload: %s.%s", name, method),
			err,
		)
	}

	// Kind-uniform work-queue dispatch (gibson#663). The "method" goes in the
	// work context; everything else (CG-JWT, AuthzContext, _system config
	// injection, enqueue, wait) is shared via dispatchWorkAndWait.
	resultBytes, err := h.dispatchWorkAndWait(ctx, tenant, "plugin", name, "query_plugin", payload, map[string]string{"method": method}, info, waitPolicy{})
	if err != nil {
		h.logger.Error("plugin work queue dispatch failed",
			"plugin", name, "method", method, "tenant", tenant, "instance_id", info.InstanceID, "error", err)
		return nil, types.WrapError(
			ErrHarnessPluginMethodNotFound,
			fmt.Sprintf("plugin work queue call failed: %s.%s", name, method),
			err,
		)
	}

	// Deserialise the JSON result into a generic value.
	var output any
	if err := json.Unmarshal(resultBytes, &output); err != nil {
		h.logger.Error("failed to unmarshal plugin work result",
			"plugin", name,
			"method", method,
			"tenant", tenant,
			"error", err)
		return nil, types.WrapError(
			ErrHarnessPluginMethodNotFound,
			fmt.Sprintf("failed to unmarshal plugin work result: %s.%s", name, method),
			err,
		)
	}

	h.logger.Debug("plugin work queue call succeeded",
		"plugin", name,
		"method", method,
		"tenant", tenant,
		"discovery", "component_registry_work_queue")

	h.metrics.RecordCounter("plugins.queries", 1, map[string]string{
		"plugin":    name,
		"method":    method,
		"remote":    "true",
		"status":    "success",
		"transport": "work_queue",
	})

	return output, nil
}

// dispatchWorkAndWait is the kind-uniform work-queue dispatch path for every
// component kind (agent/tool/plugin, gibson#663). It builds the work context
// (mission + caller extras), attaches the unsigned AuthzContext, mints the
// task-scoped capability-grant JWT, injects the tenant's decrypted config for
// SHARED (_system) instances of ANY kind, enqueues the work item, and waits for
// the result — returning the raw result bytes. Per-kind wrappers
// (callToolViaWorkQueue / callPluginViaWorkQueue) own only their payload
// marshal/unmarshal and metrics. Replaces the former duplicated dispatch bodies.
func (h *DefaultAgentHarness) dispatchWorkAndWait(
	ctx context.Context,
	tenant, kind, name, workType string,
	payload []byte,
	extraCtx map[string]string,
	info component.ComponentInfo,
	wait waitPolicy,
) ([]byte, error) {
	workCtx := map[string]string{
		"mission_id": h.missionCtx.ID.String(),
		"agent":      h.missionCtx.CurrentAgent,
	}
	for k, v := range extraCtx {
		workCtx[k] = v
	}
	if spanCtx := trace.SpanFromContext(ctx).SpanContext(); spanCtx.IsValid() {
		workCtx["trace_id"] = spanCtx.TraceID().String()
	}

	// Unsigned AuthzContext: run_id + issued_at + ttl_seconds; authorization is
	// covered by the FGA tuples binding the principal to the mission.
	if h.missionCtx.MissionRunID != "" {
		ac := sdkqueue.AuthzContext{
			RunID:      h.missionCtx.MissionRunID,
			IssuedAt:   time.Now().Unix(),
			TTLSeconds: authz.DefaultWorkTTLSeconds,
		}
		if acJSON, marshalErr := json.Marshal(ac); marshalErr == nil {
			workCtx[authz.AuthzContextWorkKey] = string(acJSON)
		} else {
			h.logger.Warn("failed to marshal AuthzContext for work item, dispatching without authz context",
				"kind", kind, "component", name, "run_id", h.missionCtx.MissionRunID, "error", marshalErr)
		}
	}

	// Task-scoped capability-grant JWT for the component's harness callbacks.
	if cgToken := h.mintCGForWork(name, kind); cgToken != "" {
		workCtx["capability_grant"] = cgToken
	}

	// Shared (_system) instances of ANY kind: inject the tenant's decrypted
	// per-component config so the remote worker has its credentials without a
	// separate lookup. Tenant-scoped instances manage their own config and must
	// never receive another tenant's credentials. Kind-agnostic via the
	// component access store (gibson#662/#663).
	if info.TenantID == "_system" && h.componentAccess != nil {
		if cfg, cfgErr := h.componentAccess.GetDecryptedConfig(ctx, tenant, name); cfgErr == nil {
			if cfgJSON, marshalErr := json.Marshal(cfg); marshalErr == nil {
				workCtx["plugin_config"] = string(cfgJSON)
			} else {
				h.logger.Warn("failed to marshal component config for work item context, proceeding without it",
					"kind", kind, "component", name, "tenant", tenant, "error", marshalErr)
			}
		} else {
			h.logger.Warn("failed to retrieve component config for work item context, proceeding without it",
				"kind", kind, "component", name, "tenant", tenant, "error", cfgErr)
		}
	}

	workID := fmt.Sprintf("%s-%s-%d", kind, name, time.Now().UnixNano())
	workItem := component.WorkItem{
		WorkID:   workID,
		WorkType: workType,
		Payload:  payload,
		Context:  workCtx,
	}

	if _, err := h.workQueue.Enqueue(ctx, tenant, kind, name, workItem); err != nil {
		return nil, fmt.Errorf("enqueue %s work item %q: %w", kind, name, err)
	}

	h.logger.Debug("work item enqueued, waiting for result",
		"kind", kind, "component", name, "tenant", tenant, "work_id", workID, "instance_id", info.InstanceID)

	// The wait is bound by the node, not by one harness-wide value (gibson#1602).
	// The dispatch knows which worker took the item, so a liveness-bounded wait
	// can tell "still working" from "gone" instead of guessing with a clock.
	wait.tenant, wait.kind, wait.name, wait.instanceID = tenant, kind, name, info.InstanceID
	result, err := h.waitForWorkResult(ctx, workID, wait)
	if err != nil {
		return nil, fmt.Errorf("%s work queue result wait failed for %q: %w", kind, name, err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("remote %s %q returned error [%s]: %s", kind, name, result.Error.Code, result.Error.Message)
	}
	return result.Result, nil
}

// ListTools returns descriptors for all tools discoverable via the
// component registry adapter. In-process tool registration was removed; all
// tools run as separate processes and are surfaced through RegistryAdapter.
func (h *DefaultAgentHarness) ListTools() []ToolDescriptor {
	descriptors := []ToolDescriptor{}
	if h.registryAdapter == nil {
		return descriptors
	}
	ctx := context.Background()
	remoteTools, err := h.registryAdapter.ListTools(ctx)
	if err != nil {
		h.logger.Warn("failed to list remote tools", "error", err)
		return descriptors
	}
	for _, remoteTool := range remoteTools {
		descriptors = append(descriptors, ToolDescriptor{
			Name:        remoteTool.Name,
			Description: remoteTool.Description,
			Version:     remoteTool.Version,
			Tags:        []string{},
			// InputSchema / OutputSchema require a per-tool descriptor fetch
			// which is expensive; callers that need schemas use
			// GetToolDescriptor(ctx, name).
		})
	}
	return descriptors
}

// GetToolDescriptor returns the descriptor for a specific tool by name.
// Resolves through the component registry adapter — in-process tool lookup
// was removed.
func (h *DefaultAgentHarness) GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error) {
	ctx, span := h.tracer.Start(ctx, "harness.GetToolDescriptor")
	defer span.End()

	if h.registryAdapter == nil {
		return nil, types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool not found: %s (no registry adapter configured)", name),
			nil,
		)
	}
	remoteTool, err := h.registryAdapter.DiscoverTool(ctx, name)
	if err != nil {
		h.logger.Error("tool not found via registry adapter", "tool", name, "error", err)
		return nil, types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool not found: %s", name),
			err,
		)
	}
	desc := FromTool(remoteTool)
	return &desc, nil
}

// GetToolCapabilities retrieves runtime capabilities for a specific tool.
// Resolves through the component registry adapter. Returns nil if the tool
// doesn't implement CapabilityProvider.
func (h *DefaultAgentHarness) GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error) {
	ctx, span := h.tracer.Start(ctx, "harness.GetToolCapabilities")
	defer span.End()

	h.logger.Debug("retrieving capabilities for tool", "tool", toolName)

	if h.registryAdapter == nil {
		return nil, types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool not found: %s (no registry adapter configured)", toolName),
			nil,
		)
	}
	t, err := h.registryAdapter.DiscoverTool(ctx, toolName)
	if err != nil {
		h.logger.Error("tool not found via registry adapter", "tool", toolName, "error", err)
		return nil, types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool not found: %s", toolName),
			err,
		)
	}

	type capabilityProvider interface {
		Capabilities(ctx context.Context) *sdktypes.Capabilities
	}

	if provider, ok := t.(capabilityProvider); ok {
		if caps := provider.Capabilities(ctx); caps != nil {
			h.logger.Debug("retrieved capabilities for tool",
				"tool", toolName,
				"has_root", caps.HasRoot,
				"has_sudo", caps.HasSudo,
				"can_raw_socket", caps.CanRawSocket,
				"blocked_args_count", len(caps.BlockedArgs))
			return caps, nil
		}
	}

	h.logger.Debug("tool does not provide capabilities", "tool", toolName)
	return nil, nil
}

// GetAllToolCapabilities returns capabilities for all registered tools.
// Tools that don't implement CapabilityProvider are excluded from the result.
func (h *DefaultAgentHarness) GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error) {
	ctx, span := h.tracer.Start(ctx, "harness.GetAllToolCapabilities")
	defer span.End()

	h.logger.Debug("retrieving capabilities for all tools")

	result := make(map[string]*sdktypes.Capabilities)
	if h.registryAdapter == nil {
		return result, nil
	}

	type capabilityProvider interface {
		Capabilities(ctx context.Context) *sdktypes.Capabilities
	}

	remoteTools, err := h.registryAdapter.ListTools(ctx)
	if err != nil {
		h.logger.Warn("failed to list remote tools for capabilities", "error", err)
		return result, nil
	}
	for _, remoteTool := range remoteTools {
		t, err := h.registryAdapter.DiscoverTool(ctx, remoteTool.Name)
		if err != nil {
			h.logger.Warn("failed to discover remote tool",
				"tool", remoteTool.Name,
				"error", err)
			continue
		}
		if provider, ok := t.(capabilityProvider); ok {
			if caps := provider.Capabilities(ctx); caps != nil {
				result[remoteTool.Name] = caps
				h.logger.Debug("retrieved capabilities for tool",
					"tool", remoteTool.Name,
					"has_root", caps.HasRoot,
					"has_sudo", caps.HasSudo,
					"can_raw_socket", caps.CanRawSocket,
					"blocked_args_count", len(caps.BlockedArgs))
			}
		}
	}

	h.logger.Info("retrieved tool capabilities",
		"tools_with_capabilities", len(result))
	return result, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Plugin Access Methods
// ────────────────────────────────────────────────────────────────────────────

// QueryPlugin calls a method on a registered plugin with the given parameters.
//
// Dispatch path (post plugin-runtime Spec 2 Phase 7 — single path):
//
//	ComponentRegistry (Redis-backed, tenant-scoped) → WorkQueue dispatch.
//	  • Tenant-scoped instances are tried first; if absent, ComponentAccess gates a
//	    fallthrough to a _system instance for tenants that have explicitly
//	    enabled and configured the plugin.
//	  • Live dispatch is via the WorkQueue (poll/result) — the same path the
//	    daemon's PluginInvokeService (component/plugin_dispatch.go) drives.
//
// The pre-release in-process plugin registry (`internal/plugin`) and its
// `Plugin.Query(...)` shape were removed by Phase 7 of the plugin-runtime spec;
// there is no in-process Plugin object to fall back to. If the component
// registry is unavailable or returns no usable instance, this method returns
// ErrHarnessPluginNotFound.
func (h *DefaultAgentHarness) QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.QueryPlugin")
	defer span.End()

	h.logger.Debug("querying plugin",
		"plugin", name,
		"method", method,
		"params", params)

	if h.componentRegistry == nil {
		h.logger.Error("plugin query: component registry not configured",
			"plugin", name)
		return nil, types.NewError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin not found: %s (component registry not configured)", name),
		)
	}

	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		h.logger.Warn("plugin query: no tenant in context",
			"plugin", name)
		return nil, types.NewError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin %s: no tenant in context — plugin dispatch is tenant-scoped", name),
		)
	}

	// ── Tenant-scoped instances ─────────────────────────────────────────────
	tenantInstances, discErr := h.componentRegistry.DiscoverTenantOnly(ctx, tenant, "plugin", name)
	if discErr != nil {
		h.logger.Error("component registry tenant discovery failed for plugin",
			"plugin", name,
			"tenant", tenant,
			"error", discErr)
		return nil, types.WrapError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin not found: %s (component registry error)", name),
			discErr,
		)
	}

	if len(tenantInstances) > 0 {
		info := tenantInstances[0]
		if h.workQueue == nil {
			h.logger.Warn("component registry found plugin but no work queue configured",
				"plugin", name,
				"tenant", tenant,
				"instance_id", info.InstanceID)
			return nil, types.NewError(
				ErrHarnessPluginNotFound,
				fmt.Sprintf("plugin %s found but harness has no work queue configured for dispatch", name),
			)
		}

		h.logger.Debug("component registry: routing plugin query via work queue (tenant instance)",
			"plugin", name,
			"tenant", tenant,
			"instance_id", info.InstanceID,
			"discovery", "component_registry")

		return h.callPluginViaWorkQueue(ctx, tenant, name, method, params, info)
	}

	// ── _system fallback (gated by ComponentAccess) ────────────────────────────
	if h.componentAccess == nil {
		h.logger.Error("plugin not found and no _system fallback path",
			"plugin", name,
			"tenant", tenant)
		return nil, types.NewError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin not found: %s (no tenant instance, no _system access store)", name),
		)
	}

	access, accessErr := h.componentAccess.GetAccess(ctx, tenant, name)
	if accessErr != nil {
		if errors.Is(accessErr, component.ErrComponentNotEnabled) {
			h.logger.Warn("plugin access denied: not enabled for tenant",
				"plugin", name,
				"tenant", tenant)
			return nil, types.WrapError(
				ErrHarnessPluginNotFound,
				fmt.Sprintf("plugin %q is not enabled for tenant %q — enable it via the plugin catalog before use", name, tenant),
				accessErr,
			)
		}
		h.logger.Error("plugin access check failed",
			"plugin", name,
			"tenant", tenant,
			"error", accessErr)
		return nil, types.WrapError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin %q access check failed for tenant %q", name, tenant),
			accessErr,
		)
	}
	if access == nil || !access.Enabled {
		return nil, types.NewError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin %q is not enabled for tenant %q", name, tenant),
		)
	}

	if _, configErr := h.componentAccess.GetDecryptedConfig(ctx, tenant, name); configErr != nil {
		if errors.Is(configErr, component.ErrComponentNotConfigured) {
			h.logger.Warn("plugin access denied: enabled but not configured",
				"plugin", name,
				"tenant", tenant)
			return nil, types.WrapError(
				ErrHarnessPluginNotFound,
				fmt.Sprintf("plugin %q is enabled for tenant %q but has no configuration — provide credentials via the plugin catalog", name, tenant),
				configErr,
			)
		}
		h.logger.Error("plugin config retrieval failed",
			"plugin", name,
			"tenant", tenant,
			"error", configErr)
		return nil, types.WrapError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin %q config retrieval failed for tenant %q", name, tenant),
			configErr,
		)
	}

	systemInstances, sysErr := h.componentRegistry.DiscoverSystemOnly(ctx, "plugin", name)
	if sysErr != nil {
		h.logger.Error("component registry system discovery failed for plugin",
			"plugin", name,
			"error", sysErr)
		return nil, types.WrapError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin not found: %s (system registry error)", name),
			sysErr,
		)
	}
	if len(systemInstances) == 0 {
		return nil, types.NewError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin %s: no _system instances available", name),
		)
	}

	info := systemInstances[0]
	if h.workQueue == nil {
		return nil, types.NewError(
			ErrHarnessPluginNotFound,
			fmt.Sprintf("plugin %s _system instance found but harness has no work queue configured", name),
		)
	}

	h.logger.Debug("component registry: routing plugin query to _system instance via work queue",
		"plugin", name,
		"tenant", tenant,
		"instance_id", info.InstanceID,
		"discovery", "component_registry_system")

	return h.callPluginViaWorkQueue(ctx, tenant, name, method, params, info)
}

// ListPlugins returns descriptors for all registered plugins.
//
// Post plugin-runtime Spec 2 Phase 7 there is no in-process plugin registry to
// enumerate; all plugins live behind the component registry / PluginInvokeService.
// This method aggregates plugin metadata from the registryAdapter only. If no
// adapter is configured, an empty slice is returned.
func (h *DefaultAgentHarness) ListPlugins() []PluginDescriptor {
	if h.registryAdapter == nil {
		return []PluginDescriptor{}
	}

	ctx := context.Background()
	remotePlugins, err := h.registryAdapter.ListPlugins(ctx)
	if err != nil {
		h.logger.Warn("failed to list remote plugins",
			"error", err)
		return []PluginDescriptor{}
	}

	descriptors := make([]PluginDescriptor, 0, len(remotePlugins))
	for _, remotePlugin := range remotePlugins {
		methods := make([]PluginMethodDescriptor, 0, len(remotePlugin.Methods))
		for _, m := range remotePlugin.Methods {
			methods = append(methods, PluginMethodDescriptor{Name: m})
		}
		descriptors = append(descriptors, PluginDescriptor{
			Name:       remotePlugin.Name,
			Version:    remotePlugin.Version,
			Methods:    methods,
			IsExternal: true, // all plugins are out-of-process under the new runtime
			Status:     PluginStatusUninitialized,
		})
	}

	return descriptors
}

// ────────────────────────────────────────────────────────────────────────────
// Sub-Agent Delegation Methods
// ────────────────────────────────────────────────────────────────────────────

// DelegateToAgent delegates a task to another registered agent for execution.
// relationCanExecute is the FGA relation checked to gate agent dispatch. In
// model.fga can_execute composes direct_execute AND in_tenant_catalog (from
// tenant_enabled) AND NOT any disable, so a false result means the agent is not
// enabled for the calling tenant. It mirrors the relation FGAAuthorizer.CanExecute
// checks at tool-invocation time.
const relationCanExecute = "can_execute"

// authorizeAgentDispatch is the fail-closed can_execute gate for AGENT dispatch
// (gibson#1595). It answers one question — may the calling tenant dispatch to
// component:agent/<name>? — the same decision the callback service makes at
// tool-invocation time, so a mission can never enqueue work for an agent the
// tenant never enabled.
//
// The subject mirrors callback_credential_authz.go exactly: the caller identity
// on the context, mapped through callbackFGAUser to a typed FGA reference
// (user:<uuid> / agent_principal:<id> / …). The object is the canonical
// component object authz.ComponentObject(authz.KindAgent, name).
//
// Fail-closed on every axis: no authorizer wired, no tenant, no caller identity,
// or an FGA error all deny. A deny returns a SANDBOX_POLICY_DENIED GibsonError
// naming the agent, matching the dispatch-policy gate above it.
func (h *DefaultAgentHarness) authorizeAgentDispatch(ctx context.Context, name string) error {
	return h.authorizeComponentDispatch(ctx, authz.KindAgent, name)
}

// authorizeToolDispatch is the fail-closed can_execute gate for a manifest-seeded
// TOOL (ADR-0117 / gibson#1638) — the tool analogue of authorizeAgentDispatch.
// A tool the calling tenant never enabled (no tenant_enabled → can_execute is
// false) is denied and nothing is launched. This is what gives tools per-tenant
// control, replacing the old ungated _system refresher path.
func (h *DefaultAgentHarness) authorizeToolDispatch(ctx context.Context, name string) error {
	return h.authorizeComponentDispatch(ctx, authz.KindTool, name)
}

// authorizeComponentDispatch is the one fail-closed can_execute gate both agent
// and tool dispatch flow through (gibson#1595/#1638) — one decision, one code
// path (ADR-0027). It answers: may the calling tenant execute
// component:<kind>/<name>? — the same decision the callback service makes at
// invocation time, so a mission can never dispatch to a component the tenant
// never enabled.
//
// The subject mirrors callback_credential_authz.go exactly: the caller identity
// on the context, mapped through callbackFGAUser to a typed FGA reference. The
// object is authz.ComponentObject(kind, name). The `kind` string ("agent" |
// "tool") is also the noun in the denial message.
//
// Fail-closed on every axis: no authorizer wired, no tenant, no caller identity,
// or an FGA error all deny, with a SANDBOX_POLICY_DENIED GibsonError naming the
// component.
func (h *DefaultAgentHarness) authorizeComponentDispatch(ctx context.Context, kind, name string) error {
	if h.componentAuthorizer == nil {
		// No authorizer wired means no decision can be made. Deny rather than
		// dispatch: an undecidable authorization question is a deny. The daemon
		// always wires one (harness_init.go passes d.authorizer); this branch
		// catches a misconfigured or partially-constructed harness. It matches
		// the callback service's nil-authorizer handling (callback_credential_authz.go).
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("%s %q dispatch denied: authorization unavailable (no authorizer wired)", kind, name), nil)
	}

	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" || tenant == auth.SystemTenantString {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("%s %q dispatch denied: no tenant in context", kind, name), nil)
	}

	identity, idErr := auth.IdentityFromContext(ctx)
	if idErr != nil || identity.Subject == "" {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("%s %q dispatch denied: no caller identity", kind, name), idErr)
	}

	fgaUser := callbackFGAUser(identity.Subject)
	fgaObject := authz.ComponentObject(kind, name)

	allowed, checkErr := h.componentAuthorizer.Check(ctx, fgaUser, relationCanExecute, fgaObject)
	if checkErr != nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("%s %q dispatch denied: authorization check failed", kind, name), checkErr)
	}
	if !allowed {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("%s %q is not enabled for tenant %q", kind, name, tenant), nil)
	}
	return nil
}

// sandboxedToolSpecFromManifest resolves a sandboxed tool's launch spec from the
// embedded kind:tool catalog manifest (ADR-0117) — the source of truth for a
// tool's runtime shape now that the runtime refresher is retired. The tool is
// selected inside the shared executor image by GIBSON_TOOL_NAME = the manifest
// id; egress is bounded by the dispatching agent's ceiling. Returns false when
// no sandboxed manifest tool of that name exists.
// liveScope is the console scope stamped on every sandboxed dispatch
// (ADR-0116 S11): the CUSTOMER tenant this call is served for and the mission
// it belongs to, so the running sandbox is enumerable on the caller's own
// console and nobody else's.
//
// Split from the dispatch path so the scoping contract is testable on its own.
// It decides who can SEE a running sandbox, and reaching it through a real
// dispatch needs a live executor and a registered manifest tool, so inline it
// went untested.
func (h *DefaultAgentHarness) liveScope(ctx context.Context) sandboxed.LiveScope {
	return sandboxed.LiveScope{
		Tenant:       auth.TenantStringFromContext(ctx),
		MissionID:    h.missionCtx.ID.String(),
		MissionRunID: h.missionCtx.MissionRunID,
	}
}

// addTargetFacts tells a sandboxed tool what it is acting against, as
// GIBSON_TARGET_ID, _NAME, _TYPE, _URL, _HOST and _DOMAIN.
//
// The tool path did not know its target at all: `grep TargetID` over
// internal/engine/tool and internal/engine/harness/sandboxed was empty, so a
// tool could only act on whatever the mission author typed into its input, and
// an authenticated tool had nowhere to learn its endpoint from (gibson#485).
//
// Resolved from the STORE by id, not from h.targetInfo. For a fan-out instance
// ForTarget swaps only the id and leaves the primary's name and URL in place —
// deliberately, since nothing reading it for scope needs the rest — so deriving
// facts from that view would pair the instance's id with another target's host.
// A tool handed that scans the wrong machine and reports a clean result for it.
//
// The values come from targetbind.Env, the same derivation {{target.*}} uses, so
// a mission author and the tool it dispatches cannot disagree about which host
// was scanned.
//
// The factory refuses a harness with no lookup (gibson#681). Every other
// failure is silent and total: no target id, a store that errors, a target
// that has gone. The tool then receives no GIBSON_TARGET_* at
// all, which is what it received before this existed. An EMPTY or PARTIAL set
// would be worse than none — a tool cannot tell "this target has no host" from
// "the platform did not tell me", and the two call for opposite behaviour.
func (h *DefaultAgentHarness) addTargetFacts(ctx context.Context, spec *sandboxed.ToolSpec) {
	id := h.Target().ID
	if id.IsZero() {
		return
	}
	t, err := h.targetFacts.Get(ctx, id)
	if err != nil || t == nil {
		h.logger.Warn("tool dispatch: target facts unavailable, dispatching without them",
			"tool_target_id", id.String(), "error", err)
		return
	}
	env := targetbind.Env(t.ID.String(), t.Name, t.Type, targetbind.URLOf(t))
	if len(env) == 0 {
		return
	}
	if spec.Env == nil {
		spec.Env = make(map[string]string, len(env))
	}
	for k, v := range env {
		spec.Env[k] = v
	}
}

// secretEnvKey is a secret's name as an environment variable, from the one copy
// of that rule: sdk/secretenv.
//
// The daemon WRITES the variable and the dispatched component READS it, and the
// component lives in another repository — gibson-executor's kube-bench and
// trivy-k8s both resolve a kubeconfig this way. The fold used to live here, so
// the two sides could have disagreed about which variable holds which
// credential. It is in the SDK both of them already depend on instead.
//
// The fold is not injective: "a-b" and "a.b" both become A_B.
// addDeclaredSecrets refuses that collision rather than letting one name
// silently win, and it can only refuse the same collision the component would
// see because both compute the key the same way.
func secretEnvKey(name string) string {
	return secretenv.Key(name)
}

// addDeclaredSecrets hands a dispatched tool the secrets its mission declared
// for it, resolved server-side at dispatch (gibson#485).
//
// The tool never named them: the mission declared them, and the union of
// mission-wide, tool-wide and per-tool is computed here. The daemon resolves
// each value AS ITSELF through the credential store, so no FGA relation is
// granted to the tool and `secret.can_resolve` stays plugin-only — the
// non-plugin-secret-isolation property is preserved exactly.
//
// Every failure REFUSES the dispatch rather than running without the secret. A
// tool that was promised a credential and silently ran without one does not
// fail: it authenticates to nothing, finds nothing, and reports a clean result
// for a scan that never happened. That is the failure mode this whole issue
// exists to remove, and it is worse than a mission that will not start.
func (h *DefaultAgentHarness) addDeclaredSecrets(ctx context.Context, toolName string, spec *sandboxed.ToolSpec) error {
	names := h.missionCtx.Secrets.ForTool(toolName)
	if len(names) == 0 {
		return nil
	}
	if h.missionSecrets == nil {
		return types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("tool %q was declared %d secret(s) by its mission but this daemon wires no credential store; "+
				"refusing to dispatch it without them", toolName, len(names)), nil)
	}

	resolved := make(map[string]string, len(names))
	for _, n := range names {
		key := secretEnvKey(n)
		if prior, dup := resolved[key]; dup {
			return types.WrapError(types.SANDBOX_POLICY_DENIED,
				fmt.Sprintf("tool %q: secrets %q and %q both map to %s; rename one, "+
					"because a tool handed the wrong credential under the right name is worse than a refusal",
					toolName, prior, n, key), nil)
		}
		_, value, err := h.missionSecrets.GetCredential(ctx, n)
		if err != nil {
			// The name, never the value, and never the error's own body — a
			// store error can quote what it was handed.
			return types.WrapError(types.SANDBOX_POLICY_DENIED,
				fmt.Sprintf("tool %q: mission declared secret %q, which did not resolve; refusing to dispatch without it",
					toolName, n), nil)
		}
		if value == "" {
			return types.WrapError(types.SANDBOX_POLICY_DENIED,
				fmt.Sprintf("tool %q: mission declared secret %q, which resolved empty; refusing to dispatch with a blank credential",
					toolName, n), nil)
		}
		resolved[key] = n
		if spec.Env == nil {
			spec.Env = make(map[string]string, len(names))
		}
		spec.Env[key] = value
	}
	return nil
}

func (h *DefaultAgentHarness) sandboxedToolSpecFromManifest(name string) (sandboxed.ToolSpec, bool) {
	entry, ok := componentcatalog.LookupTool(name)
	if !ok || entry.DispatchMode != componentcatalog.DispatchModeSandboxed {
		return sandboxed.ToolSpec{}, false
	}
	spec := sandboxed.ToolSpec{
		Image:   entry.Image,
		Command: append([]string(nil), entry.Command...),
		Env:     map[string]string{"GIBSON_TOOL_NAME": name},
		VCPU:    entry.Resources.VCPU,
		Memory:  entry.Resources.Memory,
		Egress:  agentEgressCeiling(h.missionCtx.CurrentAgent),
	}
	// A tool that runs inside a node gets the network of that node (S6).
	if n := h.missionCtx.NodeNetwork; n != nil {
		spec.NetworkMode, spec.Egress = nodeNetworkScope(n)
	}
	return spec, true
}

func (h *DefaultAgentHarness) DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.DelegateToAgent")
	defer span.End()

	// ── Depth cap ───────────────────────────────────────────────────────────
	// Resolve the effective depth limit: use the harness field when non-zero,
	// otherwise fall back to the package default.
	maxDepth := h.maxDelegationDepth
	if maxDepth <= 0 {
		maxDepth = defaultMaxDelegationDepth
	}

	currentDepth := h.missionCtx.DelegationDepth
	if currentDepth >= maxDepth {
		return agent.Result{}, fmt.Errorf(
			"delegation_depth_exceeded: chain length %d > max %d",
			currentDepth, maxDepth,
		)
	}

	// ── Dispatch gate (ADR-0110 / ADR-0116) ──────────────────────────────────
	// An agent has two dispatch paths and no third one:
	//   - the platform starts the agent, and it starts it in a setec sandbox;
	//   - a developer or a customer started the agent, and it pulls its work
	//     from the work queue.
	// The daemon runs no agent code in its own process, and it dials no
	// address that an agent reports. The gate inputs come from where the
	// agent runs and from the catalog, never from what an instance reported
	// (resolveAgentStanding). Each tool that the agent calls passes its own
	// gate in CallToolProto.
	agentPlacement, agentTrust, registered, trustErr := h.resolveAgentStanding(ctx, name)
	if trustErr != nil {
		return agent.Result{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent %q: the placement could not be established; refusing the delegation", name), trustErr)
	}
	// A catalog agent whose signed manifest declares dispatchMode==sandboxed
	// is an agent that the platform starts. It is launched on dispatch and is
	// not a registered worker, so its standing comes from the manifest and
	// not from the registry (ADR-0116). The seam is nil-safe: a nil seam or
	// an unlisted agent leaves the standing as the registry established it.
	platformStarts := false
	if h.agentDispatchMode != nil {
		if mode, listed := h.agentDispatchMode(name); listed && mode == componentcatalog.DispatchModeSandboxed {
			platformStarts = true
			agentPlacement = dispatchpolicy.PlacementCluster
			agentTrust = componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
		}
	}
	if !platformStarts && !registered {
		return agent.Result{}, types.NewError(ErrHarnessAgentNotFound,
			fmt.Sprintf("agent %q has no sandbox manifest and no work queue instance", name))
	}
	// The platform starts an agent that runs in the cluster and that the
	// catalog does not state as trusted. With no launcher, the gate denies.
	sandboxAgent := agentPlacement == dispatchpolicy.PlacementCluster &&
		agentTrust == componentpb.ContentTrust_CONTENT_TRUST_UNTRUSTED
	hasSandboxedAgentDispatch := sandboxAgent && h.agentLauncher != nil
	decision := dispatchpolicy.Decide(agentPlacement, agentTrust, hasSandboxedAgentDispatch)
	if decision == dispatchpolicy.Deny {
		return agent.Result{}, types.WrapError(types.SANDBOX_POLICY_DENIED,
			fmt.Sprintf("agent %q has no sandboxed dispatch and no work queue instance that may take the work", name), nil)
	}

	// ── Tenant-enablement gate (gibson#1595) ─────────────────────────────────
	// A mission may dispatch to an agent only when the calling tenant has that
	// agent enabled. This is the single choke point for BOTH mission→agent and
	// agent→sub-agent dispatch, so the check runs before a sandbox starts and
	// before a work item is enqueued. Fail-closed on every axis.
	if err := h.authorizeAgentDispatch(ctx, name); err != nil {
		return agent.Result{}, err
	}

	if decision == dispatchpolicy.RequireSetec {
		defer h.trackInFlightAgent(ctx, name)()
		return h.delegateToAgentViaSandbox(ctx, name, task, agentTrust)
	}

	// ── Parent-chain push ────────────────────────────────────────────────────
	// Capture the current agent's run ID *before* building the child context so
	// that the caller chain reflects the delegation path A→B→C correctly.
	// This is additive: we do NOT remove existing CurrentAgent handling.
	parentRunID := h.missionCtx.AgentRunID

	// Read the existing chain from context (may be nil on first hop).
	existingChain, _ := contextkeys.GetCallerChain(ctx)

	// Build an extended chain: [existing... parentRunID].
	// Allocate a fresh slice to avoid mutating the ancestor's slice.
	var newChain []string
	if len(existingChain) > 0 {
		newChain = make([]string, len(existingChain), len(existingChain)+1)
		copy(newChain, existingChain)
	}
	if parentRunID != "" {
		newChain = append(newChain, parentRunID)
	}

	// Stamp parent identity and chain onto the context that flows into the child.
	if parentRunID != "" {
		ctx = contextkeys.WithParentAgentRunID(ctx, parentRunID)
	}
	ctx = contextkeys.WithCallerChain(ctx, newChain)

	h.logger.Info("delegating to agent",
		"agent", name,
		"task_id", task.ID.String(),
		"task_name", task.Name,
		"parent_agent_run_id", parentRunID,
		"delegation_depth", currentDepth+1,
		"caller_chain_len", len(newChain))

	// ── Work queue dispatch (gibson#1197) ────────────────────────────────────
	// An agent registered through ComponentService lives outside this process.
	// It pulls its work from the same work queue that tools and plugins use,
	// and it calls harness operations back over HarnessCallbackService.
	tenant := auth.TenantStringFromContext(ctx)
	info, found := h.remoteAgentInstance(ctx, tenant, name)
	if !found {
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent":  name,
			"status": "failed",
		})
		return agent.Result{}, types.NewError(ErrHarnessAgentNotFound,
			fmt.Sprintf("agent %q has no sandbox manifest and no work queue instance", name))
	}
	defer h.trackInFlightAgent(ctx, name)()
	return h.delegateToAgentViaWorkQueue(ctx, tenant, name, task, info)
}

// ListAgents returns descriptors for all registered agents.
func (h *DefaultAgentHarness) ListAgents() []AgentDescriptor {
	// Use registry adapter for listing agents
	if h.registryAdapter == nil {
		h.logger.Warn("no registry adapter available for listing agents")
		return []AgentDescriptor{}
	}

	h.logger.Debug("using registry adapter for listing agents")

	// Get agents from registry adapter
	agentInfos, err := h.registryAdapter.ListAgents(context.Background())
	if err != nil {
		h.logger.Error("failed to list agents from registry adapter", "error", err)
		// Return empty list on error rather than panicking
		return []AgentDescriptor{}
	}

	// Convert from component.AgentInfo to harness.AgentDescriptor
	descriptors := make([]AgentDescriptor, len(agentInfos))
	for i, info := range agentInfos {
		descriptors[i] = AgentDescriptor{
			Name:         info.Name,
			Version:      info.Version,
			Description:  info.Description,
			Capabilities: info.Capabilities,
			Slots:        []agent.SlotDefinition{}, // AgentInfo doesn't include slots
			IsExternal:   true,                     // All registry adapter agents are external
		}
	}
	return descriptors
}

// ────────────────────────────────────────────────────────────────────────────
// Findings Management Methods
// ────────────────────────────────────────────────────────────────────────────

// SubmitFinding stores a security finding for the current mission.
func (h *DefaultAgentHarness) SubmitFinding(ctx context.Context, finding agent.Finding) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.SubmitFinding")
	defer span.End()

	// Bounds first, before anything is classified, stamped, stored or
	// emitted as an event (ADR-0112, "Write contract"). Over-limit input is
	// rejected whole and never truncated, and rejecting here — ahead of
	// every write on this path — is what makes "a rejected emit creates no
	// partial state" a property of the ordering rather than of cleanup.
	if err := emitbounds.CheckObservation(finding); err != nil {
		h.logger.Warn("finding rejected by emit bounds",
			"finding_id", finding.ID.String(),
			"error", err)
		return fmt.Errorf("submit finding: %w", err)
	}
	if err := h.emitCount.Admit(); err != nil {
		h.logger.Warn("finding rejected by emit bounds",
			"finding_id", finding.ID.String(),
			"error", err)
		return fmt.Errorf("submit finding: %w", err)
	}

	// Store original category before classification
	originalCategory := finding.Category

	// Apply category classification if classifier is configured
	if h.categoryClassifier != nil {
		normalizedCategory, err := h.categoryClassifier.Classify(ctx, finding.Category, finding.Description)
		if err != nil {
			// Graceful degradation: log warning and continue with original category
			h.logger.Warn("category classification failed, using original category",
				"original_category", finding.Category,
				"error", err)
		} else {
			// Update finding category with normalized value
			finding.Category = normalizedCategory

			// Add metadata about classification
			if finding.Metadata == nil {
				finding.Metadata = make(map[string]any)
			}
			finding.Metadata["original_category"] = originalCategory

			// Log normalization if category changed
			if normalizedCategory != originalCategory {
				h.logger.Info("normalized finding category",
					"original_category", originalCategory,
					"normalized_category", normalizedCategory,
					"finding_id", finding.ID.String())
			}
		}
	}

	// Propagate tenant identity onto the finding for defense-in-depth isolation.
	// This ensures the finding carries tenant provenance even if retrieved later
	// via a different code path. When TenantID is already set (e.g. agent
	// explicitly stamped it), we do not overwrite it.
	if finding.TenantID == "" && h.missionCtx.TenantID != "" {
		finding.TenantID = h.missionCtx.TenantID
	}

	h.logger.Info("submitting finding",
		"finding_id", finding.ID.String(),
		"title", finding.Title,
		"severity", finding.Severity,
		"confidence", finding.Confidence,
		"category", finding.Category,
		"tenant_id", finding.TenantID)

	// Store finding scoped by tenant and mission for defense-in-depth isolation.
	err := h.findingStore.Store(ctx, h.missionCtx.TenantID, h.missionCtx.ID, finding)
	if err != nil {
		h.logger.Error("failed to submit finding",
			"finding_id", finding.ID.String(),
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("findings.submissions", 1, map[string]string{
			"severity": string(finding.Severity),
			"status":   "failed",
		})

		return types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to submit finding",
			err,
		)
	}

	// Record success metrics
	h.metrics.RecordCounter("findings.submissions", 1, map[string]string{
		"severity": string(finding.Severity),
		"status":   "success",
	})
	h.metrics.RecordCounter("findings.by_severity", 1, map[string]string{
		"severity": string(finding.Severity),
	})

	h.logger.Debug("finding submitted successfully",
		"finding_id", finding.ID.String(),
		"title", finding.Title)

	// Emit finding event
	if h.eventLogger != nil {
		targetAsset := ""
		if finding.TargetID != nil {
			targetAsset = finding.TargetID.String()
		}
		h.eventLogger.Event(ctx, EventFinding, "finding submitted", FindingEventData{
			Severity:    string(finding.Severity),
			Title:       finding.Title,
			Confidence:  fmt.Sprintf("%.2f", finding.Confidence),
			TargetAsset: targetAsset,
		})
	}

	// Async store to GraphRAG knowledge graph (non-blocking)
	// This happens after local store succeeds to ensure findings are never lost
	// The finding reaches the knowledge graph via the World projection (ADR-0107):
	// SubmitFinding emits an agent.finding_submitted event → the brain folds it
	// into the tenant World as a Finding → the graph projector writes the :Finding
	// node. The old direct StoreAsync write was removed so the projector is the
	// sole writer of finding nodes (gibson#837). The canonical finding record is
	// still persisted above via findingStore (Postgres), independent of the graph.
	return nil
}

// GetFindings retrieves findings for the current mission, optionally filtered.
func (h *DefaultAgentHarness) GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GetFindings")
	defer span.End()

	h.logger.Debug("retrieving findings",
		"mission_id", h.missionCtx.ID.String())

	// Get findings from store scoped by tenant and mission.
	findings, err := h.findingStore.Get(ctx, h.missionCtx.TenantID, h.missionCtx.ID, filter)
	if err != nil {
		h.logger.Error("failed to get findings",
			"mission_id", h.missionCtx.ID.String(),
			"error", err)
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"failed to get findings",
			err,
		)
	}

	h.logger.Debug("findings retrieved",
		"mission_id", h.missionCtx.ID.String(),
		"count", len(findings))

	return findings, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Memory Access Methods
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Workspace Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Workspace returns the primary workspace for single-repository missions.
// This is a convenience method that returns the first workspace defined in the mission configuration.
// Returns nil if no workspaces are configured for this mission.
//
// Example:
//
//	ws := harness.Workspace()
//	if ws == nil {
//	    return errors.New("no workspace configured")
//	}
//	content, err := ws.ReadFile(ctx, "main.go")
func (h *DefaultAgentHarness) Workspace() workspace.Workspace {
	ctx, span := h.tracer.Start(context.Background(), "harness.Workspace")
	defer span.End()
	_ = ctx // Context used by tracer

	if h.workspaceManager == nil {
		h.logger.Debug("workspace manager not configured")
		return nil
	}

	ws := h.workspaceManager.Primary()
	if ws != nil {
		h.logger.Debug("returning primary workspace", "name", ws.Name(), "path", ws.Path())
	}
	return ws
}

// Workspaces returns all workspaces keyed by repository name.
// For multi-repository missions, use this to access specific workspaces by name.
// Returns an empty map if no workspaces are configured.
//
// Example:
//
//	workspaces := harness.Workspaces()
//	if ws, ok := workspaces["backend"]; ok {
//	    editor := ws.Editor()
//	    // Perform editing operations
//	}
func (h *DefaultAgentHarness) Workspaces() map[string]workspace.Workspace {
	ctx, span := h.tracer.Start(context.Background(), "harness.Workspaces")
	defer span.End()
	_ = ctx // Context used by tracer

	if h.workspaceManager == nil {
		h.logger.Debug("workspace manager not configured")
		return make(map[string]workspace.Workspace)
	}

	workspaces := h.workspaceManager.All()
	h.logger.Debug("returning all workspaces", "count", len(workspaces))
	return workspaces
}

// ────────────────────────────────────────────────────────────────────────────
// Context Access Methods
// ────────────────────────────────────────────────────────────────────────────

// Mission returns the current mission context.
func (h *DefaultAgentHarness) Mission() MissionContext {
	return h.missionCtx
}

// Target returns information about the current target.
func (h *DefaultAgentHarness) Target() TargetInfo {
	return h.targetInfo
}

// ForTarget returns a view that answers Target() with targetID and delegates
// everything else to h, so every scope reader — observationAttribution,
// SubmitProof, the destructive-authz callback — resolves the target this unit of
// work actually ran against.
//
// It delegates rather than copying the struct. A copy would duplicate
// inFlightTasksMu while sharing the inFlightTasks map it guards, so two
// harnesses would protect one map with two mutexes and the agent-concurrency
// quota would race. `go vet`'s copylocks says so, and it is right: the harness
// owns locked state, which makes it a thing to point at and not a thing to
// duplicate.
//
// Only the ID differs. The rest of TargetInfo describes the mission's primary
// and is not read for scope; a view that invented a name or a URL would be a
// second, wrong description of a target the daemon already has.
func (h *DefaultAgentHarness) ForTarget(targetID string) AgentHarness {
	return scopeToTarget(h, h.targetInfo, targetID)
}

// MissionID returns the mission ID for the current execution context.
func (h *DefaultAgentHarness) MissionID() types.ID {
	return h.missionCtx.ID
}

// ────────────────────────────────────────────────────────────────────────────
// Observability Methods
// ────────────────────────────────────────────────────────────────────────────

// Tracer returns the OpenTelemetry tracer for distributed tracing.
func (h *DefaultAgentHarness) Tracer() trace.Tracer {
	return h.tracer
}

// Logger returns the structured logger for this agent execution.
func (h *DefaultAgentHarness) Logger() *slog.Logger {
	return h.logger
}

// Metrics returns the metrics recorder for operational metrics.
func (h *DefaultAgentHarness) Metrics() MetricsRecorder {
	return h.metrics
}

// TokenUsage returns the token usage tracker for the current execution.
func (h *DefaultAgentHarness) TokenUsage() *llm.TokenTracker {
	return &h.tokenUsage
}

// ────────────────────────────────────────────────────────────────────────────
// Minimal agent.AgentHarness Interface Implementation
// ────────────────────────────────────────────────────────────────────────────

// Log implements the minimal agent.AgentHarness interface method.
// It writes a structured log message using the harness logger.
func (h *DefaultAgentHarness) Log(level, message string, fields map[string]any) {
	// One slog.Attr per field rather than an interleaved key, value, key,
	// value slice. Same output from slog, but the capacity is len(fields)
	// instead of len(fields)*2 — the multiplication read as a potential
	// integer overflow to static analysis — and it matches
	// MiddlewareHarness.Log, which already built its attrs this way
	// (gibson#1444).
	attrs := make([]any, 0, len(fields))
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}

	switch level {
	case "debug":
		h.logger.Debug(message, attrs...)
	case "info":
		h.logger.Info(message, attrs...)
	case "warn":
		h.logger.Warn(message, attrs...)
	case "error":
		h.logger.Error(message, attrs...)
	default:
		h.logger.Info(message, attrs...)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Mission Context Methods
// ────────────────────────────────────────────────────────────────────────────

// MissionExecutionContext returns comprehensive mission execution information.
// This includes run history, resume status, and memory continuity indicators
// to help agents make informed decisions based on mission history.
func (h *DefaultAgentHarness) MissionExecutionContext() MissionExecutionContextSDK {
	ctx := context.Background()

	// Try to get context from provider
	if h.contextProvider != nil {
		execCtx, err := h.contextProvider.GetContext(ctx)
		if err != nil {
			h.logger.Warn("failed to get mission execution context", "error", err)
			// Fall through to basic context
		} else {
			// Convert internal context to SDK type
			return convertToSDKContext(execCtx)
		}
	}

	// Return basic context from existing Mission() method
	m := h.Mission()
	return MissionExecutionContextSDK{
		MissionID:            m.ID.String(),
		MissionName:          m.Name,
		RunNumber:            1,
		IsResumed:            false,
		PreviousRunID:        "",
		PreviousRunStatus:    "",
		TotalFindingsAllRuns: 0,
		MemoryContinuity:     "first_run",
	}
}

// GetMissionRunHistory returns all runs for the current mission name.
// Results are ordered by run number descending (most recent first).
func (h *DefaultAgentHarness) GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetMissionRunHistory")
	defer span.End()

	if h.contextProvider == nil {
		// An absent provider is not "this mission has never run". Returning an
		// empty history would tell the agent there is no prior work, which it
		// cannot distinguish from a genuinely first run — the same silent false
		// negative GetRunFindings and WorldView were fixed for.
		return nil, fmt.Errorf("mission run history: no context provider wired: %w", ErrKnowledgeUnavailable)
	}

	runs, err := h.contextProvider.GetRunHistory(ctx)
	if err != nil {
		h.logger.Error("failed to get run history", "error", err)
		return nil, fmt.Errorf("failed to get mission run history: %w", err)
	}

	// Convert internal runs to SDK type
	result := make([]MissionRunSummarySDK, len(runs))
	for i, r := range runs {
		result[i] = convertToSDKRunSummary(r)
	}

	h.logger.Debug("retrieved mission run history", "count", len(result))
	return result, nil
}

// GetRunFindings retrieves findings from earlier runs of this mission.
//
// Replaces GetPreviousRunFindings and GetAllRunFindings: the scope is data, so a
// caller passes it through instead of branching before the call.
//
// An ABSENT SEAM IS AN ERROR, not an empty slice. The previous implementations
// returned []agent.Finding{}, nil when the context provider or finding store was
// missing, which an agent cannot tell from "this mission genuinely has no
// history" — it then reports a clean prior record for work nobody looked up. A
// mission with no previous run is different, and still answers empty.
func (h *DefaultAgentHarness) GetRunFindings(ctx context.Context, scope harnesspb.RunScope, filter FindingFilter) ([]agent.Finding, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetRunFindings")
	defer span.End()

	if h.contextProvider == nil {
		return nil, fmt.Errorf("run findings: mission context provider not wired: %w", ErrKnowledgeUnavailable)
	}
	if h.findingStore == nil {
		return nil, fmt.Errorf("run findings: finding store not wired: %w", ErrKnowledgeUnavailable)
	}

	var runs []*MissionRunSummary
	switch scope {
	case harnesspb.RunScope_RUN_SCOPE_PREVIOUS:
		prev, err := h.contextProvider.GetPreviousRun(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve previous run: %w", err)
		}
		if prev == nil {
			// No previous run is a real answer, not a missing seam.
			return []agent.Finding{}, nil
		}
		runs = []*MissionRunSummary{prev}
	case harnesspb.RunScope_RUN_SCOPE_UNSPECIFIED:
		return nil, errors.New("run findings: scope must be specified")
	case harnesspb.RunScope_RUN_SCOPE_ALL:
		all, err := h.contextProvider.GetRunHistory(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get run history: %w", err)
		}
		runs = all
	default:
		return nil, fmt.Errorf("run findings: scope %q is not valid", scope)
	}

	out := []agent.Finding{}
	for _, run := range runs {
		// Scope by tenant so historical reads cannot cross a tenant boundary.
		findings, err := h.findingStore.Get(ctx, h.missionCtx.TenantID, run.MissionID, filter)
		if err != nil {
			// One unreadable run must not silently shrink the answer: report it
			// rather than returning a partial history that looks complete.
			return nil, fmt.Errorf("failed to get findings for run %s: %w", run.MissionID.String(), err)
		}
		out = append(out, findings...)
	}

	h.logger.Debug("retrieved run findings", "scope", scope.String(), "runs", len(runs), "findings", len(out))
	return out, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Proto Resolution Methods
// ────────────────────────────────────────────────────────────────────────────

// Resolver returns the ProtoResolver used by this harness for dynamic type resolution.
// This resolver is used to convert between structpb.Struct and strongly-typed proto messages
// when tools use proto schemas not available in the global registry.
//
// Returns:
//   - protoresolver.ProtoResolver: The resolver instance, or nil if not configured
func (h *DefaultAgentHarness) Resolver() protoresolver.ProtoResolver {
	return h.resolver
}

// mintCGForWork mints a capability-grant JWT for a work-item dispatch.
// Returns "" when no minter is wired (test mode or pre-Phase-3
// daemons) — callers omit the workCtx entry rather than fail the
// dispatch. The allowed_rpcs list is the broad superset of methods
// agents typically need on harness callbacks; per-component scoping
// is a future iteration that needs the check-in declaration (ADR-0097)
// on this code path. Spec: Requirement 13.1, 13.2.
func (h *DefaultAgentHarness) mintCGForWork(componentName, kind string) string {
	if h.cgMinter == nil {
		return ""
	}
	tenant := h.missionCtx.TenantID
	if tenant == "" || h.missionCtx.MissionRunID == "" {
		return ""
	}
	// RecipientClass mirrors the dispatched component's kind ("tool" or
	// "plugin"). Required by the Mint deny check (non-plugin-secret-
	// isolation R4): an empty class fails closed for any secret-
	// resolution RPC. The current AllowedRPCs list does not include
	// such RPCs, so non-plugin recipients still mint successfully here;
	// the field is wired for forward compatibility with broader grants.
	// A tool or a plugin acts for the agent that dispatches it. The grant
	// carries that agent as a signed claim, and the daemon binds the
	// callbacks of the tool or the plugin to it.
	callingAgent := ""
	if kind != "agent" {
		callingAgent = h.missionCtx.CurrentAgent
	}
	tok, err := h.cgMinter.Mint(capabilitygrant.MintRequest{
		Subject:        "component:" + kind + ":" + componentName,
		CallingAgent:   callingAgent,
		Tenant:         tenant,
		MissionID:      h.missionCtx.ID.String(),
		TaskID:         h.missionCtx.MissionRunID,
		RecipientClass: kind,
		AllowedRPCs:    taskGrantAllowedRPCs(),
	})
	if err != nil {
		h.logger.Warn("failed to mint CG-JWT for work item; dispatching without CG-JWT",
			"component", componentName,
			"kind", kind,
			"error", err)
		return ""
	}
	return tok
}

// WithCGMinter wires a capability-grant minter so dispatched work
// items carry a CG-JWT in WorkItem.Context["capability_grant"]. Tests
// that don't exercise the CG-JWT path may leave this nil.
func (h *DefaultAgentHarness) WithCGMinter(m *capabilitygrant.Minter) *DefaultAgentHarness {
	h.cgMinter = m
	return h
}

// ────────────────────────────────────────────────────────────────────────────
// Lifecycle Methods
// ────────────────────────────────────────────────────────────────────────────

// Close releases resources held by the harness, including waiting for
// any pending async operations to complete.
//
// This method should be called when the harness is no longer needed, typically
// at the end of an agent's execution or when the mission is complete.
//
// Close performs the following cleanup:
//   - Waits for pending GraphRAG storage operations to complete
//   - Logs any shutdown errors at WARN level
//
// The context can be used to set a timeout for the shutdown.
func (h *DefaultAgentHarness) Close(_ context.Context) error {
	h.logger.Debug("closing harness")
	h.logger.Debug("harness closed successfully")
	return nil
}

// agentEgressCeiling returns the setec egress rules bounding the tool launches
// of the dispatching agent, from its platform-catalog egressAllow ceiling
// (ADR-0136). It returns nil when there is no dispatching agent, the agent is
// not a platform-catalog agent, or its manifest states no ceiling. The tool sandbox then
// takes the defaultNetworkMode of its SandboxClass. Tool sandbox isolation is
// unconditional regardless.
func agentEgressCeiling(agentName string) []sandboxed.EgressRule {
	if agentName == "" {
		return nil
	}
	allow, ok := componentcatalog.LookupEgress("agent", agentName)
	if !ok {
		return nil
	}
	return sandboxed.EgressRulesFromAllow(allow)
}

// resolveAgentStanding returns the dispatch gate inputs for delegating to the
// named agent (ADR-0110): where its code runs and how far the platform trusts
// it. Neither comes from what a registered instance reported. The third
// result reports whether a live instance is registered for the tenant.
//
//   - An instance whose principal enrolled with an attested identity runs in
//     the platform's cluster. If any live instance is attested, the agent
//     takes the trust the catalog states for its name, and no statement
//     means untrusted to the gate.
//   - If instances exist and none is attested, the agent runs on the tenant's
//     own machine and gets its work through the queue.
//   - With no registered instance, or with no component registry, the agent
//     has no standing here. Only a catalog manifest can then give it a
//     sandbox launch.
//
// It returns an error — meaning DENY the delegation — whenever the standing
// could not be established: a request carrying no tenant, or a registry
// lookup that failed. "We could not tell" has to deny.
func (h *DefaultAgentHarness) resolveAgentStanding(ctx context.Context, name string) (dispatchpolicy.Placement, componentpb.ContentTrust, bool, error) {
	const noTrust = componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED
	if h.componentRegistry == nil {
		return dispatchpolicy.PlacementCluster, noTrust, false, nil
	}
	tenant := auth.TenantStringFromContext(ctx)
	if tenant == "" {
		return dispatchpolicy.PlacementCluster, noTrust, false, errors.New("no tenant in context")
	}
	instances, err := h.componentRegistry.Discover(ctx, tenant, authz.KindAgent, name)
	if err != nil {
		return dispatchpolicy.PlacementCluster, noTrust, false, fmt.Errorf("component registry discover: %w", err)
	}
	if len(instances) == 0 {
		return dispatchpolicy.PlacementCluster, noTrust, false, nil
	}
	attested := false
	for _, info := range instances {
		if info.Attested {
			attested = true
			break
		}
	}
	placement, trust := component.DispatchStanding(attested, authz.KindAgent, name)
	return placement, trust, true, nil
}

// taskGrantAllowedRPCs is the callback surface a dispatched component's task
// grant may call: every HarnessCallbackService method except secret
// resolution (the minter refuses that for non-plugin recipients), plus the
// grant renewal RPC. Derived from the service descriptor so a new callback
// RPC (Observe, WorldView, QueryNodes, ... gibson#1603) is never left off
// a hand-kept list.
func taskGrantAllowedRPCs() []string {
	desc := harnesspb.HarnessCallbackService_ServiceDesc
	out := make([]string, 0, len(desc.Methods)+len(desc.Streams)+1)
	for _, m := range desc.Methods {
		if m.MethodName == "GetCredential" {
			continue
		}
		out = append(out, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	for _, st := range desc.Streams {
		out = append(out, "/"+desc.ServiceName+"/"+st.StreamName)
	}
	out = append(out, "/gibson.daemon.v1.DaemonService/RenewCapabilityGrant")
	return out
}
