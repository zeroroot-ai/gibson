package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/authz"
	"github.com/zeroroot-ai/gibson/internal/capabilitygrant"
	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/contextkeys"
	"github.com/zeroroot-ai/gibson/internal/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/memory"
	sdkqueue "github.com/zeroroot-ai/gibson/internal/queue"
	"github.com/zeroroot-ai/gibson/internal/tool"
	"github.com/zeroroot-ai/gibson/internal/types"
	componentpb "github.com/zeroroot-ai/sdk/api/gen/gibson/component/v1"
	graphragpb "github.com/zeroroot-ai/sdk/api/gen/gibson/graphrag/v1"
	missionv1 "github.com/zeroroot-ai/sdk/api/gen/gibson/mission/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"github.com/zeroroot-ai/sdk/codegen/workspace"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
	"github.com/zeroroot-ai/sdk/protoresolver"
	sdktypes "github.com/zeroroot-ai/sdk/types"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
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
	memoryStore  memory.MemoryManager
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

	// Knowledge graph integration
	graphRAGBridge      GraphRAGBridge
	graphRAGQueryBridge GraphRAGQueryBridge

	// Mission management (optional, nil = mission methods return error)
	missionClient MissionOperator
	spawnLimits   SpawnLimits

	// Event logging for structured observability
	eventLogger EventLogger

	// resolver provides dynamic proto type resolution for tool execution
	resolver protoresolver.ProtoResolver

	// checkpointAccess provides checkpoint operations (nil if checkpointing disabled)
	checkpointAccess CheckpointAccess

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

	// workQueue provides pull-based work dispatch over Redis Streams.
	// When non-nil, remote components discovered via componentRegistry (those without
	// a direct grpc_endpoint in their metadata) receive work items via this queue
	// rather than a direct gRPC call. Nil means use the existing path.
	workQueue component.WorkQueue

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

	// componentAccess enforces per-tenant opt-in control for platform (_system) plugins.
	// When non-nil and a QueryPlugin call finds no tenant-scoped instances, the harness
	// checks that the tenant has explicitly enabled the plugin and has a stored config
	// before dispatching to the _system instance. Nil disables access enforcement
	// (backward-compatible for deployments that have not yet wired this store).
	componentAccess component.ComponentAccessStore

	// maxDelegationDepth is the maximum allowed DelegateToAgent nesting depth.
	// When zero, defaultMaxDelegationDepth (8) is used. The daemon config flag
	// "harness.max_delegation_depth" can override this per deployment.
	maxDelegationDepth int

	// sandboxedExecutor dispatches tool calls into Setec microVM sandboxes
	// via gRPC. Consulted BEFORE any local/component-registry path in
	// CallToolProto; nil disables sandboxed dispatch entirely.
	sandboxedExecutor *sandboxed.Executor

	// toolRunnerEnabled gates the unified ComponentRegistry-driven
	// dispatch path. When true, CallToolProto looks up the tool in
	// ComponentRegistry first and dispatches by DispatchMode. When
	// false, the legacy sandboxed.Registry + ComponentRegistry dual
	// lookup is used. Flipped per deployment via tool_runner.enabled.
	toolRunnerEnabled bool

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

// getToolMetadata extracts metadata (including FileDescriptorSet) from a tool.
// Currently only the remote gRPC tool client carries metadata; in-process
// tools return nil.
func getToolMetadata(t tool.Tool) map[string]string {
	if grpcClient, ok := t.(*component.GRPCToolClient); ok {
		if md := grpcClient.Metadata(); md != nil {
			return md
		}
	}
	return nil
}

// CallToolProto executes a tool using proto message input/output.
//
// Dispatch order:
//  1. Sandboxed executor — when the tool is registered in the Sandboxed tool
//     registry, the call is dispatched into a Setec microVM via gRPC.
//  2. ComponentRegistry (Redis-backed, tenant-scoped) — if configured:
//     a. Component has grpc_endpoint metadata → call directly via registryAdapter
//     b. No grpc_endpoint → enqueue work via WorkQueue and wait for result
//  3. RegistryAdapter fallback — used when ComponentRegistry is not configured
//     or returned no instances (e.g. tools registered directly without
//     ComponentService).
//
// All dispatch paths route to out-of-process tool implementations. Tools are
// never compiled into the Gibson daemon.
func (h *DefaultAgentHarness) CallToolProto(ctx context.Context, name string, request proto.Message, response proto.Message) error {
	callStart := time.Now()
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

	// ── Unified ComponentRegistry dispatch ────────────────────────────────
	// Single lookup; route by dispatch_mode. DispatchMode=SANDBOXED entries
	// dispatch via SandboxedExecutor with per-call ToolSpec sourced from the
	// entry; plugin/agent entries fall through to the existing gRPC dispatch
	// paths below.
	if h.componentRegistry != nil {
		if spec, _, found, err := h.lookupSandboxedToolSpec(ctx, name); err != nil {
			h.logger.Warn("component registry sandboxed lookup errored, falling through",
				"tool", name, "error", err)
		} else if found {
			if h.sandboxedExecutor == nil {
				return types.WrapError(types.SANDBOX_TOOL_NOT_REGISTERED,
					fmt.Sprintf("tool %q dispatch_mode=SANDBOXED but no sandboxed executor wired", name), nil)
			}
			return h.sandboxedExecutor.ExecuteWithSpec(ctx, name, spec, request, response)
		}
	}

	var t tool.Tool

	// ── Path 2: ComponentRegistry (Redis-backed, tenant-scoped) ──────────────
	if h.componentRegistry != nil {
		tenant := auth.TenantStringFromContext(ctx)
		if tenant == "" {
			h.logger.Warn("component registry configured but no tenant in context, skipping registry lookup",
				"tool", name)
		} else {
			instances, discErr := h.componentRegistry.Discover(ctx, tenant, "tool", name)
			if discErr != nil {
				h.logger.Warn("component registry discovery failed, falling back to registry adapter",
					"tool", name,
					"tenant", tenant,
					"error", discErr)
			} else if len(instances) > 0 {
				info := instances[0] // Use first live instance; load-balancing is a future concern.

				// Determine routing: does this instance expose a direct gRPC endpoint?
				grpcEndpoint := info.Metadata["grpc_endpoint"]
				if grpcEndpoint != "" && h.registryAdapter != nil {
					// In-cluster tool with a direct gRPC endpoint — use the existing gRPC pool path.
					h.logger.Debug("component registry: routing tool call via direct gRPC endpoint",
						"tool", name,
						"tenant", tenant,
						"endpoint", grpcEndpoint,
						"instance_id", info.InstanceID,
						"discovery", "component_registry")

					remoteTool, adapterErr := h.registryAdapter.DiscoverTool(ctx, name)
					if adapterErr != nil {
						h.logger.Warn("component registry directed to gRPC but adapter discovery failed, falling through",
							"tool", name,
							"endpoint", grpcEndpoint,
							"error", adapterErr)
						// Fall through to the legacy adapter path below.
					} else {
						t = remoteTool
						goto executeProto
					}
				} else if h.workQueue != nil {
					// Remote component registered via ComponentService — dispatch via WorkQueue.
					h.logger.Debug("component registry: routing tool call via work queue",
						"tool", name,
						"tenant", tenant,
						"instance_id", info.InstanceID,
						"discovery", "component_registry")

					return h.callToolViaWorkQueue(ctx, tenant, name, request, response, info)
				} else {
					h.logger.Warn("component registry found tool but no work queue configured, falling back",
						"tool", name,
						"tenant", tenant,
						"instance_id", info.InstanceID)
					// Fall through to legacy adapter path.
				}
			}
		}
	}

	// ── Path 3: RegistryAdapter fallback ─────────────────────────────────────
	// Reached when ComponentRegistry is not configured, returned no instances,
	// or had no work queue available. RegistryAdapter is Redis-backed and covers
	// tools that registered directly (e.g. in-cluster gRPC tools with grpc_endpoint
	// but no ComponentService registration).
	{
		if h.registryAdapter != nil {
			h.logger.Debug("tool not found locally or via component registry, attempting registry adapter discovery",
				"tool", name,
				"discovery", "registry_adapter")

			remoteTool, discErr := h.registryAdapter.DiscoverTool(ctx, name)
			if discErr != nil {
				h.logger.Error("tool not found (component registry or registry adapter)",
					"tool", name,
					"discovery_error", discErr)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("tool not found: %s (%v)", name, discErr),
					discErr,
				)
			}

			t = remoteTool
			h.logger.Debug("discovered tool via registry adapter",
				"tool", name,
				"version", remoteTool.Version(),
				"discovery", "registry_adapter")
		} else {
			h.logger.Error("tool not found and no discovery path available", "tool", name)
			return types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("tool not found: %s (no discovery path)", name),
				nil,
			)
		}
	}

executeProto:

	// Check if tool supports proto execution by type assertion
	// The SDK tool.Tool interface has proto methods, but internal tool.Tool does not
	type protoTool interface {
		InputMessageType() string
		OutputMessageType() string
		ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error)
	}

	protoT, ok := t.(protoTool)
	if !ok {
		// Tool doesn't support proto - this is an error
		h.logger.Error("tool does not support proto execution",
			"tool", name)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool %s does not support proto execution (use CallTool instead)", name),
			nil,
		)
	}

	inputType := protoT.InputMessageType()
	outputType := protoT.OutputMessageType()

	if inputType == "" || outputType == "" {
		// Tool doesn't support proto - this is an error
		h.logger.Error("tool does not support proto execution",
			"tool", name,
			"input_type", inputType,
			"output_type", outputType)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool %s does not support proto execution (use CallTool instead)", name),
			nil,
		)
	}

	// Verify message types match
	expectedInputType := string(request.ProtoReflect().Descriptor().FullName())
	expectedOutputType := string(response.ProtoReflect().Descriptor().FullName())

	// Note: inputType and outputType from tool might be in format "package.Message"
	// while proto reflection gives "package.Message" - they should match
	//
	// However, agents using the SDK structpb fallback will send google.protobuf.Struct
	// when the tool expects a specific proto type. In this case, we need to convert
	// the Struct to the tool's expected type using the ProtoResolver.
	actualRequest := request
	if inputType != expectedInputType {
		// Check if the request is a structpb.Struct that needs conversion
		if structInput, ok := request.(*structpb.Struct); ok && expectedInputType == "google.protobuf.Struct" {
			h.logger.Debug("converting structpb.Struct input to typed message",
				"tool", name,
				"target_type", inputType)

			// Get tool metadata for resolver
			toolMetadata := getToolMetadata(t)
			if toolMetadata == nil {
				h.logger.Error("tool has no metadata for input conversion",
					"tool", name,
					"expected", inputType)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("cannot convert input: tool %s has no metadata", name),
					nil,
				)
			}

			// Convert Struct to JSON
			marshaler := protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}
			jsonBytes, err := marshaler.Marshal(structInput)
			if err != nil {
				h.logger.Error("failed to marshal struct input",
					"tool", name,
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert input: %v", err),
					err,
				)
			}

			// Log the JSON being converted (INFO level for debugging)
			h.logger.Info("converting structpb.Struct to typed message via resolver",
				"tool", name,
				"target_type", inputType,
				"json", string(jsonBytes))

			// Use resolver to unmarshal JSON into typed proto message
			dynamicMsg, err := h.resolver.UnmarshalProtoJSON(ctx, inputType, jsonBytes, toolMetadata)
			if err != nil {
				h.logger.Error("failed to unmarshal input to typed message via resolver",
					"tool", name,
					"target_type", inputType,
					"json", string(jsonBytes),
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert input to %s: %v", inputType, err),
					err,
				)
			}

			h.logger.Debug("successfully converted structpb.Struct to typed message via resolver",
				"tool", name,
				"target_type", inputType)

			// Use the converted message
			actualRequest = dynamicMsg
		} else {
			h.logger.Error("input message type mismatch",
				"tool", name,
				"expected", inputType,
				"provided", expectedInputType)
			return types.WrapError(
				ErrHarnessToolExecutionFailed,
				fmt.Sprintf("input message type mismatch: tool expects %s, got %s", inputType, expectedInputType),
				nil,
			)
		}
	}

	// Determine if tool is local or remote for logging
	isRemote := false
	if h.registryAdapter != nil {
		// Check if tool implements registry gRPC client (remote)
		if _, ok := t.(*component.GRPCToolClient); ok {
			isRemote = true
		}
	}

	// Emit tool call event
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventToolCall, "tool call", ToolCallEventData{
			ToolName: name,
		})
	}

	// Execute tool with proto messages (using actualRequest which may be converted)
	outputMsg, err := protoT.ExecuteProto(ctx, actualRequest)

	if err != nil {
		h.logger.Error("tool execution failed",
			"tool", name,
			"remote", isRemote,
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("tools.executions", 1, map[string]string{
			"tool":   name,
			"remote": fmt.Sprintf("%t", isRemote),
			"status": "failed",
			"mode":   "proto",
		})

		durationMs := time.Since(callStart).Milliseconds()
		span.SetAttributes(
			attribute.Int64("tool.duration_ms", durationMs),
			attribute.String("tool.status", "error"),
		)
		span.RecordError(err)
		span.SetStatus(otelcodes.Error, "tool execution failed")

		// Emit tool result event (failure)
		if h.eventLogger != nil {
			h.eventLogger.Event(ctx, EventToolResult, "tool result", ToolResultEventData{
				ToolName: name,
				Success:  false,
				Error:    err.Error(),
			})
		}

		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("tool execution failed: %s", name),
			err,
		)
	}

	// Verify output type matches - or convert if necessary
	actualOutputType := string(outputMsg.ProtoReflect().Descriptor().FullName())
	if actualOutputType != expectedOutputType {
		// Check if the output is a structpb.Struct that needs conversion to typed message
		// This happens when tools return generic JSON via subprocess execution
		if structOutput, ok := outputMsg.(*structpb.Struct); ok && actualOutputType == "google.protobuf.Struct" {
			h.logger.Debug("converting structpb.Struct output to typed message",
				"tool", name,
				"target_type", expectedOutputType)

			// Convert Struct to JSON, then unmarshal into the response message
			marshaler := protojson.MarshalOptions{
				UseProtoNames:   true,
				EmitUnpopulated: false,
			}
			jsonBytes, err := marshaler.Marshal(structOutput)
			if err != nil {
				h.logger.Error("failed to marshal struct output",
					"tool", name,
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert tool output: %v", err),
					err,
				)
			}

			// Unmarshal JSON into the typed response message
			unmarshaler := protojson.UnmarshalOptions{
				DiscardUnknown: true,
			}
			if err := unmarshaler.Unmarshal(jsonBytes, response); err != nil {
				h.logger.Error("failed to unmarshal output to typed message",
					"tool", name,
					"target_type", expectedOutputType,
					"error", err)
				return types.WrapError(
					ErrHarnessToolExecutionFailed,
					fmt.Sprintf("failed to convert tool output to %s: %v", expectedOutputType, err),
					err,
				)
			}

			// Skip the normal merge since we've directly populated the response
			goto metricsSuccess
		}

		h.logger.Error("output message type mismatch",
			"tool", name,
			"expected", expectedOutputType,
			"actual", actualOutputType)
		return types.WrapError(
			ErrHarnessToolExecutionFailed,
			fmt.Sprintf("output message type mismatch: expected %s, got %s", expectedOutputType, actualOutputType),
			nil,
		)
	}

	// Merge the output message into the response parameter
	proto.Merge(response, outputMsg)

metricsSuccess:

	// Record success metrics
	h.metrics.RecordCounter("tools.executions", 1, map[string]string{
		"tool":   name,
		"remote": fmt.Sprintf("%t", isRemote),
		"status": "success",
		"mode":   "proto",
	})

	h.logger.Debug("tool execution successful with proto",
		"tool", name,
		"remote", isRemote)

	durationMs := time.Since(callStart).Milliseconds()
	span.SetAttributes(
		attribute.Int64("tool.duration_ms", durationMs),
		attribute.String("tool.status", "success"),
	)
	span.SetStatus(otelcodes.Ok, "tool execution successful")

	// Emit tool result event (success)
	if h.eventLogger != nil {
		h.eventLogger.Event(ctx, EventToolResult, "tool result", ToolResultEventData{
			ToolName: name,
			Success:  true,
		})
	}

	return nil
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
//   - The component has no grpc_endpoint metadata (pull-based remote component), AND
//   - A WorkQueue is configured on the harness.
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
	resultBytes, err := h.dispatchWorkAndWait(ctx, tenant, "tool", name, "execute_proto", inputJSON, nil, info)
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
	resultBytes, err := h.dispatchWorkAndWait(ctx, tenant, "plugin", name, "query_plugin", payload, map[string]string{"method": method}, info)
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

	result, err := h.workQueue.WaitForResult(ctx, workID, h.workQueueWaitTimeout())
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

	// ── Child mission context ────────────────────────────────────────────────
	// Copy the parent mission context, then update the fields that are
	// child-specific. CurrentAgent is updated (existing behaviour preserved).
	childMissionCtx := h.missionCtx
	childMissionCtx.CurrentAgent = name
	childMissionCtx.DelegationDepth = currentDepth + 1
	// Per-node slot overrides are node-specific — do NOT inherit the parent's
	// overrides. Instead, apply the overrides carried by this task (set by the
	// orchestrator for the executing agent node). Nil means no override for this
	// execution, which preserves pre-#539 fall-through behavior.
	// Spec: per-node-slot-override (gibson#539).
	childMissionCtx.NodeSlotOverrides = task.SlotOverrides

	// Create child harness for the sub-agent
	childHarness, err := h.factory(ctx, childMissionCtx, h.targetInfo)
	if err != nil {
		h.logger.Error("failed to create child harness",
			"agent", name,
			"error", err)
		return agent.Result{}, types.WrapError(
			ErrHarnessDelegationFailed,
			"failed to create child harness",
			err,
		)
	}

	// Convert harness.AgentHarness to agent.AgentHarness
	// DefaultAgentHarness implements both interfaces, so this is a type assertion
	agentHarness, ok := childHarness.(agent.AgentHarness)
	if !ok {
		h.logger.Error("child harness does not implement agent.AgentHarness",
			"agent", name)
		return agent.Result{}, types.NewError(
			ErrHarnessDelegationFailed,
			"child harness does not implement agent.AgentHarness",
		)
	}

	// Use registry adapter for delegation
	if h.registryAdapter == nil {
		h.logger.Error("no registry adapter available for delegation", "agent", name)
		return agent.Result{}, types.NewError(
			ErrHarnessDelegationFailed,
			"registry adapter not configured for agent delegation",
		)
	}

	h.logger.Debug("using registry adapter for delegation", "agent", name)

	// Concurrent_agents quota: per-agent inFlightTasks bookkeeping.
	// 0 → 1 transition fires INCR; the deferred 1 → 0 transition fires
	// DECR. nil quotaCounter disables the path entirely. Spec
	// plans-and-quotas-simplification.
	if h.quotaCounter != nil {
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
		defer func() {
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
		}()
	}

	result, err := h.registryAdapter.DelegateToAgent(ctx, name, task, agentHarness)

	if err != nil {
		h.logger.Error("agent execution failed",
			"agent", name,
			"task_id", task.ID.String(),
			"error", err)

		// Record failure metrics
		h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
			"agent":  name,
			"status": "failed",
		})

		return result, types.WrapError(
			ErrHarnessDelegationFailed,
			fmt.Sprintf("agent execution failed: %s", name),
			err,
		)
	}

	// ── DELEGATED_TO relationship ────────────────────────────────────────────
	// Write the DELEGATED_TO edge from the parent agent_run to the child
	// agent_run so that the knowledge graph reflects the full delegation tree.
	// The child run ID is read from the child harness's mission context (not
	// childMissionCtx, which is a value copy). The factory may assign a new
	// AgentRunID inside the child; we retrieve it via a type assertion.
	//
	// Both run IDs must be non-empty, and a GraphRAG query bridge must be
	// available; otherwise we log a warning and continue (non-fatal).
	var childRunID string
	if dah, ok := childHarness.(*DefaultAgentHarness); ok {
		childRunID = dah.missionCtx.AgentRunID
	} else {
		// If childHarness is wrapped by middleware, fall back to the ID that
		// was in childMissionCtx before the factory ran.
		childRunID = childMissionCtx.AgentRunID
	}
	if parentRunID != "" && childRunID != "" && h.graphRAGQueryBridge != nil {
		rel := sdkgraphrag.NewRelationship(parentRunID, childRunID, "DELEGATED_TO")
		if relErr := h.graphRAGQueryBridge.CreateRelationship(ctx, *rel); relErr != nil {
			h.logger.Warn("failed to write DELEGATED_TO relationship",
				"parent_run_id", parentRunID,
				"child_run_id", childRunID,
				"error", relErr)
		}
	} else if parentRunID != "" && childRunID == "" {
		h.logger.Debug("skipping DELEGATED_TO edge: child agent_run_id not set on mission context",
			"parent_run_id", parentRunID,
			"agent", name)
	}

	// Submit findings from sub-agent to our finding store
	for _, finding := range result.Findings {
		err := h.SubmitFinding(ctx, finding)
		if err != nil {
			h.logger.Warn("failed to submit sub-agent finding",
				"agent", name,
				"finding", finding.Title,
				"error", err)
		}
	}

	// Record success metrics
	h.metrics.RecordCounter("agents.delegations", 1, map[string]string{
		"agent":  name,
		"status": "success",
	})
	h.metrics.RecordCounter("agents.findings_from_delegation", int64(len(result.Findings)), map[string]string{
		"agent": name,
	})

	h.logger.Info("agent execution completed",
		"agent", name,
		"task_id", task.ID.String(),
		"status", result.Status,
		"findings_count", len(result.Findings))

	return result, nil
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
	// The finding reaches the knowledge graph via the World projection (ADR-0007):
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

// Memory provides access to the unified memory store.
func (h *DefaultAgentHarness) Memory() memory.MemoryStore {
	return h.memoryStore
}

// Checkpoint provides access to the checkpointing system for state management.
// Returns a no-op implementation if checkpointing is not configured.
func (h *DefaultAgentHarness) Checkpoint() CheckpointAccess {
	if h.checkpointAccess == nil {
		// Return a disabled checkpoint access implementation
		return NewHarnessCheckpointMethods(nil, "", "", 0)
	}
	return h.checkpointAccess
}

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
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, k, v)
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
// GraphRAG Query Methods
// ────────────────────────────────────────────────────────────────────────────

// sdkNodeToProto converts an SDK GraphNode to proto GraphNode
func sdkNodeToProto(sdkNode sdkgraphrag.GraphNode) (*graphragpb.GraphNode, error) {
	// Type is now a string field
	nodeType := sdkNode.Type

	// Convert map[string]any to map[string]*graphragpb.Value
	properties := make(map[string]*graphragpb.Value)
	for k, v := range sdkNode.Properties {
		properties[k] = anyToGraphragpbValue(v)
	}

	node := &graphragpb.GraphNode{
		Id:         sdkNode.ID,
		Type:       nodeType,
		Content:    sdkNode.Content,
		Properties: properties,
	}

	return node, nil
}

// anyToGraphragpbValue converts any to a graphragpb.Value.
func anyToGraphragpbValue(v any) *graphragpb.Value {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return &graphragpb.Value{Kind: &graphragpb.Value_StringValue{StringValue: val}}
	case int:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: int64(val)}}
	case int32:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: int64(val)}}
	case int64:
		return &graphragpb.Value{Kind: &graphragpb.Value_IntValue{IntValue: val}}
	case float32:
		return &graphragpb.Value{Kind: &graphragpb.Value_DoubleValue{DoubleValue: float64(val)}}
	case float64:
		return &graphragpb.Value{Kind: &graphragpb.Value_DoubleValue{DoubleValue: val}}
	case bool:
		return &graphragpb.Value{Kind: &graphragpb.Value_BoolValue{BoolValue: val}}
	case []byte:
		return &graphragpb.Value{Kind: &graphragpb.Value_BytesValue{BytesValue: val}}
	default:
		return &graphragpb.Value{Kind: &graphragpb.Value_StringValue{StringValue: fmt.Sprintf("%v", val)}}
	}
}

// ────────────────────────────────────────────────────────────────────────────
// GraphRAG Storage Methods
// ────────────────────────────────────────────────────────────────────────────

// StoreNode stores a graph node using proto messages.
// This is the preferred method for storing nodes with explicit proto schemas.
func (h *DefaultAgentHarness) StoreNode(ctx context.Context, node *graphragpb.GraphNode) (string, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.StoreNode")
	defer span.End()

	h.logger.Debug("storing graph node (proto)",
		"node_type", node.Type)

	// Convert proto node to SDK GraphNode
	sdkNode, err := protoNodeToSDK(node)
	if err != nil {
		h.logger.Error("failed to convert proto node to SDK node",
			"error", err)
		return "", fmt.Errorf("failed to convert proto node: %w", err)
	}

	// Delegate to existing StoreGraphNode implementation
	nodeID, err := h.StoreGraphNode(ctx, *sdkNode)
	if err != nil {
		h.logger.Error("store graph node (proto) failed",
			"node_type", node.Type,
			"error", err)
		return "", err
	}

	h.logger.Debug("store graph node (proto) completed",
		"node_id", nodeID)

	return nodeID, nil
}

// protoNodeToSDK converts a proto GraphNode to SDK GraphNode
func protoNodeToSDK(protoNode *graphragpb.GraphNode) (*sdkgraphrag.GraphNode, error) {
	if protoNode == nil {
		return nil, fmt.Errorf("proto node is nil")
	}

	// Convert node type enum to string
	nodeType := protoNode.Type
	// Remove the "NODE_TYPE_" prefix that proto enums have
	if len(nodeType) > 10 && nodeType[:10] == "NODE_TYPE_" {
		nodeType = nodeType[10:]
	}

	// Convert map[string]string to map[string]any
	properties := make(map[string]any)
	for k, v := range protoNode.Properties {
		properties[k] = v
	}

	// Create SDK node (no ID field in proto, will be generated by storage)
	node := &sdkgraphrag.GraphNode{
		Type:       nodeType,
		Content:    protoNode.Content,
		Properties: properties,
	}

	return node, nil
}

// StoreGraphNode stores an arbitrary node in the knowledge graph.
func (h *DefaultAgentHarness) StoreGraphNode(ctx context.Context, node sdkgraphrag.GraphNode) (string, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.StoreGraphNode")
	defer span.End()

	h.logger.Debug("storing graph node",
		"node_type", node.Type)

	// Delegate to query bridge with mission and agent context
	nodeID, err := h.graphRAGQueryBridge.StoreNode(ctx, node, h.missionCtx.ID.String(), h.missionCtx.CurrentAgent)
	if err != nil {
		h.logger.Error("store graph node failed",
			"node_type", node.Type,
			"error", err)
		return "", err
	}

	h.logger.Debug("store graph node completed",
		"node_id", nodeID)

	return nodeID, nil
}

// CreateGraphRelationship creates a relationship between two existing nodes.
func (h *DefaultAgentHarness) CreateGraphRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.CreateGraphRelationship")
	defer span.End()

	h.logger.Debug("creating graph relationship",
		"relationship_type", rel.Type,
		"from_id", rel.FromID,
		"to_id", rel.ToID)

	// Delegate to query bridge
	err := h.graphRAGQueryBridge.CreateRelationship(ctx, rel)
	if err != nil {
		h.logger.Error("create graph relationship failed",
			"relationship_type", rel.Type,
			"error", err)
		return err
	}

	h.logger.Debug("create graph relationship completed")

	return nil
}

// StoreGraphBatch stores multiple nodes and relationships atomically.
func (h *DefaultAgentHarness) StoreGraphBatch(ctx context.Context, batch sdkgraphrag.Batch) ([]string, error) {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.StoreGraphBatch")
	defer span.End()

	h.logger.Debug("storing graph batch",
		"nodes_count", len(batch.Nodes),
		"relationships_count", len(batch.Relationships))

	// Delegate to query bridge with mission and agent context
	nodeIDs, err := h.graphRAGQueryBridge.StoreBatch(ctx, batch, h.missionCtx.ID.String(), h.missionCtx.CurrentAgent)
	if err != nil {
		h.logger.Error("store graph batch failed",
			"error", err)
		return nil, err
	}

	h.logger.Debug("store graph batch completed",
		"node_ids_count", len(nodeIDs))

	return nodeIDs, nil
}

// GraphRAGHealth returns the health status of the GraphRAG subsystem.
func (h *DefaultAgentHarness) GraphRAGHealth(ctx context.Context) types.HealthStatus {
	// Create span for distributed tracing
	ctx, span := h.tracer.Start(ctx, "harness.GraphRAGHealth")
	defer span.End()

	// Delegate to query bridge (GraphRAG is always required)
	status := h.graphRAGQueryBridge.Health(ctx)

	h.logger.Debug("graphrag health check completed",
		"state", status.State,
		"message", status.Message)

	return status
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
		h.logger.Debug("mission context provider not available")
		return []MissionRunSummarySDK{}, nil
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

// GetPreviousRunFindings retrieves findings from the previous mission run.
// This enables agents to understand what was discovered in prior attempts.
func (h *DefaultAgentHarness) GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetPreviousRunFindings")
	defer span.End()

	if h.contextProvider == nil {
		h.logger.Debug("mission context provider not available")
		return []agent.Finding{}, nil
	}

	prevRun, err := h.contextProvider.GetPreviousRun(ctx)
	if err != nil || prevRun == nil {
		h.logger.Debug("no previous run available")
		return []agent.Finding{}, nil // No previous run
	}

	// Use the finding store to retrieve findings
	if h.findingStore == nil {
		h.logger.Warn("finding store not available")
		return []agent.Finding{}, nil
	}

	// Scope by tenant to prevent cross-tenant access to historical findings.
	findings, err := h.findingStore.Get(ctx, h.missionCtx.TenantID, prevRun.MissionID, filter)
	if err != nil {
		h.logger.Error("failed to get previous run findings",
			"previous_run_id", prevRun.MissionID.String(),
			"error", err)
		return nil, fmt.Errorf("failed to get previous run findings: %w", err)
	}

	h.logger.Debug("retrieved previous run findings",
		"previous_run_id", prevRun.MissionID.String(),
		"count", len(findings))
	return findings, nil
}

// GetAllRunFindings retrieves findings from all runs of this mission.
// This provides complete historical context across all mission executions.
func (h *DefaultAgentHarness) GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error) {
	ctx, span := h.tracer.Start(ctx, "AgentHarness.GetAllRunFindings")
	defer span.End()

	if h.contextProvider == nil {
		h.logger.Debug("mission context provider not available")
		return []agent.Finding{}, nil
	}

	if h.findingStore == nil {
		h.logger.Warn("finding store not available")
		return []agent.Finding{}, nil
	}

	// Get all runs for this mission
	runs, err := h.contextProvider.GetRunHistory(ctx)
	if err != nil {
		h.logger.Error("failed to get run history", "error", err)
		return nil, fmt.Errorf("failed to get run history: %w", err)
	}

	// Collect all findings from all runs
	var allFindings []agent.Finding
	for _, run := range runs {
		// Scope by tenant to prevent cross-tenant access across historical runs.
		findings, err := h.findingStore.Get(ctx, h.missionCtx.TenantID, run.MissionID, filter)
		if err != nil {
			h.logger.Warn("failed to get findings for run",
				"run_id", run.MissionID.String(),
				"error", err)
			continue // Skip this run but continue with others
		}

		allFindings = append(allFindings, findings...)
	}

	h.logger.Debug("retrieved findings from all runs",
		"total_runs", len(runs),
		"total_findings", len(allFindings))
	return allFindings, nil
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
// agents typically need on harness callbacks; per-component-yaml
// scoping is a future iteration that requires the manifest to be
// loaded by this code path. Spec: Requirement 13.1, 13.2.
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
	tok, err := h.cgMinter.Mint(capabilitygrant.MintRequest{
		Subject:        "component:" + kind + ":" + componentName,
		Tenant:         tenant,
		MissionID:      h.missionCtx.ID.String(),
		TaskID:         h.missionCtx.MissionRunID,
		RecipientClass: kind,
		AllowedRPCs: []string{
			"/gibson.harness.v1.HarnessCallbackService/LLMComplete",
			"/gibson.harness.v1.HarnessCallbackService/LLMCompleteWithTools",
			"/gibson.harness.v1.HarnessCallbackService/LLMStream",
			"/gibson.harness.v1.HarnessCallbackService/LLMCompleteStructured",
			"/gibson.harness.v1.HarnessCallbackService/MemoryGet",
			"/gibson.harness.v1.HarnessCallbackService/MemorySet",
			"/gibson.harness.v1.HarnessCallbackService/MemoryDelete",
			"/gibson.harness.v1.HarnessCallbackService/SubmitFinding",
			"/gibson.harness.v1.HarnessCallbackService/CallToolProto",
			"/gibson.harness.v1.HarnessCallbackService/QueryPlugin",
			"/gibson.harness.v1.HarnessCallbackService/GraphRAGQuery",
			"/gibson.daemon.v1.DaemonService/RenewCapabilityGrant",
		},
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
func (h *DefaultAgentHarness) Close(ctx context.Context) error {
	h.logger.Debug("closing harness")

	// Shutdown GraphRAG bridge and wait for pending operations
	if h.graphRAGBridge != nil {
		if err := h.graphRAGBridge.Shutdown(ctx); err != nil {
			h.logger.Warn("graphrag bridge shutdown error",
				"error", err)
			return err
		}
	}

	h.logger.Debug("harness closed successfully")
	return nil
}

// lookupSandboxedToolSpec resolves a tool name against the ComponentRegistry
// as a sandboxed entry. Returns (spec, trust, true, nil) when an entry exists
// with DispatchMode=SANDBOXED; (_, _, false, nil) when no sandboxed entry is
// registered; and (_, _, _, err) only on a Redis/registry failure. The
// ContentTrust value is used by the dispatch policy gate before executor
// selection. Used by the unified dispatch path in CallToolProto.
func (h *DefaultAgentHarness) lookupSandboxedToolSpec(ctx context.Context, name string) (sandboxed.ToolSpec, componentpb.ContentTrust, bool, error) {
	// Sandboxed tool entries are written under the _system tenant so
	// every caller can discover them regardless of their own tenant.
	instances, err := h.componentRegistry.DiscoverSystemOnly(ctx, "tool", name)
	if err != nil {
		return sandboxed.ToolSpec{}, componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED, false, err
	}
	for _, info := range instances {
		if info.DispatchMode != componentpb.DispatchMode_DISPATCH_MODE_SANDBOXED {
			continue
		}
		spec := sandboxed.ToolSpec{
			Image:   info.Image,
			Command: append([]string(nil), info.Command...),
			Env:     copyStringMap(info.Env),
			VCPU:    info.Resources.VCPU,
			Memory:  info.Resources.Memory,
		}
		return spec, info.ContentTrust, true, nil
	}
	return sandboxed.ToolSpec{}, componentpb.ContentTrust_CONTENT_TRUST_UNSPECIFIED, false, nil
}

// copyStringMap returns a defensive copy of a string-to-string map so the
// returned ToolSpec is independent of the ComponentInfo reference.
func copyStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
