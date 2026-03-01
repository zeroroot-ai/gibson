package harness

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/harness/middleware"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/plugin"
	"github.com/zero-day-ai/gibson/internal/registry"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// HarnessConfig contains all dependencies needed to create an AgentHarness.
// All fields use interface types to support dependency injection and testing.
//
// The configuration follows dependency injection principles, allowing callers
// to provide mock implementations for testing or custom implementations for
// production deployments.
//
// Required fields:
//   - SlotManager: Required for LLM slot resolution and provider selection
//
// Optional fields (will use defaults if nil):
//   - LLMRegistry: Uses empty registry if nil (no providers available)
//   - ToolRegistry: Uses empty registry if nil (no tools available)
//   - PluginRegistry: Uses empty registry if nil (no plugins available)
//   - MemoryManager: Uses in-memory implementation if nil
//   - Tracer: Uses no-op tracer if nil
//   - Logger: Uses default slog logger if nil
//   - FindingStore: Uses InMemoryFindingStore if nil
//   - Metrics: Uses NoOpMetricsRecorder if nil
//   - GraphRAGBridge: Uses NoopGraphRAGBridge if nil (no knowledge graph storage)
type HarnessConfig struct {
	// LLMRegistry provides access to registered LLM providers.
	// Used for LLM completion operations (Complete, CompleteWithTools, Stream).
	// Optional: defaults to empty registry (no providers available).
	LLMRegistry llm.LLMRegistry

	// SlotManager resolves slot names to provider configurations.
	// Required for translating agent slot definitions into concrete provider/model pairs.
	// This is the only required field - harness creation will fail if nil.
	SlotManager llm.SlotManager

	// ToolRegistry provides access to registered tools.
	// Used for tool execution operations (CallTool, ListTools).
	// Optional: defaults to empty registry (no tools available).
	ToolRegistry tool.ToolRegistry

	// PluginRegistry provides access to registered plugins.
	// Used for plugin query operations (QueryPlugin, ListPlugins).
	// Optional: defaults to empty registry (no plugins available).
	PluginRegistry plugin.PluginRegistry

	// RegistryAdapter provides unified component discovery via etcd registry.
	// This is the preferred method for discovering and connecting to agents, tools, and plugins.
	// When set, this is used for agent delegation operations (DelegateToAgent, ListAgents).
	// Optional: if nil, agent delegation will not be available.
	RegistryAdapter registry.ComponentDiscovery

	// MemoryManager provides memory store creation and lifecycle management.
	// Used for accessing working, mission, and long-term memory tiers.
	// The memory manager is expected to be pre-configured for the mission scope.
	// Optional: if nil, the harness will have limited memory capabilities.
	// Note: Prefer using MemoryFactory for per-mission memory creation.
	MemoryManager memory.MemoryManager

	// MemoryFactory creates mission-scoped MemoryManager instances on demand.
	// When set, this factory is called during harness creation to create a
	// memory manager scoped to the mission ID from the MissionContext.
	// If both MemoryFactory and MemoryManager are set, MemoryFactory takes precedence.
	// Optional: if nil, MemoryManager is used directly (which may also be nil).
	MemoryFactory func(missionID types.ID) (memory.MemoryManager, error)

	// Tracer for distributed tracing (OpenTelemetry).
	// Used for creating spans around LLM operations, tool execution, etc.
	// Optional: defaults to no-op tracer if nil.
	Tracer trace.Tracer

	// Logger for structured logging.
	// Used for agent execution logging with contextual information.
	// Optional: defaults to default slog logger if nil.
	Logger *slog.Logger

	// FindingStore for persisting findings.
	// Used for storing and retrieving security findings discovered during execution.
	// Optional: defaults to InMemoryFindingStore if nil.
	FindingStore FindingStore

	// Metrics for recording operational metrics.
	// Used for tracking LLM usage, tool execution, finding counts, etc.
	// Optional: defaults to NoOpMetricsRecorder if nil.
	Metrics MetricsRecorder

	// GraphRAGBridge for storing findings to the knowledge graph.
	// Used for async storage of findings to Neo4j with relationship detection.
	// Optional: defaults to NoopGraphRAGBridge if nil.
	GraphRAGBridge GraphRAGBridge

	// GraphRAGQueryBridge provides access to GraphRAG query operations.
	// If nil, a NoopGraphRAGQueryBridge will be created (GraphRAG operations will return ErrGraphRAGNotEnabled).
	// To enable queries, provide a DefaultGraphRAGQueryBridge created with the same GraphRAGStore as GraphRAGBridge.
	GraphRAGQueryBridge GraphRAGQueryBridge

	// Middleware is the middleware chain to apply to harness operations.
	// When set, operations are routed through the configured middleware chain
	// for cross-cutting concerns like tracing, logging, and event emission.
	//
	// Build the chain using middleware.Chain() with the desired middleware:
	//   middleware.Chain(
	//       middleware.TracingMiddleware(tracer),
	//       middleware.LoggingMiddleware(logger, level),
	//       middleware.EventMiddleware(eventBus, errorHandler),
	//   )
	//
	// Optional: defaults to nil (no middleware).
	Middleware middleware.Middleware

	// LangfuseMiddlewareFactory creates Langfuse tracing middleware when provided.
	// This factory is called by the harness factory when MissionTracer and AgentExecLog
	// are both non-nil. The factory should create middleware using:
	//   observability.LangfuseTracingMiddleware(tracer, log)
	//
	// This indirection avoids import cycles (harness cannot import observability).
	// The caller (typically orchestrator/daemon) provides this factory.
	//
	// Signature: func(tracer any, log any) middleware.Middleware
	// Optional: defaults to nil (no Langfuse middleware).
	LangfuseMiddlewareFactory func(tracer any, log any) middleware.Middleware

	// MemoryWrapper is an optional function that wraps MemoryManager instances.
	// This enables composition patterns like adding observability (TracedMemoryManager)
	// or other cross-cutting concerns to memory operations.
	// The wrapper is applied when a MemoryManager is created or obtained, either from
	// MemoryFactory or MemoryManager field.
	// If nil, no wrapping is performed and the memory manager is used as-is.
	// Optional: defaults to nil (no wrapping).
	MemoryWrapper func(memory.MemoryManager) memory.MemoryManager

	// MissionClient provides mission lifecycle operations for agent-driven mission creation.
	// When set, agents can create, run, and monitor child missions through the harness.
	// When nil, mission management methods will return an error.
	// Optional: defaults to nil (mission management disabled).
	MissionClient MissionOperator

	// SpawnLimits configures mission spawning constraints to prevent runaway mission creation.
	// These limits are checked before allowing agents to create child missions.
	// If not set, DefaultSpawnLimits() will be used when MissionClient is configured.
	// Optional: defaults will be applied if MissionClient is set.
	SpawnLimits SpawnLimits

	// MissionTracer provides Langfuse tracing for mission-level operations.
	// When set, the harness will create child traces for agent executions
	// that roll up to the mission trace. Used for LLM observability and debugging.
	// Expected type: *observability.MissionTracer
	// Optional: defaults to nil (no Langfuse tracing).
	MissionTracer any

	// AgentExecLog provides parent span context for agent-level Langfuse tracing.
	// This links agent LLM calls and tool executions to the parent agent execution span.
	// Must be paired with MissionTracer to enable nested tracing.
	// Expected type: *observability.AgentExecutionLog
	// Optional: defaults to nil (no parent span context).
	AgentExecLog any

	// ActivityLogger provides structured activity stream logging for LLM interactions,
	// tool executions, and findings. Used for real-time observability in Grafana/Loki.
	// When nil, a NoopActivityLogger is used (no activity logging).
	// Expected type: observability.ActivityLogger
	// Optional: defaults to nil (activity logging disabled).
	ActivityLogger interface {
		EmitLLMPrompt(ctx context.Context, slot string, messages []interface{})
		EmitLLMResponse(ctx context.Context, slot string, response interface{})
		EmitToolCall(ctx context.Context, toolName string, params interface{})
		EmitToolResult(ctx context.Context, toolName string, result interface{}, durationMs int64, err error)
		EmitFinding(ctx context.Context, finding interface{})
		EmitError(ctx context.Context, operation string, err error)
	}
}

// Validate checks that required fields are set and returns an error if validation fails.
// Only SlotManager is strictly required - all other fields have reasonable defaults.
//
// Validation rules:
//   - SlotManager must not be nil (required for LLM operations)
//   - All other fields are optional and can be nil
//
// Returns:
//   - nil if validation passes
//   - ErrHarnessInvalidConfig if SlotManager is nil
func (c *HarnessConfig) Validate() error {
	// SlotManager is required for LLM slot resolution
	if c.SlotManager == nil {
		return types.NewError(
			ErrHarnessInvalidConfig,
			"SlotManager is required (cannot be nil)",
		)
	}

	// All other fields are optional and will be defaulted during harness creation
	return nil
}

// ApplyDefaults fills in nil fields with default implementations.
// This method is idempotent and safe to call multiple times.
//
// Default implementations:
//   - LLMRegistry: NewLLMRegistry() (empty registry)
//   - ToolRegistry: NewToolRegistry() (empty registry)
//   - PluginRegistry: NewPluginRegistry() (empty registry)
//   - Tracer: trace.NewNoopTracerProvider().Tracer("gibson.harness")
//   - Logger: slog.Default()
//   - FindingStore: NewInMemoryFindingStore()
//   - Metrics: NewNoOpMetricsRecorder()
//   - GraphRAGBridge: NoopGraphRAGBridge{} (no-op, no knowledge graph storage)
//   - GraphRAGQueryBridge: NoopGraphRAGQueryBridge{} (no-op, GraphRAG queries disabled)
//
// Note: MemoryManager is not defaulted as it requires mission-specific configuration.
// Note: SlotManager is not defaulted as it is a required field.
// Note: RegistryAdapter is not defaulted as it requires etcd configuration (if nil, agent delegation will not be available).
func (c *HarnessConfig) ApplyDefaults() {
	if c.LLMRegistry == nil {
		c.LLMRegistry = llm.NewLLMRegistry()
	}

	if c.ToolRegistry == nil {
		c.ToolRegistry = tool.NewToolRegistry()
	}

	if c.PluginRegistry == nil {
		c.PluginRegistry = plugin.NewPluginRegistry(nil) // TODO: Pass EventBus when available
	}

	if c.Tracer == nil {
		// Use no-op tracer if none provided
		c.Tracer = trace.NewNoopTracerProvider().Tracer("gibson.harness")
	}

	if c.Logger == nil {
		c.Logger = slog.Default()
	}

	if c.FindingStore == nil {
		c.FindingStore = NewInMemoryFindingStore()
	}

	if c.Metrics == nil {
		c.Metrics = NewNoOpMetricsRecorder()
	}

	if c.GraphRAGBridge == nil {
		c.GraphRAGBridge = &NoopGraphRAGBridge{}
	}

	if c.GraphRAGQueryBridge == nil {
		c.GraphRAGQueryBridge = &NoopGraphRAGQueryBridge{}
	}

	// Apply default spawn limits if MissionClient is configured but limits are not set
	// SpawnLimits are only defaulted when MissionClient is present
	if c.MissionClient != nil {
		// Check if spawn limits are at zero values (not configured)
		if c.SpawnLimits.MaxChildMissions == 0 &&
			c.SpawnLimits.MaxConcurrentMissions == 0 &&
			c.SpawnLimits.MaxMissionDepth == 0 {
			c.SpawnLimits = DefaultSpawnLimits()
		}
	}

	// Note: MemoryManager is not defaulted - it requires mission-specific configuration
	// and database dependencies that cannot be reasonably defaulted.
	// Note: MissionClient is not defaulted - mission management is opt-in functionality.
}
