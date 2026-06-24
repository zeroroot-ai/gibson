package harness

import (
	"context"
	"log/slog"
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/events"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/dispatchpolicy"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/engine/harness/sandboxed"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/sdk/protoresolver"
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

	// SlotManagerForTenant, when set, produces a tenant-scoped SlotManager +
	// LLMRegistry for a mission's tenant. The factory calls it on Create with
	// missionCtx.TenantID so slot resolution sees only that tenant's configured
	// providers (per-tenant LLM provider scoping). When nil, the global
	// SlotManager/LLMRegistry above are used (legacy single-tenant path).
	SlotManagerForTenant func(ctx context.Context, tenantID string) (llm.SlotManager, llm.LLMRegistry, error)

	// ProtoResolver provides dynamic proto type resolution for tool execution.
	// Used to convert structpb.Struct inputs to typed proto messages using FileDescriptorSets.
	// Optional: defaults to DefaultProtoResolver with standard configuration if nil.
	ProtoResolver protoresolver.ProtoResolver

	// RegistryAdapter provides unified component discovery via the component registry.
	// This is the preferred method for discovering and connecting to agents, tools, and plugins.
	// When set, this is used for agent delegation operations (DelegateToAgent, ListAgents).
	// Optional: if nil, agent delegation will not be available.
	RegistryAdapter component.ComponentDiscovery

	// Tracer for distributed tracing (OpenTelemetry).
	// Used for creating spans around LLM operations, tool execution, etc.
	// Optional: defaults to no-op tracer if nil.
	Tracer trace.Tracer

	// Logger for structured logging.
	// Used for agent execution logging with contextual information.
	// Optional: defaults to default slog logger if nil.
	Logger *slog.Logger

	// EventLogger for structured event logging with observability support.
	// This logger provides event emission with trace correlation and type safety.
	// When set, the harness will emit structured events for LLM calls, tool executions,
	// findings, memory operations, etc. using observability.EventType constants.
	// Optional: if nil, event logging will be disabled.
	EventLogger EventLogger

	// FindingStore for persisting findings.
	// Used for storing and retrieving security findings discovered during execution.
	// Optional: defaults to InMemoryFindingStore if nil.
	FindingStore FindingStore

	// Metrics for recording operational metrics.
	// Used for tracking LLM usage, tool execution, finding counts, etc.
	// Optional: defaults to NoOpMetricsRecorder if nil.
	Metrics MetricsRecorder

	// DelegationSink folds agent-delegation run-provenance into the World so the
	// graph projector materializes :AgentRun + DELEGATED_TO (ADR-0007). Optional;
	// when nil, delegation provenance is not recorded.
	DelegationSink DelegationSink

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

	// EventBus for plugin event publishing.
	// Used by the plugin registry to publish plugin lifecycle and health events.
	// Type: events.EventBus
	// Optional: if nil, plugin events will not be published.
	EventBus events.EventBus

	// ClassifierConfig provides configuration for the category classifier.
	// When set, the harness will use semantic classification to normalize
	// finding categories during SubmitFinding operations.
	// Optional: if nil, category classification is disabled.
	ClassifierConfig *ClassifierConfig

	// CategoryClassifier provides semantic category normalization for findings.
	// When set, the harness will classify categories during SubmitFinding operations
	// based on the ClassifierConfig settings.
	// Optional: if nil, category classification is disabled.
	CategoryClassifier CategoryClassifier

	// ComponentRegistry provides Redis-backed component discovery scoped by tenant.
	// When non-nil, CallToolProto and QueryPlugin consult this registry before the
	// RegistryAdapter fallback. Nil means use the RegistryAdapter path only.
	// Optional.
	ComponentRegistry component.ComponentRegistry

	// WorkQueue provides pull-based work dispatch over Redis Streams.
	// When non-nil, remote components found in ComponentRegistry (those without a
	// direct grpc_endpoint in their metadata) receive work items via this queue.
	// Nil means use the existing direct-gRPC path only.
	// Optional.
	WorkQueue component.WorkQueue

	// WorkQueueTimeout is the maximum duration to wait for a remote component to
	// return a WorkResult. Zero defaults to 5 minutes.
	// Optional.
	WorkQueueTimeout time.Duration

	// ComponentAccess enforces per-tenant opt-in control for platform (_system) plugins.
	// When set, QueryPlugin will verify that the calling tenant has explicitly enabled
	// the plugin and provided credentials before routing to a _system instance.
	// When nil, access enforcement is skipped (backward-compatible behavior).
	// Optional.
	ComponentAccess component.ComponentAccessStore

	// MaxDelegationDepth caps the number of nested DelegateToAgent hops.
	// When zero, the package default (8) is used. Set via daemon config flag
	// "harness.max_delegation_depth" for production tuning.
	// Optional.
	MaxDelegationDepth int

	// ComplianceSink is the SignalSink that ComplianceMiddleware forwards
	// compliance signals to. When nil, ComplianceMiddleware is NOT wired
	// into the harness chain — the chain behaves as if the middleware did
	// not exist. Set by daemon startup after the discovery processor and
	// graph reader are ready.
	// Optional.
	ComplianceSink SignalSink

	// ComplianceGraphReader is the GraphReader passed into
	// ComplianceMiddleware for dual-reference resource resolution. May be
	// nil — the middleware will then stamp URI-only on every signal.
	// Optional.
	ComplianceGraphReader GraphReader

	// SandboxedExecutor dispatches sandboxed tool calls into Setec microVMs
	// via gRPC. When set, CallToolProto consults its registry BEFORE the
	// local/ComponentRegistry/RegistryAdapter paths — any tool whose name is
	// registered in the executor is routed through Setec. Other tools take
	// the existing paths unchanged.
	// When nil, sandboxed dispatch is disabled (no behavior change for
	// existing deployments).
	// Optional.
	SandboxedExecutor *sandboxed.Executor

	// DeploymentShape is the untrusted-execution isolation policy the harness
	// enforces in CallToolProto (and the other execution paths). Sourced from
	// the daemon's GIBSON_UNTRUSTED_EXEC config. The zero value
	// (ShapeSetecOnly) is fail-closed: an unwired harness denies untrusted
	// in-process execution. See ADR-0010 / gibson#994.
	DeploymentShape dispatchpolicy.DeploymentShape

	// ToolRunnerEnabled routes tool dispatch through a single
	// ComponentRegistry lookup keyed by DispatchMode. When true, the
	// legacy sandboxed.Registry-first dual lookup is bypassed — entries
	// with DispatchMode=SANDBOXED dispatch via SandboxedExecutor using
	// the image/env/resources carried on the registry entry. When false,
	// the legacy path is preserved.
	// Optional; defaults to false.
	ToolRunnerEnabled bool

	// QuotaCounter maintains the per-tenant concurrent_agents Redis
	// counter via idle→busy / busy→idle transition callbacks driven by
	// per-agent inFlightTasks bookkeeping inside DefaultAgentHarness.
	// Optional; nil disables per-agent quota counting entirely.
	// Spec plans-and-quotas-simplification.
	QuotaCounter QuotaCounter
}

// QuotaCounter is the narrow interface DefaultAgentHarness uses to
// maintain the concurrent_agents Redis counter. *component.QuotaManager
// satisfies it; the types are deliberately decoupled to avoid the
// harness package taking a hard dep on the daemon's component package.
type QuotaCounter interface {
	IncrementAgentCount(ctx context.Context) error
	DecrementAgentCount(ctx context.Context) error
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
//   - ProtoResolver: NewDefaultProtoResolver() (default resolver with standard config)
//   - Tracer: trace.NewNoopTracerProvider().Tracer("gibson.harness")
//   - Logger: slog.Default()
//   - FindingStore: NewInMemoryFindingStore()
//   - Metrics: NewNoOpMetricsRecorder()
//
// Note: MemoryManager is not defaulted as it requires mission-specific configuration.
// Note: SlotManager is not defaulted as it is a required field.
// Note: RegistryAdapter is not defaulted as it requires external configuration (if nil, agent delegation will not be available).
func (c *HarnessConfig) ApplyDefaults() {
	if c.LLMRegistry == nil {
		c.LLMRegistry = llm.NewLLMRegistry()
	}

	if c.ProtoResolver == nil {
		c.ProtoResolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
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

	// Apply default classifier config if not set
	// ClassifierConfig is defaulted to disabled for backward compatibility
	if c.ClassifierConfig == nil {
		c.ClassifierConfig = DefaultClassifierConfig()
	}

	// Note: MemoryManager is not defaulted - it requires mission-specific configuration
	// and database dependencies that cannot be reasonably defaulted.
	// Note: MissionClient is not defaulted - mission management is opt-in functionality.
}

// ClassifierConfig configures the category classifier for finding normalization.
// The classifier uses semantic similarity to match proposed categories against
// existing ones, enabling LLM agents to use natural language category names
// while maintaining consistency across findings.
type ClassifierConfig struct {
	// Enabled controls whether category classification is active.
	// When false, findings are stored with their original categories unchanged.
	// Default: false (for backward compatibility).
	Enabled bool

	// Threshold is the minimum cosine similarity score (0.0-1.0) required to
	// match a proposed category to an existing one. Higher values require closer
	// semantic matches, while lower values are more permissive.
	// Typical values: 0.80-0.90 for related concepts, 0.90-0.95 for near-exact matches.
	// Default: 0.85
	Threshold float64

	// AutoRegister determines whether new categories should be automatically
	// registered when no existing category meets the similarity threshold.
	// When true, proposed categories that don't match are added to the index.
	// When false, proposed categories are used as-is without registration.
	// Default: true
	AutoRegister bool
}

// DefaultClassifierConfig returns the default classifier configuration.
// This configuration is conservative to avoid unwanted normalization during
// initial rollout. Adjust threshold based on observed matching behavior.
func DefaultClassifierConfig() *ClassifierConfig {
	return &ClassifierConfig{
		Enabled:      false, // Disabled by default for backward compatibility
		Threshold:    0.85,  // Balanced threshold for semantic similarity
		AutoRegister: true,  // Auto-register new categories by default
	}
}
