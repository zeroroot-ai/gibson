package harness

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/sdk/protoresolver"
)

// HarnessFactory is a function type for creating child harnesses.
// This is used by concrete harness implementations for creating child harnesses during delegation.
// The function receives context, mission context, and target info to create a new harness.
type HarnessFactory func(ctx context.Context, missionCtx MissionContext, targetInfo TargetInfo) (AgentHarness, error)

// HarnessFactoryInterface creates configured AgentHarness instances.
// This factory interface provides a structured way to create harnesses with
// proper dependency injection and context propagation.
//
// The factory pattern enables:
//   - Consistent harness initialization across the framework
//   - Testability through dependency injection
//   - Support for hierarchical agent execution (parent-child relationships)
//   - Centralized configuration validation
type HarnessFactoryInterface interface {
	// Create creates a new AgentHarness for the given agent and mission context.
	//
	// Parameters:
	//   - agentName: Name of the agent this harness is for
	//   - missionCtx: Mission context providing mission-level metadata
	//   - target: Target information for the current mission
	//
	// Returns:
	//   - AgentHarness: Fully configured harness ready for agent execution
	//   - error: Non-nil if creation fails
	Create(agentName string, missionCtx MissionContext, target TargetInfo) (AgentHarness, error)

	// CreateChild creates a child harness from a parent for sub-agent delegation.
	//
	// Parameters:
	//   - parent: The parent harness that is delegating to a sub-agent
	//   - agentName: Name of the child agent this harness is for
	//
	// Returns:
	//   - AgentHarness: Child harness ready for sub-agent execution
	//   - error: Non-nil if creation fails
	//
	// The child harness shares certain state with the parent to enable coordination
	// while maintaining isolation for agent-specific concerns.
	CreateChild(parent AgentHarness, agentName string) (AgentHarness, error)
}

// DefaultHarnessFactory implements HarnessFactoryInterface using the HarnessConfig.
// It provides a production-ready implementation of the factory pattern for creating
// agent harnesses with proper dependency injection and state management.
type DefaultHarnessFactory struct {
	config HarnessConfig
}

// NewHarnessFactory creates a new DefaultHarnessFactory with the given configuration.
//
// The factory validates the configuration and applies defaults before storing it.
// This ensures that all harnesses created by this factory have consistent,
// valid configuration.
//
// Parameters:
//   - config: Harness configuration with registries and optional dependencies
//
// Returns:
//   - *DefaultHarnessFactory: Ready-to-use factory instance
//   - error: Non-nil if config validation fails
func NewHarnessFactory(config HarnessConfig) (*DefaultHarnessFactory, error) {
	// Apply defaults for optional fields
	config.ApplyDefaults()

	// Validate the configuration
	if err := config.Validate(); err != nil {
		return nil, types.WrapError(
			ErrHarnessInvalidConfig,
			"harness configuration validation failed",
			err,
		)
	}

	return &DefaultHarnessFactory{
		config: config,
	}, nil
}

// SetPluginAccess updates the ComponentAccess store after the factory has been constructed.
//
// This is used during daemon startup to wire in the plugin access store after the
// KeyProvider is initialized (which happens after newHarnessFactory runs).
// Passing nil is a no-op so callers do not need to guard.
func (f *DefaultHarnessFactory) SetPluginAccess(store component.ComponentAccessStore) {
	f.config.ComponentAccess = store
}

// Create creates a new AgentHarness for the given agent and mission context.
//
// The harness is configured with:
//   - Fresh token usage tracker scoped to mission + agent
//   - Logger with "agent", "mission_id", and "mission_name" attributes
//   - All registries from factory configuration
//   - Memory manager (created via MemoryFactory if set, otherwise from config)
//   - Finding store from factory configuration
//   - Metrics recorder from factory configuration
//   - Tracer from factory configuration
func (f *DefaultHarnessFactory) Create(agentName string, missionCtx MissionContext, target TargetInfo) (AgentHarness, error) {
	// Validate agent name
	if agentName == "" {
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"agent name cannot be empty",
		)
	}

	// Update mission context to reflect current agent
	updatedMissionCtx := missionCtx
	updatedMissionCtx.CurrentAgent = agentName

	// Create token usage tracker for this agent
	tokenTrackerPtr := llm.NewTokenTracker(nil)
	var tokenTracker llm.TokenTracker = tokenTrackerPtr

	// Create logger with agent context
	logger := f.config.Logger.With(
		slog.String("agent", agentName),
		slog.String("mission_id", missionCtx.ID.String()),
		slog.String("mission_name", missionCtx.Name),
	)

	// Create self-referential factory for child harness creation during delegation
	selfFactory := func(ctx context.Context, childMissionCtx MissionContext, childTarget TargetInfo) (AgentHarness, error) {
		childAgentName := childMissionCtx.CurrentAgent
		if childAgentName == "" {
			return nil, types.NewError(ErrHarnessInvalidConfig, "mission context missing CurrentAgent field")
		}
		return f.Create(childAgentName, childMissionCtx, childTarget)
	}

	// Get or create ProtoResolver for dynamic type resolution
	// Priority:
	// 1. Use config.ProtoResolver if set (explicit configuration)
	// 2. If RegistryAdapter is available, reuse its resolver for cache sharing
	// 3. Otherwise use the default resolver from ApplyDefaults (should not be nil)
	var resolver protoresolver.ProtoResolver
	if f.config.ProtoResolver != nil {
		// Use explicitly configured resolver
		resolver = f.config.ProtoResolver
		logger.Debug("using proto resolver from config")
	} else if f.config.RegistryAdapter != nil {
		// Try to reuse resolver from RegistryAdapter for cache sharing
		type resolverProvider interface {
			GetResolver() protoresolver.ProtoResolver
		}
		if rp, ok := f.config.RegistryAdapter.(resolverProvider); ok {
			resolver = rp.GetResolver()
			logger.Debug("reusing proto resolver from registry adapter")
		} else {
			// Fallback to creating new resolver (should not happen after ApplyDefaults)
			resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
			logger.Debug("created new proto resolver (registry adapter doesn't provide resolver)")
		}
	} else {
		// Fallback to creating new resolver (should not happen after ApplyDefaults)
		resolver = protoresolver.NewDefaultProtoResolver(protoresolver.DefaultConfig())
		logger.Debug("created new proto resolver (no registry adapter)")
	}

	// Determine if category classifier should be enabled
	var categoryClassifier CategoryClassifier
	if f.config.ClassifierConfig != nil && f.config.ClassifierConfig.Enabled {
		categoryClassifier = f.config.CategoryClassifier
		if categoryClassifier != nil {
			logger.Debug("category classifier enabled for harness",
				slog.Float64("threshold", f.config.ClassifierConfig.Threshold),
				slog.Bool("auto_register", f.config.ClassifierConfig.AutoRegister),
			)
		} else {
			logger.Warn("classifier config enabled but no CategoryClassifier provided")
		}
	}

	// Per-tenant LLM provider scoping (gibson#528): mission/agent execution
	// resolves slots against the calling tenant's configured providers via
	// SlotManagerForTenant. The production daemon ALWAYS wires this hook, so the
	// legacy global config/env registry is never an execution source in prod.
	// The f.config.SlotManager fallback below exists only as a unit-test seam
	// (tests inject a slot manager directly without tenant resolution).
	slotManager := f.config.SlotManager
	llmRegistry := f.config.LLMRegistry
	if f.config.SlotManagerForTenant != nil {
		sm, reg, err := f.config.SlotManagerForTenant(context.Background(), missionCtx.TenantID)
		if err != nil {
			return nil, types.NewError(
				ErrHarnessInvalidConfig,
				fmt.Sprintf("failed to resolve providers for tenant %q: %v", missionCtx.TenantID, err),
			)
		}
		slotManager = sm
		llmRegistry = reg
	}

	// Create and return DefaultAgentHarness
	var harness AgentHarness = &DefaultAgentHarness{
		slotManager:        slotManager,
		llmRegistry:        llmRegistry,
		registryAdapter:    f.config.RegistryAdapter,
		findingStore:       f.config.FindingStore,
		factory:            selfFactory,
		missionCtx:         updatedMissionCtx,
		targetInfo:         target,
		tracer:             f.config.Tracer,
		logger:             logger,
		metrics:            f.config.Metrics,
		tokenUsage:         tokenTracker,
		delegationSink:     f.config.DelegationSink,
		missionClient:      f.config.MissionClient,
		spawnLimits:        f.config.SpawnLimits,
		eventLogger:        f.config.EventLogger,
		resolver:           resolver,
		categoryClassifier: categoryClassifier,
		componentRegistry:  f.config.ComponentRegistry,
		workQueue:          f.config.WorkQueue,
		workQueueTimeout:   f.config.WorkQueueTimeout,
		componentAccess:    f.config.ComponentAccess,
		maxDelegationDepth: f.config.MaxDelegationDepth,
		sandboxedExecutor:  f.config.SandboxedExecutor,
		toolRunnerEnabled:  f.config.ToolRunnerEnabled,
		quotaCounter:       f.config.QuotaCounter,
		// Per-node slot overrides: lifted from MissionContext so every
		// ResolveSlot call within this agent execution sees the node's
		// declared llm_slots bindings. Child harnesses created by
		// DelegateToAgent start with their own (possibly empty) overrides
		// from their own MissionContext — they do NOT inherit these.
		// Spec: per-node-slot-override (gibson#539).
		nodeSlotOverrides: missionCtx.NodeSlotOverrides,
	}

	// Wrap with ComplianceMiddleware BEFORE the OTel middleware so the OTel
	// span captures the emit overhead. This is the insertion order from
	// audit-compliance-emitter requirement 1.2.
	//
	// ComplianceMiddleware is skipped when the signal sink is nil (default
	// in the factory config today — daemon startup wiring lands the sink in
	// task 10's daemon-level change). A nil sink means "emitter not yet
	// wired"; once wired, every harness in the factory path gains signal
	// emission automatically.
	if f.config.ComplianceSink != nil {
		cm, err := NewComplianceMiddleware(ComplianceMiddlewareConfig{
			Inner:       harness,
			GraphReader: f.config.ComplianceGraphReader,
			Sink:        f.config.ComplianceSink,
			Logger:      logger,
		})
		if err != nil {
			logger.Warn("compliance middleware construction failed — emitter disabled",
				slog.String("error", err.Error()))
		} else {
			harness = cm
			logger.Info("compliance_middleware: emitter active",
				slog.Int("covered_methods", cm.CoveredMethodCount()))
		}
	}

	// Apply middleware if configured.
	middlewareChain := f.config.Middleware
	if middlewareChain != nil {
		harness = NewMiddlewareHarness(harness, middlewareChain)
	}

	// Log mission management status
	if f.config.MissionClient != nil {
		logger.Debug("mission management enabled for harness",
			slog.Int("max_child_missions", f.config.SpawnLimits.MaxChildMissions),
			slog.Int("max_concurrent_missions", f.config.SpawnLimits.MaxConcurrentMissions),
			slog.Int("max_mission_depth", f.config.SpawnLimits.MaxMissionDepth),
		)
	} else {
		logger.Debug("mission management disabled for harness (no mission client configured)")
	}

	return harness, nil
}

// CreateChild creates a child harness from a parent for sub-agent delegation.
//
// The child harness will:
//   - Share memory store with parent (mission and long-term memory shared)
//   - Share finding store with parent
//   - Update MissionContext.CurrentAgent to the child agent name
//   - Have its own token usage tracker (scoped to child agent)
//   - Have logger with updated "agent" attribute for context
//   - Inherit all registries and configuration from parent
func (f *DefaultHarnessFactory) CreateChild(parent AgentHarness, agentName string) (AgentHarness, error) {
	// Validate inputs
	if parent == nil {
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"parent harness cannot be nil",
		)
	}
	if agentName == "" {
		return nil, types.NewError(
			ErrHarnessInvalidConfig,
			"agent name cannot be empty",
		)
	}

	// Get parent's mission context and update the current agent
	parentMission := parent.Mission()
	childMission := parentMission
	childMission.CurrentAgent = agentName

	// Get parent's target info (shared with child)
	targetInfo := parent.Target()

	// Create the child harness with updated mission context
	// The child will share the parent's memory store (through the factory config)
	return f.Create(agentName, childMission, targetInfo)
}

// Config returns a copy of the factory's configuration.
// This is useful for inspection and debugging.
func (f *DefaultHarnessFactory) Config() HarnessConfig {
	return f.config
}

// Ensure DefaultHarnessFactory implements HarnessFactoryInterface
var _ HarnessFactoryInterface = (*DefaultHarnessFactory)(nil)

// ────────────────────────────────────────────────────────────────────────────
// Type Aliases for Spec Compatibility
// ────────────────────────────────────────────────────────────────────────────

// HarnessFactoryConfig is an alias for HarnessConfig for spec compatibility.
// This provides the naming convention used in the attack-orchestration-integration spec.
type HarnessFactoryConfig = HarnessConfig

// NewDefaultHarnessFactory is an alias for NewHarnessFactory for spec compatibility.
// This provides the naming convention used in the attack-orchestration-integration spec.
//
// The factory validates the configuration and applies defaults before storing it.
// This ensures that all harnesses created by this factory have consistent,
// valid configuration.
//
// Parameters:
//   - config: Harness configuration with registries and optional dependencies
//
// Returns:
//   - *DefaultHarnessFactory: Ready-to-use factory instance
//   - error: Non-nil if config validation fails
func NewDefaultHarnessFactory(config HarnessFactoryConfig) (*DefaultHarnessFactory, error) {
	return NewHarnessFactory(config)
}
