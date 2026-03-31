package harness

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/harness/middleware"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/protoresolver"
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

	// Get memory store - either from factory (per-mission) or static config
	memoryStore := f.config.MemoryManager
	if f.config.MemoryFactory != nil {
		// Create mission-scoped memory manager using the factory.
		// Pass tenantID alongside missionID for defense-in-depth tenant isolation.
		mm, err := f.config.MemoryFactory(missionCtx.ID, missionCtx.TenantID)
		if err != nil {
			logger.Warn("failed to create memory manager via factory, using nil",
				slog.String("error", err.Error()),
				slog.String("mission_id", missionCtx.ID.String()),
				slog.String("tenant_id", missionCtx.TenantID),
			)
			// Continue with nil memory - harness will have limited memory capabilities
		} else {
			memoryStore = mm
		}
	}

	// Apply optional memory wrapper (e.g., TracedMemoryManager)
	if memoryStore != nil && f.config.MemoryWrapper != nil {
		memoryStore = f.config.MemoryWrapper(memoryStore)
	}

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

	// Initialize checkpoint access if checkpointer is configured
	var checkpointAccess CheckpointAccess
	if f.config.Checkpointer != nil {
		checkpointAccess = NewHarnessCheckpointMethods(
			f.config.Checkpointer,
			f.config.ThreadID,
			missionCtx.ID,
			f.config.RunNumber,
		)
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

	// Create and return DefaultAgentHarness
	var harness AgentHarness = &DefaultAgentHarness{
		slotManager:         f.config.SlotManager,
		llmRegistry:         f.config.LLMRegistry,
		toolRegistry:        f.config.ToolRegistry,
		pluginRegistry:      f.config.PluginRegistry,
		registryAdapter:     f.config.RegistryAdapter,
		memoryStore:         memoryStore,
		findingStore:        f.config.FindingStore,
		factory:             selfFactory,
		missionCtx:          updatedMissionCtx,
		targetInfo:          target,
		tracer:              f.config.Tracer,
		logger:              logger,
		metrics:             f.config.Metrics,
		tokenUsage:          tokenTracker,
		graphRAGBridge:      f.config.GraphRAGBridge,
		graphRAGQueryBridge: f.config.GraphRAGQueryBridge,
		missionClient:       f.config.MissionClient,
		spawnLimits:         f.config.SpawnLimits,
		eventLogger:         f.config.EventLogger,
		resolver:            resolver,
		checkpointAccess:    checkpointAccess,
		categoryClassifier:  categoryClassifier,
		componentRegistry:   f.config.ComponentRegistry,
		workQueue:           f.config.WorkQueue,
		workQueueTimeout:    f.config.WorkQueueTimeout,
	}

	// Apply middleware if configured
	// Build middleware chain with Langfuse middleware if tracer and log are provided
	middlewareChain := f.config.Middleware
	if f.config.MissionTracer != nil && f.config.AgentExecLog != nil && f.config.LangfuseMiddlewareFactory != nil {
		// Create Langfuse tracing middleware using the factory
		langfuseMW := f.config.LangfuseMiddlewareFactory(f.config.MissionTracer, f.config.AgentExecLog)

		// Chain with existing middleware if present
		if middlewareChain != nil {
			middlewareChain = middleware.Chain(middlewareChain, langfuseMW)
		} else {
			middlewareChain = langfuseMW
		}

		logger.Debug("langfuse tracing enabled for agent harness",
			slog.String("mission_id", missionCtx.ID.String()),
			slog.String("agent", agentName),
		)
	}

	// Apply the final middleware chain
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

	// Store tool capabilities in working memory for agent access
	// This allows agents to check tool privilege requirements before execution
	if memoryStore != nil {
		ctx := context.Background()
		caps, err := harness.GetAllToolCapabilities(ctx)
		if err != nil {
			logger.Warn("failed to retrieve tool capabilities for working memory",
				slog.String("error", err.Error()),
			)
		} else if len(caps) > 0 {
			// Store capabilities in working memory under "tool_capabilities" key
			err = memoryStore.Working().Set("tool_capabilities", caps)
			if err != nil {
				logger.Warn("failed to store tool capabilities in working memory",
					slog.String("error", err.Error()),
				)
			} else {
				logger.Info("stored tool capabilities in working memory",
					slog.Int("tools_with_capabilities", len(caps)),
				)
			}
		}
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
