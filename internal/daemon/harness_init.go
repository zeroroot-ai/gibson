package daemon

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/harness/middleware"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/tool/builtins"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/queue"
	"go.opentelemetry.io/otel/trace"
)

// newHarnessFactory creates a new HarnessFactory with all required dependencies.
//
// The factory is configured with middleware for observability (tracing, logging, events)
// and all necessary registries for agent execution.
//
// Returns:
//   - harness.HarnessFactoryInterface: Configured factory ready to create harnesses
//   - error: Non-nil if factory creation fails
func (d *daemonImpl) newHarnessFactory(ctx context.Context) (harness.HarnessFactoryInterface, error) {
	d.logger.Debug(ctx, "creating harness factory")

	// Get tracer from provider if available
	var tracer trace.Tracer
	if d.infrastructure != nil && d.infrastructure.tracerProvider != nil {
		tracer = d.infrastructure.tracerProvider.Tracer("gibson")
	}

	// Build middleware chain for harness operations
	var middlewareChain middleware.Middleware
	if tracer != nil {
		// Build middleware chain with tracing
		// Additional middleware (logging, events) can be added here
		middlewareChain = middleware.Chain(
			middleware.TracingMiddleware(tracer),
			// middleware.LoggingMiddleware(logger, middleware.LevelNormal),
			// middleware.EventMiddleware(eventBus, errorHandler),
		)
	}

	// Create memory wrapper if tracer is available
	var memoryWrapper func(memory.MemoryManager) memory.MemoryManager
	if tracer != nil {
		memoryWrapper = func(mm memory.MemoryManager) memory.MemoryManager {
			return memory.NewTracedMemoryManager(mm, tracer)
		}
	}

	// Create tool registry and populate with Redis-based tools
	toolRegistry := tool.NewToolRegistry()
	if d.infrastructure.RedisClient() != nil {
		// Create Redis tool registry
		redisClient, ok := d.infrastructure.RedisClient().(*queue.RedisClient)
		if !ok {
			d.logger.Warn(ctx, "Redis client type assertion failed, skipping Redis tool registry population")
		} else {
			redisToolRegistry := harness.NewRedisToolRegistry(redisClient, d.logger.Slog())

			// Refresh to discover available tools from Redis
			if err := redisToolRegistry.Refresh(ctx); err != nil {
				d.logger.Warn(ctx, "failed to refresh Redis tool registry",
					"error", err.Error(),
				)
			}

			// Populate tool registry with Redis tools
			registered := 0
			for _, toolName := range redisToolRegistry.List() {
				if proxy, ok := redisToolRegistry.Get(toolName); ok {
					if err := toolRegistry.RegisterInternal(proxy); err != nil {
						d.logger.Warn(ctx, "failed to register Redis tool",
							"tool", toolName,
							"error", err.Error(),
						)
						continue
					}
					registered++
				}
			}

			if registered > 0 {
				d.logger.Info(ctx, "populated tool registry with Redis tools",
					"tools_registered", registered,
				)
			} else {
				d.logger.Info(ctx, "no Redis tools available yet (workers may not be registered)")
			}
		}
	} else {
		d.logger.Info(ctx, "Redis client not available, skipping Redis tool registry population")
	}

	// Register builtin tools - Phase 8
	// These tools provide agent access to knowledge store and payload library
	builtinCount := 0

	// Register knowledge_search tool
	// Pass nil for knowledge store - the tool handles this gracefully by returning empty results
	// The knowledge store will be wired in future phases
	knowledgeTool := builtins.NewKnowledgeSearchTool(nil)
	if err := toolRegistry.RegisterInternal(knowledgeTool); err != nil {
		d.logger.Warn(ctx, "failed to register knowledge_search tool", "error", err.Error())
	} else {
		builtinCount++
		d.logger.Debug(ctx, "registered builtin tool", "name", "knowledge_search", "status", "stub")
	}

	// Register payload_search tool
	// Pass nil for payload registry - the tool handles this gracefully
	// The payload registry will be wired in future phases
	payloadSearchTool := builtins.NewPayloadSearchTool(nil)
	if err := toolRegistry.RegisterInternal(payloadSearchTool); err != nil {
		d.logger.Warn(ctx, "failed to register payload_search tool", "error", err.Error())
	} else {
		builtinCount++
		d.logger.Debug(ctx, "registered builtin tool", "name", "payload_search", "status", "stub")
	}

	// Register payload_execute tool
	// Pass nil for payload executor - the tool returns an error if called
	// The payload executor will be wired in future phases
	payloadExecuteTool := builtins.NewPayloadExecuteTool(nil)
	if err := toolRegistry.RegisterInternal(payloadExecuteTool); err != nil {
		d.logger.Warn(ctx, "failed to register payload_execute tool", "error", err.Error())
	} else {
		builtinCount++
		d.logger.Debug(ctx, "registered builtin tool", "name", "payload_execute", "status", "stub")
	}

	if builtinCount > 0 {
		d.logger.Info(ctx, "registered builtin tools", "count", builtinCount)
	}

	// Build HarnessConfig with all required dependencies
	config := harness.HarnessConfig{
		// LLM components
		LLMRegistry: d.infrastructure.llmRegistry,
		SlotManager: d.infrastructure.slotManager,

		// Component registries
		ToolRegistry:   toolRegistry,
		PluginRegistry: nil,

		// Registry adapter for component discovery
		RegistryAdapter: d.registryAdapter,

		// Finding storage (in-memory for agent execution)
		FindingStore: harness.NewInMemoryFindingStore(),

		// MemoryFactory creates mission-scoped memory managers on demand
		MemoryManager: nil,
		MemoryFactory: func(missionID types.ID) (memory.MemoryManager, error) {
			return d.infrastructure.memoryManagerFactory.CreateForMission(context.Background(), missionID)
		},

		// Observability
		Logger:  d.logger.WithComponent("harness").Slog(),
		Tracer:  tracer,
		Metrics: nil, // Defaulted to no-op

		// Middleware chain for cross-cutting concerns
		Middleware: middlewareChain,

		// Memory wrapper for tracing
		MemoryWrapper: memoryWrapper,

		// GraphRAG components
		GraphRAGBridge:      d.infrastructure.graphRAGBridge,
		GraphRAGQueryBridge: d.infrastructure.graphRAGQueryBridge,
	}

	// Create the factory
	factory, err := harness.NewHarnessFactory(config)
	if err != nil {
		return nil, err
	}

	d.logger.Info(ctx, "harness factory created successfully")
	return factory, nil
}
