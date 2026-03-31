package daemon

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/component"
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
// Middleware Selection:
// The factory uses OTel middleware when available for observability integration.
//
// Returns:
//   - harness.HarnessFactoryInterface: Configured factory ready to create harnesses
//   - error: Non-nil if factory creation fails
func (d *daemonImpl) newHarnessFactory(ctx context.Context) (harness.HarnessFactoryInterface, error) {
	d.logger.Debug(ctx, "creating harness factory")

	// Configure OTel middleware when OTel stack is available
	var middlewareChain middleware.Middleware
	if d.infrastructure != nil && d.infrastructure.otelStack != nil {
		d.logger.Info(ctx, "using OpenTelemetry tracing middleware for harness operations")

		// OTel middleware will be configured per-harness with agentSpan
		// Here we just note that OTel is available - actual middleware is created
		// when each harness is instantiated with its specific agent context
		// The middleware factory will check for otelStack availability
		middlewareChain = nil // Configured per-harness in agent execution context
	} else {
		d.logger.Info(ctx, "no tracing middleware configured (OTel disabled)")
	}

	// Create memory wrapper for tracing if OTel is available
	var memoryWrapper func(memory.MemoryManager) memory.MemoryManager
	if d.infrastructure != nil && d.infrastructure.otelStack != nil {
		tracer := d.infrastructure.otelStack.TracerProvider.Tracer("gibson.memory")
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

			// Store on daemon for use by ListTools() gRPC method
			d.redisToolRegistry = redisToolRegistry

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

	// Build a Redis-backed WorkQueue for remote component dispatch.
	// This enables the harness to route tool/plugin calls to pull-based workers
	// (components registered in ComponentRegistry without a direct gRPC endpoint).
	var workQueue component.WorkQueue
	if d.stateClient != nil {
		workQueue = component.NewRedisWorkQueue(d.stateClient.Client())
		d.logger.Info(ctx, "initialized Redis work queue for remote component dispatch")
	}

	// Build HarnessConfig with all required dependencies
	config := harness.HarnessConfig{
		// LLM components
		LLMRegistry: d.infrastructure.llmRegistry,
		SlotManager: d.infrastructure.slotManager,

		// Component registries
		ToolRegistry:   toolRegistry,
		PluginRegistry: nil,
		PluginAccess:   d.pluginAccessStore, // nil when no KeyProvider configured; harness skips opt-in checks

		// ComponentRegistry enables tenant-scoped discovery (Path 2 in CallToolProto/QueryPlugin).
		// RegistryAdapter handles direct gRPC dispatch when a component exposes grpc_endpoint.
		// WorkQueue handles pull-based dispatch for components without a direct gRPC endpoint.
		ComponentRegistry: d.compRegistry,
		RegistryAdapter:   d.registryAdapter,
		WorkQueue:         workQueue,

		// Finding storage (in-memory for agent execution)
		FindingStore: harness.NewInMemoryFindingStore(),

		// MemoryFactory creates mission-scoped memory managers on demand.
		// tenantID is forwarded for defense-in-depth tenant isolation in the memory layer.
		MemoryManager: nil,
		MemoryFactory: func(missionID types.ID, tenantID string) (memory.MemoryManager, error) {
			return d.infrastructure.memoryManagerFactory.CreateForMission(context.Background(), missionID, tenantID)
		},

		// Observability
		Logger: d.logger.WithComponent("harness").Slog(),
		Tracer: func() trace.Tracer {
			if d.infrastructure != nil && d.infrastructure.otelStack != nil {
				return d.infrastructure.otelStack.TracerProvider.Tracer("gibson.harness")
			}
			return nil // No tracer available - harness will use no-op tracer
		}(),
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
