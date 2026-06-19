package daemon

import (
	"context"
	"fmt"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/component"
	"github.com/zeroroot-ai/gibson/internal/graphrag/ingest"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/harness/middleware"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/llm/modelgate"
	"github.com/zeroroot-ai/gibson/internal/llm/providers"
	"github.com/zeroroot-ai/gibson/internal/memory"
	"github.com/zeroroot-ai/gibson/internal/providerconfig"
	"github.com/zeroroot-ai/gibson/internal/tenantprovider"
	"github.com/zeroroot-ai/gibson/internal/types"
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

	// Build a Redis-backed WorkQueue for remote component dispatch.
	// This enables the harness to route tool/plugin calls to pull-based workers
	// (components registered in ComponentRegistry without a direct gRPC endpoint).
	var workQueue component.WorkQueue
	if d.stateClient != nil {
		workQueue = component.NewRedisWorkQueue(d.stateClient.Client())
		d.logger.Info(ctx, "initialized Redis work queue for remote component dispatch")
	}

	// Per-tenant LLM provider scoping (gibson#526): resolve each mission's slot
	// manager + registry from the calling tenant's configured providers (via the
	// broker-backed providerconfig store), replacing the global single-tenant
	// registry. The resolver + store are built lazily on first mission run so the
	// broker stack is guaranteed wired by then.
	var (
		tpOnce     sync.Once
		tpResolver *tenantprovider.Resolver
		tpInitErr  error
	)
	slotManagerForTenant := func(rctx context.Context, tenantID string) (llm.SlotManager, llm.LLMRegistry, error) {
		tpOnce.Do(func() {
			if d.pool == nil || d.secretsService == nil {
				tpInitErr = fmt.Errorf("per-tenant provider store unavailable (pool/secretsService nil)")
				return
			}
			store := providerconfig.NewBrokerBackedStore(d.pool, d.secretsService)
			tpResolver = tenantprovider.NewResolver(store, providers.NewProvider)
		})
		if tpInitErr != nil {
			return nil, nil, tpInitErr
		}
		set, err := tpResolver.Resolve(rctx, tenantID)
		if err != nil {
			return nil, nil, err
		}
		sm := NewDaemonSlotManager(set.Registry, d.logger.WithComponent("slot-manager").Slog())
		// Prefer the tenant's default provider for unpinned slots (gibson#531).
		sm.WithDefaultProvider(set.DefaultName)
		// Hard-enforce the FGA model-access gate on every per-tenant slot
		// resolution (gibson#527): the acting principal (user / team-inherited /
		// agent CG, from ctx) must be permitted to use the resolved model.
		if d.authorizer != nil {
			sm.WithModelFilter(modelgate.NewFGAFilter(d.authorizer, d.logger.Slog(), 0))
		}
		return sm, set.Registry, nil
	}

	// Build HarnessConfig with all required dependencies
	config := harness.HarnessConfig{
		// LLM components
		LLMRegistry:          d.infrastructure.llmRegistry,
		SlotManager:          d.infrastructure.slotManager,
		SlotManagerForTenant: slotManagerForTenant,

		// Component registries
		// ComponentInstallRegistry field was removed in plugin-runtime Spec 2 Phase 7;
		// plugin dispatch goes through ComponentRegistry + WorkQueue
		// (PluginInvokeService, see internal/component/plugin_dispatch.go).
		ComponentAccess: d.pluginAccessStore, // nil when no KeyProvider configured; harness skips opt-in checks

		// ComponentRegistry enables tenant-scoped discovery (Path 2 in CallToolProto/QueryPlugin).
		// RegistryAdapter handles direct gRPC dispatch when a component exposes grpc_endpoint.
		// WorkQueue handles pull-based dispatch for components without a direct gRPC endpoint.
		// EnvelopeSigner removed (admin-services-completion Req 6.4): AuthzContext is now
		// populated unsigned; FGA tuples binding agent_principal to mission are the auth gate.
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
		GraphRAGQueryBridge: d.infrastructure.graphRAGQueryBridge,

		// Compliance emitter — wires the ComplianceMiddleware into the
		// harness chain so every harness call emits a compliance_signal
		// node to Neo4j. The sink adapts the DiscoveryProcessor.
		// When nil (no graphRAG available), the middleware is skipped.
		ComplianceSink: nil, // shared-Neo4j-backed compliance sink removed (spec graphrag-tenant-scope)

		// ToolRunnerEnabled flips CallToolProto's sandboxed lookup path
		// from static sandbox.Registry to dynamic ComponentRegistry
		// driven by the catalog refresher. Gated by the same flag that
		// starts the refresher goroutine.
		ToolRunnerEnabled: d.config != nil && d.config.ToolRunner.Enabled,

		// QuotaCounter maintains the per-tenant concurrent_agents Redis
		// counter on agent idle→busy / busy→idle transitions inside
		// DelegateToAgent. nil-safe in dev (no quota manager wired).
		// Spec plans-and-quotas-simplification.
		QuotaCounter: d.quotaManager,
	}

	// Sandboxed tool executor (Setec microVM dispatch) — constructed only
	// when sandbox.enabled=true in config AND gibson was built with
	// -tags=setec_integration. The no-op constructor for the un-tagged
	// build returns (nil, nil) so config.Sandbox.Enabled=true without the
	// tag logs a warning and continues; per-call failures surface at
	// tool invocation time (design Requirement 5.4).
	if d.config != nil && d.config.Sandbox.Enabled {
		sandboxTracer := func() trace.Tracer {
			if d.infrastructure != nil && d.infrastructure.otelStack != nil {
				return d.infrastructure.otelStack.TracerProvider.Tracer("gibson.sandboxed")
			}
			return nil
		}()
		sandboxLogger := d.logger.WithComponent("sandboxed").Slog()
		// Pass the infrastructure's DiscoveryProcessor so sandboxed tool
		// responses populate the knowledge graph alongside live-callback tools.
		// nil when GraphRAG is disabled; sandboxed.Executor tolerates nil.
		var sbxDiscovery ingest.DiscoveryProcessor
		// discoveryProcessor removed from infrastructure (spec graphrag-tenant-scope);
		// sbxDiscovery remains nil — sandboxed.Executor tolerates nil.
		execer, err := NewSetecSandboxedExecutor(d.config.Sandbox, sandboxTracer, sandboxLogger, sbxDiscovery)
		if err != nil {
			d.logger.Warn(ctx, "sandboxed tool executor construction failed; continuing without sandboxed dispatch",
				"error", err)
		} else if execer == nil {
			d.logger.Warn(ctx, "sandbox.enabled=true but setec_integration build tag is not set; sandboxed tool calls will fail at invocation time (rebuild with -tags=setec_integration to enable)")
		} else {
			config.SandboxedExecutor = execer
			d.logger.Info(ctx, "sandboxed tool executor wired",
				"setec_address", d.config.Sandbox.Setec.Address,
				"tenant", d.config.Sandbox.Setec.Tenant,
				"catalog_source", "component_registry")
		}
	}

	// Create the factory
	factory, err := harness.NewHarnessFactory(config)
	if err != nil {
		return nil, err
	}

	d.logger.Info(ctx, "harness factory created successfully")
	return factory, nil
}
