package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/gibson/internal/graphrag"
	"github.com/zeroroot-ai/gibson/internal/graphrag/provider"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/memory/vector"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"

	"github.com/zeroroot-ai/sdk/auth"
)

// errNoTenantInContext is returned when a harness call arrives without a tenant
// in the request context. This maps to codes.FailedPrecondition at the gRPC layer.
var errNoTenantInContext = errors.New("graphrag bridge: no tenant in context (FailedPrecondition)")

// GraphRAGBridgeConfig holds the dependencies for GraphRAGBridgeAdapter.
// All per-call Neo4j access is resolved through PoolGetter; no shared driver
// is held. PoolGetter is a deferred accessor because the daemon's pool is
// initialized later in Start() than the bridge — pool init depends on the
// key provider + secrets broker, which come up after infrastructure init.
type GraphRAGBridgeConfig struct {
	// PoolGetter returns the per-tenant data-plane pool. Required. The getter
	// is invoked at request time (not at adapter construction) so callers may
	// pass a closure that reads `&d.pool` even while pool is still nil at
	// adapter-construction time. The getter MAY return nil if the pool has
	// not yet initialized; the bridge surfaces this as a typed Unavailable
	// error to the caller.
	PoolGetter func() datapool.Pool

	// Embedder generates vector embeddings. Shared across all tenants.
	Embedder embedder.Embedder

	// VectorStore is the shared in-process vector store. Per-tenant namespacing
	// is applied via NewVectorStoreForTenantWithStore inside each method call.
	VectorStore vector.VectorStore

	// Logger for diagnostic output. Defaults to slog.Default() if nil.
	Logger *slog.Logger
}

// GraphRAGBridgeAdapter is the per-call GraphRAG bridge. It resolves a tenant
// from the request context, acquires a per-tenant Neo4j session from the pool,
// constructs an ephemeral LocalGraphRAGProvider + GraphRAGStore, and executes the
// operation — all within a single method call.
//
// The adapter implements harness.GraphRAGQueryBridge (synchronous graph queries).
//
// Thread-safety: safe for concurrent use. Each call is fully independent.
type GraphRAGBridgeAdapter struct {
	getPool     func() datapool.Pool
	embedder    embedder.Embedder
	vectorStore vector.VectorStore
	logger      *slog.Logger
}

// errPoolNotReady is returned when the bridge is invoked before the daemon's
// per-tenant pool has been initialized. Maps to codes.Unavailable at the gRPC
// layer — transient, retry-safe.
var errPoolNotReady = errors.New("graphrag bridge: data-plane pool not yet initialized (Unavailable)")

// NewGraphRAGBridgeAdapter creates a new per-call GraphRAGBridgeAdapter.
func NewGraphRAGBridgeAdapter(cfg GraphRAGBridgeConfig) (*GraphRAGBridgeAdapter, error) {
	if cfg.PoolGetter == nil {
		return nil, fmt.Errorf("graphrag bridge: PoolGetter cannot be nil")
	}
	if cfg.Embedder == nil {
		return nil, fmt.Errorf("graphrag bridge: Embedder cannot be nil")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "graphrag_bridge_adapter")

	a := &GraphRAGBridgeAdapter{
		getPool:     cfg.PoolGetter,
		embedder:    cfg.Embedder,
		vectorStore: cfg.VectorStore,
		logger:      logger,
	}

	logger.Info("graphrag bridge adapter created (per-call per-tenant pool-backed)")
	return a, nil
}

// QueryBridge returns this adapter as a harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) QueryBridge() harness.GraphRAGQueryBridge {
	return a
}

// buildEphemeralQueryBridge resolves the tenant from ctx, acquires a per-tenant
// pool connection, builds an ephemeral provider + store, and returns a
// DefaultGraphRAGQueryBridge backed by that store. The returned release func
// MUST be called when the caller is done (typically via defer).
//
// On error, release is a no-op and the error describes the failure.
func (a *GraphRAGBridgeAdapter) buildEphemeralQueryBridge(ctx context.Context) (qb *harness.DefaultGraphRAGQueryBridge, release func(), err error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, func() {}, errNoTenantInContext
	}

	pool := a.getPool()
	if pool == nil {
		return nil, func() {}, errPoolNotReady
	}

	conn, poolErr := pool.For(ctx, tenant)
	if poolErr != nil {
		return nil, func() {}, poolErr
	}

	release = conn.Release

	// Build per-tenant vector store namespace.
	var vs vector.VectorStore
	if a.vectorStore != nil {
		vs = vector.NewVectorStoreForTenantWithStore(a.vectorStore, tenant)
	}

	// Construct ephemeral provider from the pre-opened session (no Initialize call).
	prov := provider.NewLocalGraphRAGProviderWithSession(conn.Neo4j, vs)

	// Construct ephemeral store (skips Neo4j URI validation).
	store, storeErr := graphrag.NewGraphRAGStoreForSession(a.embedder, prov)
	if storeErr != nil {
		conn.Release()
		return nil, func() {}, fmt.Errorf("graphrag bridge: failed to create session store: %w", storeErr)
	}

	qb = harness.NewGraphRAGQueryBridge(store)
	return qb, release, nil
}

// --- harness.GraphRAGQueryBridge implementation ---
// Each method delegates to an ephemeral DefaultGraphRAGQueryBridge built per-call.

// StoreNode implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) StoreNode(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return qb.StoreNode(ctx, node, missionID, agentName)
}

// CreateRelationship implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) CreateRelationship(ctx context.Context, rel sdkgraphrag.Relationship) error {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return err
	}
	defer release()
	return qb.CreateRelationship(ctx, rel)
}

// StoreBatch implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) StoreBatch(ctx context.Context, batch sdkgraphrag.Batch, missionID, agentName string) ([]string, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.StoreBatch(ctx, batch, missionID, agentName)
}

// StoreSemantic implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) StoreSemantic(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return qb.StoreSemantic(ctx, node, missionID, agentName)
}

// StoreStructured implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) StoreStructured(ctx context.Context, node sdkgraphrag.GraphNode, missionID, agentName string) (string, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return "", err
	}
	defer release()
	return qb.StoreStructured(ctx, node, missionID, agentName)
}

// Health implements harness.GraphRAGQueryBridge. Returns healthy when the adapter
// is configured; actual Neo4j health is per-tenant and checked at call time.
func (a *GraphRAGBridgeAdapter) Health(_ context.Context) types.HealthStatus {
	if a.getPool() == nil {
		return types.Unhealthy("graphrag bridge: pool not yet initialized")
	}
	return types.Healthy("graphrag bridge: pool-backed, per-tenant (no shared Neo4j)")
}

// HealthErr returns nil when the adapter is healthy.
func (a *GraphRAGBridgeAdapter) HealthErr(ctx context.Context) error {
	status := a.Health(ctx)
	if !status.IsHealthy() {
		return fmt.Errorf("graphrag bridge unhealthy: %s", status.Message)
	}
	return nil
}

// ConfigValidationError is a configuration validation error (retained for compatibility).
type ConfigValidationError struct {
	Field   string
	Message string
}

func (e *ConfigValidationError) Error() string {
	return "graphrag adapter config: " + e.Field + " " + e.Message
}

// HealthCheckError is a health check failure (retained for compatibility).
type HealthCheckError struct {
	Component string
	Message   string
}

func (e *HealthCheckError) Error() string {
	return "graphrag health check failed: " + e.Component + ": " + e.Message
}
