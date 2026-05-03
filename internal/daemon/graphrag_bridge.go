package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/graphrag"
	"github.com/zero-day-ai/gibson/internal/graphrag/provider"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkgraphrag "github.com/zero-day-ai/sdk/graphrag"

	agentpkg "github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/sdk/auth"
)

// errNoTenantInContext is returned when a harness call arrives without a tenant
// in the request context. This maps to codes.FailedPrecondition at the gRPC layer.
var errNoTenantInContext = errors.New("graphrag bridge: no tenant in context (FailedPrecondition)")

// GraphRAGBridgeConfig holds the dependencies for GraphRAGBridgeAdapter.
// All per-call Neo4j access is resolved through Pool; no shared driver is held.
type GraphRAGBridgeConfig struct {
	// Pool is the per-tenant data-plane pool. Required.
	Pool datapool.Pool

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
// The adapter implements both harness.GraphRAGBridge (async finding storage) and
// harness.GraphRAGQueryBridge (synchronous graph queries). Harness consumers see
// the same interface shapes as before; only the implementation changed.
//
// Thread-safety: safe for concurrent use. Each call is fully independent.
type GraphRAGBridgeAdapter struct {
	pool        datapool.Pool
	embedder    embedder.Embedder
	vectorStore vector.VectorStore
	logger      *slog.Logger

	// async bridge for StoreAsync / Shutdown / Health (GraphRAGBridge interface).
	// StoreAsync is fire-and-forget; it constructs a per-call store internally.
	asyncBridge *asyncBridge
}

// NewGraphRAGBridgeAdapter creates a new per-call GraphRAGBridgeAdapter.
func NewGraphRAGBridgeAdapter(cfg GraphRAGBridgeConfig) (*GraphRAGBridgeAdapter, error) {
	if cfg.Pool == nil {
		return nil, fmt.Errorf("graphrag bridge: Pool cannot be nil")
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
		pool:        cfg.Pool,
		embedder:    cfg.Embedder,
		vectorStore: cfg.VectorStore,
		logger:      logger,
	}
	a.asyncBridge = newAsyncBridge(a)

	logger.Info("graphrag bridge adapter created (per-call per-tenant pool-backed)")
	return a, nil
}

// Bridge returns this adapter as a harness.GraphRAGBridge.
func (a *GraphRAGBridgeAdapter) Bridge() harness.GraphRAGBridge {
	return a.asyncBridge
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

	conn, poolErr := a.pool.For(ctx, tenant)
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

	qb = harness.NewGraphRAGQueryBridge(store, nil)
	return qb, release, nil
}

// --- harness.GraphRAGQueryBridge implementation ---
// Each method delegates to an ephemeral DefaultGraphRAGQueryBridge built per-call.

// Query implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) Query(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.Query(ctx, query)
}

// FindSimilarAttacks implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) FindSimilarAttacks(ctx context.Context, content string, topK int) ([]sdkgraphrag.AttackPattern, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.FindSimilarAttacks(ctx, content, topK)
}

// FindSimilarFindings implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) FindSimilarFindings(ctx context.Context, findingID string, topK int) ([]sdkgraphrag.FindingNode, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.FindSimilarFindings(ctx, findingID, topK)
}

// GetAttackChains implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) GetAttackChains(ctx context.Context, techniqueID string, maxDepth int) ([]sdkgraphrag.AttackChain, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.GetAttackChains(ctx, techniqueID, maxDepth)
}

// GetRelatedFindings implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) GetRelatedFindings(ctx context.Context, findingID string) ([]sdkgraphrag.FindingNode, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.GetRelatedFindings(ctx, findingID)
}

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

// Traverse implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) Traverse(ctx context.Context, startNodeID string, opts sdkgraphrag.TraversalOptions) ([]sdkgraphrag.TraversalResult, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.Traverse(ctx, startNodeID, opts)
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

// QuerySemantic implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) QuerySemantic(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.QuerySemantic(ctx, query)
}

// QueryStructured implements harness.GraphRAGQueryBridge.
func (a *GraphRAGBridgeAdapter) QueryStructured(ctx context.Context, query sdkgraphrag.Query) ([]sdkgraphrag.Result, error) {
	qb, release, err := a.buildEphemeralQueryBridge(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return qb.QueryStructured(ctx, query)
}

// Health implements harness.GraphRAGQueryBridge. Returns healthy when the adapter
// is configured; actual Neo4j health is per-tenant and checked at call time.
func (a *GraphRAGBridgeAdapter) Health(_ context.Context) types.HealthStatus {
	if a.pool == nil {
		return types.Unhealthy("graphrag bridge: pool not configured")
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

// --- asyncBridge implements harness.GraphRAGBridge (StoreAsync / Shutdown / Health) ---

// asyncBridge wraps the adapter for the async finding-storage interface.
// StoreAsync is fire-and-forget; it builds an ephemeral store per call.
type asyncBridge struct {
	adapter   *GraphRAGBridgeAdapter
	logger    *slog.Logger
	wg        sync.WaitGroup
	semaphore chan struct{}
}

func newAsyncBridge(a *GraphRAGBridgeAdapter) *asyncBridge {
	return &asyncBridge{
		adapter:   a,
		logger:    a.logger.With("bridge_type", "async"),
		semaphore: make(chan struct{}, 10),
	}
}

// StoreAsync implements harness.GraphRAGBridge. The finding is stored
// asynchronously; errors are logged at WARN level and do not propagate.
func (b *asyncBridge) StoreAsync(ctx context.Context, finding agentpkg.Finding, missionID types.ID, targetID *types.ID) {
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()

		select {
		case b.semaphore <- struct{}{}:
		case <-ctx.Done():
			b.logger.Warn("StoreAsync: context cancelled while waiting for semaphore",
				"finding_id", finding.ID,
			)
			return
		}
		defer func() { <-b.semaphore }()

		// Use a background context so shutdown doesn't kill in-flight stores.
		storageCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Propagate the tenant from the original request context.
		tenant, ok := auth.TenantFromContext(ctx)
		if !ok || tenant.IsZero() {
			b.logger.Warn("StoreAsync: no tenant in context; skipping async store",
				"finding_id", finding.ID,
			)
			return
		}
		storageCtx = auth.WithTenant(storageCtx, tenant)

		qb, release, err := b.adapter.buildEphemeralQueryBridge(storageCtx)
		if err != nil {
			b.logger.Warn("StoreAsync: failed to build ephemeral bridge",
				"finding_id", finding.ID,
				"error", err,
			)
			return
		}
		defer release()

		// Use the query bridge's StoreNode to persist the finding.
		node := sdkgraphrag.GraphNode{
			ID:      finding.ID.String(),
			Content: finding.Description,
			Type:    "Finding",
		}
		if _, storeErr := qb.StoreNode(storageCtx, node, missionID.String(), ""); storeErr != nil {
			b.logger.Warn("StoreAsync: failed to store finding node",
				"finding_id", finding.ID,
				"error", storeErr,
			)
		}
	}()
}

// Shutdown waits for all pending async storage operations to complete.
func (b *asyncBridge) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		b.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("graphrag async bridge shutdown: context cancelled: %w", ctx.Err())
	}
}

// Health implements harness.GraphRAGBridge.
func (b *asyncBridge) Health(ctx context.Context) types.HealthStatus {
	return b.adapter.Health(ctx)
}
