package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	sdkmemory "github.com/zero-day-ai/sdk/memory"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// ContinuityOpts holds parameters for cross-run memory continuity.
type ContinuityOpts struct {
	// Mode controls how mission memory is shared across runs.
	Mode memory.MemoryContinuityMode

	// PreviousMissionID is the mission ID of the prior run (for inherit/shared modes).
	PreviousMissionID types.ID

	// MissionName is the human-readable name shared across runs.
	MissionName string
}

// MemoryManagerFactory creates MemoryManager instances for missions.
//
// Each mission needs isolated memory storage so agents can use working memory,
// mission memory, and long-term memory without cross-mission contamination.
// The factory ensures consistent configuration across all memory managers while
// scoping storage to individual missions.
//
// Long-term memory uses a **shared** vector store across all missions so that
// semantic search can surface cross-mission patterns and findings. Mission memory
// and working memory remain per-mission scoped.
//
// The factory is initialized once during daemon startup and reused for all
// mission memory manager creation.
//
// Redis Architecture:
// The factory creates Redis-backed memory stores:
//   - Working memory: SDK RedisWorkingMemory (distributed, ephemeral)
//   - Mission memory: RedisMissionMemory (persistent, with FTS, configurable TTL)
//   - Long-term memory: Shared vector store for cross-mission semantic search
type MemoryManagerFactory struct {
	// stateClient provides Redis connectivity for distributed memory stores
	stateClient *state.StateClient

	// config is the memory configuration to apply to all managers
	config *memory.MemoryConfig

	// pool is the Phase D per-tenant data-plane pool. When set, CreateForMission
	// acquires a Conn for the tenant and uses the per-tenant Redis client for
	// ConnBoundMissionMemory. Falls back to the stateClient (global, prefixed)
	// when pool is nil or when the tenant string is empty/invalid.
	pool datapool.Pool

	// sharedLongTerm is the cross-mission long-term memory instance.
	// Created lazily on first use and reused for all missions.
	sharedLongTerm memory.LongTermMemory

	// sharedVectorStore is the backing vector store for shared long-term memory.
	sharedVectorStore vector.VectorStore

	// sharedEmbedder is the embedder instance reused across missions.
	sharedEmbedder embedder.Embedder
}

// SetPool wires the Phase D per-tenant data-plane pool into the factory.
// When set, CreateForMission uses the per-tenant Redis client from Pool.For
// rather than the global stateClient for mission memory.
// Safe to call at any time before CreateForMission is first called.
func (f *MemoryManagerFactory) SetPool(p datapool.Pool) {
	f.pool = p
}

// NewMemoryManagerFactory creates a new MemoryManagerFactory.
//
// Parameters:
//   - stateClient: Redis client for distributed memory stores (required)
//   - config: Memory configuration (uses defaults if nil)
//
// Returns:
//   - *MemoryManagerFactory: Ready to create memory managers
//   - error: Non-nil if validation fails
func NewMemoryManagerFactory(stateClient *state.StateClient, config *memory.MemoryConfig) (*MemoryManagerFactory, error) {
	if stateClient == nil {
		return nil, fmt.Errorf("state client cannot be nil")
	}

	// Apply defaults if config is nil
	if config == nil {
		config = memory.NewDefaultMemoryConfig()
	} else {
		config.ApplyDefaults()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("memory configuration validation failed: %w", err)
	}

	return &MemoryManagerFactory{
		stateClient: stateClient,
		config:      config,
	}, nil
}

// CreateForMission creates a new MemoryManager scoped to a specific mission and tenant.
//
// Each mission receives a fresh MemoryManager with:
//   - Working memory: Redis-backed for distributed, ephemeral storage
//   - Mission memory: Redis-backed with RediSearch for full-text search
//   - Long-term memory: Vector store for semantic search
//
// The MemoryManager should be closed when the mission completes to release
// resources (working memory is cleared, vector store is closed).
//
// Parameters:
//   - ctx: Context for initialization operations
//   - missionID: The mission ID to scope this memory manager to
//   - tenantID: Tenant identifier for defense-in-depth memory isolation.
//     When non-empty, all Redis keys and search queries are scoped per-tenant.
//     When empty, the backward-compatible key format (no tenant prefix) is used.
//
// Returns:
//   - memory.MemoryManager: Configured memory manager for the mission
//   - error: Non-nil if creation or initialization fails
func (f *MemoryManagerFactory) CreateForMission(ctx context.Context, missionID types.ID, tenantID string) (memory.MemoryManager, error) {
	return f.CreateForMissionWithContinuity(ctx, missionID, tenantID, nil)
}

// CreateForMissionWithContinuity creates a MemoryManager with optional cross-run continuity.
//
// When continuity is nil or mode is Isolated, behavior is identical to CreateForMission.
// When mode is Inherit, the mission memory can read values from the previous run.
// When mode is Shared, all runs of the same mission name share a memory namespace.
//
// Long-term memory is always shared across missions for cross-run pattern learning.
func (f *MemoryManagerFactory) CreateForMissionWithContinuity(ctx context.Context, missionID types.ID, tenantID string, continuity *ContinuityOpts) (memory.MemoryManager, error) {
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID cannot be zero")
	}

	if err := missionID.Validate(); err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	return f.createRedisBackedManager(ctx, missionID, tenantID, continuity)
}

// createRedisBackedManager creates a MemoryManager with Redis-backed working and mission memory.
//
// It creates:
//   - Working memory: SDK RedisWorkingMemory (distributed, ephemeral) wrapped with adapter
//   - Mission memory: ConnBoundMissionMemory (per-tenant Redis client, Phase D) when a Pool
//     and valid tenantID are available, otherwise RedisMissionMemory (global, prefixed).
//   - Long-term memory: Vector store for semantic search
//
// The Redis implementations provide distributed, high-performance storage suitable
// for multi-agent coordination and mission recovery after daemon restarts.
//
// Working memory uses an adapter to bridge SDK RedisWorkingMemory (context-based API)
// with Gibson's WorkingMemory interface (non-context API).
func (f *MemoryManagerFactory) createRedisBackedManager(ctx context.Context, missionID types.ID, tenantID string, continuity *ContinuityOpts) (memory.MemoryManager, error) {
	// Create Redis-backed working memory
	workingMem, err := f.createRedisWorkingMemory(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis working memory: %w", err)
	}

	var missionMem memory.MissionMemory

	// Phase D: use per-tenant Redis client from Pool when available.
	// The pool provides structural tenant isolation (per-tenant logical DB)
	// replacing the global stateClient with tenant-prefixed keys.
	if f.pool != nil && tenantID != "" {
		if tid, tidErr := sdkauth.NewTenantID(tenantID); tidErr == nil {
			if conn, connErr := f.pool.For(ctx, tid); connErr == nil {
				connOpts := []memory.ConnBoundMissionMemoryOption{
					memory.WithConnTTL(f.config.Mission.TTL),
				}
				if continuity != nil && continuity.Mode != memory.MemoryIsolated {
					connOpts = append(connOpts, memory.WithConnContinuity(
						continuity.Mode,
						continuity.PreviousMissionID,
					))
				}
				missionMem = memory.NewConnBoundMissionMemory(conn.Redis, missionID, connOpts...)
				// Release the Conn immediately: the per-tenant Redis client is long-lived
				// in the pool and remains valid after conn.Release(). MissionMemory operations
				// go directly through the client, not through the Conn lifecycle.
				conn.Release()
			}
			// If Pool.For fails (e.g., tenant not provisioned), fall through to legacy path below.
		}
	}

	// Fallback: global stateClient with tenant-prefixed keys (Phase C / single-tenant mode).
	if missionMem == nil {
		legacyOpts := []memory.RedisMissionMemoryOption{
			memory.WithTTL(f.config.Mission.TTL),
		}
		if continuity != nil && continuity.Mode != memory.MemoryIsolated {
			legacyOpts = append(legacyOpts, memory.WithContinuity(
				continuity.Mode,
				continuity.PreviousMissionID,
				continuity.MissionName,
			))
		}
		missionMem = memory.NewRedisMissionMemory(f.stateClient, missionID, tenantID, legacyOpts...)
	}

	// Get or create shared long-term memory (cross-mission vector store)
	longTermMem, vectorStore, err := f.getOrCreateSharedLongTermMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to create long-term memory: %w", err)
	}

	// Create MemoryManager with components
	return memory.NewMemoryManagerWithComponents(
		missionID,
		workingMem,
		missionMem,
		longTermMem,
		vectorStore,
	), nil
}

// getOrCreateSharedLongTermMemory returns the shared long-term memory and vector store.
// The embedder and vector store are created lazily on first call and reused for all
// subsequent missions. This enables cross-mission semantic search — agents can discover
// patterns and findings from prior missions via vector similarity.
func (f *MemoryManagerFactory) getOrCreateSharedLongTermMemory() (memory.LongTermMemory, vector.VectorStore, error) {
	if f.sharedLongTerm != nil {
		return f.sharedLongTerm, f.sharedVectorStore, nil
	}

	// Create embedder (reused across all missions)
	embedderCfg := embedder.EmbedderConfig{
		Provider: f.config.LongTerm.Embedder.Provider,
	}
	emb, err := embedder.CreateEmbedder(embedderCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create embedder: %w", err)
	}

	dims := emb.Dimensions()

	// Create a shared (non-mission-scoped) vector store.
	// For Redis backend, use the StateClient directly for persistent cross-mission storage.
	// For embedded backend, use a single shared in-memory store.
	var store vector.VectorStore

	if f.config.LongTerm.Backend == "redis" {
		store = vector.NewRedisVectorStore(f.stateClient, dims)
	} else {
		// Embedded: single shared in-memory store (not per-mission)
		store = vector.NewEmbeddedVectorStore(dims)
	}

	ltm := memory.NewLongTermMemory(store, emb)

	f.sharedEmbedder = emb
	f.sharedVectorStore = store
	f.sharedLongTerm = ltm

	return ltm, store, nil
}

// Config returns the memory configuration used by this factory.
//
// This is useful for testing and introspection.
func (f *MemoryManagerFactory) Config() *memory.MemoryConfig {
	return f.config
}

// StateClient returns the state client used by this factory.
//
// This is useful for testing and introspection.
func (f *MemoryManagerFactory) StateClient() *state.StateClient {
	return f.stateClient
}

// createRedisWorkingMemory creates a Redis-backed working memory instance.
//
// This method extracts a concrete *redis.Client from the StateClient's UniversalClient
// and wraps the SDK RedisWorkingMemory with an adapter to match Gibson's WorkingMemory interface.
//
// The working memory is scoped to the mission ID using a key prefix pattern:
// gibson:working:{mission_id}:*
func (f *MemoryManagerFactory) createRedisWorkingMemory(ctx context.Context, missionID types.ID) (memory.WorkingMemory, error) {
	// Extract the underlying Redis client from StateClient's UniversalClient
	// The StateClient uses redis.UniversalClient which can be:
	// - *redis.Client (standalone)
	// - *redis.ClusterClient (cluster mode)
	// - *redis.Ring (ring/sharding mode)
	//
	// For SDK RedisWorkingMemory, we need *redis.Client.
	// If StateClient is using cluster mode, we'll fall back to in-memory for now.
	universalClient := f.stateClient.Client()

	// Type assert to *redis.Client (standalone mode)
	redisClient, ok := universalClient.(*redis.Client)
	if !ok {
		// Cluster or Ring mode - SDK RedisWorkingMemory doesn't support UniversalClient yet
		// Fall back to in-memory working memory
		return memory.NewWorkingMemory(f.config.Working.MaxTokens), nil
	}

	// Configure SDK RedisWorkingMemory with mission-scoped prefix
	cfg := &sdkmemory.RedisConfig{
		Address:      "", // Already connected via redisClient
		KeyPrefix:    fmt.Sprintf("gibson:working:%s:", missionID),
		DefaultTTL:   1 * time.Hour, // Working memory expires after 1 hour of inactivity
		MaxValueSize: 1024 * 1024,   // 1MB per value
	}
	cfg.ApplyDefaults()

	// Create SDK RedisWorkingMemory
	sdkWorkingMem := sdkmemory.NewRedisWorkingMemory(redisClient, cfg)

	// Wrap with adapter to match Gibson's WorkingMemory interface
	return newWorkingMemoryAdapter(sdkWorkingMem), nil
}

// workingMemoryAdapter adapts SDK RedisWorkingMemory to Gibson's WorkingMemory interface.
//
// The SDK uses context-based methods (Get(ctx, key), Set(ctx, key, value))
// while Gibson's internal interface uses simpler methods (Get(key), Set(key, value)).
//
// This adapter bridges the gap by using context.Background() for all operations.
// In the future, Gibson's WorkingMemory interface could be updated to accept contexts.
type workingMemoryAdapter struct {
	sdk sdkmemory.WorkingMemory
}

// newWorkingMemoryAdapter creates a new adapter wrapping SDK RedisWorkingMemory.
func newWorkingMemoryAdapter(sdk sdkmemory.WorkingMemory) memory.WorkingMemory {
	return &workingMemoryAdapter{sdk: sdk}
}

// Get retrieves a value by key, returns nil and false if not found.
func (a *workingMemoryAdapter) Get(key string) (any, bool) {
	ctx := context.Background()
	val, err := a.sdk.Get(ctx, key)
	if err != nil {
		// SDK returns error for not found, we return (nil, false)
		return nil, false
	}
	return val, true
}

// Set stores a value with the given key.
func (a *workingMemoryAdapter) Set(key string, value any) error {
	ctx := context.Background()
	return a.sdk.Set(ctx, key, value)
}

// Delete removes an entry and returns true if it existed.
func (a *workingMemoryAdapter) Delete(key string) bool {
	ctx := context.Background()
	err := a.sdk.Delete(ctx, key)
	// SDK returns error if key doesn't exist, we return false
	return err == nil
}

// Clear removes all entries.
func (a *workingMemoryAdapter) Clear() {
	ctx := context.Background()
	_ = a.sdk.Clear(ctx) // Ignore errors on clear
}

// List returns all keys currently stored in no particular order.
func (a *workingMemoryAdapter) List() []string {
	ctx := context.Background()
	keys, err := a.sdk.Keys(ctx)
	if err != nil {
		return []string{}
	}
	return keys
}

// TokenCount returns an estimated token count (not implemented in SDK version).
// Returns 0 for Redis-backed working memory since token counting is not enforced.
func (a *workingMemoryAdapter) TokenCount() int {
	// Redis-backed working memory doesn't track token count
	// Token budget enforcement happens at a different layer
	return 0
}

// MaxTokens returns the configured token limit.
// Returns 0 for Redis-backed working memory since token counting is not enforced.
func (a *workingMemoryAdapter) MaxTokens() int {
	// Redis-backed working memory doesn't enforce token limits
	// Value-based limits (MaxValueSize) are enforced by SDK instead
	return 0
}
