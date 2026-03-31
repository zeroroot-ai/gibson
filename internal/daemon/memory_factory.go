package daemon

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	sdkmemory "github.com/zero-day-ai/sdk/memory"

	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MemoryManagerFactory creates MemoryManager instances for missions.
//
// Each mission needs isolated memory storage so agents can use working memory,
// mission memory, and long-term memory without cross-mission contamination.
// The factory ensures consistent configuration across all memory managers while
// scoping storage to individual missions.
//
// The factory is initialized once during daemon startup and reused for all
// mission memory manager creation.
//
// Redis Architecture:
// The factory creates Redis-backed memory stores:
//   - Working memory: SDK RedisWorkingMemory (distributed, ephemeral)
//   - Mission memory: RedisMissionMemory (persistent, with FTS)
//   - Long-term memory: Vector store for semantic search
type MemoryManagerFactory struct {
	// stateClient provides Redis connectivity for distributed memory stores
	stateClient *state.StateClient

	// config is the memory configuration to apply to all managers
	config *memory.MemoryConfig
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
	if missionID.IsZero() {
		return nil, fmt.Errorf("mission ID cannot be zero")
	}

	// Validate mission ID
	if err := missionID.Validate(); err != nil {
		return nil, fmt.Errorf("invalid mission ID: %w", err)
	}

	return f.createRedisBackedManager(ctx, missionID, tenantID)
}

// createRedisBackedManager creates a MemoryManager with Redis-backed working and mission memory.
//
// It creates:
//   - Working memory: SDK RedisWorkingMemory (distributed, ephemeral) wrapped with adapter
//   - Mission memory: RedisMissionMemory with RediSearch for full-text search and tenant isolation
//   - Long-term memory: Vector store for semantic search
//
// The Redis implementations provide distributed, high-performance storage suitable
// for multi-agent coordination and mission recovery after daemon restarts.
//
// Working memory uses an adapter to bridge SDK RedisWorkingMemory (context-based API)
// with Gibson's WorkingMemory interface (non-context API).
func (f *MemoryManagerFactory) createRedisBackedManager(ctx context.Context, missionID types.ID, tenantID string) (memory.MemoryManager, error) {
	// Create Redis-backed working memory
	workingMem, err := f.createRedisWorkingMemory(ctx, missionID)
	if err != nil {
		return nil, fmt.Errorf("failed to create Redis working memory: %w", err)
	}

	// Create Redis-backed mission memory scoped to the tenant for defense-in-depth isolation
	missionMem := memory.NewRedisMissionMemory(f.stateClient, missionID, tenantID)

	// Create long-term memory
	// This uses embedder and vector store
	longTermMem, vectorStore, err := f.createLongTermMemory(ctx, missionID)
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

// createLongTermMemory creates the long-term memory tier with embedder and vector store.
func (f *MemoryManagerFactory) createLongTermMemory(ctx context.Context, missionID types.ID) (memory.LongTermMemory, vector.VectorStore, error) {
	// Create embedder and vector store
	emb, vectorStore, err := f.createEmbedderAndVectorStore(missionID)
	if err != nil {
		return nil, nil, err
	}

	// Initialize long-term memory
	longTermMem := memory.NewLongTermMemory(vectorStore, emb)

	return longTermMem, vectorStore, nil
}

// createEmbedderAndVectorStore creates the embedder and vector store based on configuration.
func (f *MemoryManagerFactory) createEmbedderAndVectorStore(missionID types.ID) (embedder.Embedder, vector.VectorStore, error) {
	// Convert memory.EmbedderConfig to embedder.EmbedderConfig
	// Note: The embedder package only supports native (offline) embedding
	embedderCfg := embedder.EmbedderConfig{
		Provider: f.config.LongTerm.Embedder.Provider,
	}

	// Initialize embedder based on config
	emb, err := embedder.CreateEmbedder(embedderCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create embedder: %w", err)
	}

	// Get embedding dimensions from embedder
	dims := emb.Dimensions()

	// Determine storage path for vector store backend
	storagePath := f.config.LongTerm.StoragePath
	if storagePath == "" {
		// Default: use mission-scoped database in ~/.gibson/vectors/
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, memory.NewInvalidConfigError("failed to determine home directory: " + err.Error())
		}
		storagePath = fmt.Sprintf("%s/.gibson/vectors/%s.db", homeDir, missionID)
	}

	// Initialize vector store using factory
	vectorStore, err := vector.NewVectorStore(vector.VectorStoreConfig{
		Backend:     f.config.LongTerm.Backend,
		StoragePath: storagePath,
		Dimensions:  dims,
	})
	if err != nil {
		return nil, nil, memory.NewVectorStoreError("failed to create vector store", err)
	}

	return emb, vectorStore, nil
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
