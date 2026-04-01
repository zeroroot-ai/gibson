package component

// memory_resolver.go provides MemoryResolver, the interface that maps a
// work item ID to its mission-scoped MissionMemory instance, and
// RedisMemoryResolver, the production implementation backed by Redis.
//
// Design overview:
//
//  1. When the harness enqueues a work item it embeds mission_id in
//     WorkItem.Context (see harness/implementation.go callToolViaWorkQueue).
//
//  2. PollWork reads the WorkItem from Redis Streams and writes a short-lived
//     mapping key so that subsequent harness-proxy RPCs (MemoryGet, MemorySet,
//     MemorySearch) can look up the mission context from the work_id alone.
//
//  3. RedisMemoryResolver reads that mapping key, then lazily creates or
//     returns a cached *memory.RedisMissionMemory scoped to that mission.
//     Instances are held in a sync.Map so concurrent RPCs for the same mission
//     share one instance and avoid duplicate Redis connections.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

const (
	// workContextKeyPrefix is the Redis key prefix used to store
	// work-item-to-mission mappings written by PollWork.
	//
	//   gibson:work:ctx:{work_id}
	workContextKeyPrefix = "gibson:work:ctx:"

	// workContextTTL is how long the work-item→mission mapping is retained.
	// This must exceed the maximum possible agent execution time. The 4-hour
	// default is generous; a future config knob can tighten it.
	workContextTTL = 4 * time.Hour

	// workContextMissionField is the hash field that holds the mission ID inside
	// the work-context hash.
	workContextMissionField = "mission_id"

	// workContextTenantField is the hash field that holds the originating tenant.
	workContextTenantField = "tenant_id"
)

// workContextKey returns the Redis key for a work item's context hash.
func workContextKey(workID string) string {
	return workContextKeyPrefix + workID
}

// ---------------------------------------------------------------------------
// MemoryResolver interface
// ---------------------------------------------------------------------------

// MemoryResolver resolves a work item ID to its mission-scoped MissionMemory
// instance. ComponentServiceServer uses this to route MemoryGet, MemorySet, and
// MemorySearch to the correct per-mission namespace without holding a direct
// reference to every active mission.
//
// Implementors must handle missing work IDs gracefully:
//   - Return a wrapped codes.NotFound-compatible error when the mapping does
//     not exist so that callers can translate to the appropriate gRPC status.
type MemoryResolver interface {
	// ResolveForWork maps workID to the MissionMemory scoped to its mission.
	//
	// Parameters:
	//   - ctx:    request context (used for Redis calls and timeout propagation)
	//   - workID: the work_id from the MemoryRequest proto (never empty)
	//   - tenant: the calling tenant extracted from auth context
	//
	// Returns ErrWorkContextNotFound (wrapped in *types.GibsonError) when the
	// mapping has expired or was never registered; callers should surface this as
	// codes.NotFound.
	ResolveForWork(ctx context.Context, workID, tenant string) (memory.MissionMemory, error)

	// RegisterWorkContext writes the work-item→mission mapping so that a
	// subsequent ResolveForWork call can find it. Called by PollWork after
	// successfully claiming a work item that carries a mission_id in its context.
	//
	// This is a best-effort operation: if it fails the work item is still
	// dispatched to the agent; memory RPCs for that work item will return NotFound
	// rather than crashing.
	RegisterWorkContext(ctx context.Context, workID, missionID, tenantID string) error
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

// ErrWorkContextNotFound is returned by MemoryResolver when the work-item
// context mapping has expired or was never written.
const ErrCodeWorkContextNotFound types.ErrorCode = "WORK_CONTEXT_NOT_FOUND"

// NewWorkContextNotFoundError creates a typed error for missing work context.
func NewWorkContextNotFoundError(workID string) *types.GibsonError {
	return types.NewError(ErrCodeWorkContextNotFound,
		fmt.Sprintf("no mission context found for work item %q; mapping may have expired", workID))
}

// ---------------------------------------------------------------------------
// RedisMemoryResolver
// ---------------------------------------------------------------------------

// RedisMemoryResolver implements MemoryResolver using Redis for the
// work-item→mission mapping and caches *RedisMissionMemory instances in a
// sync.Map keyed by "{tenant}:{missionID}".
//
// Thread safety: all methods are safe for concurrent use. The sync.Map ensures
// that at most one RedisMissionMemory is created per mission even under
// concurrent requests.
type RedisMemoryResolver struct {
	stateClient *state.StateClient

	// cache maps "{tenant}:{missionID}" → memory.MissionMemory
	cache sync.Map
}

// Verify interface compliance at compile time.
var _ MemoryResolver = (*RedisMemoryResolver)(nil)

// NewRedisMemoryResolver creates a resolver backed by the provided StateClient.
// The stateClient is used for both the mapping lookups and the RedisMissionMemory
// instances it creates; it must already be connected and healthy.
func NewRedisMemoryResolver(stateClient *state.StateClient) *RedisMemoryResolver {
	return &RedisMemoryResolver{stateClient: stateClient}
}

// RegisterWorkContext writes a Redis hash at gibson:work:ctx:{work_id} with
// fields mission_id and tenant_id and a workContextTTL expiry.
//
// Empty missionID or tenantID arguments are allowed (the empty string is stored
// as-is) because some work items may be dispatched outside a mission context;
// callers that need mission memory must supply both.
func (r *RedisMemoryResolver) RegisterWorkContext(
	ctx context.Context,
	workID, missionID, tenantID string,
) error {
	if workID == "" {
		return fmt.Errorf("memory resolver: RegisterWorkContext: workID must not be empty")
	}

	key := workContextKey(workID)

	pipe := r.stateClient.Client().Pipeline()
	pipe.HSet(ctx, key,
		workContextMissionField, missionID,
		workContextTenantField, tenantID,
	)
	pipe.Expire(ctx, key, workContextTTL)

	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("memory resolver: failed to register work context for work %q: %w", workID, err)
	}

	return nil
}

// ResolveForWork looks up the work-item context from Redis, then returns a
// cached (or newly created) RedisMissionMemory scoped to the mission.
//
// Error conditions:
//   - work_id has no entry in Redis → NewWorkContextNotFoundError (callers map to NotFound)
//   - Redis unavailable → wrapped internal error
//   - missionID is empty in the stored mapping → NotFound (mapping was written without context)
func (r *RedisMemoryResolver) ResolveForWork(
	ctx context.Context,
	workID, tenant string,
) (memory.MissionMemory, error) {
	if workID == "" {
		return nil, fmt.Errorf("memory resolver: workID must not be empty")
	}

	key := workContextKey(workID)

	fields, err := r.stateClient.Client().HGetAll(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, NewWorkContextNotFoundError(workID)
		}
		return nil, fmt.Errorf("memory resolver: failed to fetch work context for work %q: %w", workID, err)
	}

	// HGetAll returns an empty map (not redis.Nil) when the key does not exist.
	if len(fields) == 0 {
		return nil, NewWorkContextNotFoundError(workID)
	}

	missionID := fields[workContextMissionField]
	if missionID == "" {
		// The mapping was registered but without a mission_id (e.g., the work
		// item was dispatched outside a mission). Memory access is not possible.
		return nil, NewWorkContextNotFoundError(workID)
	}

	// Use the stored tenantID to scope the RedisMissionMemory correctly,
	// falling back to the caller's tenant in case the field was not written.
	storedTenant := fields[workContextTenantField]
	if storedTenant == "" {
		storedTenant = tenant
	}

	// Cache key is tenant+mission so that two different tenants whose missions
	// happen to have the same ID (UUID collision is astronomically unlikely but
	// logically possible) get isolated instances.
	cacheKey := storedTenant + ":" + missionID

	// Load or store: if another goroutine is already creating this instance we
	// will get theirs; both paths are equivalent since RedisMissionMemory is
	// stateless with respect to the Redis connection.
	if cached, ok := r.cache.Load(cacheKey); ok {
		return cached.(memory.MissionMemory), nil
	}

	mm := memory.NewRedisMissionMemory(r.stateClient, types.ID(missionID), storedTenant)

	// LoadOrStore is safe: if two goroutines race here we simply discard the
	// duplicate; both RedisMissionMemory values are equivalent wrappers.
	actual, _ := r.cache.LoadOrStore(cacheKey, mm)
	return actual.(memory.MissionMemory), nil
}
