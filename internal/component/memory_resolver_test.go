package component

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/memory"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// newTestMemoryResolver creates a RedisMemoryResolver backed by miniredis.
// The miniredis server and state client are cleaned up via t.Cleanup.
func newTestMemoryResolver(t *testing.T) (*RedisMemoryResolver, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err, "failed to create state client against miniredis")
	t.Cleanup(func() { _ = stateClient.Close() })

	return NewRedisMemoryResolver(stateClient), mr
}

// ---------------------------------------------------------------------------
// RegisterWorkContext tests
// ---------------------------------------------------------------------------

func TestRedisMemoryResolver_RegisterWorkContext_StoresMapping(t *testing.T) {
	resolver, mr := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-test-001"
	missionID := "mission-abc-123"
	tenantID := "tenant-acme"

	err := resolver.RegisterWorkContext(ctx, workID, missionID, tenantID)
	require.NoError(t, err)

	// Verify the hash fields exist in miniredis.
	// miniredis.HGet returns empty string when missing (no error return).
	key := workContextKey(workID)
	got := mr.HGet(key, workContextMissionField)
	assert.Equal(t, missionID, got)

	got = mr.HGet(key, workContextTenantField)
	assert.Equal(t, tenantID, got)
}

func TestRedisMemoryResolver_RegisterWorkContext_EmptyWorkIDReturnsError(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	err := resolver.RegisterWorkContext(ctx, "", "mission-abc", "tenant-acme")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "workID must not be empty")
}

func TestRedisMemoryResolver_RegisterWorkContext_SetsTTL(t *testing.T) {
	resolver, mr := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-ttl-test"
	err := resolver.RegisterWorkContext(ctx, workID, "mission-x", "tenant-y")
	require.NoError(t, err)

	key := workContextKey(workID)
	ttl := mr.TTL(key)
	// TTL should be workContextTTL (4 hours). Allow a small window for test
	// execution time but verify it is well above 0.
	assert.Greater(t, ttl, time.Duration(0))
	assert.LessOrEqual(t, ttl, workContextTTL)
}

// ---------------------------------------------------------------------------
// ResolveForWork tests
// ---------------------------------------------------------------------------

func TestRedisMemoryResolver_ResolveForWork_ReturnsMissionMemory(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-resolve-001"
	missionID := "mission-resolve-001"
	tenantID := "tenant-resolve"

	// Register the mapping first (simulates PollWork writing the entry).
	err := resolver.RegisterWorkContext(ctx, workID, missionID, tenantID)
	require.NoError(t, err)

	mm, err := resolver.ResolveForWork(ctx, workID, tenantID)
	require.NoError(t, err)
	require.NotNil(t, mm)

	// The returned MissionMemory must be scoped to the registered mission.
	assert.Equal(t, types.ID(missionID), mm.MissionID())
}

func TestRedisMemoryResolver_ResolveForWork_MissingMappingReturnsNotFound(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	_, err := resolver.ResolveForWork(ctx, "nonexistent-work-id", "tenant-acme")
	require.Error(t, err)

	var gibsonErr *types.GibsonError
	require.True(t, errors.As(err, &gibsonErr),
		"expected *types.GibsonError, got %T: %v", err, err)
	assert.Equal(t, ErrCodeWorkContextNotFound, gibsonErr.Code)
}

func TestRedisMemoryResolver_ResolveForWork_EmptyMissionIDInMappingReturnsNotFound(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-empty-mission"
	// Register with an empty missionID — happens when work is dispatched outside
	// a mission context (e.g., ad-hoc tool calls without a mission).
	err := resolver.RegisterWorkContext(ctx, workID, "", "tenant-acme")
	require.NoError(t, err)

	_, resolveErr := resolver.ResolveForWork(ctx, workID, "tenant-acme")
	require.Error(t, resolveErr)

	var gibsonErr *types.GibsonError
	require.True(t, errors.As(resolveErr, &gibsonErr))
	assert.Equal(t, ErrCodeWorkContextNotFound, gibsonErr.Code)
}

func TestRedisMemoryResolver_ResolveForWork_EmptyWorkIDReturnsError(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	_, err := resolver.ResolveForWork(ctx, "", "tenant-acme")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "workID must not be empty")
}

func TestRedisMemoryResolver_ResolveForWork_CachesInstance(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-cache-test"
	missionID := "mission-cache-001"
	tenantID := "tenant-cache"

	err := resolver.RegisterWorkContext(ctx, workID, missionID, tenantID)
	require.NoError(t, err)

	mm1, err := resolver.ResolveForWork(ctx, workID, tenantID)
	require.NoError(t, err)

	// Register a second work item that maps to the same mission.
	workID2 := "work-cache-test-2"
	err = resolver.RegisterWorkContext(ctx, workID2, missionID, tenantID)
	require.NoError(t, err)

	mm2, err := resolver.ResolveForWork(ctx, workID2, tenantID)
	require.NoError(t, err)

	// Both instances must resolve to the same mission ID.
	assert.Equal(t, mm1.MissionID(), mm2.MissionID())
}

func TestRedisMemoryResolver_ResolveForWork_UsesFallbackTenantFromContext(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-tenant-fallback"
	missionID := "mission-fallback-001"

	// RegisterWorkContext with empty tenantID — stored field will be empty.
	err := resolver.RegisterWorkContext(ctx, workID, missionID, "")
	require.NoError(t, err)

	// Resolve using the caller's tenant as fallback.
	mm, err := resolver.ResolveForWork(ctx, workID, "tenant-caller")
	require.NoError(t, err)
	require.NotNil(t, mm)
	assert.Equal(t, types.ID(missionID), mm.MissionID())
}

// ---------------------------------------------------------------------------
// Integration: RegisterWorkContext + ResolveForWork round-trip
// ---------------------------------------------------------------------------

func TestRedisMemoryResolver_RoundTrip_StoreAndRetrieve(t *testing.T) {
	resolver, _ := newTestMemoryResolver(t)
	ctx := context.Background()

	workID := "work-roundtrip-001"
	missionID := "mission-roundtrip-001"
	tenantID := "tenant-roundtrip"

	require.NoError(t, resolver.RegisterWorkContext(ctx, workID, missionID, tenantID))

	mm, err := resolver.ResolveForWork(ctx, workID, tenantID)
	require.NoError(t, err)
	require.NotNil(t, mm)
	assert.Equal(t, types.ID(missionID), mm.MissionID())

	// The returned instance must implement MissionMemory completely.
	var _ memory.MissionMemory = mm
}

// ---------------------------------------------------------------------------
// workContextKey helper
// ---------------------------------------------------------------------------

func TestWorkContextKey_Format(t *testing.T) {
	tests := []struct {
		workID   string
		expected string
	}{
		{"work-123", "gibson:work:ctx:work-123"},
		{"tool-nmap-1700000000000000000", "gibson:work:ctx:tool-nmap-1700000000000000000"},
	}

	for _, tt := range tests {
		t.Run(tt.workID, func(t *testing.T) {
			got := workContextKey(tt.workID)
			assert.Equal(t, tt.expected, got)
		})
	}
}
