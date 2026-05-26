package ratelimit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/ratelimit"
)

// newTestClient starts an in-process miniredis server and returns a Redis
// client wired to it. The server is closed automatically when the test ends.
func newTestClient(t *testing.T) redis.UniversalClient {
	t.Helper()
	mr := miniredis.RunT(t)
	return redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

// TestTenantLimiter_AllowsUnderLimit verifies that requests below the
// configured threshold all succeed.
func TestTenantLimiter_AllowsUnderLimit(t *testing.T) {
	client := newTestClient(t)
	limits := map[string]ratelimit.RateLimit{
		"ExecuteLLM": {RequestsPerMinute: 10},
	}
	limiter := ratelimit.NewRedisLimiter(client, limits)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		err := limiter.Check(ctx, "tenant-a", "ExecuteLLM")
		require.NoError(t, err, "call %d should be allowed", i+1)
	}
}

// TestTenantLimiter_BlocksOnEleventhCall verifies that the 11th call within a
// minute is rejected when the limit is 10.
func TestTenantLimiter_BlocksOnEleventhCall(t *testing.T) {
	client := newTestClient(t)
	limits := map[string]ratelimit.RateLimit{
		"ExecuteLLM": {RequestsPerMinute: 10},
	}
	limiter := ratelimit.NewRedisLimiter(client, limits)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		require.NoError(t, limiter.Check(ctx, "tenant-a", "ExecuteLLM"))
	}

	err := limiter.Check(ctx, "tenant-a", "ExecuteLLM")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ratelimit.ErrRateLimited),
		"expected ErrRateLimited, got %v", err)
}

// TestTenantLimiter_TenantsAreIsolated verifies that tenant-a exhausting its
// bucket does not affect tenant-b.
func TestTenantLimiter_TenantsAreIsolated(t *testing.T) {
	client := newTestClient(t)
	limits := map[string]ratelimit.RateLimit{
		"ExecuteLLM": {RequestsPerMinute: 5},
	}
	limiter := ratelimit.NewRedisLimiter(client, limits)
	ctx := context.Background()

	// Exhaust tenant-a.
	for i := 0; i < 5; i++ {
		require.NoError(t, limiter.Check(ctx, "tenant-a", "ExecuteLLM"))
	}
	require.Error(t, limiter.Check(ctx, "tenant-a", "ExecuteLLM"))

	// tenant-b must be unaffected.
	err := limiter.Check(ctx, "tenant-b", "ExecuteLLM")
	assert.NoError(t, err, "tenant-b should not be affected by tenant-a exhaustion")
}

// TestTenantLimiter_RPCsHaveIndependentBuckets verifies that exhausting the
// limit for one RPC name does not affect another.
func TestTenantLimiter_RPCsHaveIndependentBuckets(t *testing.T) {
	client := newTestClient(t)
	limits := map[string]ratelimit.RateLimit{
		"ExecuteLLM": {RequestsPerMinute: 3},
		"StreamLLM":  {RequestsPerMinute: 1000},
	}
	limiter := ratelimit.NewRedisLimiter(client, limits)
	ctx := context.Background()

	// Exhaust ExecuteLLM for tenant-a.
	for i := 0; i < 3; i++ {
		require.NoError(t, limiter.Check(ctx, "tenant-a", "ExecuteLLM"))
	}
	require.Error(t, limiter.Check(ctx, "tenant-a", "ExecuteLLM"),
		"ExecuteLLM should be rate limited")

	// StreamLLM for the same tenant must remain unaffected.
	err := limiter.Check(ctx, "tenant-a", "StreamLLM")
	assert.NoError(t, err, "StreamLLM bucket must be independent from ExecuteLLM")
}

// TestTenantLimiter_UnknownRPCAlwaysAllowed verifies that an RPC not present
// in the limits map is never blocked.
func TestTenantLimiter_UnknownRPCAlwaysAllowed(t *testing.T) {
	client := newTestClient(t)
	limits := map[string]ratelimit.RateLimit{} // empty — no limits configured
	limiter := ratelimit.NewRedisLimiter(client, limits)
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		require.NoError(t, limiter.Check(ctx, "tenant-a", "SomeUnknownRPC"))
	}
}

// TestTenantLimiter_EmptyTenantAlwaysAllowed verifies that an empty tenantID
// bypasses the limiter (graceful degradation when auth context is missing).
func TestTenantLimiter_EmptyTenantAlwaysAllowed(t *testing.T) {
	client := newTestClient(t)
	limits := map[string]ratelimit.RateLimit{
		"ExecuteLLM": {RequestsPerMinute: 1},
	}
	limiter := ratelimit.NewRedisLimiter(client, limits)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		require.NoError(t, limiter.Check(ctx, "", "ExecuteLLM"),
			"empty tenantID should always be allowed")
	}
}

// TestTenantLimiter_DefaultLimitsApplied verifies that passing nil for limits
// applies the DefaultLimits map (ExecuteLLM=1000, StreamLLM=1000,
// TestProvider=10).
func TestTenantLimiter_DefaultLimitsApplied(t *testing.T) {
	client := newTestClient(t)
	limiter := ratelimit.NewRedisLimiter(client, nil) // use defaults
	ctx := context.Background()

	// TestProvider default is 10 — the 11th call should be rate-limited.
	for i := 0; i < 10; i++ {
		require.NoError(t, limiter.Check(ctx, "tenant-defaults", "TestProvider"))
	}
	err := limiter.Check(ctx, "tenant-defaults", "TestProvider")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ratelimit.ErrRateLimited))
}
