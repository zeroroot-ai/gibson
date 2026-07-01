package secrets

// auth_cache_test.go — tests for the per-(tenant, provider) auth-token cache.
//
// Key assertion: 1 000 concurrent GetOrRefresh calls against a fake
// AuthRefreshFn with a 60-second "token TTL" must produce ≤ 10 actual
// refresh calls (i.e. the singleflight + TTL cache reduces auth churn by
// at least 99 %).
//
// Spec: secrets-broker NFR Performance, Requirement 9.6.

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRefreshFn returns a simple counter-based AuthRefreshFn for testing.
// It records how many times it has been called and returns a fixed token
// and the supplied ttl.
func fakeRefreshFn(callCount *atomic.Int64, ttl time.Duration) AuthRefreshFn {
	return func(_ context.Context, _, _ string) (string, time.Duration, error) {
		n := callCount.Add(1)
		return fmt.Sprintf("token-%d", n), ttl, nil
	}
}

// TestAuthCache_HitReturnsCachedToken verifies that a second GetOrRefresh call
// within the effective TTL window returns the same token without calling the
// refresh function a second time.
func TestAuthCache_HitReturnsCachedToken(t *testing.T) {
	var calls atomic.Int64
	cache := NewAuthCache(fakeRefreshFn(&calls, 60*time.Second), slog.Default(), nil)

	ctx := context.Background()
	tok1, err := cache.GetOrRefresh(ctx, "tenant-a", "vault")
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok1)

	tok2, err := cache.GetOrRefresh(ctx, "tenant-a", "vault")
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok2, "second call should return cached token")

	assert.Equal(t, int64(1), calls.Load(), "refresh must be called only once for two in-TTL requests")
}

// TestAuthCache_MissAfterExpiry verifies that after the effective TTL has
// elapsed a new token is fetched.
func TestAuthCache_MissAfterExpiry(t *testing.T) {
	var calls atomic.Int64

	// Fake clock starts at a fixed point; we advance it manually.
	now := time.Now()
	clockMu := sync.Mutex{}
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		now = now.Add(d)
	}

	// Token TTL is 10 s; effective TTL is 8 s (80 %).
	cache := NewAuthCache(fakeRefreshFn(&calls, 10*time.Second), slog.Default(), clock)

	ctx := context.Background()
	tok1, err := cache.GetOrRefresh(ctx, "tenant-b", "vault")
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok1)

	// Advance time past the effective TTL (8 s).
	advance(9 * time.Second)

	tok2, err := cache.GetOrRefresh(ctx, "tenant-b", "vault")
	require.NoError(t, err)
	assert.Equal(t, "token-2", tok2, "expired entry should trigger a refresh")
	assert.Equal(t, int64(2), calls.Load())
}

// TestAuthCache_1000RPS asserts that 1 000 concurrent GetOrRefresh calls
// against a single (tenant, provider) pair with a 60-second token TTL trigger
// at most 10 actual refresh calls (singleflight + TTL cache dramatically
// reduces auth churn).
func TestAuthCache_1000RPS(t *testing.T) {
	var calls atomic.Int64

	// Each token is valid for 60 s; effective TTL = 48 s. All 1 000 calls
	// happen in a negligible time window so only 1 refresh should fire.
	cache := NewAuthCache(fakeRefreshFn(&calls, 60*time.Second), slog.Default(), nil)

	ctx := context.Background()
	const n = 1000

	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, err := cache.GetOrRefresh(ctx, "tenant-c", "vault")
			if err != nil {
				t.Errorf("GetOrRefresh returned unexpected error: %v", err)
			}
		}()
	}
	wg.Wait()

	actualCalls := calls.Load()
	assert.LessOrEqual(t, actualCalls, int64(10),
		"1000 concurrent requests should produce ≤ 10 refresh calls; got %d", actualCalls)
}

// TestAuthCache_Invalidate verifies that Invalidate evicts the cached token
// so the next GetOrRefresh fetches a new one.
func TestAuthCache_Invalidate(t *testing.T) {
	var calls atomic.Int64
	cache := NewAuthCache(fakeRefreshFn(&calls, 60*time.Second), slog.Default(), nil)

	ctx := context.Background()
	tok1, err := cache.GetOrRefresh(ctx, "tenant-d", "vault")
	require.NoError(t, err)
	assert.Equal(t, "token-1", tok1)

	cache.Invalidate("tenant-d", "vault")

	tok2, err := cache.GetOrRefresh(ctx, "tenant-d", "vault")
	require.NoError(t, err)
	assert.Equal(t, "token-2", tok2, "after invalidation a new token should be fetched")
	assert.Equal(t, int64(2), calls.Load())
}

// TestAuthCache_InvalidateAll verifies that InvalidateAll clears all cached
// tokens for a tenant across all providers.
func TestAuthCache_InvalidateAll(t *testing.T) {
	var hostedCalls, byoCalls atomic.Int64

	hostedRefresh := func(_ context.Context, _, _ string) (string, time.Duration, error) {
		n := hostedCalls.Add(1)
		return fmt.Sprintf("hosted-token-%d", n), 60 * time.Second, nil
	}
	byoRefresh := func(_ context.Context, _, _ string) (string, time.Duration, error) {
		n := byoCalls.Add(1)
		return fmt.Sprintf("byo-token-%d", n), 60 * time.Second, nil
	}

	ctx := context.Background()

	// Cache A: Vault Hosted provider for tenant-e
	cacheHosted := NewAuthCache(hostedRefresh, slog.Default(), nil)
	_, err := cacheHosted.GetOrRefresh(ctx, "tenant-e", "vault")
	require.NoError(t, err)

	// Cache B: a second provider label for tenant-e (in production a single
	// AuthCache services all providers; here we use two for isolation of the
	// per-provider counter).
	cacheBYO := NewAuthCache(byoRefresh, slog.Default(), nil)
	_, err = cacheBYO.GetOrRefresh(ctx, "tenant-e", "vault-byo")
	require.NoError(t, err)

	// Invalidate all tokens for tenant-e in each cache.
	cacheHosted.InvalidateAll("tenant-e")
	cacheBYO.InvalidateAll("tenant-e")

	// Both caches should trigger a second refresh call.
	_, err = cacheHosted.GetOrRefresh(ctx, "tenant-e", "vault")
	require.NoError(t, err)
	assert.Equal(t, int64(2), hostedCalls.Load(), "hosted refresh should fire again after InvalidateAll")

	_, err = cacheBYO.GetOrRefresh(ctx, "tenant-e", "vault-byo")
	require.NoError(t, err)
	assert.Equal(t, int64(2), byoCalls.Load(), "byo refresh should fire again after InvalidateAll")
}

// TestAuthCache_DifferentTenantsDontCollide verifies that tokens for separate
// tenants are stored independently and do not overwrite each other.
func TestAuthCache_DifferentTenantsDontCollide(t *testing.T) {
	var calls atomic.Int64
	cache := NewAuthCache(fakeRefreshFn(&calls, 60*time.Second), slog.Default(), nil)

	ctx := context.Background()

	tok1, err := cache.GetOrRefresh(ctx, "tenant-f", "vault")
	require.NoError(t, err)

	tok2, err := cache.GetOrRefresh(ctx, "tenant-g", "vault")
	require.NoError(t, err)

	assert.NotEqual(t, tok1, tok2, "different tenants must receive different tokens")
	assert.Equal(t, int64(2), calls.Load(), "one refresh per tenant")

	// Now verify that subsequent calls for each tenant still return the
	// originally cached tokens.
	tokF2, err := cache.GetOrRefresh(ctx, "tenant-f", "vault")
	require.NoError(t, err)
	assert.Equal(t, tok1, tokF2, "tenant-f should still have its original cached token")

	assert.Equal(t, int64(2), calls.Load(), "no additional refreshes should have occurred")
}

// TestAuthCache_RefreshError verifies that when the refresh function returns
// an error, GetOrRefresh propagates it and does not cache a bad entry.
func TestAuthCache_RefreshError(t *testing.T) {
	failOnce := true
	var mu sync.Mutex
	refreshFn := func(_ context.Context, _, _ string) (string, time.Duration, error) {
		mu.Lock()
		defer mu.Unlock()
		if failOnce {
			failOnce = false
			return "", 0, fmt.Errorf("upstream auth failed: connection refused")
		}
		return "good-token", 60 * time.Second, nil
	}

	cache := NewAuthCache(refreshFn, slog.Default(), nil)
	ctx := context.Background()

	// First call should fail.
	_, err := cache.GetOrRefresh(ctx, "tenant-h", "vault")
	require.Error(t, err, "refresh error should propagate")

	// Second call should succeed (nothing was cached on failure).
	tok, err := cache.GetOrRefresh(ctx, "tenant-h", "vault")
	require.NoError(t, err)
	assert.Equal(t, "good-token", tok)
}

// TestAuthCache_EffectiveTTL verifies that the effective TTL is 80 % of the
// issued TTL by asserting the cache treats a token as expired at 81 % of the
// issued TTL but still valid at 79 %.
func TestAuthCache_EffectiveTTL(t *testing.T) {
	var calls atomic.Int64

	issuedTTL := 100 * time.Second
	effectiveTTL := time.Duration(float64(issuedTTL) * authCacheTTLFraction) // 80 s

	now := time.Now()
	clockMu := sync.Mutex{}
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}
	advance := func(d time.Duration) {
		clockMu.Lock()
		defer clockMu.Unlock()
		now = now.Add(d)
	}

	cache := NewAuthCache(fakeRefreshFn(&calls, issuedTTL), slog.Default(), clock)
	ctx := context.Background()

	_, err := cache.GetOrRefresh(ctx, "tenant-i", "vault")
	require.NoError(t, err)
	assert.Equal(t, int64(1), calls.Load())

	// 79 % of the issued TTL — still within the effective TTL.
	advance(time.Duration(float64(issuedTTL) * 0.79))
	_, err = cache.GetOrRefresh(ctx, "tenant-i", "vault")
	require.NoError(t, err)
	assert.Equal(t, int64(1), calls.Load(), "should be a cache hit at 79% of issued TTL")

	// Advance to just past the effective TTL (80 %).
	advance(effectiveTTL - time.Duration(float64(issuedTTL)*0.79) + time.Millisecond)
	_, err = cache.GetOrRefresh(ctx, "tenant-i", "vault")
	require.NoError(t, err)
	assert.Equal(t, int64(2), calls.Load(), "should miss past effective TTL (80%)")
}

// TestAuthCache_ConcurrentInvalidate verifies that concurrent calls to
// GetOrRefresh and Invalidate do not race or deadlock.
func TestAuthCache_ConcurrentInvalidate(t *testing.T) {
	var calls atomic.Int64
	cache := NewAuthCache(fakeRefreshFn(&calls, 5*time.Second), slog.Default(), nil)

	ctx := context.Background()
	var wg sync.WaitGroup
	const goroutines = 50

	for i := 0; i < goroutines; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = cache.GetOrRefresh(ctx, "tenant-j", "vault")
		}()
		go func() {
			defer wg.Done()
			cache.Invalidate("tenant-j", "vault")
		}()
	}
	wg.Wait()
	// If we reach here without a race-detector failure, the test passes.
}
