// Package quota — quota_test.go
//
// Race-safe tests for RedisQuota (Tasks 39, 41,
// setec-sandbox-prod-default §"Resource quotas" R4.1, R4.2).
//
// All tests are hermetic: miniredis replaces a real Redis instance.
// Run with -race.
package quota

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func newTestQuota(t *testing.T, maxConcurrent int64) (*RedisQuota, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	client := goredis.NewUniversalClient(&goredis.UniversalOptions{Addrs: []string{mr.Addr()}})
	t.Cleanup(func() { _ = client.Close() })

	q := NewRedisQuota(client, Config{MaxConcurrentDetonations: maxConcurrent})
	return q, mr
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestAcquireRelease verifies the basic acquire/release cycle.
func TestAcquireRelease(t *testing.T) {
	t.Parallel()
	q, _ := newTestQuota(t, 5)
	ctx := context.Background()

	require.NoError(t, q.Acquire(ctx, "tenant-1"))
	n, err := q.CurrentConcurrent(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	q.Release(ctx, "tenant-1")
	n, err = q.CurrentConcurrent(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// TestConcurrentCapEnforced verifies that exactly cap=N goroutines succeed
// when N+1 goroutines compete for the quota simultaneously.
func TestConcurrentCapEnforced(t *testing.T) {
	t.Parallel()

	const cap = 5
	const attempts = cap + 1 // one extra should be rejected

	q, _ := newTestQuota(t, cap)
	ctx := context.Background()

	var (
		mu        sync.Mutex
		succeeded []int
		failed    []int
	)

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			err := q.Acquire(ctx, "tenant-cap")
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				succeeded = append(succeeded, i)
			} else {
				failed = append(failed, i)
			}
		}()
	}
	wg.Wait()

	assert.Len(t, succeeded, cap,
		"exactly %d goroutines should succeed with cap=%d", cap, cap)
	assert.Len(t, failed, 1,
		"exactly 1 goroutine should fail")
}

// TestQuotaExceededError verifies that ErrQuotaExceeded is wrapped in the
// returned error so callers can use errors.Is.
func TestQuotaExceededError(t *testing.T) {
	t.Parallel()

	q, _ := newTestQuota(t, 1)
	ctx := context.Background()

	require.NoError(t, q.Acquire(ctx, "tenant-exceed"))

	err := q.Acquire(ctx, "tenant-exceed")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrQuotaExceeded,
		"error must wrap ErrQuotaExceeded")
	assert.Contains(t, err.Error(), "max_concurrent_detonations=1",
		"error message must contain the cap value (design Scenario 5)")
}

// TestUnlimitedQuota verifies that cap=0 (unlimited) allows any number of
// concurrent acquires.
func TestUnlimitedQuota(t *testing.T) {
	t.Parallel()

	q, _ := newTestQuota(t, 0) // unlimited
	ctx := context.Background()

	for i := 0; i < 100; i++ {
		err := q.Acquire(ctx, "tenant-unlimited")
		assert.NoError(t, err, "acquire %d should succeed with unlimited cap", i)
	}
}

// TestReleaseDecrementsCounter verifies that Release actually decrements the
// counter so a subsequent Acquire succeeds after the cap was reached.
func TestReleaseDecrementsCounter(t *testing.T) {
	t.Parallel()

	q, _ := newTestQuota(t, 2)
	ctx := context.Background()

	require.NoError(t, q.Acquire(ctx, "tenant-release"))
	require.NoError(t, q.Acquire(ctx, "tenant-release"))

	// At cap — next acquire must fail.
	err := q.Acquire(ctx, "tenant-release")
	require.ErrorIs(t, err, ErrQuotaExceeded)

	// Release one slot.
	q.Release(ctx, "tenant-release")

	// Now it should succeed.
	err = q.Acquire(ctx, "tenant-release")
	assert.NoError(t, err, "Acquire after Release should succeed")
}

// TestConcurrentSafeRelease hammers Acquire/Release from many goroutines
// and verifies the counter returns to zero when all goroutines finish.
func TestConcurrentSafeRelease(t *testing.T) {
	t.Parallel()

	const (
		cap      = 10
		workers  = 50
		attempts = 200
	)

	q, _ := newTestQuota(t, cap)
	ctx := context.Background()

	var (
		acquired int64 // atomic
		denied   int64
	)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < attempts/workers; j++ {
				if err := q.Acquire(ctx, "tenant-concurrent"); err == nil {
					atomic.AddInt64(&acquired, 1)
					// simulate some work
					time.Sleep(time.Microsecond)
					q.Release(ctx, "tenant-concurrent")
				} else {
					atomic.AddInt64(&denied, 1)
				}
			}
		}()
	}
	wg.Wait()

	// After all goroutines finish the counter must be zero.
	n, err := q.CurrentConcurrent(ctx, "tenant-concurrent")
	require.NoError(t, err)
	assert.Equal(t, int64(0), n,
		"all releases must balance all acquires; counter must be 0 after all goroutines exit")

	t.Logf("acquired=%d denied=%d", acquired, denied)
}

// TestTenantIsolation verifies that quota counters for different tenants
// are independent — exhausting one tenant's quota doesn't affect another.
func TestTenantIsolation(t *testing.T) {
	t.Parallel()

	q, _ := newTestQuota(t, 1)
	ctx := context.Background()

	// Exhaust tenant-A's quota.
	require.NoError(t, q.Acquire(ctx, "tenant-A"))
	require.ErrorIs(t, q.Acquire(ctx, "tenant-A"), ErrQuotaExceeded)

	// Tenant-B is unaffected.
	require.NoError(t, q.Acquire(ctx, "tenant-B"),
		"tenant-B quota must be independent of tenant-A")
}

// TestNoopQuota verifies that NoopQuota always succeeds.
func TestNoopQuota(t *testing.T) {
	t.Parallel()

	q := NoopQuota{}
	ctx := context.Background()

	for i := 0; i < 1000; i++ {
		assert.NoError(t, q.Acquire(ctx, "any-tenant"))
	}
	q.Release(ctx, "any-tenant") // no-op; must not panic
}
