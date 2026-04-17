package manifest

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newMiniredis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	return mr, redis.NewClient(&redis.Options{Addr: mr.Addr()})
}

func TestVersionStore_BumpIsMonotonic(t *testing.T) {
	_, rdb := newMiniredis(t)
	s := NewVersionStore(rdb, time.Second)
	ctx := context.Background()

	for want := uint64(1); want <= 5; want++ {
		got, err := s.Bump(ctx, "tenant-a")
		if err != nil {
			t.Fatalf("Bump: %v", err)
		}
		if got != want {
			t.Fatalf("Bump #%d = %d, want %d", want, got, want)
		}
	}
}

func TestVersionStore_BumpConcurrent(t *testing.T) {
	_, rdb := newMiniredis(t)
	s := NewVersionStore(rdb, time.Second)
	ctx := context.Background()

	const n = 100
	var wg sync.WaitGroup
	seen := make([]uint64, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := s.Bump(ctx, "tenant-concurrent")
			if err != nil {
				t.Errorf("Bump: %v", err)
				return
			}
			seen[i] = v
		}(i)
	}
	wg.Wait()

	// All values must be in [1..n] and unique.
	found := make(map[uint64]struct{}, n)
	for _, v := range seen {
		if v < 1 || v > uint64(n) {
			t.Fatalf("value %d outside [1..%d]", v, n)
		}
		if _, dup := found[v]; dup {
			t.Fatalf("duplicate value %d from concurrent Bump — INCR atomicity violated", v)
		}
		found[v] = struct{}{}
	}
}

// countingClient wraps a Redis client and counts calls to Get so we can
// confirm the in-memory cache actually short-circuits Redis.
type countingClient struct {
	inner    RedisVersionClient
	getCalls int64
}

func (c *countingClient) Incr(ctx context.Context, key string) *redis.IntCmd {
	return c.inner.Incr(ctx, key)
}

func (c *countingClient) Get(ctx context.Context, key string) *redis.StringCmd {
	atomic.AddInt64(&c.getCalls, 1)
	return c.inner.Get(ctx, key)
}

func TestVersionStore_Current_CacheShortCircuitsRedis(t *testing.T) {
	_, rdb := newMiniredis(t)
	cc := &countingClient{inner: rdb}
	// 1s cache; we'll issue two calls within the window.
	s := NewVersionStore(cc, time.Second)
	ctx := context.Background()

	// Prime with a Bump so Redis has a value (Bump also caches).
	if _, err := s.Bump(ctx, "tenant-c"); err != nil {
		t.Fatalf("Bump: %v", err)
	}

	v1, err := s.Current(ctx, "tenant-c")
	if err != nil || v1 != 1 {
		t.Fatalf("Current1 = %d err %v, want 1", v1, err)
	}
	v2, err := s.Current(ctx, "tenant-c")
	if err != nil || v2 != 1 {
		t.Fatalf("Current2 = %d err %v", v2, err)
	}
	// Both Current calls should be cache hits — zero Gets in Redis.
	if got := atomic.LoadInt64(&cc.getCalls); got != 0 {
		t.Fatalf("Get calls within cache window = %d, want 0 (Bump cached the value)", got)
	}
}

func TestVersionStore_Current_ExpiredCacheRefetches(t *testing.T) {
	mr, rdb := newMiniredis(t)
	cc := &countingClient{inner: rdb}
	s := NewVersionStore(cc, 20*time.Millisecond)
	ctx := context.Background()

	if _, err := s.Bump(ctx, "tenant-e"); err != nil {
		t.Fatalf("Bump: %v", err)
	}
	// First call within window — cached via Bump.
	if _, err := s.Current(ctx, "tenant-e"); err != nil {
		t.Fatalf("Current1: %v", err)
	}
	// Wait past the cache TTL.
	mr.FastForward(30 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	// Second call must refetch from Redis.
	if _, err := s.Current(ctx, "tenant-e"); err != nil {
		t.Fatalf("Current2: %v", err)
	}
	if got := atomic.LoadInt64(&cc.getCalls); got == 0 {
		t.Fatalf("expected at least 1 Get after cache expiry, got 0")
	}
}

func TestVersionStore_Current_UnseenTenantIsZero(t *testing.T) {
	_, rdb := newMiniredis(t)
	s := NewVersionStore(rdb, time.Second)
	ctx := context.Background()

	v, err := s.Current(ctx, "never-written")
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if v != 0 {
		t.Fatalf("Current on unseen tenant = %d, want 0", v)
	}
}

func TestVersionStore_EmptyTenantIDRejected(t *testing.T) {
	_, rdb := newMiniredis(t)
	s := NewVersionStore(rdb, time.Second)
	ctx := context.Background()
	if _, err := s.Bump(ctx, ""); err == nil {
		t.Fatalf("Bump with empty tenantID should error")
	}
	if _, err := s.Current(ctx, ""); err == nil {
		t.Fatalf("Current with empty tenantID should error")
	}
}
