package auth

// tenant_validator_test.go contains unit tests for CachedTenantValidator and
// IsTenantAccessible.
//
// All tests use a lightweight in-process mockTenantValidator — no Redis or
// external dependencies required.  Cache-expiry tests use short TTLs (10-50 ms)
// so the suite completes in well under a second.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

// mockTenantValidator is a thread-safe stub for the TenantValidator interface.
type mockTenantValidator struct {
	mu     sync.Mutex
	calls  int
	status string
	err    error
}

func (m *mockTenantValidator) ValidateTenantStatus(_ context.Context, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.status, m.err
}

func (m *mockTenantValidator) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — cache miss
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_CacheMiss_DelegatesToUnderlying(t *testing.T) {
	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 30*time.Second)

	status, err := v.ValidateTenantStatus(context.Background(), "tenant-1")

	require.NoError(t, err)
	assert.Equal(t, "active", status)
	assert.Equal(t, 1, mock.callCount(), "delegate must be called exactly once on cache miss")
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — cache hit within TTL
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_CacheHit_NoSecondDelegate(t *testing.T) {
	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 30*time.Second)

	ctx := context.Background()

	// First call populates the cache.
	s1, err := v.ValidateTenantStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "active", s1)

	// Change the mock's status — the cached value must be returned instead.
	mock.mu.Lock()
	mock.status = "suspended"
	mock.mu.Unlock()

	// Second call must hit the cache.
	s2, err := v.ValidateTenantStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "active", s2, "cache should return original status without re-delegating")
	assert.Equal(t, 1, mock.callCount(), "delegate must only be called once within TTL")
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — cache expiry re-delegates
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_CacheExpiry_ReDelegatesAfterTTL(t *testing.T) {
	const shortTTL = 20 * time.Millisecond

	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, shortTTL)

	ctx := context.Background()

	// First call — populates cache.
	s1, err := v.ValidateTenantStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "active", s1)
	assert.Equal(t, 1, mock.callCount())

	// Wait for TTL to expire.
	time.Sleep(shortTTL + 5*time.Millisecond)

	// Update mock to reflect a status change that should now be visible.
	mock.mu.Lock()
	mock.status = "suspended"
	mock.mu.Unlock()

	// Second call after expiry — must re-delegate and return fresh value.
	s2, err := v.ValidateTenantStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "suspended", s2, "expired cache should fetch fresh status from delegate")
	assert.Equal(t, 2, mock.callCount(), "delegate must be called again after TTL expires")
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — errors are cached
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_ErrorCaching_PreventsThunderingHerd(t *testing.T) {
	const shortTTL = 30 * time.Second
	sentinel := errors.New("backend unavailable")

	mock := &mockTenantValidator{err: sentinel}
	v := NewCachedTenantValidator(mock, shortTTL)

	ctx := context.Background()

	// First call — hits the delegate and receives an error.
	_, err1 := v.ValidateTenantStatus(ctx, "bad-tenant")
	require.Error(t, err1)
	assert.ErrorIs(t, err1, sentinel)
	assert.Equal(t, 1, mock.callCount())

	// Second call within TTL — must return the cached error without re-delegating.
	_, err2 := v.ValidateTenantStatus(ctx, "bad-tenant")
	require.Error(t, err2)
	assert.ErrorIs(t, err2, sentinel)
	assert.Equal(t, 1, mock.callCount(), "error should be served from cache without hitting delegate again")
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — different tenant IDs use independent cache entries
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_PerTenantCacheIsolation(t *testing.T) {
	callMap := make(map[string]int)
	var mu sync.Mutex

	// Use a custom mock that tracks per-tenant calls and returns different statuses.
	type perTenantValidator struct {
		TenantValidator
	}
	delegate := &struct {
		sync.Mutex
		counts map[string]int
	}{counts: make(map[string]int)}

	// Implement via a simple closure-based mock by embedding mockTenantValidator
	// and overriding with per-call behaviour.
	mockA := &mockTenantValidator{status: "active"}
	mockB := &mockTenantValidator{status: "suspended"}

	// We need a combined validator; use a simple wrapper.
	combined := &routingValidator{routes: map[string]*mockTenantValidator{
		"tenant-a": mockA,
		"tenant-b": mockB,
	}}
	_ = callMap
	_ = mu
	_ = delegate
	_ = perTenantValidator{}

	v := NewCachedTenantValidator(combined, 30*time.Second)
	ctx := context.Background()

	sA, err := v.ValidateTenantStatus(ctx, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, "active", sA)

	sB, err := v.ValidateTenantStatus(ctx, "tenant-b")
	require.NoError(t, err)
	assert.Equal(t, "suspended", sB)

	// Second calls — both must be served from cache.
	sA2, _ := v.ValidateTenantStatus(ctx, "tenant-a")
	sB2, _ := v.ValidateTenantStatus(ctx, "tenant-b")
	assert.Equal(t, "active", sA2)
	assert.Equal(t, "suspended", sB2)

	assert.Equal(t, 1, mockA.callCount(), "tenant-a delegate must only be called once")
	assert.Equal(t, 1, mockB.callCount(), "tenant-b delegate must only be called once")
}

// routingValidator dispatches to per-tenant mocks.
type routingValidator struct {
	routes map[string]*mockTenantValidator
}

func (r *routingValidator) ValidateTenantStatus(ctx context.Context, tenantID string) (string, error) {
	if m, ok := r.routes[tenantID]; ok {
		return m.ValidateTenantStatus(ctx, tenantID)
	}
	return "", errors.New("no route for tenant: " + tenantID)
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — InvalidateCache removes entry
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_InvalidateCache_ForcesReDelegation(t *testing.T) {
	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 30*time.Second)

	ctx := context.Background()

	// Populate cache.
	s1, err := v.ValidateTenantStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "active", s1)
	assert.Equal(t, 1, mock.callCount())

	// Invalidate — the next call must bypass the cache.
	v.InvalidateCache("tenant-1")

	mock.mu.Lock()
	mock.status = "provisioning"
	mock.mu.Unlock()

	s2, err := v.ValidateTenantStatus(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "provisioning", s2, "post-invalidation call must fetch fresh status")
	assert.Equal(t, 2, mock.callCount(), "delegate must be called again after cache invalidation")
}

// TestCachedTenantValidator_InvalidateCache_NonExistentKey tests that
// InvalidateCache is a no-op for a key that was never cached.
func TestCachedTenantValidator_InvalidateCache_NonExistentKey(t *testing.T) {
	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 30*time.Second)

	// Must not panic.
	assert.NotPanics(t, func() {
		v.InvalidateCache("never-seen-tenant")
	})
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — zero TTL defaults to 60 seconds
// ---------------------------------------------------------------------------

func TestNewCachedTenantValidator_ZeroTTLDefaultsSixtySeconds(t *testing.T) {
	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 0)

	assert.Equal(t, 60*time.Second, v.ttl, "zero TTL must default to 60 seconds")
}

// ---------------------------------------------------------------------------
// CachedTenantValidator — thread safety
// ---------------------------------------------------------------------------

func TestCachedTenantValidator_ThreadSafety_NoPanic(t *testing.T) {
	const goroutines = 50
	const callsPerGoroutine = 20

	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 10*time.Millisecond) // short TTL to exercise expiry path too

	ctx := context.Background()
	var wg sync.WaitGroup

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			tenantID := "tenant-concurrent"
			for j := 0; j < callsPerGoroutine; j++ {
				_, _ = v.ValidateTenantStatus(ctx, tenantID)
				if j%5 == 0 {
					v.InvalidateCache(tenantID)
				}
			}
		}(i)
	}

	// Must complete without panic or data race (run with -race to verify).
	wg.Wait()
}

// TestCachedTenantValidator_ThreadSafety_MultiTenant verifies concurrent
// operations across different tenant IDs do not interfere.
func TestCachedTenantValidator_ThreadSafety_MultiTenant(t *testing.T) {
	mock := &mockTenantValidator{status: "active"}
	v := NewCachedTenantValidator(mock, 50*time.Millisecond)

	ctx := context.Background()
	tenants := []string{"alpha", "beta", "gamma", "delta", "epsilon"}

	var wg sync.WaitGroup
	for _, tid := range tenants {
		wg.Add(1)
		go func(tenantID string) {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				_, _ = v.ValidateTenantStatus(ctx, tenantID)
			}
		}(tid)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// IsTenantAccessible
// ---------------------------------------------------------------------------

func TestIsTenantAccessible(t *testing.T) {
	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{
			name:   "active is accessible",
			status: "active",
			want:   true,
		},
		{
			name:   "provisioning is accessible",
			status: "provisioning",
			want:   true,
		},
		{
			name:   "suspended is accessible (read-only; write restriction is downstream)",
			status: "suspended",
			want:   true,
		},
		{
			name:   "deleted is not accessible",
			status: "deleted",
			want:   false,
		},
		{
			name:   "empty string is not accessible",
			status: "",
			want:   false,
		},
		{
			name:   "unknown status is not accessible",
			status: "unknown",
			want:   false,
		},
		{
			name:   "arbitrary string is not accessible",
			status: "banana",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTenantAccessible(tt.status)
			assert.Equal(t, tt.want, got,
				"IsTenantAccessible(%q) = %v, want %v", tt.status, got, tt.want)
		})
	}
}
