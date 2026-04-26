package testing

import (
	"context"

	"github.com/zero-day-ai/sdk/auth"
)

const (
	// DefaultTestTenant is the default tenant ID used for tests.
	// This ensures test isolation and compatibility with tenant-scoped operations.
	DefaultTestTenant = "test-tenant"
)

// WithTestTenant creates a context with the default test tenant injected.
//
// This helper should be used in tests that interact with tenant-scoped
// resources like Redis (via TenantScopedStore) or Neo4j operations.
//
// Example:
//
//	func TestSomethingWithRedis(t *testing.T) {
//	    ctx := testutil.WithTestTenant()
//	    err := store.Set(ctx, "key", "value", 0)
//	    // ...
//	}
func WithTestTenant() context.Context {
	return WithTenant(context.Background(), DefaultTestTenant)
}

// WithTenant creates a context with a specific tenant ID injected.
//
// Use this when you need to test with a custom tenant ID,
// such as testing tenant isolation.
//
// Example:
//
//	func TestTenantIsolation(t *testing.T) {
//	    ctx1 := testutil.WithTenant(context.Background(), "tenant-1")
//	    ctx2 := testutil.WithTenant(context.Background(), "tenant-2")
//	    // ... test isolation between tenant-1 and tenant-2
//	}
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return auth.ContextWithTenantString(ctx, tenantID)
}

// WithTestTenantCancel creates a context with the default test tenant injected
// and a cancel function.
//
// This is useful for tests that need context cancellation.
//
// Example:
//
//	func TestWithCancellation(t *testing.T) {
//	    ctx, cancel := testutil.WithTestTenantCancel()
//	    defer cancel()
//	    // ... use ctx
//	}
func WithTestTenantCancel() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return auth.ContextWithTenantString(ctx, DefaultTestTenant), cancel
}
