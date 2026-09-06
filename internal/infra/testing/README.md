# Test Utilities

This package provides test utilities and helpers for Gibson tests, particularly for multi-tenant testing.

## Tenant Context Helpers

The tenant helpers ensure that tests work correctly with tenant-scoped resources like Redis and Neo4j. In SaaS mode, all data operations require a tenant context for proper isolation.

### Basic Usage

```go
import testutil "github.com/zeroroot-ai/gibson/internal/infra/testing"

func TestWithRedis(t *testing.T) {
    client := setupTestRedisClient(t)
    defer client.Close()

    store := NewRedisFindingStore(client)

    // Use WithTestTenant() instead of context.Background()
    ctx := testutil.WithTestTenant()

    err := store.Store(ctx, finding)
    require.NoError(t, err)
}
```

### Testing Tenant Isolation

```go
func TestTenantIsolation(t *testing.T) {
    client := setupTestRedisClient(t)
    defer client.Close()

    store := NewTenantScopedStore(client, cfg)

    // Create contexts with different tenants
    ctx1 := testutil.WithTenant(context.Background(), "tenant-1")
    ctx2 := testutil.WithTenant(context.Background(), "tenant-2")

    // Store data in tenant-1
    err := store.Set(ctx1, "key", "value-1", 0)
    require.NoError(t, err)

    // Store data in tenant-2
    err = store.Set(ctx2, "key", "value-2", 0)
    require.NoError(t, err)

    // Verify isolation
    val1, _ := store.Get(ctx1, "key")
    val2, _ := store.Get(ctx2, "key")
    assert.Equal(t, "value-1", val1)
    assert.Equal(t, "value-2", val2)
}
```

### With Context Cancellation

```go
func TestWithCancellation(t *testing.T) {
    ctx, cancel := testutil.WithTestTenantCancel()
    defer cancel()

    // ctx has both tenant context and cancellation
    err := longRunningOperation(ctx)
    // ...
}
```

## API Reference

### `WithTestTenant() context.Context`

Creates a context with the default test tenant (`test-tenant`) injected. Use this for most tests that interact with tenant-scoped resources.

### `WithTenant(ctx context.Context, tenantID string) context.Context`

Creates a context with a specific tenant ID. Use this when testing multi-tenant isolation or when you need a custom tenant ID.

### `WithTestTenantCancel() (context.Context, context.CancelFunc)`

Creates a context with the default test tenant and a cancel function. Useful for tests that need context cancellation.

### `DefaultTestTenant`

Constant for the default test tenant ID: `"test-tenant"`

## When to Use Tenant Helpers

Use tenant context helpers in tests that:

- Interact with Redis via `StateClient` or `TenantScopedStore`
- Perform Neo4j operations that use tenant filtering
- Call functions that extract tenant from context
- Test tenant isolation behavior

## Migration Guide

To update existing tests:

1. Import the helper: `import testutil "github.com/zeroroot-ai/gibson/internal/infra/testing"`
2. Replace `ctx := context.Background()` with `ctx := testutil.WithTestTenant()`
3. For tenant isolation tests, use `testutil.WithTenant(ctx, "tenant-id")`

Example diff:

```diff
 func TestStoreData(t *testing.T) {
     client := setupTestRedisClient(t)
     defer client.Close()

-    ctx := context.Background()
+    ctx := testutil.WithTestTenant()

     err := store.Set(ctx, "key", "value", 0)
     require.NoError(t, err)
 }
```
