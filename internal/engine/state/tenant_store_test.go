// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package state

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/sdk/auth"
)

func TestTenantScopedStore_ResolveTenant(t *testing.T) {
	tests := []struct {
		name          string
		config        *TenantStoreConfig
		contextTenant string
		want          string
		wantErr       bool
	}{
		{
			name: "tenant from context",
			config: &TenantStoreConfig{
				AuthMode:      "saas",
				RequireTenant: true,
			},
			contextTenant: "acme-corp",
			want:          "acme-corp",
			wantErr:       false,
		},
		{
			name: "default tenant when no context tenant",
			config: &TenantStoreConfig{
				AuthMode:      "enterprise",
				DefaultTenant: "main",
				RequireTenant: false,
			},
			contextTenant: "",
			want:          "main",
			wantErr:       false,
		},
		{
			name: "error when tenant required but missing",
			config: &TenantStoreConfig{
				AuthMode:      "saas",
				RequireTenant: true,
			},
			contextTenant: "",
			want:          "",
			wantErr:       true,
		},
		{
			name: "dev mode uses default",
			config: &TenantStoreConfig{
				AuthMode:      "dev",
				DefaultTenant: "dev",
				RequireTenant: false,
			},
			contextTenant: "",
			want:          "dev",
			wantErr:       false,
		},
		{
			name: "context tenant overrides default",
			config: &TenantStoreConfig{
				AuthMode:      "enterprise",
				DefaultTenant: "main",
				RequireTenant: false,
			},
			contextTenant: "team-alpha",
			want:          "team-alpha",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTenantScopedStore(nil, tt.config)

			ctx := context.Background()
			if tt.contextTenant != "" {
				ctx = auth.ContextWithTenantString(ctx, tt.contextTenant)
			}

			got, err := store.resolveTenant(ctx)

			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, ErrTenantRequired)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestTenantScopedStore_ScopeKey(t *testing.T) {
	tests := []struct {
		name          string
		config        *TenantStoreConfig
		contextTenant string
		key           string
		want          string
		wantErr       bool
	}{
		{
			name: "basic key scoping",
			config: &TenantStoreConfig{
				AuthMode:      "saas",
				RequireTenant: true,
			},
			contextTenant: "acme",
			key:           "mission:123",
			want:          "tenant:acme:mission:123",
			wantErr:       false,
		},
		{
			name: "nested key scoping",
			config: &TenantStoreConfig{
				AuthMode:      "enterprise",
				DefaultTenant: "main",
			},
			contextTenant: "widgets-inc",
			key:           "memory:mission:abc:key1",
			want:          "tenant:widgets-inc:memory:mission:abc:key1",
			wantErr:       false,
		},
		{
			name: "default tenant scoping",
			config: &TenantStoreConfig{
				AuthMode:      "enterprise",
				DefaultTenant: "default",
			},
			contextTenant: "",
			key:           "checkpoint:123",
			want:          "tenant:default:checkpoint:123",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTenantScopedStore(nil, tt.config)

			ctx := context.Background()
			if tt.contextTenant != "" {
				ctx = auth.ContextWithTenantString(ctx, tt.contextTenant)
			}

			got, err := store.scopeKey(ctx, tt.key)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

// requireTenantStoreRedis dials the Redis instance the tenant-isolation tests
// below need, and skips when it is not reachable.
//
// The three tests that call it used to open with a bare `t.Skip("Integration
// test - requires Redis")`, which disabled them in every lane — including the
// lanes that do have a Redis. gibson#1294. This gate is the same shape the
// rest of the package already uses (client_test.go, streams_test.go): skip in
// -short mode, otherwise probe and skip only if the probe fails.
//
// A probe that skips is still a test that can quietly stop running, which is
// the state gibson#1297 found these in — so the skip is BOUNDED. When
// GIBSON_TEST_REQUIRE_REDIS is set, an unreachable Redis is a FAILURE, not a
// skip. The `coverage` job in .github/workflows/go-ci.yml runs `go test ./...`
// against a `redis/redis-stack-server` service and sets it, so if that service
// is ever dropped, renamed or downgraded to a module-less Redis, these tests go
// red instead of reverting to never running while CI stays green.
//
// GIBSON_TEST_REDIS_URL points the probe somewhere other than the default, so
// the suite can be run locally against a throwaway container without having to
// own port 6379.
func requireTenantStoreRedis(t *testing.T) *StateClient {
	t.Helper()

	// Set by the one CI lane that guarantees a Redis Stack. Outside it, an
	// absent Redis is a legitimate skip.
	required := os.Getenv("GIBSON_TEST_REQUIRE_REDIS") != ""

	if testing.Short() && !required {
		t.Skip("skipping integration test in short mode")
	}

	cfg := DefaultConfig()
	cfg.URL = "redis://localhost:6379"
	if url := os.Getenv("GIBSON_TEST_REDIS_URL"); url != "" {
		cfg.URL = url
	}
	cfg.Database = 15 // Use test database

	client, err := NewStateClient(cfg)
	if err != nil {
		if required {
			t.Fatalf("GIBSON_TEST_REQUIRE_REDIS is set, so this lane promises a Redis Stack at %s, but it is unusable: %v"+
				" (NewStateClient requires the RediSearch and RedisJSON modules — a plain redis image is not enough)",
				cfg.URL, err)
		}
		t.Skipf("Redis not available: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client
}

func TestTenantScopedStore_Integration(t *testing.T) {
	client := requireTenantStoreRedis(t)

	storeConfig := &TenantStoreConfig{
		AuthMode:      "saas",
		RequireTenant: true,
	}
	store := NewTenantScopedStore(client, storeConfig)

	// Create two tenant contexts
	ctxTenant1 := auth.ContextWithTenantString(context.Background(), "tenant1")
	ctxTenant2 := auth.ContextWithTenantString(context.Background(), "tenant2")

	// Clean up any existing test data
	defer func() {
		store.Delete(ctxTenant1, "test:key")
		store.Delete(ctxTenant2, "test:key")
	}()

	t.Run("tenant isolation for Get/Set", func(t *testing.T) {
		// Tenant 1 sets a value
		err := store.Set(ctxTenant1, "test:key", "tenant1-value", 0)
		require.NoError(t, err)

		// Tenant 2 sets a value with the same key
		err = store.Set(ctxTenant2, "test:key", "tenant2-value", 0)
		require.NoError(t, err)

		// Tenant 1 gets its own value
		val1, err := store.Get(ctxTenant1, "test:key")
		require.NoError(t, err)
		assert.Equal(t, "tenant1-value", val1)

		// Tenant 2 gets its own value
		val2, err := store.Get(ctxTenant2, "test:key")
		require.NoError(t, err)
		assert.Equal(t, "tenant2-value", val2)
	})

	t.Run("tenant isolation for Delete", func(t *testing.T) {
		// Tenant 1 sets a value
		err := store.Set(ctxTenant1, "test:delete", "value1", 0)
		require.NoError(t, err)

		// Tenant 2 sets a value with the same key
		err = store.Set(ctxTenant2, "test:delete", "value2", 0)
		require.NoError(t, err)

		// Tenant 1 deletes its key
		err = store.Delete(ctxTenant1, "test:delete")
		require.NoError(t, err)

		// Tenant 1's key should not exist
		_, err = store.Get(ctxTenant1, "test:delete")
		assert.ErrorIs(t, err, ErrNotFound)

		// Tenant 2's key should still exist
		val2, err := store.Get(ctxTenant2, "test:delete")
		require.NoError(t, err)
		assert.Equal(t, "value2", val2)

		// Clean up
		store.Delete(ctxTenant2, "test:delete")
	})

	t.Run("tenant isolation for Incr", func(t *testing.T) {
		// Tenant 1 increments counter
		count1, err := store.Incr(ctxTenant1, "test:counter")
		require.NoError(t, err)
		assert.Equal(t, int64(1), count1)

		count1, err = store.Incr(ctxTenant1, "test:counter")
		require.NoError(t, err)
		assert.Equal(t, int64(2), count1)

		// Tenant 2 has separate counter
		count2, err := store.Incr(ctxTenant2, "test:counter")
		require.NoError(t, err)
		assert.Equal(t, int64(1), count2)

		// Clean up
		store.Delete(ctxTenant1, "test:counter")
		store.Delete(ctxTenant2, "test:counter")
	})

	t.Run("tenant isolation for Hash operations", func(t *testing.T) {
		// Tenant 1 sets hash fields
		err := store.HSet(ctxTenant1, "test:hash", "field1", "value1", "field2", "value2")
		require.NoError(t, err)

		// Tenant 2 sets hash fields with same key
		err = store.HSet(ctxTenant2, "test:hash", "field1", "different1", "field2", "different2")
		require.NoError(t, err)

		// Tenant 1 gets its values
		val1, err := store.HGet(ctxTenant1, "test:hash", "field1")
		require.NoError(t, err)
		assert.Equal(t, "value1", val1)

		all1, err := store.HGetAll(ctxTenant1, "test:hash")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"field1": "value1", "field2": "value2"}, all1)

		// Tenant 2 gets its values
		val2, err := store.HGet(ctxTenant2, "test:hash", "field1")
		require.NoError(t, err)
		assert.Equal(t, "different1", val2)

		// Clean up
		store.Delete(ctxTenant1, "test:hash")
		store.Delete(ctxTenant2, "test:hash")
	})

	t.Run("tenant isolation for Set operations", func(t *testing.T) {
		// Tenant 1 adds to set
		_, err := store.SAdd(ctxTenant1, "test:set", "member1", "member2")
		require.NoError(t, err)

		// Tenant 2 adds to set with same key
		_, err = store.SAdd(ctxTenant2, "test:set", "member3", "member4")
		require.NoError(t, err)

		// Tenant 1 gets its members
		members1, err := store.SMembers(ctxTenant1, "test:set")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"member1", "member2"}, members1)

		// Tenant 2 gets its members
		members2, err := store.SMembers(ctxTenant2, "test:set")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"member3", "member4"}, members2)

		// Clean up
		store.Delete(ctxTenant1, "test:set")
		store.Delete(ctxTenant2, "test:set")
	})

	t.Run("expiration works with tenant scoping", func(t *testing.T) {
		// Set key with short TTL
		err := store.Set(ctxTenant1, "test:ttl", "value", 100*time.Millisecond)
		require.NoError(t, err)

		// Key should exist immediately
		val, err := store.Get(ctxTenant1, "test:ttl")
		require.NoError(t, err)
		assert.Equal(t, "value", val)

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Key should be gone
		_, err = store.Get(ctxTenant1, "test:ttl")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestTenantScopedStore_NoTenantError(t *testing.T) {
	client := requireTenantStoreRedis(t)

	// Create store that requires tenant
	storeConfig := &TenantStoreConfig{
		AuthMode:      "saas",
		RequireTenant: true,
	}
	store := NewTenantScopedStore(client, storeConfig)

	// Context with no tenant
	ctx := context.Background()

	// All operations should fail
	t.Run("Get fails without tenant", func(t *testing.T) {
		_, err := store.Get(ctx, "test:key")
		assert.ErrorIs(t, err, ErrTenantRequired)
	})

	t.Run("Set fails without tenant", func(t *testing.T) {
		err := store.Set(ctx, "test:key", "value", 0)
		assert.ErrorIs(t, err, ErrTenantRequired)
	})

	t.Run("Delete fails without tenant", func(t *testing.T) {
		err := store.Delete(ctx, "test:key")
		assert.ErrorIs(t, err, ErrTenantRequired)
	})
}

func TestTenantScopedStore_DefaultTenantMode(t *testing.T) {
	client := requireTenantStoreRedis(t)

	// Create store with default tenant
	storeConfig := &TenantStoreConfig{
		AuthMode:      "enterprise",
		DefaultTenant: "main",
		RequireTenant: false,
	}
	store := NewTenantScopedStore(client, storeConfig)

	ctx := context.Background()

	defer store.Delete(ctx, "test:default")

	t.Run("operations use default tenant", func(t *testing.T) {
		// Set without tenant in context
		err := store.Set(ctx, "test:default", "default-value", 0)
		require.NoError(t, err)

		// Get without tenant in context
		val, err := store.Get(ctx, "test:default")
		require.NoError(t, err)
		assert.Equal(t, "default-value", val)

		// Verify the key was scoped with default tenant
		tenant, err := store.GetTenant(ctx)
		require.NoError(t, err)
		assert.Equal(t, "main", tenant)
	})

	t.Run("context tenant overrides default", func(t *testing.T) {
		// Create context with specific tenant
		ctxWithTenant := auth.ContextWithTenantString(context.Background(), "team-alpha")

		// Set with tenant in context
		err := store.Set(ctxWithTenant, "test:override", "team-value", 0)
		require.NoError(t, err)

		// Get with tenant in context
		val, err := store.Get(ctxWithTenant, "test:override")
		require.NoError(t, err)
		assert.Equal(t, "team-value", val)

		// Should not be accessible without tenant context
		_, err = store.Get(ctx, "test:override")
		assert.ErrorIs(t, err, ErrNotFound)

		// Clean up
		store.Delete(ctxWithTenant, "test:override")
	})
}

func TestTenantScopedStore_GetTenant(t *testing.T) {
	tests := []struct {
		name          string
		config        *TenantStoreConfig
		contextTenant string
		want          string
		wantErr       bool
	}{
		{
			name: "returns context tenant",
			config: &TenantStoreConfig{
				AuthMode:      "saas",
				RequireTenant: true,
			},
			contextTenant: "acme-corp",
			want:          "acme-corp",
			wantErr:       false,
		},
		{
			name: "returns default tenant",
			config: &TenantStoreConfig{
				AuthMode:      "enterprise",
				DefaultTenant: "main",
			},
			contextTenant: "",
			want:          "main",
			wantErr:       false,
		},
		{
			name: "error when required but missing",
			config: &TenantStoreConfig{
				AuthMode:      "saas",
				RequireTenant: true,
			},
			contextTenant: "",
			want:          "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := NewTenantScopedStore(nil, tt.config)

			ctx := context.Background()
			if tt.contextTenant != "" {
				ctx = auth.ContextWithTenantString(ctx, tt.contextTenant)
			}

			got, err := store.GetTenant(ctx)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
