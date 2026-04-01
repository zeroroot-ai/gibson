//go:build e2e
// +build e2e

package e2e

// multi_tenant_test.go contains end-to-end integration tests that verify
// multi-tenant data isolation across Redis-backed Gibson components.
//
// All tests use miniredis so no real Redis or module stack is required.
// Run with:
//
//	go test -tags=e2e -race ./tests/e2e/...

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/state"
	sdkauth "github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Helpers shared across this file
// ---------------------------------------------------------------------------

// newMiniredisStateClient starts an in-process Redis server and returns a
// *state.StateClient connected to it.  The miniredis instance is stopped and
// the client closed via t.Cleanup.
func newMiniredisStateClient(t *testing.T) (*state.StateClient, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err, "NewStateClient against miniredis must succeed")
	t.Cleanup(func() { _ = sc.Close() })

	return sc, mr
}

// newMiniredisRedisClient starts an in-process Redis server and returns a
// bare *redis.Client connected to it.  Components that take *redis.Client
// directly (e.g. TenantService) use this helper so they share the same
// miniredis namespace as the TenantScopedStore when needed.
func newMiniredisRedisClient(t *testing.T) (*redis.Client, *miniredis.Miniredis) {
	t.Helper()

	mr := miniredis.RunT(t)

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	return client, mr
}

// quietLogger returns a slog.Logger that suppresses output below Error level,
// keeping test output readable.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// adminIdentityCtx builds a context carrying a Gibson Identity with the
// "admin" role, scoped to the supplied tenant.
func adminIdentityCtx(tenantID string) context.Context {
	identity := &auth.Identity{
		Identity: sdkauth.Identity{
			Subject: "admin-user",
			Issuer:  "test-issuer",
			Groups:  []string{"admin"},
			Claims:  map[string]any{},
		},
		Roles: []string{"admin"},
		Permissions: []auth.Permission{
			{Action: "*", Resource: "*", Scope: "*"},
		},
	}

	ctx := auth.ContextWithIdentity(context.Background(), identity)
	if tenantID != "" {
		ctx = auth.ContextWithTenant(ctx, tenantID)
	}
	return ctx
}

// ---------------------------------------------------------------------------
// Test 1: Two-tenant data isolation via TenantScopedStore
// ---------------------------------------------------------------------------

// TestMultiTenantDataIsolation_E2E verifies that two tenants writing to the
// same logical key name receive independent values and cannot see each other's
// key space via list operations.
func TestMultiTenantDataIsolation_E2E(t *testing.T) {
	t.Parallel()

	sc, _ := newMiniredisStateClient(t)

	storeConfig := &state.TenantStoreConfig{
		AuthMode:      "saas",
		RequireTenant: true,
	}
	store := state.NewTenantScopedStore(sc, storeConfig)

	// Build tenant-scoped contexts.
	ctxAlpha := auth.ContextWithTenant(context.Background(), "team-alpha")
	ctxBeta := auth.ContextWithTenant(context.Background(), "team-beta")

	t.Run("Set and Get are isolated per tenant", func(t *testing.T) {
		// Each tenant writes the same logical key with a different value.
		require.NoError(t, store.Set(ctxAlpha, "mission:1", "alpha-data", 0))
		require.NoError(t, store.Set(ctxBeta, "mission:1", "beta-data", 0))

		valAlpha, err := store.Get(ctxAlpha, "mission:1")
		require.NoError(t, err)
		assert.Equal(t, "alpha-data", valAlpha, "team-alpha must see its own value")

		valBeta, err := store.Get(ctxBeta, "mission:1")
		require.NoError(t, err)
		assert.Equal(t, "beta-data", valBeta, "team-beta must see its own value")

		// Neither tenant's value must bleed into the other tenant's namespace.
		assert.NotEqual(t, valAlpha, valBeta,
			"values for the same key name must differ between tenants")
	})

	t.Run("Keys listing is scoped to the requesting tenant", func(t *testing.T) {
		// Write additional keys so the pattern match is non-trivial.
		require.NoError(t, store.Set(ctxAlpha, "mission:2", "alpha-data-2", 0))
		require.NoError(t, store.Set(ctxBeta, "mission:2", "beta-data-2", 0))
		require.NoError(t, store.Set(ctxBeta, "mission:3", "beta-data-3", 0))

		keysAlpha, err := store.Keys(ctxAlpha, "mission:*")
		require.NoError(t, err)
		// All returned keys must belong to the alpha namespace.
		for _, k := range keysAlpha {
			assert.Contains(t, k, "tenant:team-alpha:",
				"key %q must be scoped to team-alpha", k)
		}

		keysBeta, err := store.Keys(ctxBeta, "mission:*")
		require.NoError(t, err)
		for _, k := range keysBeta {
			assert.Contains(t, k, "tenant:team-beta:",
				"key %q must be scoped to team-beta", k)
		}

		// team-alpha must not see team-beta keys and vice-versa.
		for _, alphaKey := range keysAlpha {
			assert.NotContains(t, keysBeta, alphaKey,
				"team-beta's key list must not contain team-alpha keys")
		}
		for _, betaKey := range keysBeta {
			assert.NotContains(t, keysAlpha, betaKey,
				"team-alpha's key list must not contain team-beta keys")
		}

		// team-beta wrote 3 mission keys; team-alpha wrote 2.
		assert.Len(t, keysAlpha, 2, "team-alpha should have exactly 2 mission keys")
		assert.Len(t, keysBeta, 3, "team-beta should have exactly 3 mission keys")
	})

	t.Run("Delete is scoped — removing one tenant's key leaves the other's intact", func(t *testing.T) {
		require.NoError(t, store.Set(ctxAlpha, "scratch:key", "alpha-scratch", 0))
		require.NoError(t, store.Set(ctxBeta, "scratch:key", "beta-scratch", 0))

		// team-alpha deletes its copy.
		require.NoError(t, store.Delete(ctxAlpha, "scratch:key"))

		// team-alpha's copy is gone.
		_, err := store.Get(ctxAlpha, "scratch:key")
		assert.ErrorIs(t, err, state.ErrNotFound,
			"team-alpha should get ErrNotFound after deleting its own key")

		// team-beta's copy remains untouched.
		valBeta, err := store.Get(ctxBeta, "scratch:key")
		require.NoError(t, err)
		assert.Equal(t, "beta-scratch", valBeta,
			"team-beta's key must survive team-alpha's delete")
	})
}

// ---------------------------------------------------------------------------
// Test 2: Auto-provisioning end-to-end
// ---------------------------------------------------------------------------

// TestAutoProvisioning_E2E verifies that TenantAutoProvisioner creates a
// tenant record on first call to EnsureTenant and is idempotent on subsequent
// calls.
func TestAutoProvisioning_E2E(t *testing.T) {
	t.Parallel()

	client, _ := newMiniredisRedisClient(t)
	logger := quietLogger()

	svc := component.NewTenantService(client, logger, nil)
	prov := component.NewTenantAutoProvisioner(svc, nil, nil, nil, logger)

	ctx := context.Background()

	// First call: tenant does not exist yet.
	err := prov.EnsureTenant(ctx, "new-team")
	require.NoError(t, err, "EnsureTenant must succeed for a brand-new tenant")

	// Verify the tenant record was created via CreateTenant's public surface.
	// We read it using an admin context since GetTenant enforces RBAC.
	adminCtx := adminIdentityCtx("new-team")

	record, err := svc.GetTenant(adminCtx, "new-team")
	require.NoError(t, err, "GetTenant must succeed after auto-provisioning")
	assert.Equal(t, "new-team", record.TenantID)
	assert.Equal(t, "active", record.Status,
		"auto-provisioned tenant must have 'active' status")
	assert.Equal(t, "true", record.Config["auto_provisioned"],
		"auto_provisioned config flag must be set")

	// Second call: tenant already exists — must be idempotent.
	err = prov.EnsureTenant(ctx, "new-team")
	require.NoError(t, err, "EnsureTenant must be idempotent")

	// Only one tenant record should exist.
	records, err := svc.ListTenants(adminIdentityCtx(""))
	require.NoError(t, err)

	count := 0
	for _, r := range records {
		if r.TenantID == "new-team" {
			count++
		}
	}
	assert.Equal(t, 1, count,
		"exactly one tenant record should exist after two EnsureTenant calls")
}

// ---------------------------------------------------------------------------
// Test 3: Concurrent auto-provisioning (race condition)
// ---------------------------------------------------------------------------

// TestConcurrentAutoProvisioning_E2E verifies that ten goroutines racing to
// provision the same tenant ID each receive a nil error and that exactly one
// TenantRecord is stored in Redis.
func TestConcurrentAutoProvisioning_E2E(t *testing.T) {
	// Do not use t.Parallel here — the test deliberately exercises concurrent
	// writes against a shared miniredis instance; running it alongside other
	// parallel tests increases flakiness risk without adding coverage value.

	client, _ := newMiniredisRedisClient(t)
	logger := quietLogger()

	svc := component.NewTenantService(client, logger, nil)
	prov := component.NewTenantAutoProvisioner(svc, nil, nil, nil, logger)

	const numGoroutines = 10
	errs := make([]error, numGoroutines)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			errs[idx] = prov.EnsureTenant(context.Background(), "race-team")
		}(i)
	}

	wg.Wait()

	// All goroutines must succeed — no error should propagate regardless of
	// whether the goroutine won or lost the provisioning lock race.
	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d must not receive an error from EnsureTenant", i)
	}

	// Exactly one record for "race-team" must exist.
	adminCtx := adminIdentityCtx("")

	records, err := svc.ListTenants(adminCtx)
	require.NoError(t, err)

	count := 0
	for _, r := range records {
		if r.TenantID == "race-team" {
			count++
		}
	}
	assert.Equal(t, 1, count,
		"exactly one TenantRecord must exist after concurrent EnsureTenant calls")
}

// ---------------------------------------------------------------------------
// Test 4: Enterprise backward compatibility (single-tenant / default tenant)
// ---------------------------------------------------------------------------

// TestEnterpriseBackwardCompat_E2E verifies that a TenantScopedStore
// configured with a default tenant correctly scopes all data under that tenant
// when no explicit tenant is present in the context, preserving backward
// compatibility for enterprise single-tenant deployments.
func TestEnterpriseBackwardCompat_E2E(t *testing.T) {
	t.Parallel()

	sc, _ := newMiniredisStateClient(t)

	// Enterprise single-tenant mode: context tenant is not required; all
	// operations fall back to "legacy-corp".
	storeConfig := &state.TenantStoreConfig{
		AuthMode:      "enterprise",
		DefaultTenant: "legacy-corp",
		RequireTenant: false,
	}
	store := state.NewTenantScopedStore(sc, storeConfig)

	// Use a bare context with no tenant injected.
	ctx := context.Background()

	t.Run("Write without explicit tenant context uses default tenant", func(t *testing.T) {
		require.NoError(t, store.Set(ctx, "mission:legacy-1", "legacy-data", 0))
	})

	t.Run("Data is stored under the default tenant prefix", func(t *testing.T) {
		// Verify via Keys that the raw Redis key carries the expected prefix.
		keys, err := store.Keys(ctx, "mission:legacy-1")
		require.NoError(t, err)
		require.Len(t, keys, 1, "should find exactly one key")
		assert.Equal(t, "tenant:legacy-corp:mission:legacy-1", keys[0],
			"key must be stored under the default tenant namespace")
	})

	t.Run("Read without explicit tenant context returns stored data", func(t *testing.T) {
		val, err := store.Get(ctx, "mission:legacy-1")
		require.NoError(t, err)
		assert.Equal(t, "legacy-data", val)
	})

	t.Run("GetTenant resolves to the default tenant when context is empty", func(t *testing.T) {
		resolved, err := store.GetTenant(ctx)
		require.NoError(t, err)
		assert.Equal(t, "legacy-corp", resolved,
			"GetTenant must return the configured default tenant")
	})
}

