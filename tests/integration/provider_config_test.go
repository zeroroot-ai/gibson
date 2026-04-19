//go:build integration
// +build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/providerconfig"
	"github.com/zero-day-ai/gibson/internal/types"
)

const (
	redisImage = "redis:7-alpine"
)

// ---------------------------------------------------------------------------
// Fake KeyProvider — deterministic 32-byte key, test-only
// ---------------------------------------------------------------------------

// testKeyProvider is a minimal crypto.KeyProvider that returns a static 32-byte key.
// NEVER use anything derived from this in production — it exists solely to allow
// deterministic round-trip assertions in tests.
type testKeyProvider struct {
	key []byte
}

func newTestKeyProvider() *testKeyProvider {
	// 32 deterministic bytes (01 02 03 … 20 in hex)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &testKeyProvider{key: key}
}

func (p *testKeyProvider) GetEncryptionKey(_ context.Context) ([]byte, error) {
	return p.key, nil
}

func (p *testKeyProvider) Name() string { return "test-static" }

func (p *testKeyProvider) Health(_ context.Context) types.HealthStatus {
	return types.Healthy("ok")
}

func (p *testKeyProvider) Close() error { return nil }

var _ crypto.KeyProvider = (*testKeyProvider)(nil)

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// setupIntegrationStore starts a real Redis container, constructs a
// providerconfig.Store backed by it, and returns the store, a raw redis client,
// and a cleanup function that terminates the container.
//
// If Docker is not available the test is skipped gracefully.
func setupIntegrationStore(t *testing.T) (providerconfig.ProviderConfigStore, redis.UniversalClient, func()) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	ctx := context.Background()

	// Check Docker availability before attempting to spin up a container.
	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping integration test: %v", err)
		return nil, nil, func() {}
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker daemon not running, skipping integration test: %v", healthErr)
		return nil, nil, func() {}
	}

	req := testcontainers.ContainerRequest{
		Image:        redisImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("Ready to accept connections"),
			wait.ForListeningPort("6379/tcp"),
		).WithDeadline(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err, "failed to start Redis container")

	host, err := container.Host(ctx)
	require.NoError(t, err, "failed to get Redis container host")

	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err, "failed to get Redis container port")

	addr := fmt.Sprintf("%s:%s", host, port.Port())
	t.Logf("Redis container started at %s", addr)

	rdb := redis.NewClient(&redis.Options{Addr: addr})

	// Ping to confirm connectivity.
	require.NoError(t, rdb.Ping(ctx).Err(), "Redis ping failed")

	enc := crypto.NewAESGCMEncryptor()
	kp := newTestKeyProvider()

	store, err := providerconfig.NewStore(rdb, enc, kp)
	require.NoError(t, err, "NewStore failed")

	cleanup := func() {
		_ = rdb.Close()
		if termErr := container.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate Redis container: %v", termErr)
		}
	}

	t.Cleanup(cleanup)

	return store, rdb, cleanup
}

// newStoreFromClient constructs a fresh providerconfig.Store against an existing
// Redis client. Used by the restart-durability sub-test to prove that a second
// store instance can decrypt data written by the first.
func newStoreFromClient(t *testing.T, rdb redis.UniversalClient) providerconfig.ProviderConfigStore {
	t.Helper()
	enc := crypto.NewAESGCMEncryptor()
	kp := newTestKeyProvider()
	store, err := providerconfig.NewStore(rdb, enc, kp)
	require.NoError(t, err, "NewStore (second instance) failed")
	return store
}

// ---------------------------------------------------------------------------
// TestProviderConfigLifecycle — top-level integration test
// ---------------------------------------------------------------------------

func TestProviderConfigLifecycle(t *testing.T) {
	store, rdb, _ := setupIntegrationStore(t)

	t.Run("A_FullCRUDLifecycle", func(t *testing.T) {
		testFullCRUDLifecycle(t, store)
	})

	t.Run("B_TwoTenantIsolation", func(t *testing.T) {
		testTwoTenantIsolation(t, store)
	})

	t.Run("C_RestartDurability", func(t *testing.T) {
		testRestartDurability(t, rdb)
	})
}

// ---------------------------------------------------------------------------
// Sub-test A: Full CRUD lifecycle for one tenant
// ---------------------------------------------------------------------------

func testFullCRUDLifecycle(t *testing.T, store providerconfig.ProviderConfigStore) {
	t.Helper()
	ctx := context.Background()

	tenantID := fmt.Sprintf("tenant-crud-%d", time.Now().UnixNano())

	input := &providerconfig.ProviderConfigInput{
		Name:         "primary",
		Type:         llm.ProviderAnthropic,
		DefaultModel: "claude-3-5-sonnet",
		Credentials: map[string]string{
			"api_key": "sk-test-12345678",
		},
		Enabled:      true,
		SetAsDefault: false,
	}

	// --- Create ---
	created, err := store.Create(ctx, tenantID, input)
	require.NoError(t, err, "Create failed")
	require.NotNil(t, created)
	assert.Equal(t, "primary", created.Name)
	assert.Equal(t, llm.ProviderAnthropic, created.Type)
	assert.Equal(t, "claude-3-5-sonnet", created.DefaultModel)
	assert.True(t, created.Enabled)
	// Credentials must be masked — "sk-test-12345678" is 18 chars → "****5678"
	assert.Equal(t, "****5678", created.CredentialsMasked["api_key"],
		"credentials must be masked on create response")

	// --- List → 1 result ---
	list, err := store.List(ctx, tenantID)
	require.NoError(t, err, "List failed")
	require.Len(t, list, 1, "expected exactly 1 provider after create")
	assert.Equal(t, "primary", list[0].Name)

	// --- Get → same record, credentials masked ---
	got, err := store.Get(ctx, tenantID, "primary")
	require.NoError(t, err, "Get failed")
	require.NotNil(t, got)
	assert.Equal(t, "primary", got.Name)
	assert.Equal(t, llm.ProviderAnthropic, got.Type)
	assert.Equal(t, "claude-3-5-sonnet", got.DefaultModel)
	assert.Equal(t, "****5678", got.CredentialsMasked["api_key"],
		"Get must return masked credentials")

	// --- Duplicate Create → ErrAlreadyExists ---
	_, dupErr := store.Create(ctx, tenantID, input)
	assert.True(t, errors.Is(dupErr, providerconfig.ErrAlreadyExists),
		"duplicate Create must return ErrAlreadyExists, got: %v", dupErr)

	// --- Update DefaultModel ---
	updateInput := &providerconfig.ProviderConfigInput{
		Name:         "primary",
		Type:         llm.ProviderAnthropic,
		DefaultModel: "claude-opus-4",
		Credentials: map[string]string{
			"api_key": "sk-test-12345678",
		},
		Enabled:      true,
		SetAsDefault: false,
	}
	updated, err := store.Update(ctx, tenantID, "primary", updateInput)
	require.NoError(t, err, "Update failed")
	assert.Equal(t, "claude-opus-4", updated.DefaultModel)

	// Confirm via Get
	afterUpdate, err := store.Get(ctx, tenantID, "primary")
	require.NoError(t, err)
	assert.Equal(t, "claude-opus-4", afterUpdate.DefaultModel,
		"Get after Update must reflect new DefaultModel")

	// --- SetDefault → GetDefault returns "primary" ---
	require.NoError(t, store.SetDefault(ctx, tenantID, "primary"), "SetDefault failed")

	defCfg, err := store.GetDefault(ctx, tenantID)
	require.NoError(t, err, "GetDefault failed")
	require.NotNil(t, defCfg)
	assert.Equal(t, "primary", defCfg.Name, "GetDefault must return the provider set as default")

	// --- SetFallbackChain / GetFallbackChain ---
	require.NoError(t, store.SetFallbackChain(ctx, tenantID, []string{"primary"}),
		"SetFallbackChain failed")

	chain, err := store.GetFallbackChain(ctx, tenantID)
	require.NoError(t, err, "GetFallbackChain failed")
	assert.Equal(t, []string{"primary"}, chain,
		"GetFallbackChain must return the chain that was set")

	// --- Resolve → decrypted credentials ---
	// Resolve is the execution-path helper; it must return plaintext credentials.
	resolved, err := store.Resolve(ctx, tenantID, "primary")
	require.NoError(t, err, "Resolve failed")
	require.NotNil(t, resolved)
	assert.Equal(t, "sk-test-12345678", resolved.Credentials["api_key"],
		"Resolve must return the plaintext credential")

	// --- Delete → List returns 0, Get returns ErrNotFound ---
	require.NoError(t, store.Delete(ctx, tenantID, "primary"), "Delete failed")

	afterDelete, err := store.List(ctx, tenantID)
	require.NoError(t, err)
	assert.Empty(t, afterDelete, "List after Delete must return empty slice")

	_, err = store.Get(ctx, tenantID, "primary")
	assert.True(t, errors.Is(err, providerconfig.ErrNotFound),
		"Get after Delete must return ErrNotFound, got: %v", err)

	// --- GetDefault after delete ---
	_, err = store.GetDefault(ctx, tenantID)
	// The default pointer is cleared when the named provider is deleted.
	// Either ErrNotFound or a natural miss; assert it does not return the deleted record.
	if err == nil {
		t.Error("GetDefault after deleting the default provider should fail")
	}
}

// ---------------------------------------------------------------------------
// Sub-test B: Two-tenant isolation + concurrent CRUD
// ---------------------------------------------------------------------------

func testTwoTenantIsolation(t *testing.T, store providerconfig.ProviderConfigStore) {
	t.Helper()
	ctx := context.Background()

	tenantA := fmt.Sprintf("tenant-a-%d", time.Now().UnixNano())
	tenantB := fmt.Sprintf("tenant-b-%d", time.Now().UnixNano())

	// Tenant A creates "foo".
	_, err := store.Create(ctx, tenantA, &providerconfig.ProviderConfigInput{
		Name:        "foo",
		Type:        llm.ProviderOpenAI,
		Credentials: map[string]string{"api_key": "sk-openai-00000001"},
		Enabled:     true,
	})
	require.NoError(t, err, "Tenant A create failed")

	// Tenant B must not see "foo".
	bList, err := store.List(ctx, tenantB)
	require.NoError(t, err)
	assert.Empty(t, bList, "Tenant B must not see Tenant A's providers")

	_, err = store.Get(ctx, tenantB, "foo")
	assert.True(t, errors.Is(err, providerconfig.ErrNotFound),
		"Tenant B Get of Tenant A's provider must return ErrNotFound")

	// Concurrent CRUD: 5 goroutines per tenant, each creating a uniquely-named provider.
	var wg sync.WaitGroup
	goroutinesPerTenant := 5

	createProviders := func(tenantID, prefix string) {
		for i := 0; i < goroutinesPerTenant; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				name := fmt.Sprintf("%s-provider-%d", prefix, idx)
				input := &providerconfig.ProviderConfigInput{
					Name: name,
					Type: llm.ProviderAnthropic,
					Credentials: map[string]string{
						"api_key": fmt.Sprintf("sk-ant-%s-%04d", prefix, idx),
					},
					Enabled: true,
				}
				if _, createErr := store.Create(ctx, tenantID, input); createErr != nil {
					t.Errorf("goroutine %d: Create failed for tenant %s: %v", idx, tenantID, createErr)
				}
			}(i)
		}
	}

	createProviders(tenantA, "goroutine")
	createProviders(tenantB, "goroutine")
	wg.Wait()

	// Assert record counts and isolation: Tenant A should have goroutinesPerTenant+1
	// providers (the "foo" created earlier plus the 5 goroutine-created ones).
	aList, err := store.List(ctx, tenantA)
	require.NoError(t, err)
	assert.Len(t, aList, goroutinesPerTenant+1,
		"Tenant A should have %d providers", goroutinesPerTenant+1)

	bList, err = store.List(ctx, tenantB)
	require.NoError(t, err)
	assert.Len(t, bList, goroutinesPerTenant,
		"Tenant B should have %d providers", goroutinesPerTenant)

	// Isolation assertion: all records returned by each tenant's List must carry
	// that tenant's ID. This is the authoritative cross-tenant leakage check —
	// provider names may legitimately collide across tenants; the TenantID field
	// must not.
	for _, cfg := range aList {
		assert.Equal(t, tenantA, cfg.TenantID,
			"record %q in Tenant A's list must have TenantID == tenantA", cfg.Name)
	}
	for _, cfg := range bList {
		assert.Equal(t, tenantB, cfg.TenantID,
			"record %q in Tenant B's list must have TenantID == tenantB", cfg.Name)
	}
}

// ---------------------------------------------------------------------------
// Sub-test C: Restart durability — second store instance reads same Redis
// ---------------------------------------------------------------------------

func testRestartDurability(t *testing.T, rdb redis.UniversalClient) {
	t.Helper()
	ctx := context.Background()

	tenantID := fmt.Sprintf("tenant-restart-%d", time.Now().UnixNano())

	// Store-instance-1: write a provider.
	store1 := newStoreFromClient(t, rdb)

	input := &providerconfig.ProviderConfigInput{
		Name:         "durable-provider",
		Type:         llm.ProviderAnthropic,
		DefaultModel: "claude-opus-4",
		Credentials: map[string]string{
			"api_key": "sk-durable-abcdef12",
		},
		Enabled:      true,
		SetAsDefault: true,
	}

	created, err := store1.Create(ctx, tenantID, input)
	require.NoError(t, err, "store1 Create failed")
	require.NotNil(t, created)

	createdID := created.ID

	// Release any reference to store1 — the interface has no Close(), but we
	// deliberately construct store2 fresh to prove there is no in-process state
	// being shared. store1 is now unreachable.
	store1 = nil //nolint:ineffassign // intentional — proves no shared reference

	// Store-instance-2: constructed with the SAME Redis client, SAME encryptor
	// type, SAME key provider returning the SAME deterministic key.
	store2 := newStoreFromClient(t, rdb)

	// Get by name must work and return the same record.
	retrieved, err := store2.Get(ctx, tenantID, "durable-provider")
	require.NoError(t, err, "store2 Get failed — encryption is not durable across instances")
	require.NotNil(t, retrieved)

	assert.Equal(t, createdID, retrieved.ID,
		"ID must survive a store restart")
	assert.Equal(t, "durable-provider", retrieved.Name)
	assert.Equal(t, llm.ProviderAnthropic, retrieved.Type)
	assert.Equal(t, "claude-opus-4", retrieved.DefaultModel)
	// Masked form is "****ef12" (last 4 of "sk-durable-abcdef12" is "ef12")
	assert.Equal(t, "****ef12", retrieved.CredentialsMasked["api_key"],
		"masked credential must survive store restart")

	// Resolve must decrypt the credential correctly from pure Redis state.
	resolved, err := store2.Resolve(ctx, tenantID, "durable-provider")
	require.NoError(t, err, "store2 Resolve failed — decryption not durable across instances")
	require.NotNil(t, resolved)
	assert.Equal(t, "sk-durable-abcdef12", resolved.Credentials["api_key"],
		"Resolve must return plaintext credential from pure Redis state — no in-process state is load-bearing")

	// Default pointer must also survive.
	defCfg, err := store2.GetDefault(ctx, tenantID)
	require.NoError(t, err, "store2 GetDefault failed")
	assert.Equal(t, "durable-provider", defCfg.Name,
		"default provider pointer must survive store restart")
}
