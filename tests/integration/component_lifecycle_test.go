//go:build integration
// +build integration

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/apikeys"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Test infrastructure helpers
// ---------------------------------------------------------------------------

// componentTestEnv holds a registry and work queue that share a single miniredis
// instance, ensuring that registry keys and work-stream keys live in the same
// Redis namespace (which is required for realistic lifecycle tests).
type componentTestEnv struct {
	reg   *component.RedisComponentRegistry
	queue component.WorkQueue
	mr    *miniredis.Miniredis
}

// newComponentTestEnv creates a fresh miniredis-backed registry + work queue.
// The miniredis server and both Redis clients are cleaned up automatically via
// t.Cleanup when the test ends.
func newComponentTestEnv(t *testing.T) *componentTestEnv {
	t.Helper()

	mr := miniredis.RunT(t)

	// Registry uses *redis.Client.
	regClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = regClient.Close() })

	// WorkQueue uses redis.UniversalClient — a *redis.Client satisfies the interface.
	queueClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = queueClient.Close() })

	return &componentTestEnv{
		reg:   component.NewRedisComponentRegistry(regClient, 30*time.Second),
		queue: component.NewRedisWorkQueue(queueClient),
		mr:    mr,
	}
}

// newAuthDB starts a Postgres container, runs migrations, and returns an
// apikeys.Store backed by it. The container is terminated via cleanup.
func newAuthDB(t *testing.T) (*apikeys.Store, func()) {
	t.Helper()
	ctx := context.Background()

	provider, err := testcontainers.ProviderDocker.GetProvider()
	if err != nil {
		t.Skipf("Docker not available, skipping test: %v", err)
		return nil, func() {}
	}
	if healthErr := provider.Health(ctx); healthErr != nil {
		t.Skipf("Docker not running, skipping test: %v", healthErr)
		return nil, func() {}
	}

	const (
		pgUser     = "testuser"
		pgPassword = "testpassword"
		pgDB       = "testdb"
	)

	req := testcontainers.ContainerRequest{
		Image: "postgres:15-alpine",
		Env: map[string]string{
			"POSTGRES_USER":     pgUser,
			"POSTGRES_PASSWORD": pgPassword,
			"POSTGRES_DB":       pgDB,
		},
		ExposedPorts: []string{"5432/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("database system is ready to accept connections"),
			wait.ForListeningPort("5432/tcp"),
		),
	}

	pgC, startErr := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, startErr, "failed to start Postgres container")

	cleanup := func() {
		if termErr := pgC.Terminate(ctx); termErr != nil {
			t.Logf("warning: failed to terminate Postgres container: %v", termErr)
		}
	}

	host, hostErr := pgC.Host(ctx)
	require.NoError(t, hostErr)

	mappedPort, portErr := pgC.MappedPort(ctx, "5432")
	require.NoError(t, portErr)

	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, mappedPort.Port(), pgUser, pgPassword, pgDB)

	db, openErr := sql.Open("postgres", dsn)
	require.NoError(t, openErr)
	t.Cleanup(func() { _ = db.Close() })

	require.Eventually(t, func() bool {
		return db.PingContext(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready in time")

	// Inline DDL for the api_keys table. Historically this was done via
	// provisioner.RunMigrations, but the provisioner package has moved into the
	// tenant-operator. The integration test only needs the schema local to the
	// APIKeyAuthenticator under test, so the DDL is inlined here.
	const apiKeysDDL = `
CREATE TABLE IF NOT EXISTS api_keys (
    key_id         TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    key_hash       TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL DEFAULT '',
    created_by     TEXT NOT NULL DEFAULT '',
    allowed_kinds  TEXT[] NOT NULL DEFAULT '{}',
    allowed_names  TEXT[] NOT NULL DEFAULT '{}',
    capabilities   TEXT[] NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT 'active',
    max_uses       INTEGER,
    use_count      INTEGER NOT NULL DEFAULT 0,
    expires_at     TIMESTAMPTZ,
    last_used_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
`
	_, ddlErr := db.ExecContext(ctx, apiKeysDDL)
	require.NoError(t, ddlErr, "failed to create api_keys table")

	a, authErr := apikeys.New(db)
	require.NoError(t, authErr)
	require.NotNil(t, a)

	return a, cleanup
}

// ---------------------------------------------------------------------------
// Test 1: Full Component Lifecycle
// ---------------------------------------------------------------------------

// TestComponentLifecycle_FullRoundTrip exercises the complete lifecycle of a
// single component through the registry and work queue:
//
//  1. Register a component.
//  2. Discover it by tenant/kind/name.
//  3. Enqueue a work item.
//  4. Claim the work item (simulating the component polling).
//  5. Verify all WorkItem fields survive the round-trip.
//  6. Deliver a result from a concurrent goroutine.
//  7. Wait for the result and verify its payload.
//  8. Acknowledge the stream message.
//  9. Deregister the component.
//  10. Verify it is no longer discoverable.
func TestComponentLifecycle_FullRoundTrip(t *testing.T) {
	env := newComponentTestEnv(t)
	ctx := context.Background()

	const (
		tenant     = "acme"
		kind       = "agent"
		name       = "test-agent"
		consumerID = "consumer-1"
		workType   = "recon-scan"
	)

	// Step 1: Register the component.
	instanceID, err := env.reg.Register(ctx, tenant, kind, name, component.ComponentInfo{
		Version: "1.0.0",
		Metadata: map[string]string{
			"region": "us-east-1",
		},
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceID, "Register must return a non-empty instance ID")

	// Step 2: Discover it by tenant/kind/name.
	instances, err := env.reg.Discover(ctx, tenant, kind, name)
	require.NoError(t, err)
	require.Len(t, instances, 1, "Discover must return exactly one instance after registration")

	disc := instances[0]
	assert.Equal(t, kind, disc.Kind)
	assert.Equal(t, name, disc.Name)
	assert.Equal(t, "1.0.0", disc.Version)
	assert.Equal(t, tenant, disc.TenantID)
	assert.Equal(t, instanceID, disc.InstanceID)
	assert.Equal(t, "us-east-1", disc.Metadata["region"])
	assert.False(t, disc.StartedAt.IsZero(), "StartedAt must be populated by the registry")

	// Step 3: Enqueue a work item.
	payload := []byte(`{"target":"10.0.0.1","depth":2}`)
	item := component.WorkItem{
		WorkID:    "lifecycle-work-001",
		WorkType:  workType,
		Payload:   payload,
		Context:   map[string]string{"mission": "m-001", "priority": "high"},
		TimeoutMs: 10000,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}

	msgID, err := env.queue.Enqueue(ctx, tenant, kind, name, item)
	require.NoError(t, err)
	assert.NotEmpty(t, msgID, "Enqueue must return a non-empty stream message ID")

	// Step 4: Claim the work item.
	claimed, err := env.queue.Claim(ctx, tenant, kind, name, consumerID, 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed, "Claim must return the enqueued work item")

	// Step 5: Verify work item fields survive the serialisation round-trip.
	assert.Equal(t, item.WorkID, claimed.WorkID)
	assert.Equal(t, item.WorkType, claimed.WorkType)
	assert.Equal(t, item.Payload, claimed.Payload)
	assert.Equal(t, item.Context, claimed.Context)
	assert.Equal(t, item.TimeoutMs, claimed.TimeoutMs)
	assert.False(t, claimed.CreatedAt.IsZero(), "CreatedAt must survive JSON round-trip")

	// Step 6: Deliver a result from a concurrent goroutine while the main
	// goroutine is already blocked in WaitForResult (step 7).
	expectedResult := component.WorkResult{
		WorkID: item.WorkID,
		Result: []byte(`{"hosts_found":3,"open_ports":7}`),
	}

	var deliverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give WaitForResult a moment to establish its pub/sub subscription.
		time.Sleep(30 * time.Millisecond)
		deliverErr = env.queue.DeliverResult(ctx, item.WorkID, expectedResult)
	}()

	// Step 7: Wait for the result.
	result, err := env.queue.WaitForResult(ctx, item.WorkID, 5*time.Second)
	wg.Wait()

	require.NoError(t, deliverErr, "DeliverResult must not error")
	require.NoError(t, err, "WaitForResult must not error")
	require.NotNil(t, result)
	assert.Equal(t, expectedResult.WorkID, result.WorkID)
	assert.Equal(t, expectedResult.Result, result.Result)
	assert.Nil(t, result.Error, "WorkResult.Error must be nil for a successful result")

	// Step 8: Acknowledge the stream message.
	err = env.queue.Acknowledge(ctx, tenant, kind, name, msgID)
	require.NoError(t, err, "Acknowledge must not error for a valid message ID")

	// Step 9: Deregister the component.
	err = env.reg.Deregister(ctx, tenant, kind, name, instanceID)
	require.NoError(t, err, "Deregister must succeed for a registered instance")

	// Step 10: Verify it is no longer discoverable.
	instances, err = env.reg.Discover(ctx, tenant, kind, name)
	require.NoError(t, err)
	assert.Empty(t, instances, "Discover must return no results after Deregister")
}

// ---------------------------------------------------------------------------
// Test 2: Multi-Tenant Isolation
// ---------------------------------------------------------------------------

// TestComponentLifecycle_MultiTenantIsolation verifies that registry entries and
// work streams are fully isolated between tenants.  Two tenants register an agent
// under the same name; each can only see and claim its own work.
func TestComponentLifecycle_MultiTenantIsolation(t *testing.T) {
	env := newComponentTestEnv(t)
	ctx := context.Background()

	const (
		kind      = "agent"
		name      = "dns-recon"
		consumerA = "consumer-tenantA"
		consumerB = "consumer-tenantB"
		tenantA   = "tenant-alpha"
		tenantB   = "tenant-beta"
	)

	// Step 1: Register the same-named agent for both tenants.
	instanceA, err := env.reg.Register(ctx, tenantA, kind, name, component.ComponentInfo{
		Version: "2.0.0",
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceA)

	instanceB, err := env.reg.Register(ctx, tenantB, kind, name, component.ComponentInfo{
		Version: "2.1.0",
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceB)

	// Instances must be distinct — UUIDs are generated per registration.
	assert.NotEqual(t, instanceA, instanceB,
		"Each registration must receive a unique instance ID")

	// Step 2: Discover for tenant A — must see only tenant A's instance.
	resultsA, err := env.reg.Discover(ctx, tenantA, kind, name)
	require.NoError(t, err)
	require.Len(t, resultsA, 1, "tenantA Discover must return exactly one result")
	assert.Equal(t, tenantA, resultsA[0].TenantID)
	assert.Equal(t, instanceA, resultsA[0].InstanceID)
	assert.Equal(t, "2.0.0", resultsA[0].Version)

	// Step 3: Discover for tenant B — must see only tenant B's instance.
	resultsB, err := env.reg.Discover(ctx, tenantB, kind, name)
	require.NoError(t, err)
	require.Len(t, resultsB, 1, "tenantB Discover must return exactly one result")
	assert.Equal(t, tenantB, resultsB[0].TenantID)
	assert.Equal(t, instanceB, resultsB[0].InstanceID)
	assert.Equal(t, "2.1.0", resultsB[0].Version)

	// Step 4: Enqueue work specifically for tenant A's agent.
	workForA := component.WorkItem{
		WorkID:   "work-tenantA-001",
		WorkType: "dns-bruteforce",
		Payload:  []byte(`{"domain":"alpha.example.com"}`),
	}
	msgIDForA, err := env.queue.Enqueue(ctx, tenantA, kind, name, workForA)
	require.NoError(t, err)
	require.NotEmpty(t, msgIDForA)

	// Step 5: Claim as tenant A's consumer — must receive the work item.
	claimedByA, err := env.queue.Claim(ctx, tenantA, kind, name, consumerA, 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimedByA, "tenant A consumer must claim the work item enqueued for tenant A")
	assert.Equal(t, workForA.WorkID, claimedByA.WorkID)
	assert.Equal(t, workForA.Payload, claimedByA.Payload)

	// Step 6: Claim as tenant B's consumer — must get nothing because the work
	// was enqueued under the tenant A stream key.
	// The tenant B stream is empty; Claim should return nil, nil on timeout.
	claimedByB, err := env.queue.Claim(ctx, tenantB, kind, name, consumerB, 50*time.Millisecond)
	require.NoError(t, err)
	assert.Nil(t, claimedByB,
		"tenant B consumer must not receive work enqueued for tenant A (different stream key)")

	// Confirm the registry still sees both as independent instances.
	allA, err := env.reg.ListTenantComponents(ctx, tenantA)
	require.NoError(t, err)
	require.Len(t, allA, 1)
	assert.Equal(t, instanceA, allA[0].InstanceID)

	allB, err := env.reg.ListTenantComponents(ctx, tenantB)
	require.NoError(t, err)
	require.Len(t, allB, 1)
	assert.Equal(t, instanceB, allB[0].InstanceID)
}

// ---------------------------------------------------------------------------
// Test 3: API Key → Tenant Context → Component Registration Flow
// ---------------------------------------------------------------------------

// TestComponentLifecycle_APIKeyToTenantFlow verifies the API key management
// and tenant context plumbing: an API key is minted for a tenant via
// apikeys.Store, the tenant from the record is injected into context via
// auth.ContextWithTenantString, and the registry enforces that scoping.
//
// Note: API key validation (Authenticate) has moved to the ext_authz sidecar.
// The daemon only manages key records; it does not authenticate them at runtime.
func TestComponentLifecycle_APIKeyToTenantFlow(t *testing.T) {
	// API keys are Postgres-backed; spin up a container for the store.
	store, authCleanup := newAuthDB(t)
	defer authCleanup()

	// The component registry continues to use Redis.
	mr := newComponentTestEnv(t)
	redisClient := redis.NewClient(&redis.Options{Addr: mr.mr.Addr()})
	t.Cleanup(func() { _ = redisClient.Close() })

	reg := component.NewRedisComponentRegistry(redisClient, 30*time.Second)

	ctx := context.Background()
	const (
		targetTenant = "acme"
		otherTenant  = "other-corp"
		kind         = "tool"
		name         = "port-scanner"
	)

	// Step 1: Create an API key for the target tenant.
	rawKey, record, err := store.CreateKey(ctx, targetTenant, nil, nil, nil, "", "")
	require.NoError(t, err)
	require.NotEmpty(t, rawKey)
	require.NotNil(t, record)
	assert.Equal(t, targetTenant, record.TenantID)

	// Step 2: The tenant is available directly from the record (validation is
	// performed by ext_authz; the daemon trusts the signed identity headers it
	// receives after ext_authz has authenticated the API key).
	tenantFromRecord := record.TenantID
	assert.Equal(t, targetTenant, tenantFromRecord,
		"Record must carry the tenant_id matching the key's tenant")

	// Step 3: Inject the tenant into the context using auth.ContextWithTenantString.
	tenantCtx := auth.ContextWithTenantString(ctx, tenantFromRecord)
	assert.Equal(t, targetTenant, auth.TenantStringFromContext(tenantCtx),
		"TenantFromContext must return the tenant injected by ContextWithTenant")

	// Step 4: Register a component using the tenant extracted from the context.
	tenantID := auth.TenantStringFromContext(tenantCtx)
	instanceID, err := reg.Register(tenantCtx, tenantID, kind, name, component.ComponentInfo{
		Version: "3.0.0",
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceID)

	// Step 5: Verify the component is discoverable for the correct tenant.
	results, err := reg.Discover(tenantCtx, targetTenant, kind, name)
	require.NoError(t, err)
	require.Len(t, results, 1, "component must be discoverable for the registering tenant")
	assert.Equal(t, targetTenant, results[0].TenantID)
	assert.Equal(t, instanceID, results[0].InstanceID)

	// Step 6: Verify the component is NOT discoverable for a different tenant
	// (both the tenant namespace and the _system namespace must be empty for otherTenant).
	otherResults, err := reg.Discover(ctx, otherTenant, kind, name)
	require.NoError(t, err)
	assert.Empty(t, otherResults,
		"component registered for %q must not appear under %q",
		targetTenant, otherTenant)
}

// ---------------------------------------------------------------------------
// Test 4: System Components Visible to All Tenants
// ---------------------------------------------------------------------------

// TestComponentLifecycle_SystemComponents verifies the _system tenant behaviour:
//
//  1. A tool registered under _system is visible to all tenants via Discover.
//  2. A tenant-scoped tool with the same name shadows the _system tool for that
//     tenant but does not affect other tenants.
func TestComponentLifecycle_SystemComponents(t *testing.T) {
	env := newComponentTestEnv(t)
	ctx := context.Background()

	const (
		kind     = "tool"
		toolName = "whois-lookup"
		tenantA  = "tenant-alpha"
		tenantB  = "tenant-beta"
	)

	// Step 1: Register the tool under the _system tenant.
	// The _system tenant string is the module-internal constant "\"_system\".
	// We use it directly here because integration tests exercise the public API
	// at the same layer as production code.
	const systemTenant = "_system"
	systemInstanceID, err := env.reg.Register(ctx, systemTenant, kind, toolName, component.ComponentInfo{
		Version:  "1.0.0",
		Metadata: map[string]string{"scope": "global"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, systemInstanceID)

	// Step 2: Tenant A discovers the tool — should find the _system copy.
	resultsA, err := env.reg.Discover(ctx, tenantA, kind, toolName)
	require.NoError(t, err)
	require.Len(t, resultsA, 1, "tenant A must discover the _system tool")
	assert.Equal(t, systemTenant, resultsA[0].TenantID)
	assert.Equal(t, systemInstanceID, resultsA[0].InstanceID)

	// Step 3: Tenant B also discovers the _system tool.
	resultsB, err := env.reg.Discover(ctx, tenantB, kind, toolName)
	require.NoError(t, err)
	require.Len(t, resultsB, 1, "tenant B must also discover the _system tool")
	assert.Equal(t, systemTenant, resultsB[0].TenantID)
	assert.Equal(t, systemInstanceID, resultsB[0].InstanceID)

	// Step 4: Register a tenant-scoped tool under tenant A with the same name.
	tenantAInstanceID, err := env.reg.Register(ctx, tenantA, kind, toolName, component.ComponentInfo{
		Version:  "2.0.0",
		Metadata: map[string]string{"scope": "tenant-override"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, tenantAInstanceID)
	assert.NotEqual(t, systemInstanceID, tenantAInstanceID)

	// Step 5: Tenant A now discovers TWO instances (its own + the _system one).
	// The Discover contract combines tenant-scoped results with _system results.
	resultsAAfter, err := env.reg.Discover(ctx, tenantA, kind, toolName)
	require.NoError(t, err)
	require.Len(t, resultsAAfter, 2,
		"tenant A must see both its own tool and the _system tool after registering a local copy")

	tenantIDs := make(map[string]bool, 2)
	for _, r := range resultsAAfter {
		tenantIDs[r.TenantID] = true
	}
	assert.True(t, tenantIDs[tenantA],
		"tenant A's own instance must appear in combined results")
	assert.True(t, tenantIDs[systemTenant],
		"_system instance must still appear in tenant A's combined results")

	// Step 6: Tenant B still sees only the _system tool (unaffected by tenant A's registration).
	resultsBAfter, err := env.reg.Discover(ctx, tenantB, kind, toolName)
	require.NoError(t, err)
	require.Len(t, resultsBAfter, 1, "tenant B must still see only the _system tool")
	assert.Equal(t, systemTenant, resultsBAfter[0].TenantID)
	assert.Equal(t, systemInstanceID, resultsBAfter[0].InstanceID)
}

// ---------------------------------------------------------------------------
// Test 5: Result Delivery With Work Error
// ---------------------------------------------------------------------------

// TestComponentLifecycle_WorkError verifies that structured WorkErrors survive
// the full enqueue-claim-deliver-wait round-trip so that callers can inspect
// retryability and error codes after a failed execution.
func TestComponentLifecycle_WorkError(t *testing.T) {
	env := newComponentTestEnv(t)
	ctx := context.Background()

	const (
		tenant     = "acme"
		kind       = "agent"
		name       = "fragile-agent"
		consumerID = "consumer-1"
	)

	// Register, enqueue, and claim are exercised here but kept brief because
	// those paths are fully validated in TestComponentLifecycle_FullRoundTrip.
	_, err := env.reg.Register(ctx, tenant, kind, name, component.ComponentInfo{
		Version: "0.1.0",
	})
	require.NoError(t, err)

	item := component.WorkItem{
		WorkID:   "work-error-001",
		WorkType: "exploit",
		Payload:  []byte(`{"target":"10.0.0.99"}`),
	}
	_, err = env.queue.Enqueue(ctx, tenant, kind, name, item)
	require.NoError(t, err)

	claimed, err := env.queue.Claim(ctx, tenant, kind, name, consumerID, 500*time.Millisecond)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	assert.Equal(t, item.WorkID, claimed.WorkID)

	// Deliver a result that signals a retryable failure.
	failResult := component.WorkResult{
		WorkID: item.WorkID,
		Error: &component.WorkError{
			Code:      "TARGET_UNREACHABLE",
			Message:   "connection refused after 3 attempts",
			Retryable: true,
		},
	}

	var deliverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(20 * time.Millisecond)
		deliverErr = env.queue.DeliverResult(ctx, item.WorkID, failResult)
	}()

	result, err := env.queue.WaitForResult(ctx, item.WorkID, 5*time.Second)
	wg.Wait()

	require.NoError(t, deliverErr)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.Error, "WorkResult must carry the structured error")

	assert.Equal(t, "TARGET_UNREACHABLE", result.Error.Code)
	assert.Equal(t, "connection refused after 3 attempts", result.Error.Message)
	assert.True(t, result.Error.Retryable,
		"Retryable flag must survive the serialisation round-trip")
	assert.Nil(t, result.Result, "Result payload must be nil when an error is present")
}

// ---------------------------------------------------------------------------
// Test 6: TTL Expiry Deregisters Components
// ---------------------------------------------------------------------------

// TestComponentLifecycle_TTLExpiry verifies that the registry's time-to-live
// mechanism automatically deregisters components that stop heartbeating.
// This uses miniredis's FastForward to simulate clock advancement without
// sleeping, keeping the test deterministic and fast.
func TestComponentLifecycle_TTLExpiry(t *testing.T) {
	mr := miniredis.RunT(t)

	regClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = regClient.Close() })

	// Use a very short TTL so we can expire keys with a small FastForward.
	const shortTTL = 2 * time.Second
	reg := component.NewRedisComponentRegistry(regClient, shortTTL)
	ctx := context.Background()

	const (
		tenant = "acme"
		kind   = "agent"
		name   = "expiring-agent"
	)

	instanceID, err := reg.Register(ctx, tenant, kind, name, component.ComponentInfo{
		Version: "1.0.0",
	})
	require.NoError(t, err)
	require.NotEmpty(t, instanceID)

	// Verify the component is visible immediately after registration.
	results, err := reg.Discover(ctx, tenant, kind, name)
	require.NoError(t, err)
	require.Len(t, results, 1, "component must be discoverable immediately after registration")

	// Advance miniredis's internal clock past the TTL to trigger key expiry.
	mr.FastForward(shortTTL + 500*time.Millisecond)

	// After TTL expiry the key must be gone; Discover must return empty.
	results, err = reg.Discover(ctx, tenant, kind, name)
	require.NoError(t, err)
	assert.Empty(t, results,
		"component must be absent from Discover after its TTL has elapsed")

	// RefreshTTL on the now-expired key must return ErrComponentNotFound.
	err = reg.RefreshTTL(ctx, tenant, kind, name, instanceID)
	assert.ErrorIs(t, err, component.ErrComponentNotFound,
		"RefreshTTL must return ErrComponentNotFound for an expired key")
}
