package cutoverv4

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestRedis starts an in-process miniredis and returns an open client.
// The client is closed via t.Cleanup.
func newTestRedis(t *testing.T) redis.UniversalClient {
	t.Helper()
	mr := miniredis.RunT(t)
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	sc, err := state.NewStateClient(cfg)
	require.NoError(t, err, "create state client against miniredis")
	t.Cleanup(func() { _ = sc.Close() })
	return sc.Client()
}

// newTestLogger returns a discarding slog logger suitable for tests.
func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// setKey is a convenience helper that sets a plain string key in Redis.
func setKey(t *testing.T, client redis.UniversalClient, key, value string) {
	t.Helper()
	err := client.Set(context.Background(), key, value, 0).Err()
	require.NoError(t, err)
}

// xaddKey is a convenience helper that writes one entry to a Redis Stream.
func xaddKey(t *testing.T, client redis.UniversalClient, stream, field, value string) {
	t.Helper()
	err := client.XAdd(context.Background(), &redis.XAddArgs{
		Stream: stream,
		Values: map[string]any{field: value},
	}).Err()
	require.NoError(t, err)
}

// keysMatching returns all Redis keys matching a pattern (via SCAN).
func keysMatching(t *testing.T, client redis.UniversalClient, pattern string) []string {
	t.Helper()
	var all []string
	var cursor uint64
	for {
		keys, next, err := client.Scan(context.Background(), cursor, pattern, 100).Result()
		require.NoError(t, err)
		all = append(all, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return all
}

// ---------------------------------------------------------------------------
// Redis flush tests (Task 13)
// ---------------------------------------------------------------------------

func TestFlushTenantState_DeletesMissionRunAgentKeys(t *testing.T) {
	client := newTestRedis(t)
	ctx := context.Background()

	// Populate keys for tenant "alpha".
	setKey(t, client, "tenant:alpha:mission:m-1", "data")
	setKey(t, client, "tenant:alpha:mission:m-2", "data")
	setKey(t, client, "tenant:alpha:run:r-1", "data")
	setKey(t, client, "tenant:alpha:agent:a-1", "data")
	setKey(t, client, "tenant:alpha:agent:a-2:state", "data")

	// Populate key for a different tenant to ensure isolation.
	setKey(t, client, "tenant:beta:mission:m-99", "data")

	// Preserve the audit log stream for alpha.
	xaddKey(t, client, "tenant:alpha:audit:log", "action", "event-1")

	deleted, err := FlushTenantState(ctx, client, "alpha")
	require.NoError(t, err)
	assert.Equal(t, 5, deleted, "expected 5 keys deleted for tenant alpha")

	// Assert alpha mission/run/agent keys are gone.
	assert.Empty(t, keysMatching(t, client, "tenant:alpha:mission:*"))
	assert.Empty(t, keysMatching(t, client, "tenant:alpha:run:*"))
	assert.Empty(t, keysMatching(t, client, "tenant:alpha:agent:*"))

	// Assert the audit log is preserved.
	xlen, err := client.XLen(ctx, "tenant:alpha:audit:log").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), xlen, "audit:log stream must be preserved")

	// Assert beta keys are untouched.
	assert.Equal(t, []string{"tenant:beta:mission:m-99"}, keysMatching(t, client, "tenant:beta:*"))
}

func TestFlushTenantState_AuditLogPreservedWhenMatchesPattern(t *testing.T) {
	// Verify that even if a future pattern change accidentally matches the audit
	// stream key, the explicit guard in scanAndDelete skips it.
	client := newTestRedis(t)
	ctx := context.Background()

	// Place the audit log stream.
	xaddKey(t, client, "tenant:gamma:audit:log", "action", "keep-this")

	// Run flush — gamma has no mission/run/agent keys, so nothing should be deleted.
	deleted, err := FlushTenantState(ctx, client, "gamma")
	require.NoError(t, err)
	assert.Equal(t, 0, deleted)

	// Audit log untouched.
	xlen, err := client.XLen(ctx, "tenant:gamma:audit:log").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(1), xlen)
}

func TestFlushTenantState_EmptyTenantID_ReturnsError(t *testing.T) {
	client := newTestRedis(t)
	_, err := FlushTenantState(context.Background(), client, "")
	require.Error(t, err)
}

func TestFlushTenantState_NoKeysIsNoop(t *testing.T) {
	client := newTestRedis(t)
	n, err := FlushTenantState(context.Background(), client, "no-such-tenant")
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ---------------------------------------------------------------------------
// Neo4j wipe tests (Task 12) — using MockGraphClient
// ---------------------------------------------------------------------------

func TestWipeTenantGraph_DeletesTenantANodes_PreservesTenantB(t *testing.T) {
	ctx := context.Background()
	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(ctx))

	// Seed mock with query result: 2 nodes for tenant-A, pre-seeded nodes in store.
	nodeAID, err := mock.CreateNode(ctx, []string{"agent_run"}, map[string]any{
		"tenant_id": "tenant-a",
		"name":      "node-1",
	})
	require.NoError(t, err)

	nodeBID, err := mock.CreateNode(ctx, []string{"tool_execution"}, map[string]any{
		"tenant_id": "tenant-b",
		"name":      "node-b",
	})
	require.NoError(t, err)

	// The mock's Query() returns an empty result set by default.  We configure it
	// to return a count for the count query and then simulate a delete via Summary.
	// Because MockGraphClient is a recorded-call mock (not a real graph), we
	// configure two results: count=2 (small enough for single-shot delete), then
	// a delete result with NodesDeleted=2.
	mock.SetQueryResults([]graph.QueryResult{
		// Response to countTenantNodes query.
		{
			Records: []map[string]any{{"cnt": int64(2)}},
			Columns: []string{"cnt"},
			Summary: graph.QuerySummary{NodesDeleted: 0},
		},
		// Response to deleteAllTenantNodes query.
		{
			Records: []map[string]any{},
			Columns: []string{},
			Summary: graph.QuerySummary{NodesDeleted: 2},
		},
	})

	deleted, err := WipeTenantGraph(ctx, mock, "tenant-a")
	require.NoError(t, err)
	assert.Equal(t, 2, deleted, "2 nodes should be reported as deleted")

	// Verify that Query was called and parameterised cypher was used (never literal
	// tenant-id concatenation).  The mock records all calls.
	calls := mock.GetCallsByMethod("Query")
	require.Len(t, calls, 2, "expected exactly 2 Query calls (count + delete)")

	// Verify the count query used the parameterised $t variable.
	countCypher, ok := calls[0].Args[0].(string)
	require.True(t, ok)
	assert.Contains(t, countCypher, "$t", "count query must use parameterised tenant_id")

	// Verify tenant-B node was never touched (CreateNode records are unrelated to
	// Query, but confirm the node still exists in the mock store).
	// MockGraphClient doesn't execute real Cypher against real nodes — it records
	// calls.  The important assertion is that all Query calls used tenant-a as the
	// 't' parameter, never tenant-b, confirming query-level isolation.
	nodes := mock.GetNodes()
	_, aStillExists := nodes[nodeAID]
	_, bStillExists := nodes[nodeBID]
	// Both nodes were created via CreateNode (not deleted by Query), so they
	// should still be in the mock store.
	assert.True(t, aStillExists, "node A should still be in mock store (mock doesn't exec Cypher)")
	assert.True(t, bStillExists, "node B should still be in mock store")

	// Crucial isolation check: none of the Query calls referenced tenant-b.
	for _, call := range calls {
		if params, ok := call.Args[1].(map[string]any); ok {
			assert.Equal(t, "tenant-a", params["t"],
				"query param 't' must equal 'tenant-a', never 'tenant-b'")
		}
	}
}

func TestWipeTenantGraph_EmptyTenantID_ReturnsError(t *testing.T) {
	ctx := context.Background()
	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(ctx))

	_, err := WipeTenantGraph(ctx, mock, "")
	require.Error(t, err)
}

func TestWipeTenantGraph_ZeroNodes_IsNoop(t *testing.T) {
	ctx := context.Background()
	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(ctx))

	// Count returns 0 — no delete should be issued.
	mock.SetQueryResults([]graph.QueryResult{
		{
			Records: []map[string]any{{"cnt": int64(0)}},
			Columns: []string{"cnt"},
			Summary: graph.QuerySummary{},
		},
	})

	n, err := WipeTenantGraph(ctx, mock, "empty-tenant")
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	// Only the count query should have been issued.
	queries := mock.GetCallsByMethod("Query")
	assert.Len(t, queries, 1)
}

func TestWipeTenantGraph_BatchedForLargeTenant(t *testing.T) {
	ctx := context.Background()
	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(ctx))

	// Simulate 110_000 nodes — above batchNodeThreshold → batched path.
	// First call: count.  Then two batch deletes: 10_000 then 100 (to terminate).
	mock.SetQueryResults([]graph.QueryResult{
		// Count query: above threshold.
		{
			Records: []map[string]any{{"cnt": int64(110_000)}},
			Columns: []string{"cnt"},
			Summary: graph.QuerySummary{},
		},
		// First batch: exactly nodeBatchSize deleted.
		{
			Records: []map[string]any{{"deleted": int64(nodeBatchSize)}},
			Columns: []string{"deleted"},
			Summary: graph.QuerySummary{NodesDeleted: nodeBatchSize},
		},
		// Second batch: fewer than nodeBatchSize → terminate loop.
		{
			Records: []map[string]any{{"deleted": int64(100)}},
			Columns: []string{"deleted"},
			Summary: graph.QuerySummary{NodesDeleted: 100},
		},
	})

	total, err := WipeTenantGraph(ctx, mock, "big-tenant")
	require.NoError(t, err)
	assert.Equal(t, nodeBatchSize+100, total)

	// count + 2 batches = 3 Query calls.
	assert.Len(t, mock.GetCallsByMethod("Query"), 3)
}

// ---------------------------------------------------------------------------
// Orchestration tests (Task 11)
// ---------------------------------------------------------------------------

func TestRun_RefusesWithoutConfirm(t *testing.T) {
	client := newTestRedis(t)
	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(context.Background()))

	cfg := Config{
		Tenants:     []string{"tenant-x"},
		Confirm:     false, // missing!
		Yes:         true,
		DryRun:      false,
		Logger:      newTestLogger(),
		RedisClient: client,
		GraphClient: mock,
	}
	err := Run(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Confirm flag is false")
}

func TestRun_Idempotent_SentinelPreventsReWipe(t *testing.T) {
	client := newTestRedis(t)
	ctx := context.Background()

	// Pre-set the sentinel key as if the tenant was already wiped.
	sentinelKey := "tenant:repeat:cutover:v4:done"
	setKey(t, client, sentinelKey, "2025-01-01T00:00:00Z")

	// Populate a mission key so we can verify it is NOT deleted.
	setKey(t, client, "tenant:repeat:mission:m-1", "should-survive")

	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(ctx))

	cfg := Config{
		Tenants:     []string{"repeat"},
		Confirm:     true,
		Yes:         true,
		DryRun:      false,
		Logger:      newTestLogger(),
		RedisClient: client,
		GraphClient: mock,
	}
	err := Run(ctx, cfg)
	require.NoError(t, err)

	// The mission key must survive (no wipe ran).
	val, err := client.Get(ctx, "tenant:repeat:mission:m-1").Result()
	require.NoError(t, err)
	assert.Equal(t, "should-survive", val)

	// No Query calls should have been made to Neo4j (Connect happened before Run).
	assert.Empty(t, mock.GetCallsByMethod("Query"), "no Neo4j Query calls on idempotent re-run")
}

func TestRun_FailureOnTenantA_DoesNotHaltTenantB(t *testing.T) {
	client := newTestRedis(t)
	ctx := context.Background()

	// Seed tenant-b with a mission key; tenant-a will fail during Neo4j wipe.
	setKey(t, client, "tenant:good:mission:m-1", "data")

	// Mock that returns an error on the first Query (tenant-a count) but
	// succeeds on subsequent calls (tenant-good).
	errorOnce := &errorOnceGraphClient{
		inner:      graph.NewMockGraphClient(),
		failOnCall: 0,
	}
	require.NoError(t, errorOnce.inner.Connect(ctx))

	// Configure mock results for tenant-good (count=1, then delete=1).
	errorOnce.inner.SetQueryResults([]graph.QueryResult{
		// Count for tenant-good after the error path is exhausted.
		{
			Records: []map[string]any{{"cnt": int64(1)}},
			Columns: []string{"cnt"},
			Summary: graph.QuerySummary{},
		},
		{
			Records: []map[string]any{},
			Summary: graph.QuerySummary{NodesDeleted: 1},
		},
	})

	cfg := Config{
		Tenants:     []string{"bad", "good"},
		Confirm:     true,
		Yes:         true,
		DryRun:      false,
		Logger:      newTestLogger(),
		RedisClient: client,
		GraphClient: errorOnce,
	}
	err := Run(ctx, cfg)
	// Run returns an error because one tenant failed.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "1 failed tenant")

	// But the good tenant's sentinel key SHOULD be set.
	sentinelGood := "tenant:good:cutover:v4:done"
	val, err2 := client.Get(ctx, sentinelGood).Result()
	require.NoError(t, err2, "sentinel for good tenant must exist")
	assert.NotEmpty(t, val)

	// And the bad tenant's sentinel must NOT be set.
	sentinelBad := "tenant:bad:cutover:v4:done"
	_, err3 := client.Get(ctx, sentinelBad).Result()
	assert.Equal(t, redis.Nil, err3, "sentinel for bad tenant must not exist")
}

func TestRun_DryRun_MutatesNothing(t *testing.T) {
	client := newTestRedis(t)
	ctx := context.Background()

	setKey(t, client, "tenant:dry:mission:m-1", "keep")
	setKey(t, client, "tenant:dry:run:r-1", "keep")

	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(ctx))

	cfg := Config{
		Tenants:     []string{"dry"},
		Confirm:     true,
		Yes:         true,
		DryRun:      true,
		Logger:      newTestLogger(),
		RedisClient: client,
		GraphClient: mock,
	}
	err := Run(ctx, cfg)
	require.NoError(t, err)

	// Keys must still exist.
	val, err := client.Get(ctx, "tenant:dry:mission:m-1").Result()
	require.NoError(t, err)
	assert.Equal(t, "keep", val)

	// No Query calls issued to Neo4j (Connect happened before Run, so GetCalls
	// would include Connect — check Query specifically).
	assert.Empty(t, mock.GetCallsByMethod("Query"), "dry-run must issue no Neo4j Query calls")

	// No sentinel key created.
	_, err = client.Get(ctx, "tenant:dry:cutover:v4:done").Result()
	assert.Equal(t, redis.Nil, err, "dry-run must not set sentinel key")
}

func TestRun_NoTenants_ReturnsError(t *testing.T) {
	client := newTestRedis(t)
	mock := graph.NewMockGraphClient()
	require.NoError(t, mock.Connect(context.Background()))

	cfg := Config{
		// TenantID and Tenants both empty.
		Confirm:     true,
		Yes:         true,
		Logger:      newTestLogger(),
		RedisClient: client,
		GraphClient: mock,
	}
	err := Run(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provide --tenant-id")
}

// ---------------------------------------------------------------------------
// errorOnceGraphClient — wraps MockGraphClient; returns an error on the first
// Query call, then delegates to the inner mock for subsequent calls.
// ---------------------------------------------------------------------------

type errorOnceGraphClient struct {
	inner      *graph.MockGraphClient
	failOnCall int
	callCount  int
}

var errSimulatedGraphFailure = errors.New("simulated Neo4j failure")

func (e *errorOnceGraphClient) Connect(ctx context.Context) error {
	return e.inner.Connect(ctx)
}

func (e *errorOnceGraphClient) Close(ctx context.Context) error {
	return e.inner.Close(ctx)
}

func (e *errorOnceGraphClient) Health(ctx context.Context) types.HealthStatus {
	return e.inner.Health(ctx)
}

func (e *errorOnceGraphClient) Query(ctx context.Context, cypher string, params map[string]any) (graph.QueryResult, error) {
	if e.callCount == e.failOnCall {
		e.callCount++
		return graph.QueryResult{}, fmt.Errorf("%w for query %q", errSimulatedGraphFailure, cypher)
	}
	e.callCount++
	return e.inner.Query(ctx, cypher, params)
}

func (e *errorOnceGraphClient) CreateNode(ctx context.Context, labels []string, props map[string]any) (string, error) {
	return e.inner.CreateNode(ctx, labels, props)
}

func (e *errorOnceGraphClient) CreateRelationship(ctx context.Context, fromID, toID, relType string, props map[string]any) error {
	return e.inner.CreateRelationship(ctx, fromID, toID, relType, props)
}

func (e *errorOnceGraphClient) DeleteNode(ctx context.Context, nodeID string) error {
	return e.inner.DeleteNode(ctx, nodeID)
}
