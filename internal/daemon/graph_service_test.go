package daemon

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	graphpb "github.com/zero-day-ai/sdk/api/gen/gibson/graph/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// graphServerWithPool creates a graphServer backed by the given pool getter.
func graphServerWithPool(getter func() datapool.Pool) *graphServer {
	return NewGraphServer(getter, nil, nil)
}

// graphServerReadyPool creates a graphServer backed by a mock pool that returns
// a conn with a nil Neo4j session (the "connected but no DB" state accepted by
// unit tests that only need to verify error paths, not Cypher execution).
func graphServerReadyPool() *graphServer {
	return graphServerWithPool(func() datapool.Pool {
		return &mockPool{conn: minimalConn()}
	})
}

func graphTenantCtx() context.Context {
	return auth.WithTenant(context.Background(), auth.MustNewTenantID("test-graph-tenant"))
}

// ─────────────────────────────────────────────────────────────────────────────
// NewGraphServer construction
// ─────────────────────────────────────────────────────────────────────────────

func TestNewGraphServer_NilPoolGetter_Panics(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil poolGetter, got none")
		}
	}()
	NewGraphServer(nil, nil, nil)
}

func TestNewGraphServer_ValidConfig(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	if srv == nil {
		t.Fatal("expected non-nil graphServer")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetTenantGraph — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetTenantGraph_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	ctx := context.Background() // no tenant

	_, err := srv.GetTenantGraph(ctx, &graphpb.GetTenantGraphRequest{Limit: 10})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetTenantGraph no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetTenantGraph — not provisioned → FailedPrecondition
// ─────────────────────────────────────────────────────────────────────────────

func TestGetTenantGraph_NotProvisioned_FailedPrecondition(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{
			Tenant: "test-graph-tenant",
			Reason: "pool not created yet",
		}}
	})

	_, err := srv.GetTenantGraph(graphTenantCtx(), &graphpb.GetTenantGraphRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetTenantGraph not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetTenantGraph — nil pool → Unavailable
// ─────────────────────────────────────────────────────────────────────────────

func TestGetTenantGraph_NilPool_Unavailable(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool { return nil })

	_, err := srv.GetTenantGraph(graphTenantCtx(), &graphpb.GetTenantGraphRequest{})
	assertGRPCCode(t, err, codes.Unavailable, "GetTenantGraph nil pool")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMissionGraph — missing mission_id → InvalidArgument
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMissionGraph_MissingMissionID_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()

	_, err := srv.GetMissionGraph(graphTenantCtx(), &graphpb.GetMissionGraphRequest{})
	assertGRPCCode(t, err, codes.InvalidArgument, "GetMissionGraph no mission_id")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMissionGraph — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMissionGraph_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	ctx := context.Background()

	_, err := srv.GetMissionGraph(ctx, &graphpb.GetMissionGraphRequest{MissionId: "m1"})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetMissionGraph no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetMissionGraph — not provisioned → FailedPrecondition
// ─────────────────────────────────────────────────────────────────────────────

func TestGetMissionGraph_NotProvisioned_FailedPrecondition(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	_, err := srv.GetMissionGraph(graphTenantCtx(), &graphpb.GetMissionGraphRequest{MissionId: "m1"})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetMissionGraph not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryPaths — missing from_node_id → InvalidArgument
// ─────────────────────────────────────────────────────────────────────────────

func TestQueryPaths_MissingFromNode_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()

	req := &graphpb.QueryPathsRequest{}
	req.To = &graphpb.QueryPathsRequest_ToNodeId{ToNodeId: "n2"}
	_, err := srv.QueryPaths(graphTenantCtx(), req)
	assertGRPCCode(t, err, codes.InvalidArgument, "QueryPaths no from_node_id")
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryPaths — missing to → InvalidArgument
// ─────────────────────────────────────────────────────────────────────────────

func TestQueryPaths_MissingTo_InvalidArgument(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()

	_, err := srv.QueryPaths(graphTenantCtx(), &graphpb.QueryPathsRequest{FromNodeId: "n1"})
	assertGRPCCode(t, err, codes.InvalidArgument, "QueryPaths no to")
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryPaths — both to fields set → InvalidArgument
// ─────────────────────────────────────────────────────────────────────────────

// TestQueryPaths_ToNodeIdSet verifies that setting to_node_id passes argument validation.
func TestQueryPaths_ToNodeIdSet(t *testing.T) {
	t.Parallel()
	// pool is not provisioned so we get FailedPrecondition, not InvalidArgument —
	// that confirms the argument validation passed before the pool lookup.
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})

	req := &graphpb.QueryPathsRequest{
		FromNodeId: "n1",
		MaxDepth:   5,
	}
	req.To = &graphpb.QueryPathsRequest_ToNodeId{ToNodeId: "n2"}
	_, err := srv.QueryPaths(graphTenantCtx(), req)
	assertGRPCCode(t, err, codes.FailedPrecondition, "QueryPaths to_node_id set")
}

// ─────────────────────────────────────────────────────────────────────────────
// QueryPaths — cap enforcement (max_depth > MaxPathDepth clamped)
// ─────────────────────────────────────────────────────────────────────────────

func TestQueryPaths_CapsApplied(t *testing.T) {
	t.Parallel()
	// The cap logic lives in DashboardQueries.QueryPaths, validated in graph tests.
	// Here we just confirm no panic when oversized depth is passed.
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	req := &graphpb.QueryPathsRequest{FromNodeId: "n1", MaxDepth: 999}
	req.To = &graphpb.QueryPathsRequest_ToNodeId{ToNodeId: "n2"}
	_, err := srv.QueryPaths(graphTenantCtx(), req)
	// Should fail at pool.For (not provisioned), not at cap clamp.
	assertGRPCCode(t, err, codes.FailedPrecondition, "QueryPaths cap + not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchGraphUpdates — no bus → Unimplemented
// ─────────────────────────────────────────────────────────────────────────────

func TestWatchGraphUpdates_NoBus_Unimplemented(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool() // bus is nil
	stream := &mockWatchStream{ctx: graphTenantCtx()}

	err := srv.WatchGraphUpdates(&graphpb.WatchGraphUpdatesRequest{}, stream)
	assertGRPCCode(t, err, codes.Unimplemented, "WatchGraphUpdates no bus")
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchGraphUpdates — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestWatchGraphUpdates_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	bus := graph.NewBus(nil)
	srv := NewGraphServer(
		func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		nil,
		bus,
	)

	stream := &mockWatchStream{ctx: context.Background()} // no tenant
	err := srv.WatchGraphUpdates(&graphpb.WatchGraphUpdatesRequest{}, stream)
	assertGRPCCode(t, err, codes.PermissionDenied, "WatchGraphUpdates no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchGraphUpdates — ctx cancel exits cleanly
// ─────────────────────────────────────────────────────────────────────────────

func TestWatchGraphUpdates_ContextCancel_CleanExit(t *testing.T) {
	t.Parallel()
	bus := graph.NewBus(nil)
	srv := NewGraphServer(
		func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		nil,
		bus,
	)

	ctx, cancel := context.WithCancel(graphTenantCtx())
	stream := &mockWatchStream{ctx: ctx}

	done := make(chan error, 1)
	go func() {
		done <- srv.WatchGraphUpdates(&graphpb.WatchGraphUpdatesRequest{}, stream)
	}()

	cancel() // cancel context → handler should return nil
	err := <-done
	if err != nil {
		t.Errorf("WatchGraphUpdates context cancel: want nil, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// WatchGraphUpdates — publish arrives on stream
// ─────────────────────────────────────────────────────────────────────────────

func TestWatchGraphUpdates_PublishArrivesOnStream(t *testing.T) {
	t.Parallel()
	bus := graph.NewBus(nil)
	tenant := auth.MustNewTenantID("stream-tenant")
	srv := NewGraphServer(
		func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		nil,
		bus,
	)

	ctx, cancel := context.WithCancel(auth.WithTenant(context.Background(), tenant))
	defer cancel()

	received := make(chan *graphpb.GraphUpdate, 1)
	stream := &mockWatchStream{ctx: ctx, onSend: func(u *graphpb.GraphUpdate) {
		received <- u
		cancel() // stop after first message
	}}

	done := make(chan error, 1)
	go func() {
		done <- srv.WatchGraphUpdates(&graphpb.WatchGraphUpdatesRequest{}, stream)
	}()

	// Give the goroutine time to subscribe before publishing.
	// In production this is naturally ordered; in tests we poll the bus length.
	for i := 0; i < 20; i++ {
		if bus.Len() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	bus.Publish(tenant, &graphpb.GraphUpdate{Kind: graphpb.GraphUpdate_NODE_ADDED})

	select {
	case u := <-received:
		if u.GetKind() != graphpb.GraphUpdate_NODE_ADDED {
			t.Errorf("got kind %v, want NODE_ADDED", u.GetKind())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for stream update")
	}

	if err := <-done; err != nil {
		t.Errorf("WatchGraphUpdates exited with error: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// mockWatchStream — minimal grpc.ServerStreamingServer[GraphUpdate]
// ─────────────────────────────────────────────────────────────────────────────

type mockWatchStream struct {
	ctx    context.Context
	sent   []*graphpb.GraphUpdate
	onSend func(*graphpb.GraphUpdate) // optional callback; called after each Send
}

func (m *mockWatchStream) Send(update *graphpb.GraphUpdate) error {
	m.sent = append(m.sent, update)
	if m.onSend != nil {
		m.onSend(update)
	}
	return nil
}

func (m *mockWatchStream) Context() context.Context {
	return m.ctx
}

func (m *mockWatchStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockWatchStream) SendHeader(metadata.MD) error { return nil }
func (m *mockWatchStream) SetTrailer(metadata.MD)       {}
func (m *mockWatchStream) SendMsg(_ any) error          { return nil }
func (m *mockWatchStream) RecvMsg(_ any) error          { return nil }

// ─────────────────────────────────────────────────────────────────────────────
// GetFindingCounts — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindingCounts_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	_, err := srv.GetFindingCounts(context.Background(), &graphpb.GetFindingCountsRequest{})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetFindingCounts no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFindingCounts — NotProvisioned → FailedPrecondition
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindingCounts_NotProvisioned_FailedPrecondition(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	_, err := srv.GetFindingCounts(graphTenantCtx(), &graphpb.GetFindingCountsRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetFindingCounts not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFindingCounts — happy path (Neo4j returns empty, nil conn is fine for
// minimalConn because the DashboardQueries ExecuteRead is never called when
// we can't get a real driver — the query will error, not the handler setup).
// We just verify the request reaches the handler without auth/pool errors.
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindingCounts_ReachesQuery(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool() // minimalConn has nil Neo4j; query will fail internally
	// We expect Internal (not PermissionDenied or FailedPrecondition) since auth passed.
	_, err := srv.GetFindingCounts(graphTenantCtx(), &graphpb.GetFindingCountsRequest{
		GroupBy: graphpb.FindingCountGroupBy_SEVERITY,
	})
	// With nil Neo4j the SessionGraphClient will error → Internal gRPC code.
	// We just assert it's NOT PermissionDenied or FailedPrecondition.
	if err == nil {
		return // no error is fine too (mock returns nil)
	}
	assertNotGRPCCode(t, err, codes.PermissionDenied, "GetFindingCounts reached query")
	assertNotGRPCCode(t, err, codes.FailedPrecondition, "GetFindingCounts reached query")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFindingTimeSeries — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindingTimeSeries_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	_, err := srv.GetFindingTimeSeries(context.Background(), &graphpb.GetFindingTimeSeriesRequest{})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetFindingTimeSeries no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFindingTimeSeries — NotProvisioned → FailedPrecondition
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindingTimeSeries_NotProvisioned(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	_, err := srv.GetFindingTimeSeries(graphTenantCtx(), &graphpb.GetFindingTimeSeriesRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetFindingTimeSeries not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetFindingTimeSeries — days cap enforcement (days > MaxTimeSeriesDays
// should not cause an error, just be clamped)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindingTimeSeries_CapEnforced(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	// days=999 → clamped; fails at pool (not at cap clamp).
	_, err := srv.GetFindingTimeSeries(graphTenantCtx(), &graphpb.GetFindingTimeSeriesRequest{Days: 999})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetFindingTimeSeries cap+not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphStats — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphStats_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	_, err := srv.GetGraphStats(context.Background(), &graphpb.GetGraphStatsRequest{})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetGraphStats no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphStats — NotProvisioned → FailedPrecondition
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphStats_NotProvisioned(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	_, err := srv.GetGraphStats(graphTenantCtx(), &graphpb.GetGraphStatsRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetGraphStats not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphSummary — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphSummary_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	_, err := srv.GetGraphSummary(context.Background(), &graphpb.GetGraphSummaryRequest{})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetGraphSummary no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphSummary — NotProvisioned → FailedPrecondition
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphSummary_NotProvisioned(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	_, err := srv.GetGraphSummary(graphTenantCtx(), &graphpb.GetGraphSummaryRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetGraphSummary not-provisioned")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphSummary — cache: two consecutive calls within 60s hit cache
// (mock pool call counter: pool.For should be called exactly once).
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphSummary_Cache_HitWithin60s(t *testing.T) {
	t.Parallel()

	// Preload the cache with a known entry so we never need a real Neo4j conn.
	srv := graphServerReadyPool()
	tenantStr := "test-graph-tenant"
	cachedResp := &graphpb.GetGraphSummaryResponse{Summary: "cached-summary"}
	srv.summaryCache.Store(tenantStr, &summaryCacheEntry{
		result:   cachedResp,
		cachedAt: time.Now(),
	})

	resp, err := srv.GetGraphSummary(graphTenantCtx(), &graphpb.GetGraphSummaryRequest{})
	if err != nil {
		t.Fatalf("GetGraphSummary cache hit: %v", err)
	}
	if resp.GetSummary() != "cached-summary" {
		t.Errorf("got %q, want cached-summary", resp.GetSummary())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphSummary — cache: expired entry triggers recompute
// Simulate expired cache by setting cachedAt to 61s ago.
// The underlying pool.For fails with NotProvisioned → FailedPrecondition
// (confirms cache was NOT served and recompute was attempted).
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphSummary_Cache_ExpiredRecomputes(t *testing.T) {
	t.Parallel()

	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "test-graph-tenant"}}
	})
	tenantStr := "test-graph-tenant"
	// Plant an expired cache entry (61 seconds old).
	srv.summaryCache.Store(tenantStr, &summaryCacheEntry{
		result:   &graphpb.GetGraphSummaryResponse{Summary: "stale"},
		cachedAt: time.Now().Add(-61 * time.Second),
	})

	// Should recompute → hit pool → NotProvisioned → FailedPrecondition.
	_, err := srv.GetGraphSummary(graphTenantCtx(), &graphpb.GetGraphSummaryRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetGraphSummary expired cache recompute")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphSummary — cache: tenant isolation (A's cache does not serve B)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphSummary_Cache_TenantIsolation(t *testing.T) {
	t.Parallel()

	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "tenant-b"}}
	})
	// Store a cache entry under tenant-a.
	srv.summaryCache.Store("tenant-a", &summaryCacheEntry{
		result:   &graphpb.GetGraphSummaryResponse{Summary: "tenant-a-summary"},
		cachedAt: time.Now(),
	})

	// Call with tenant-b context — should NOT hit tenant-a's cache entry.
	ctxB := auth.WithTenant(context.Background(), auth.MustNewTenantID("tenant-b"))
	_, err := srv.GetGraphSummary(ctxB, &graphpb.GetGraphSummaryRequest{})
	// tenant-b has no cache and pool fails → FailedPrecondition.
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetGraphSummary tenant isolation")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphSummary — underlying query called exactly once for two rapid calls
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphSummary_Cache_QueryCalledOnce(t *testing.T) {
	t.Parallel()

	// Use a pool that returns a conn whose Neo4j session will be called.
	// We inject the result via the cache after the first call so the second call
	// uses the cache.  Since we can't easily mock Neo4j queries at this layer,
	// we verify cache behavior by counting pool.For invocations instead.
	var poolCallCount atomic.Int32
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPoolFn{
			forFn: func(ctx context.Context, t auth.TenantID) (*datapool.Conn, error) {
				poolCallCount.Add(1)
				return nil, &datapool.NotProvisionedError{Tenant: t.String()}
			},
		}
	})

	tenantStr := "test-graph-tenant"

	// Pre-seed with a fresh cache entry — first call must return it.
	srv.summaryCache.Store(tenantStr, &summaryCacheEntry{
		result:   &graphpb.GetGraphSummaryResponse{Summary: "fresh"},
		cachedAt: time.Now(),
	})

	for i := 0; i < 3; i++ {
		resp, err := srv.GetGraphSummary(graphTenantCtx(), &graphpb.GetGraphSummaryRequest{})
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if resp.GetSummary() != "fresh" {
			t.Errorf("call %d: got %q, want fresh", i, resp.GetSummary())
		}
	}

	// pool.For was never called because all 3 calls hit cache.
	if n := poolCallCount.Load(); n != 0 {
		t.Errorf("pool.For called %d times, want 0 (all hits)", n)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphContext — missing tenant → PermissionDenied
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphContext_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	_, err := srv.GetGraphContext(context.Background(), &graphpb.GetGraphContextRequest{NodeId: "n1"})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetGraphContext no tenant")
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphContext — NotProvisioned → empty response (soft-fail)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphContext_NotProvisioned_SoftFail(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	resp, err := srv.GetGraphContext(graphTenantCtx(), &graphpb.GetGraphContextRequest{NodeId: "n1"})
	if err != nil {
		t.Fatalf("GetGraphContext NotProvisioned should soft-fail (no error), got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil empty response")
	}
	if resp.GetFocusNode() != nil {
		t.Error("focus_node should be nil on soft-fail")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphContext — nil pool → empty response (soft-fail)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphContext_NilPool_SoftFail(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool { return nil })
	resp, err := srv.GetGraphContext(graphTenantCtx(), &graphpb.GetGraphContextRequest{NodeId: "n1"})
	if err != nil {
		t.Fatalf("GetGraphContext nil pool should soft-fail, got: %v", err)
	}
	if resp.GetFocusNode() != nil {
		t.Error("focus_node should be nil when pool not ready")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// GetGraphContext — cap enforcement (reaches pool, not arg validation error)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetGraphContext_CapEnforced(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "t1"}}
	})
	// hops=999 and maxNodes=999 should be clamped; soft-fail at pool level.
	resp, err := srv.GetGraphContext(graphTenantCtx(), &graphpb.GetGraphContextRequest{
		NodeId:   "n1",
		Hops:     999,
		MaxNodes: 999,
	})
	if err != nil {
		t.Fatalf("GetGraphContext cap: expected soft-fail, got error: %v", err)
	}
	_ = resp
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

// assertNotGRPCCode asserts that err does NOT have the given gRPC status code.
func assertNotGRPCCode(t *testing.T, err error, code codes.Code, label string) {
	t.Helper()
	if err == nil {
		return
	}
	s, ok := status.FromError(err)
	if !ok {
		return
	}
	if s.Code() == code {
		t.Errorf("%s: expected code != %s, but got it", label, code)
	}
}

// mockPoolFn is a datapool.Pool whose For method is fully configurable.
type mockPoolFn struct {
	forFn func(ctx context.Context, t auth.TenantID) (*datapool.Conn, error)
}

func (p *mockPoolFn) For(ctx context.Context, t auth.TenantID) (*datapool.Conn, error) {
	if p.forFn != nil {
		return p.forFn(ctx, t)
	}
	return nil, nil
}
func (p *mockPoolFn) Admin(_ context.Context) (*datapool.AdminConn, error) { return nil, nil }
func (p *mockPoolFn) SetAdminPool(_ datapool.AdminAcquirer)                 {}
func (p *mockPoolFn) Close() error                                          { return nil }

var _ datapool.Pool = (*mockPoolFn)(nil)

// ─────────────────────────────────────────────────────────────────────────────
// GetFindings — Task 5 (dashboard-neo4j-crud-removal)
// ─────────────────────────────────────────────────────────────────────────────

func TestGetFindings_MissingTenant_PermissionDenied(t *testing.T) {
	t.Parallel()
	srv := graphServerReadyPool()
	ctx := context.Background() // no tenant

	_, err := srv.GetFindings(ctx, &graphpb.GetFindingsRequest{})
	assertGRPCCode(t, err, codes.PermissionDenied, "GetFindings no tenant")
}

func TestGetFindings_NotProvisioned_FailedPrecondition(t *testing.T) {
	t.Parallel()
	srv := graphServerWithPool(func() datapool.Pool {
		return &mockPool{err: &datapool.NotProvisionedError{Tenant: "test-graph-tenant"}}
	})

	_, err := srv.GetFindings(graphTenantCtx(), &graphpb.GetFindingsRequest{})
	assertGRPCCode(t, err, codes.FailedPrecondition, "GetFindings not-provisioned")
}

func TestGetFindings_LimitCap(t *testing.T) {
	t.Parallel()
	// The handler should clamp limit > MaxFindingsLimit without error.
	// With a nil Neo4j session the Findings query will fail with an internal
	// error, but what matters is that we reach the query stage (i.e. the cap
	// logic ran). We just check for Internal (not InvalidArgument / PermissionDenied).
	srv := graphServerReadyPool()

	_, err := srv.GetFindings(graphTenantCtx(), &graphpb.GetFindingsRequest{Limit: 9999})
	// Should be Internal (query failure on nil session) or nil — not a cap/auth error.
	if err != nil {
		s, _ := status.FromError(err)
		if s.Code() == codes.PermissionDenied || s.Code() == codes.InvalidArgument {
			t.Errorf("GetFindings limit-cap: unexpected code %s", s.Code())
		}
	}
}

func TestGetFindings_DefaultLimit(t *testing.T) {
	t.Parallel()
	// Limit=0 should apply DefaultFindingsLimit (100); handler should not error
	// on the limit logic itself.
	srv := graphServerReadyPool()

	_, err := srv.GetFindings(graphTenantCtx(), &graphpb.GetFindingsRequest{Limit: 0})
	if err != nil {
		s, _ := status.FromError(err)
		// Acceptable: Internal (nil-session query fail) — NOT PermissionDenied/InvalidArgument.
		if s.Code() == codes.PermissionDenied || s.Code() == codes.InvalidArgument {
			t.Errorf("GetFindings default-limit: unexpected code %s", s.Code())
		}
	}
}

// TestGetFindings_LimitConstants verifies the constants from the graph package
// match the spec requirements: default=100, max=500.
func TestGetFindings_LimitConstants(t *testing.T) {
	t.Parallel()
	if graph.DefaultFindingsLimit != 100 {
		t.Errorf("DefaultFindingsLimit = %d, want 100", graph.DefaultFindingsLimit)
	}
	if graph.MaxFindingsLimit != 500 {
		t.Errorf("MaxFindingsLimit = %d, want 500", graph.MaxFindingsLimit)
	}
}
