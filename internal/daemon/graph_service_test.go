package daemon

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

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
