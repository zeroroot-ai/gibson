package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/datapool"
	"github.com/zeroroot-ai/gibson/internal/memory/embedder"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/sdk/auth"
	sdkgraphrag "github.com/zeroroot-ai/sdk/graphrag"
)

// --- mock implementations ---

// mockPool is a controllable datapool.Pool for unit tests.
type mockPool struct {
	conn *datapool.Conn
	err  error
}

func (p *mockPool) For(_ context.Context, _ auth.TenantID) (*datapool.Conn, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.conn, nil
}

func (p *mockPool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, fmt.Errorf("admin pool not configured in mock")
}

func (p *mockPool) SetAdminPool(_ datapool.AdminAcquirer) {}

func (p *mockPool) Close() error { return nil }

// Ensure mockPool satisfies datapool.Pool at compile time.
var _ datapool.Pool = (*mockPool)(nil)

// minimalConn returns a *datapool.Conn with all nil fields. SessionGraphClient is
// nil-safe so operations on a nil session will return driver-not-connected errors
// (not panics), which is acceptable for these unit tests.
func minimalConn() *datapool.Conn {
	return &datapool.Conn{
		Neo4j: nil,
	}
}

// --- tests ---

// TestGraphRAGBridgeAdapter_MissingTenant asserts that all bridge methods return
// errNoTenantInContext when the request context carries no tenant.
func TestGraphRAGBridgeAdapter_MissingTenant(t *testing.T) {
	t.Parallel()

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		Embedder:   emb,
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewGraphRAGBridgeAdapter: %v", err)
	}

	ctx := context.Background() // no tenant

	// QueryBridge.Query must fail with errNoTenantInContext.
	_, qErr := adapter.Query(ctx, sdkgraphrag.Query{Text: "test"})
	if !errors.Is(qErr, errNoTenantInContext) {
		t.Errorf("Query with no tenant: got %v, want errNoTenantInContext", qErr)
	}

	// FindSimilarAttacks must fail with errNoTenantInContext.
	_, fErr := adapter.FindSimilarAttacks(ctx, "test content", 5)
	if !errors.Is(fErr, errNoTenantInContext) {
		t.Errorf("FindSimilarAttacks with no tenant: got %v, want errNoTenantInContext", fErr)
	}

	// StoreNode must fail with errNoTenantInContext.
	_, sErr := adapter.StoreNode(ctx, sdkgraphrag.GraphNode{ID: "x", Type: "Finding"}, "mission1", "agent1")
	if !errors.Is(sErr, errNoTenantInContext) {
		t.Errorf("StoreNode with no tenant: got %v, want errNoTenantInContext", sErr)
	}
}

// TestGraphRAGBridgeAdapter_UnprovisionedTenant asserts that NotProvisionedError
// propagates unchanged when pool.For returns it.
func TestGraphRAGBridgeAdapter_UnprovisionedTenant(t *testing.T) {
	t.Parallel()

	notProvisioned := &datapool.NotProvisionedError{Tenant: "00000000-0000-0000-0000-000000000011"}
	pool := &mockPool{err: notProvisioned}

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return pool },
		Embedder:   emb,
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewGraphRAGBridgeAdapter: %v", err)
	}

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("test-tenant"))
	_, qErr := adapter.Query(ctx, sdkgraphrag.Query{Text: "test"})
	if qErr == nil {
		t.Fatal("expected error for unprovisioned tenant; got nil")
	}
	var npe *datapool.NotProvisionedError
	if !errors.As(qErr, &npe) {
		t.Errorf("expected *NotProvisionedError in error chain; got %T: %v", qErr, qErr)
	}
}

// TestGraphRAGBridgeAdapter_TransientUnavailable asserts that transient pool errors propagate.
func TestGraphRAGBridgeAdapter_TransientUnavailable(t *testing.T) {
	t.Parallel()

	transient := fmt.Errorf("connection timeout")
	pool := &mockPool{err: transient}

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return pool },
		Embedder:   emb,
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewGraphRAGBridgeAdapter: %v", err)
	}

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("test-tenant-2"))
	_, fErr := adapter.FindSimilarAttacks(ctx, "test", 5)
	if fErr == nil {
		t.Fatal("expected error from transient pool failure; got nil")
	}
	if !errors.Is(fErr, transient) {
		t.Errorf("error chain should wrap transient error; got %v", fErr)
	}
}

// TestGraphRAGBridgeAdapter_Health asserts the health method returns healthy
// when the pool is configured.
func TestGraphRAGBridgeAdapter_Health(t *testing.T) {
	t.Parallel()

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		Embedder:   emb,
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewGraphRAGBridgeAdapter: %v", err)
	}

	status := adapter.Health(context.Background())
	if !status.IsHealthy() {
		t.Errorf("Health() = %v (not healthy); want healthy", status)
	}
}

// TestGraphRAGBridgeAdapter_AsyncBridge_MissingTenant verifies that StoreAsync
// is a no-op (logs warn) when the context carries no tenant and Shutdown completes.
func TestGraphRAGBridgeAdapter_AsyncBridge_MissingTenant(t *testing.T) {
	t.Parallel()

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		Embedder:   emb,
		Logger:     slog.Default(),
	})
	if err != nil {
		t.Fatalf("NewGraphRAGBridgeAdapter: %v", err)
	}

	bridge := adapter.Bridge()
	ctx := context.Background() // no tenant
	finding := agent.Finding{
		ID:          types.NewID(),
		Description: "test finding",
	}
	missionID := types.NewID()
	bridge.StoreAsync(ctx, finding, missionID, nil)

	// Shutdown with a 5-second budget — must not hang.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if sErr := bridge.Shutdown(shutdownCtx); sErr != nil {
		t.Errorf("Shutdown: %v", sErr)
	}
}

// TestGraphRAGBridgeAdapter_InterfaceShapes verifies compile-time interface compliance.
func TestGraphRAGBridgeAdapter_InterfaceShapes(t *testing.T) {
	t.Parallel()

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return &mockPool{conn: minimalConn()} },
		Embedder:   emb,
	})
	if err != nil {
		t.Fatalf("NewGraphRAGBridgeAdapter: %v", err)
	}

	// Bridge() and QueryBridge() must satisfy the harness interfaces.
	// Compilation verifies this; just exercise the call here.
	b := adapter.Bridge()
	if b == nil {
		t.Error("Bridge() returned nil")
	}
	qb := adapter.QueryBridge()
	if qb == nil {
		t.Error("QueryBridge() returned nil")
	}
}

// TestNewGraphRAGBridgeAdapter_NilPoolGetter verifies that a nil PoolGetter returns an error.
func TestNewGraphRAGBridgeAdapter_NilPoolGetter(t *testing.T) {
	t.Parallel()

	emb := embedder.NewMockEmbedder()
	_, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: nil,
		Embedder:   emb,
	})
	if err == nil {
		t.Fatal("expected error for nil PoolGetter; got nil")
	}
}

// TestNewGraphRAGBridgeAdapter_NilEmbedder verifies that a nil Embedder returns an error.
func TestNewGraphRAGBridgeAdapter_NilEmbedder(t *testing.T) {
	t.Parallel()

	_, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return &mockPool{} },
		Embedder:   nil,
	})
	if err == nil {
		t.Fatal("expected error for nil Embedder; got nil")
	}
}

// TestGraphRAGBridge_PoolNotReady verifies the bridge returns errPoolNotReady
// when the getter returns nil at request time (race against pool init).
func TestGraphRAGBridge_PoolNotReady(t *testing.T) {
	t.Parallel()

	emb := embedder.NewMockEmbedder()
	adapter, err := NewGraphRAGBridgeAdapter(GraphRAGBridgeConfig{
		PoolGetter: func() datapool.Pool { return nil }, // never ready
		Embedder:   emb,
	})
	if err != nil {
		t.Fatalf("unexpected constructor error: %v", err)
	}
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("zeroroot-ai"))
	_, _, err = adapter.buildEphemeralQueryBridge(ctx)
	if !errors.Is(err, errPoolNotReady) {
		t.Fatalf("expected errPoolNotReady; got %v", err)
	}
}
