package entitlements

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	entitlementsv1 "github.com/zeroroot-ai/gibson/pkg/billing/entitlements/v1"
)

// fakeEntitlementsServer is an in-process EntitlementsServiceServer stub.
type fakeEntitlementsServer struct {
	entitlementsv1.UnimplementedEntitlementsServiceServer

	mu      sync.Mutex
	results map[string]*entitlementsv1.Limits // keyed by tenant_id
	err     error                             // when non-nil, returned for every call
	calls   []string                          // tenant IDs seen, for assertion
}

func (s *fakeEntitlementsServer) GetLimits(_ context.Context, req *entitlementsv1.GetLimitsRequest) (*entitlementsv1.Limits, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, req.GetTenantId())
	if s.err != nil {
		return nil, s.err
	}
	if lim, ok := s.results[req.GetTenantId()]; ok {
		return lim, nil
	}
	return &entitlementsv1.Limits{}, nil
}

// newTestGRPCProvider starts an in-process gRPC server backed by srv and
// returns a Provider whose Limits calls are wired to it directly (no TLS).
// The caller is responsible for calling grpcServer.Stop() and provider.(*grpcProvider).Close()
// after the test.
func newTestGRPCProvider(t *testing.T, srv *fakeEntitlementsServer, ttl time.Duration) (Provider, *grpc.Server) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	grpcSrv := grpc.NewServer()
	entitlementsv1.RegisterEntitlementsServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()

	// Dial insecurely for in-process tests.
	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		grpcSrv.Stop()
		t.Fatalf("dial: %v", err)
	}

	p, err := NewGRPCProvider(GRPCProviderOptions{
		Endpoint: lis.Addr().String(),
		CacheTTL: ttl,
		DialConn: conn,
	})
	if err != nil {
		grpcSrv.Stop()
		t.Fatalf("NewGRPCProvider: %v", err)
	}

	return p, grpcSrv
}

// TestGRPCProvider_CacheHit verifies that a second call for the same tenant
// is served from cache without touching the upstream server.
func TestGRPCProvider_CacheHit(t *testing.T) {
	srv := &fakeEntitlementsServer{
		results: map[string]*entitlementsv1.Limits{
			"acme": {ConcurrentMissions: 5, ConcurrentAgents: 10},
		},
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	defer grpcSrv.Stop()

	ctx := context.Background()

	got1, err := p.Limits(ctx, "acme")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	want := Limits{ConcurrentMissions: 5, ConcurrentAgents: 10}
	if got1 != want {
		t.Fatalf("first call: got %+v want %+v", got1, want)
	}

	// Second call — must not increment server call count.
	got2, err := p.Limits(ctx, "acme")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got2 != want {
		t.Fatalf("second call: got %+v want %+v", got2, want)
	}

	srv.mu.Lock()
	n := len(srv.calls)
	srv.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected exactly 1 upstream call (cache hit on 2nd), got %d", n)
	}
}

// TestGRPCProvider_CacheMiss verifies that different tenants each make their
// own upstream call.
func TestGRPCProvider_CacheMiss(t *testing.T) {
	srv := &fakeEntitlementsServer{
		results: map[string]*entitlementsv1.Limits{
			"tenant-a": {ConcurrentMissions: 2},
			"tenant-b": {ConcurrentMissions: 7},
		},
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	defer grpcSrv.Stop()

	ctx := context.Background()

	limA, _ := p.Limits(ctx, "tenant-a")
	limB, _ := p.Limits(ctx, "tenant-b")

	if limA.ConcurrentMissions != 2 {
		t.Errorf("tenant-a: got %d want 2", limA.ConcurrentMissions)
	}
	if limB.ConcurrentMissions != 7 {
		t.Errorf("tenant-b: got %d want 7", limB.ConcurrentMissions)
	}

	srv.mu.Lock()
	n := len(srv.calls)
	srv.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected 2 upstream calls (one per tenant), got %d", n)
	}
}

// TestGRPCProvider_TTLExpiry verifies that a cached entry is re-fetched after
// the TTL elapses.
func TestGRPCProvider_TTLExpiry(t *testing.T) {
	srv := &fakeEntitlementsServer{
		results: map[string]*entitlementsv1.Limits{
			"acme": {ConcurrentMissions: 3},
		},
	}
	// Very short TTL so we can test expiry without a real sleep.
	const shortTTL = 10 * time.Millisecond
	p, grpcSrv := newTestGRPCProvider(t, srv, shortTTL)
	defer grpcSrv.Stop()

	ctx := context.Background()

	if _, err := p.Limits(ctx, "acme"); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Wait for the TTL to expire.
	time.Sleep(2 * shortTTL)

	if _, err := p.Limits(ctx, "acme"); err != nil {
		t.Fatalf("second call (after TTL): %v", err)
	}

	srv.mu.Lock()
	n := len(srv.calls)
	srv.mu.Unlock()
	if n < 2 {
		t.Fatalf("expected >= 2 upstream calls after TTL expiry, got %d", n)
	}
}

// TestGRPCProvider_InvalidationCausesRefetch verifies that calling Invalidate
// drops the cached entry so the next Limits call goes upstream.
func TestGRPCProvider_InvalidationCausesRefetch(t *testing.T) {
	srv := &fakeEntitlementsServer{
		results: map[string]*entitlementsv1.Limits{
			"acme": {ConcurrentMissions: 1},
		},
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	defer grpcSrv.Stop()

	ctx := context.Background()

	// Prime the cache.
	if _, err := p.Limits(ctx, "acme"); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// grpcProvider must satisfy Invalidator.
	inv, ok := p.(Invalidator)
	if !ok {
		t.Fatal("grpcProvider must implement Invalidator")
	}
	inv.Invalidate("acme")

	// Update the upstream value.
	srv.mu.Lock()
	srv.results["acme"] = &entitlementsv1.Limits{ConcurrentMissions: 99}
	srv.mu.Unlock()

	// Next call must bypass cache.
	got, err := p.Limits(ctx, "acme")
	if err != nil {
		t.Fatalf("post-invalidate call: %v", err)
	}
	if got.ConcurrentMissions != 99 {
		t.Fatalf("expected refreshed limits after invalidation, got %+v", got)
	}

	srv.mu.Lock()
	n := len(srv.calls)
	srv.mu.Unlock()
	if n < 2 {
		t.Fatalf("expected >= 2 upstream calls after invalidation, got %d", n)
	}
}

// TestGRPCProvider_FailOpenOnTransportError verifies that a transport error
// results in the zero (unlimited) Limits value and no propagated error.
func TestGRPCProvider_FailOpenOnTransportError(t *testing.T) {
	srv := &fakeEntitlementsServer{
		err: status.Error(codes.Unavailable, "billing service down"),
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	// Stop the server immediately so all calls fail.
	grpcSrv.Stop()

	ctx := context.Background()
	got, err := p.Limits(ctx, "acme")
	if err != nil {
		t.Fatalf("fail-open: expected nil error on transport failure, got %v", err)
	}
	if got != (Limits{}) {
		t.Fatalf("fail-open: expected zero (unlimited) Limits on transport failure, got %+v", got)
	}
}

// TestGRPCProvider_FailOpenOnRPCError verifies that a non-OK gRPC status code
// (returned by the server, not a transport drop) also results in fail-open
// unlimited Limits.
func TestGRPCProvider_FailOpenOnRPCError(t *testing.T) {
	srv := &fakeEntitlementsServer{
		err: status.Error(codes.Internal, "billing service internal error"),
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	defer grpcSrv.Stop()

	ctx := context.Background()
	got, err := p.Limits(ctx, "acme")
	if err != nil {
		t.Fatalf("fail-open: expected nil error on RPC error, got %v", err)
	}
	if got != (Limits{}) {
		t.Fatalf("fail-open: expected zero (unlimited) Limits on RPC error, got %+v", got)
	}
}

// TestGRPCProvider_LimitsFieldMapping verifies that all proto fields are
// correctly mapped to the package-level Limits type.
func TestGRPCProvider_LimitsFieldMapping(t *testing.T) {
	want := Limits{
		ConcurrentMissions:   3,
		ConcurrentAgents:     7,
		ConcurrentConnectors: 2,
		MonthlyTokens:        1_000_000,
		MonthlySpendUSDCents: 99_00,
	}
	srv := &fakeEntitlementsServer{
		results: map[string]*entitlementsv1.Limits{
			"acme": {
				ConcurrentMissions:   3,
				ConcurrentAgents:     7,
				ConcurrentConnectors: 2,
				MonthlyTokens:        1_000_000,
				MonthlySpendUsdCents: 99_00,
			},
		},
	}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	defer grpcSrv.Stop()

	got, err := p.Limits(context.Background(), "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("field mapping: got %+v want %+v", got, want)
	}
}

// TestGRPCProvider_EmptyTenantErrors verifies that an empty tenant ID returns
// an error without calling the upstream service.
func TestGRPCProvider_EmptyTenantErrors(t *testing.T) {
	srv := &fakeEntitlementsServer{}
	p, grpcSrv := newTestGRPCProvider(t, srv, 60*time.Second)
	defer grpcSrv.Stop()

	if _, err := p.Limits(context.Background(), ""); err == nil {
		t.Fatal("empty tenant must error")
	}

	srv.mu.Lock()
	n := len(srv.calls)
	srv.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected 0 upstream calls for empty tenant, got %d", n)
	}
}

// TestNew_SelectsGRPCProviderViaEnv verifies the config-gated selection: when
// ENTITLEMENTS_ENDPOINT is set to a valid (though unreachable) address, New
// returns a Provider (possibly the configProvider fallback if SPIRE is absent
// — that is acceptable; the point is it does not panic).
func TestNew_SelectsGRPCProviderViaEnv(t *testing.T) {
	t.Setenv("ENTITLEMENTS_ENDPOINT", "127.0.0.1:59999")
	p := New(nil)
	if p == nil {
		t.Fatal("New must not return nil")
	}
	// Must be usable (fail-open).
	_, _ = p.Limits(context.Background(), "tenant")
}

// TestNew_SelectsConfigProviderWhenEndpointUnset verifies that without
// ENTITLEMENTS_ENDPOINT set New returns the configProvider.
func TestNew_SelectsConfigProviderWhenEndpointUnset(t *testing.T) {
	t.Setenv("ENTITLEMENTS_ENDPOINT", "")
	p := New(nil)
	if _, ok := p.(*configProvider); !ok {
		t.Fatalf("expected *configProvider when ENTITLEMENTS_ENDPOINT is unset, got %T", p)
	}
}
