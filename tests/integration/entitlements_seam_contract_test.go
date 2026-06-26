// Package integration — entitlements_seam_contract_test.go
//
// Contract / e2e test for the entitlements runtime seam (ADR-0003, ADR-0054,
// gibson#1026, gibson#1029).
//
// Architecture background:
//
// The entitlements seam converts from compile-time injection (Option A) to a
// runtime gRPC boundary (Option B). The OSS daemon ships a caching gRPC client
// (pkg/billing/entitlements.grpcProvider). The closed billing repo ships the
// server that derives per-tenant limits from plan + subscription state. This
// file stands up a real in-process EntitlementsService server — the same
// generated proto stubs the billing repo implements — and connects the
// grpcProvider client to it over a real TCP loopback socket. Using generated
// proto on both sides catches field mapping, number assignment, or wire
// encoding drift that unit tests cannot see.
//
// What each test asserts:
//
//   - TestEntitlementsSeam_AllFieldsRoundTrip: all five Limits proto fields
//     survive an encode/decode round-trip through the real gRPC stack.
//
//   - TestEntitlementsSeam_QuotaManagerObservesProviderLimits: the concurrency
//     enforcement path (component.QuotaManager.GetQuota) resolves the correct
//     TenantQuota values from the grpcProvider over the real wire. No Redis is
//     needed for the limit-resolution path — only the active counters use Redis.
//
//   - TestEntitlementsSeam_BudgetEnforcerObservesProviderLimits: the token/spend
//     enforcement path (budget.Enforcer.Check) reads MonthlyTokens from the
//     grpcProvider and gates calls correctly when no admin-set budget is
//     present (provider ceiling is the only floor).
//
//   - TestEntitlementsSeam_FailOpenOnServerStop: stops the billing service
//     mid-test and asserts the provider returns zero Limits (unlimited) with a
//     nil error — the fail-open production contract holds over a real broken
//     TCP connection.
package integration

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/gibson/internal/platform/budget"
	"github.com/zeroroot-ai/gibson/internal/platform/component"
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
	entitlementsv1 "github.com/zeroroot-ai/gibson/pkg/billing/entitlements/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// Billing-service stand-in server
// ---------------------------------------------------------------------------

// billingStandInServer is a concrete in-process EntitlementsServiceServer.
// It represents the billing repo's server — same generated proto, known Limits.
// Using the generated stubs on both sides (not just a mock interface) means
// the full encode/unmarshal path runs, catching any drift between the proto
// definition and the package-level Limits struct.
type billingStandInServer struct {
	entitlementsv1.UnimplementedEntitlementsServiceServer
	results map[string]*entitlementsv1.Limits
}

func (s *billingStandInServer) GetLimits(_ context.Context, req *entitlementsv1.GetLimitsRequest) (*entitlementsv1.Limits, error) {
	if lim, ok := s.results[req.GetTenantId()]; ok {
		return lim, nil
	}
	return &entitlementsv1.Limits{}, nil
}

// ---------------------------------------------------------------------------
// Test infrastructure
// ---------------------------------------------------------------------------

// startBillingServer starts a real in-process gRPC server on a random loopback
// TCP port and returns the server address and handle. No TLS — the test focus
// is wire contract and enforcer behaviour, not transport security. The caller
// registers a t.Cleanup for grpcSrv.Stop().
func startBillingServer(t *testing.T, srv *billingStandInServer) (addr string, grpcSrv *grpc.Server) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen loopback")

	grpcSrv = grpc.NewServer()
	entitlementsv1.RegisterEntitlementsServiceServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	return lis.Addr().String(), grpcSrv
}

// newSeamProvider constructs a pkg/billing/entitlements.Provider whose
// underlying grpcProvider is connected to addr via an insecure loopback
// connection. The dialConn injection point on GRPCProviderOptions is used so
// the SPIRE/mTLS path is skipped while the full gRPC client stack (codecs,
// interceptors, connection management) still runs.
func newSeamProvider(t *testing.T, addr string, ttl time.Duration) entitlements.Provider {
	t.Helper()

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err, "dial billing server")
	t.Cleanup(func() { _ = conn.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError, // suppress warn-level fail-open logs in test output
	}))

	p, err := entitlements.NewGRPCProvider(entitlements.GRPCProviderOptions{
		Endpoint: addr,
		CacheTTL: ttl,
		Logger:   logger,
		// DialConn skips the SPIRE path; all other gRPC machinery is live.
		DialConn: conn,
	})
	require.NoError(t, err, "NewGRPCProvider")
	t.Cleanup(func() {
		if c, ok := p.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	})
	return p
}

// newQuotaManagerWithProvider builds a component.QuotaManager backed by a
// miniredis-backed TenantScopedStore (for the active counters) and the given
// entitlements provider (for the limit configuration). The QuotaManager does
// NOT read Redis to obtain limits — only to read/write mission and agent
// counters — so the Redis backing is a no-op for the limits assertions.
func newQuotaManagerWithProvider(t *testing.T, tenant string, p entitlements.Provider) *component.QuotaManager {
	t.Helper()

	mr := miniredis.RunT(t)

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err, "state.NewStateClient")
	t.Cleanup(func() { _ = stateClient.Close() })

	store := state.NewTenantScopedStore(stateClient, &state.TenantStoreConfig{
		AuthMode:      "enterprise",
		DefaultTenant: tenant,
		RequireTenant: false,
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	return component.NewQuotaManager(store, p, logger)
}

// ---------------------------------------------------------------------------
// Test 1 — all five proto fields round-trip through the wire encoding
// ---------------------------------------------------------------------------

// TestEntitlementsSeam_AllFieldsRoundTrip asserts that every proto field in
// entitlementsv1.Limits survives an encode/decode round-trip through a real
// gRPC client+server. This is the drift guard: a field rename, number change,
// or missing protoToLimits mapping shows up here before it reaches production.
func TestEntitlementsSeam_AllFieldsRoundTrip(t *testing.T) {
	const tenant = "acme"

	srv := &billingStandInServer{
		results: map[string]*entitlementsv1.Limits{
			tenant: {
				ConcurrentMissions:   3,
				ConcurrentAgents:     7,
				ConcurrentConnectors: 2,
				MonthlyTokens:        1_500_000,
				MonthlySpendUsdCents: 9_999,
			},
		},
	}

	addr, grpcSrv := startBillingServer(t, srv)
	t.Cleanup(grpcSrv.Stop)

	p := newSeamProvider(t, addr, 60*time.Second)

	got, err := p.Limits(context.Background(), tenant)
	require.NoError(t, err)

	want := entitlements.Limits{
		ConcurrentMissions:   3,
		ConcurrentAgents:     7,
		ConcurrentConnectors: 2,
		MonthlyTokens:        1_500_000,
		MonthlySpendUSDCents: 9_999,
	}
	assert.Equal(t, want, got,
		"all five Limits fields must round-trip through the proto wire encoding unchanged")
}

// ---------------------------------------------------------------------------
// Test 2 — QuotaManager (concurrency enforcement) observes provider limits
// ---------------------------------------------------------------------------

// TestEntitlementsSeam_QuotaManagerObservesProviderLimits drives the concurrency
// enforcement path (component.QuotaManager.GetQuota) end-to-end through the
// grpcProvider. It asserts that the TenantQuota the QuotaManager returns
// reflects exactly what the billing server returned over the wire.
//
// This validates the full chain:
//
//	billing gRPC server → grpcProvider.Limits() → protoToLimits() → QuotaManager.GetQuota()
func TestEntitlementsSeam_QuotaManagerObservesProviderLimits(t *testing.T) {
	const tenant = "quota-tenant"

	srv := &billingStandInServer{
		results: map[string]*entitlementsv1.Limits{
			tenant: {
				ConcurrentMissions:   5,
				ConcurrentAgents:     10,
				ConcurrentConnectors: 3,
			},
		},
	}

	addr, grpcSrv := startBillingServer(t, srv)
	t.Cleanup(grpcSrv.Stop)

	p := newSeamProvider(t, addr, 60*time.Second)
	qm := newQuotaManagerWithProvider(t, tenant, p)

	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	quota, err := qm.GetQuota(ctx, tenant)
	require.NoError(t, err)
	require.NotNil(t, quota, "GetQuota must return a non-nil quota when provider reports non-zero limits")

	assert.Equal(t, 5, quota.ConcurrentMissions,
		"ConcurrentMissions must reflect the billing server's value")
	assert.Equal(t, 10, quota.ConcurrentAgents,
		"ConcurrentAgents must reflect the billing server's value")
	assert.Equal(t, 3, quota.ConcurrentConnectors,
		"ConcurrentConnectors must reflect the billing server's value")
}

// ---------------------------------------------------------------------------
// Test 3 — budget.Enforcer (token/spend enforcement) observes provider limits
// ---------------------------------------------------------------------------

// TestEntitlementsSeam_BudgetEnforcerObservesProviderLimits drives the token
// enforcement path (budget.Enforcer.Check) end-to-end through the grpcProvider.
//
// No explicit admin-set budget is configured in Redis, so the enforcer falls
// through to the entitlements provider's MonthlyTokens ceiling (ADR-0003 seam).
// A call within the ceiling must pass; a call projecting beyond it must be
// denied with ErrTokenBudgetExceededTenant.
//
// This validates the full chain:
//
//	billing gRPC server → grpcProvider.Limits() → redisEnforcer.loadTenantBudget() → Check()
func TestEntitlementsSeam_BudgetEnforcerObservesProviderLimits(t *testing.T) {
	const tenant = "budget-tenant"
	const user = "user-1"
	const tokenCeiling = int64(1_000)

	srv := &billingStandInServer{
		results: map[string]*entitlementsv1.Limits{
			tenant: {
				MonthlyTokens: tokenCeiling,
			},
		},
	}

	addr, grpcSrv := startBillingServer(t, srv)
	t.Cleanup(grpcSrv.Stop)

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	p := newSeamProvider(t, addr, 60*time.Second)
	enf := budget.NewEnforcer(rdb, logger, nil, nil, p)

	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	ctx = auth.ContextWithActingUser(ctx, user)

	// A call within the provider ceiling must be allowed.
	_, err := enf.Check(ctx, tokenCeiling/2)
	require.NoError(t, err,
		"a call within the provider's MonthlyTokens ceiling must not be denied")

	// A call that projects beyond the ceiling must be denied.
	_, err = enf.Check(ctx, tokenCeiling+1)
	require.Error(t, err,
		"a call projecting beyond the provider's MonthlyTokens ceiling must be denied")
	assert.ErrorIs(t, err, budget.ErrTokenBudgetExceededTenant,
		"the denial error must be the tenant-scope token sentinel")
}

// ---------------------------------------------------------------------------
// Test 4 — fail-open: server stops mid-test → next call returns unlimited
// ---------------------------------------------------------------------------

// TestEntitlementsSeam_FailOpenOnServerStop validates the production fail-open
// contract (ADR-0003 Req 5.4): when the billing service becomes unreachable the
// provider must return zero Limits (unlimited) with a nil error rather than
// propagating the connection failure to the daemon's enforcement path.
//
// The test kills the server AFTER the first successful call, then invalidates
// the cache so the next Limits call must re-dial — hitting the dead server.
// The assertion covers a real broken TCP connection (not a simulated gRPC
// status code), matching the actual failure mode in production.
func TestEntitlementsSeam_FailOpenOnServerStop(t *testing.T) {
	const tenant = "failopen-tenant"

	srv := &billingStandInServer{
		results: map[string]*entitlementsv1.Limits{
			tenant: {
				ConcurrentMissions: 5,
				MonthlyTokens:      50_000,
			},
		},
	}

	addr, grpcSrv := startBillingServer(t, srv)

	// Short TTL: cache expires fast; the stopped-server path is exercised on the
	// next call without requiring a long sleep.
	const shortTTL = 10 * time.Millisecond
	p := newSeamProvider(t, addr, shortTTL)

	ctx := context.Background()

	// Prime: first call must succeed while the server is up.
	lim, err := p.Limits(ctx, tenant)
	require.NoError(t, err, "first call (server up) must succeed")
	assert.Equal(t, 5, lim.ConcurrentMissions,
		"first call must return the server's ConcurrentMissions value")

	// Stop the billing server — connection broken from here.
	grpcSrv.Stop()

	// Invalidate the cache so the next Limits call bypasses the cached entry.
	inv, ok := p.(entitlements.Invalidator)
	require.True(t, ok, "grpcProvider must implement entitlements.Invalidator")
	inv.Invalidate(tenant)

	// Fail-open assertion: nil error + zero Limits (= unlimited on every dimension).
	lim, err = p.Limits(ctx, tenant)
	require.NoError(t, err,
		"fail-open: provider must return nil error when the billing server is unreachable")
	assert.Equal(t, entitlements.Limits{}, lim,
		"fail-open: provider must return zero (unlimited) Limits when the billing server is unreachable")
}
