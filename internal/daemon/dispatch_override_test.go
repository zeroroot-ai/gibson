// Package daemon — dispatch_override_test.go
//
// End-to-end tests for DispatchOverrideServer.OverrideDispatchPolicy
// (Task 31, setec-sandbox-prod-default §C4, R3.4).
//
// Tests are hermetic: miniredis replaces a real Redis instance, and the
// server is wired without a real audit.Writer (nil — acceptable for tests
// that verify logic rather than audit delivery).
//
// Coverage:
//   - TTL upper bound: request 7200s → stored 3600s (1-hour hard cap)
//   - Mandatory reason: empty reason returns codes.InvalidArgument
//   - Install + lookup: active override is visible via LookupOverride
//   - Post-expiry reversion: override auto-evicts after TTL
//   - Revoke path: allow=false clears the override
//   - LookupTenantOverride: AsOverrideLookup() adapter returns correct OverrideState
//   - Redis persistence: LookupOverride recovers the record from Redis on in-memory miss
//   - Unauthenticated request: returns codes.Unauthenticated
//   - Empty tenant_id: returns codes.InvalidArgument
package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	platformv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/platform/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ── Test helpers ──────────────────────────────────────────────────────────────

// newMiniredisClient creates a miniredis server + goredis client for tests.
func newMiniredisClient(t *testing.T) (*miniredis.Miniredis, goredis.UniversalClient) {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	client := goredis.NewUniversalClient(&goredis.UniversalOptions{Addrs: []string{mr.Addr()}})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

// authCtxWithUser injects a fake auth.Identity with the given subject into ctx.
func authCtxWithUser(ctx context.Context, subject string) context.Context {
	return auth.WithIdentity(ctx, auth.Identity{Subject: subject})
}

// newOverrideSrv builds a DispatchOverrideServer backed by miniredis.
// The audit writer is nil — tests that require audit capture should verify
// via the override's returned audit_event_id instead.
func newOverrideSrv(t *testing.T) (*DispatchOverrideServer, *miniredis.Miniredis) {
	t.Helper()
	mr, client := newMiniredisClient(t)
	srv := NewDispatchOverrideServer(client, nil, slog.Default())
	return srv, mr
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestOverride_TTLCapped verifies that a request with ttl_seconds=7200 is
// stored with an applied TTL of at most 3600s (the 1-hour hard cap).
func TestOverride_TTLCapped(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-1")
	resp, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-a",
		Allow:      true,
		TtlSeconds: 7200, // above the 3600s cap
		Reason:     "testing TTL cap",
	})
	require.NoError(t, err)
	assert.Equal(t, int32(3600), resp.GetAppliedTtlSeconds(),
		"applied TTL must be clamped to 3600s")
	assert.Greater(t, resp.GetExpiresAtUnix(), int64(0))
	assert.NotEmpty(t, resp.GetAuditEventId())

	// The in-memory record should reflect the capped TTL.
	rec := srv.LookupOverride(context.Background(), "tenant-a")
	require.NotNil(t, rec)
	assert.True(t, rec.Active())
	assert.LessOrEqual(t,
		rec.ExpiresAt.Sub(time.Now()),
		maxOverrideTTL+5*time.Second, // 5s slop
		"stored expiry must not exceed the hard cap")
}

// TestOverride_EmptyReason verifies that an empty reason returns InvalidArgument.
func TestOverride_EmptyReason(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-1")
	_, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-b",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "", // must be rejected
	})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// TestOverride_ActiveLookup verifies that after installation, LookupOverride
// returns an active record for the tenant.
func TestOverride_ActiveLookup(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-2")
	resp, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-c",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "active lookup test",
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.GetAuditEventId())

	rec := srv.LookupOverride(context.Background(), "tenant-c")
	require.NotNil(t, rec)
	assert.True(t, rec.Active())
	assert.Equal(t, "tenant-c", rec.TenantID)
	assert.Equal(t, "operator-2", rec.OperatorID)
	assert.Equal(t, resp.GetAuditEventId(), rec.AuditEventID)
}

// TestOverride_PostExpiry verifies that after miniredis FastForward past the
// TTL, LookupOverride (Redis path) returns nil.
func TestOverride_PostExpiry(t *testing.T) {
	t.Parallel()
	srv, mr := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-3")
	_, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-d",
		Allow:      true,
		TtlSeconds: 60,
		Reason:     "expiry test",
	})
	require.NoError(t, err)
	require.NotNil(t, srv.LookupOverride(context.Background(), "tenant-d"))

	// Clear in-memory cache to force a Redis lookup.
	srv.mu.Lock()
	delete(srv.inMem, "tenant-d")
	srv.mu.Unlock()

	// Expire the Redis key.
	mr.FastForward(61 * time.Second)

	// Redis lookup should miss (key expired).
	rec := srv.LookupOverride(context.Background(), "tenant-d")
	assert.Nil(t, rec, "override should have expired after TTL")
}

// TestOverride_InMemoryExpiry verifies that a naturally-expired in-memory record
// is treated as absent by LookupOverride.
func TestOverride_InMemoryExpiry(t *testing.T) {
	t.Parallel()
	srv, mr := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-4")
	_, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-e",
		Allow:      true,
		TtlSeconds: 1,
		Reason:     "in-memory expiry test",
	})
	require.NoError(t, err)
	require.NotNil(t, srv.LookupOverride(context.Background(), "tenant-e"),
		"override should be active immediately after install")

	// Expire the key in Redis and wait for the 1s TTL.
	mr.FastForward(2 * time.Second)
	time.Sleep(1100 * time.Millisecond)

	// Clear in-memory cache to force path through Active() check.
	srv.mu.Lock()
	rec := srv.inMem["tenant-e"]
	srv.mu.Unlock()
	if rec != nil {
		assert.False(t, rec.Active(), "in-memory record should be expired")
	}
	result := srv.LookupOverride(context.Background(), "tenant-e")
	assert.Nil(t, result)
}

// TestOverride_Revoke verifies that a revoke call (allow=false) clears the
// override and LookupOverride returns nil afterward.
func TestOverride_Revoke(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-5")

	_, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-f",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "revoke test setup",
	})
	require.NoError(t, err)
	require.NotNil(t, srv.LookupOverride(context.Background(), "tenant-f"))

	// Revoke.
	_, err = srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId: "tenant-f",
		Allow:    false,
		Reason:   "Setec recovered",
	})
	require.NoError(t, err)

	assert.Nil(t, srv.LookupOverride(context.Background(), "tenant-f"),
		"override should be nil after revoke")
}

// TestOverride_AsOverrideLookup verifies the dispatch.OverrideLookup adapter
// returns correct OverrideState values.
func TestOverride_AsOverrideLookup(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-6")
	resp, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-g",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "adapter test",
	})
	require.NoError(t, err)

	adapter := srv.AsOverrideLookup()
	state := adapter.LookupTenantOverride(context.Background(), "tenant-g")

	assert.True(t, state.Active, "OverrideState.Active should be true")
	assert.Equal(t, resp.GetAuditEventId(), state.AuditEventID)

	// No override for unknown tenant.
	noState := adapter.LookupTenantOverride(context.Background(), "no-such-tenant")
	assert.False(t, noState.Active)
}

// TestOverride_RedisPersistence verifies that after clearing the in-memory
// cache, LookupOverride recovers the record from Redis.
func TestOverride_RedisPersistence(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-7")
	_, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-h",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "Redis persistence test",
	})
	require.NoError(t, err)

	// Simulate restart by clearing in-memory cache.
	srv.mu.Lock()
	delete(srv.inMem, "tenant-h")
	srv.mu.Unlock()

	rec := srv.LookupOverride(context.Background(), "tenant-h")
	require.NotNil(t, rec, "override should be recovered from Redis")
	assert.True(t, rec.Active())
	assert.Equal(t, "tenant-h", rec.TenantID)
}

// TestOverride_UnauthenticatedRequest verifies that requests without an
// auth identity in context return codes.Unauthenticated.
func TestOverride_UnauthenticatedRequest(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	_, err := srv.OverrideDispatchPolicy(context.Background(), &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "tenant-i",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "should fail",
	})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

// TestOverride_EmptyTenantID verifies that an empty tenant_id returns
// codes.InvalidArgument.
func TestOverride_EmptyTenantID(t *testing.T) {
	t.Parallel()
	srv, _ := newOverrideSrv(t)

	ctx := authCtxWithUser(context.Background(), "operator-8")
	_, err := srv.OverrideDispatchPolicy(ctx, &platformv1.OverrideDispatchPolicyRequest{
		TenantId:   "",
		Allow:      true,
		TtlSeconds: 300,
		Reason:     "missing tenant",
	})
	require.Error(t, err)
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}
