package component

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/state"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// newTestQuotaManager creates a QuotaManager backed by miniredis with the
// given tenant already injected into the returned context.
//
// It constructs the TenantScopedStore by bypassing the NewStateClient module
// checks — the StateClient is built by wrapping a live miniredis redis.Client
// through the state package's NewTenantScopedStore helper, which only requires
// a *state.StateClient. Because NewStateClient performs a ping + MODULE LIST
// (gracefully ignoring MODULE LIST failures), we use the URL-based constructor
// with the miniredis address.
func newTestQuotaManager(t *testing.T, tenant string) (*QuotaManager, context.Context) {
	t.Helper()

	mr := miniredis.RunT(t)

	// NewStateClient pings the server and calls Health(); Health() calls
	// MODULE LIST which miniredis does not support — but the Health()
	// implementation treats that failure as a warning and returns nil, so the
	// overall NewStateClient call succeeds.
	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err, "failed to create state client against miniredis")
	t.Cleanup(func() { _ = stateClient.Close() })

	store := state.NewTenantScopedStore(stateClient, &state.TenantStoreConfig{
		AuthMode:      "enterprise",
		DefaultTenant: tenant,
		RequireTenant: false,
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	qm := NewQuotaManager(store, logger)
	ctx := auth.ContextWithTenant(context.Background(), tenant)

	return qm, ctx
}

// isResourceExhausted returns true if err is a gRPC ResourceExhausted status.
func isResourceExhausted(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	return ok && s.Code() == codes.ResourceExhausted
}

// ---------------------------------------------------------------------------
// GetQuota / SetQuota round-trip
// ---------------------------------------------------------------------------

func TestQuotaManager_GetSetQuota_RoundTrip(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	want := &TenantQuota{
		MaxMissions:  10,
		MaxAgents:    50,
		MaxMemoryMB:  1024,
		APIRateLimit: 100,
		MaxFindings:  500,
	}

	require.NoError(t, qm.SetQuota(ctx, "acme", want))

	got, err := qm.GetQuota(ctx, "acme")
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, "acme", got.TenantID)
	assert.Equal(t, want.MaxMissions, got.MaxMissions)
	assert.Equal(t, want.MaxAgents, got.MaxAgents)
	assert.Equal(t, want.MaxMemoryMB, got.MaxMemoryMB)
	assert.Equal(t, want.APIRateLimit, got.APIRateLimit)
	assert.Equal(t, want.MaxFindings, got.MaxFindings)
}

func TestQuotaManager_SetQuota_OverwritesTenantID(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	quota := &TenantQuota{TenantID: "wrong-tenant", MaxMissions: 5}
	require.NoError(t, qm.SetQuota(ctx, "acme", quota))

	got, err := qm.GetQuota(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, "acme", got.TenantID, "SetQuota must overwrite TenantID with the tenant parameter")
}

func TestQuotaManager_SetQuota_NilQuotaReturnsError(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	err := qm.SetQuota(ctx, "acme", nil)
	assert.Error(t, err)
}

func TestQuotaManager_GetQuota_MissingReturnsNil(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "new-tenant")

	got, err := qm.GetQuota(ctx, "new-tenant")
	require.NoError(t, err)
	assert.Nil(t, got, "missing quota must return nil, not an error")
}

// ---------------------------------------------------------------------------
// CheckMissionQuota — boundary tests
// ---------------------------------------------------------------------------

func TestQuotaManager_CheckMissionQuota_BelowLimit_Passes(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 5}))

	// Set counter to limit-1 (4).
	for i := 0; i < 4; i++ {
		require.NoError(t, qm.IncrementMissionCount(ctx))
	}

	err := qm.CheckMissionQuota(ctx)
	assert.NoError(t, err, "count=4, limit=5: check must pass")
}

func TestQuotaManager_CheckMissionQuota_AtLimit_Fails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 5}))

	// Set counter to exactly the limit.
	for i := 0; i < 5; i++ {
		require.NoError(t, qm.IncrementMissionCount(ctx))
	}

	err := qm.CheckMissionQuota(ctx)
	assert.True(t, isResourceExhausted(err), "count=5, limit=5: check must return ResourceExhausted, got: %v", err)
}

func TestQuotaManager_CheckMissionQuota_AboveLimit_Fails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 5}))

	// Overshoot the limit.
	for i := 0; i < 7; i++ {
		require.NoError(t, qm.IncrementMissionCount(ctx))
	}

	err := qm.CheckMissionQuota(ctx)
	assert.True(t, isResourceExhausted(err), "count=7, limit=5: check must return ResourceExhausted, got: %v", err)
}

func TestQuotaManager_CheckMissionQuota_Unlimited_AlwaysPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 0}))

	// Even with a large counter, unlimited passes.
	for i := 0; i < 1000; i++ {
		require.NoError(t, qm.IncrementMissionCount(ctx))
	}

	err := qm.CheckMissionQuota(ctx)
	assert.NoError(t, err, "MaxMissions=0 means unlimited: check must always pass")
}

func TestQuotaManager_CheckMissionQuota_NoQuota_AlwaysPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "new-tenant")

	// No quota configured — must be treated as unlimited.
	err := qm.CheckMissionQuota(ctx)
	assert.NoError(t, err, "missing quota must be treated as unlimited")
}

// ---------------------------------------------------------------------------
// CheckAgentQuota — boundary tests
// ---------------------------------------------------------------------------

func TestQuotaManager_CheckAgentQuota_BelowLimit_Passes(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxAgents: 10}))

	for i := 0; i < 9; i++ {
		require.NoError(t, qm.IncrementAgentCount(ctx))
	}

	assert.NoError(t, qm.CheckAgentQuota(ctx), "count=9, limit=10: must pass")
}

func TestQuotaManager_CheckAgentQuota_AtLimit_Fails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxAgents: 10}))

	for i := 0; i < 10; i++ {
		require.NoError(t, qm.IncrementAgentCount(ctx))
	}

	err := qm.CheckAgentQuota(ctx)
	assert.True(t, isResourceExhausted(err), "count=10, limit=10: must return ResourceExhausted, got: %v", err)
}

func TestQuotaManager_CheckAgentQuota_Unlimited_AlwaysPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxAgents: 0}))

	for i := 0; i < 500; i++ {
		require.NoError(t, qm.IncrementAgentCount(ctx))
	}

	assert.NoError(t, qm.CheckAgentQuota(ctx), "MaxAgents=0 means unlimited")
}

func TestQuotaManager_CheckAgentQuota_NoQuota_AlwaysPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "new-tenant")
	assert.NoError(t, qm.CheckAgentQuota(ctx), "missing quota must be treated as unlimited")
}

// ---------------------------------------------------------------------------
// CheckMemoryQuota
// ---------------------------------------------------------------------------

func TestQuotaManager_CheckMemoryQuota_WithinLimit_Passes(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMemoryMB: 1024}))

	// Current usage = 0; request 512 MB → total 512 ≤ 1024.
	assert.NoError(t, qm.CheckMemoryQuota(ctx, 512))
}

func TestQuotaManager_CheckMemoryQuota_ExceedsLimit_Fails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMemoryMB: 1024}))

	// Current usage = 0; request 2048 MB → total 2048 > 1024.
	err := qm.CheckMemoryQuota(ctx, 2048)
	assert.True(t, isResourceExhausted(err), "requesting 2048MB against 1024MB limit must fail, got: %v", err)
}

func TestQuotaManager_CheckMemoryQuota_Unlimited_AlwaysPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMemoryMB: 0}))

	assert.NoError(t, qm.CheckMemoryQuota(ctx, 1_000_000))
}

func TestQuotaManager_CheckMemoryQuota_NoQuota_AlwaysPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "new-tenant")
	assert.NoError(t, qm.CheckMemoryQuota(ctx, 99999))
}

// ---------------------------------------------------------------------------
// Counter management
// ---------------------------------------------------------------------------

func TestQuotaManager_IncrementDecrementMissionCount(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 3}))

	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))

	// At limit — must fail.
	require.True(t, isResourceExhausted(qm.CheckMissionQuota(ctx)))

	// Decrement brings it back below limit.
	require.NoError(t, qm.DecrementMissionCount(ctx))

	assert.NoError(t, qm.CheckMissionQuota(ctx), "after decrement count should be 2 < limit 3")
}

func TestQuotaManager_DecrementMissionCount_AtZero_IsNoop(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	// Decrement on a missing (zero) counter must not error and must not
	// produce a negative value.
	require.NoError(t, qm.DecrementMissionCount(ctx))

	// Check that a quota of 1 is not exhausted (counter should be 0).
	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 1}))
	assert.NoError(t, qm.CheckMissionQuota(ctx), "counter must stay at ≥ 0 after decrement")
}

func TestQuotaManager_IncrementDecrementAgentCount(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxAgents: 2}))

	require.NoError(t, qm.IncrementAgentCount(ctx))
	require.NoError(t, qm.IncrementAgentCount(ctx))

	require.True(t, isResourceExhausted(qm.CheckAgentQuota(ctx)), "at limit must fail")

	require.NoError(t, qm.DecrementAgentCount(ctx))
	assert.NoError(t, qm.CheckAgentQuota(ctx), "after decrement must pass")
}

func TestQuotaManager_DecrementAgentCount_AtZero_IsNoop(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.DecrementAgentCount(ctx))

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxAgents: 1}))
	assert.NoError(t, qm.CheckAgentQuota(ctx), "counter must stay at ≥ 0 after decrement")
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

func TestQuotaManager_TenantIsolation_QuotaDoesNotLeak(t *testing.T) {
	// Both tenants share the same miniredis instance.
	mr := miniredis.RunT(t)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	// QuotaManager is intentionally shared to replicate production usage.
	store := state.NewTenantScopedStore(stateClient, &state.TenantStoreConfig{
		AuthMode:      "saas",
		RequireTenant: true,
	})
	qm := NewQuotaManager(store, logger)

	ctxA := auth.ContextWithTenant(context.Background(), "tenant-a")
	ctxB := auth.ContextWithTenant(context.Background(), "tenant-b")

	// Give tenant-a a tight quota and tenant-b a generous quota.
	require.NoError(t, qm.SetQuota(ctxA, "tenant-a", &TenantQuota{MaxMissions: 1}))
	require.NoError(t, qm.SetQuota(ctxB, "tenant-b", &TenantQuota{MaxMissions: 100}))

	// Exhaust tenant-a's quota.
	require.NoError(t, qm.IncrementMissionCount(ctxA))
	assert.True(t, isResourceExhausted(qm.CheckMissionQuota(ctxA)), "tenant-a must be exhausted")

	// Tenant-b must be unaffected.
	assert.NoError(t, qm.CheckMissionQuota(ctxB), "tenant-b must not be affected by tenant-a's counter")
}

func TestQuotaManager_TenantIsolation_QuotaConfigDoesNotLeak(t *testing.T) {
	mr := miniredis.RunT(t)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	cfg := state.DefaultConfig()
	cfg.URL = "redis://" + mr.Addr()

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = stateClient.Close() })

	store := state.NewTenantScopedStore(stateClient, &state.TenantStoreConfig{
		AuthMode:      "saas",
		RequireTenant: true,
	})
	qm := NewQuotaManager(store, logger)

	ctxA := auth.ContextWithTenant(context.Background(), "tenant-a")
	ctxB := auth.ContextWithTenant(context.Background(), "tenant-b")

	// Only configure tenant-a.
	require.NoError(t, qm.SetQuota(ctxA, "tenant-a", &TenantQuota{MaxMissions: 5}))

	// Tenant-b must not see tenant-a's quota config.
	gotB, err := qm.GetQuota(ctxB, "tenant-b")
	require.NoError(t, err)
	assert.Nil(t, gotB, "tenant-b must not inherit tenant-a's quota")
}

// ---------------------------------------------------------------------------
// gRPC status code verification
// ---------------------------------------------------------------------------

func TestQuotaManager_CheckMissionQuota_ErrorCodeIsResourceExhausted(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMissions: 1}))
	require.NoError(t, qm.IncrementMissionCount(ctx))

	err := qm.CheckMissionQuota(ctx)
	require.Error(t, err)

	s, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status error")
	assert.Equal(t, codes.ResourceExhausted, s.Code())
}

func TestQuotaManager_CheckAgentQuota_ErrorCodeIsResourceExhausted(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxAgents: 1}))
	require.NoError(t, qm.IncrementAgentCount(ctx))

	err := qm.CheckAgentQuota(ctx)
	require.Error(t, err)

	s, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status error")
	assert.Equal(t, codes.ResourceExhausted, s.Code())
}

func TestQuotaManager_CheckMemoryQuota_ErrorCodeIsResourceExhausted(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")

	require.NoError(t, qm.SetQuota(ctx, "acme", &TenantQuota{MaxMemoryMB: 100}))

	err := qm.CheckMemoryQuota(ctx, 200)
	require.Error(t, err)

	s, ok := status.FromError(err)
	require.True(t, ok, "error must be a gRPC status error")
	assert.Equal(t, codes.ResourceExhausted, s.Code())
}

// ---------------------------------------------------------------------------
// Redis key scheme helpers (no Redis needed)
// ---------------------------------------------------------------------------

func TestQuotaKeyConstants(t *testing.T) {
	assert.Equal(t, "quota:config", quotaConfigKey)
	assert.Equal(t, "quota:missions:count", quotaMissionsCountKey)
	assert.Equal(t, "quota:agents:count", quotaAgentsCountKey)
	assert.Equal(t, "quota:memory:used_mb", quotaMemoryUsedMBKey)
}

