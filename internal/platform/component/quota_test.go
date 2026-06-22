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

	"github.com/zeroroot-ai/gibson/internal/engine/state"
	"github.com/zeroroot-ai/sdk/auth"
)

// Test helpers ---------------------------------------------------------------

// newTestQuotaManager creates a QuotaManager backed by miniredis with the
// given tenant already injected into the returned context. The Postgres
// pool argument is nil — tests that need quota limits stub QuotaManager.cache
// directly via setLimits (below).
//
// Spec plans-and-quotas-simplification: limits live in Postgres; the test
// helper injects them into the in-process cache to avoid spinning up a real
// DB. This mirrors the production flow (cached after the first DB read).
func newTestQuotaManager(t *testing.T, tenant string) (*QuotaManager, context.Context) {
	t.Helper()

	mr := miniredis.RunT(t)

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

	qm := NewQuotaManager(store, nil, logger)
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	return qm, ctx
}

// setLimits seeds the QuotaManager's cache with a TenantQuota row so the
// Postgres-backed GetQuota path returns it without hitting a real DB.
func setLimits(qm *QuotaManager, tenant string, missions, agents int) {
	qm.cacheMu.Lock()
	defer qm.cacheMu.Unlock()
	if qm.cache == nil {
		qm.cache = make(map[string]quotaCacheEntry)
	}
	qm.cache[tenant] = quotaCacheEntry{
		q: TenantQuota{
			TenantID:           tenant,
			ConcurrentMissions: missions,
			ConcurrentAgents:   agents,
		},
	}
}

// isResourceExhausted returns true if err is a gRPC ResourceExhausted status.
func isResourceExhausted(err error) bool {
	if err == nil {
		return false
	}
	s, ok := status.FromError(err)
	return ok && s.Code() == codes.ResourceExhausted
}

// CheckMissionQuota -----------------------------------------------------------

func TestQuotaManager_CheckMissionQuota_NoQuotaPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	// No setLimits → no quota → unlimited.
	assert.NoError(t, qm.CheckMissionQuota(ctx))
}

func TestQuotaManager_CheckMissionQuota_UnlimitedPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setLimits(qm, "acme", 0, 0)
	// IncrementMissionCount many times — 0 limit means unlimited.
	for i := 0; i < 50; i++ {
		require.NoError(t, qm.IncrementMissionCount(ctx))
	}
	assert.NoError(t, qm.CheckMissionQuota(ctx))
}

func TestQuotaManager_CheckMissionQuota_BelowLimitPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setLimits(qm, "acme", 5, 0)
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	assert.NoError(t, qm.CheckMissionQuota(ctx))
}

func TestQuotaManager_CheckMissionQuota_AtLimitFails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setLimits(qm, "acme", 2, 0)
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	err := qm.CheckMissionQuota(ctx)
	assert.True(t, isResourceExhausted(err), "want ResourceExhausted, got %v", err)
}

func TestQuotaManager_CheckMissionQuota_DecrementOpensSlot(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setLimits(qm, "acme", 2, 0)
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.True(t, isResourceExhausted(qm.CheckMissionQuota(ctx)))
	require.NoError(t, qm.DecrementMissionCount(ctx))
	assert.NoError(t, qm.CheckMissionQuota(ctx))
}

// CheckConnectorQuota ---------------------------------------------------------

// setConnectorLimit seeds the cache with a connector budget for the tenant.
func setConnectorLimit(qm *QuotaManager, tenant string, connectors int) {
	qm.cacheMu.Lock()
	defer qm.cacheMu.Unlock()
	if qm.cache == nil {
		qm.cache = make(map[string]quotaCacheEntry)
	}
	qm.cache[tenant] = quotaCacheEntry{
		q: TenantQuota{TenantID: tenant, ConcurrentConnectors: connectors},
	}
}

func TestQuotaManager_CheckConnectorQuota_NoQuotaPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	assert.NoError(t, qm.CheckConnectorQuota(ctx, 999))
}

func TestQuotaManager_CheckConnectorQuota_UnlimitedPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setConnectorLimit(qm, "acme", 0) // 0 = unlimited
	assert.NoError(t, qm.CheckConnectorQuota(ctx, 999))
}

func TestQuotaManager_CheckConnectorQuota_BelowLimitPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setConnectorLimit(qm, "acme", 5)
	assert.NoError(t, qm.CheckConnectorQuota(ctx, 4))
}

func TestQuotaManager_CheckConnectorQuota_AtLimitFails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setConnectorLimit(qm, "acme", 3)
	err := qm.CheckConnectorQuota(ctx, 3)
	assert.True(t, isResourceExhausted(err), "want ResourceExhausted, got %v", err)
}

// CheckAgentQuota -------------------------------------------------------------

func TestQuotaManager_CheckAgentQuota_NoQuotaPasses(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	assert.NoError(t, qm.CheckAgentQuota(ctx))
}

func TestQuotaManager_CheckAgentQuota_AtLimitFails(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setLimits(qm, "acme", 0, 3)
	for i := 0; i < 3; i++ {
		require.NoError(t, qm.IncrementAgentCount(ctx))
	}
	err := qm.CheckAgentQuota(ctx)
	assert.True(t, isResourceExhausted(err), "want ResourceExhausted, got %v", err)
}

func TestQuotaManager_CheckAgentQuota_DecrementOpensSlot(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	setLimits(qm, "acme", 0, 2)
	require.NoError(t, qm.IncrementAgentCount(ctx))
	require.NoError(t, qm.IncrementAgentCount(ctx))
	require.True(t, isResourceExhausted(qm.CheckAgentQuota(ctx)))
	require.NoError(t, qm.DecrementAgentCount(ctx))
	assert.NoError(t, qm.CheckAgentQuota(ctx))
}

// Decrement floor-zero --------------------------------------------------------

func TestQuotaManager_Decrement_FlooredAtZero(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	// Decrementing a non-existent counter is a no-op.
	assert.NoError(t, qm.DecrementMissionCount(ctx))
	assert.NoError(t, qm.DecrementAgentCount(ctx))
	// Decrement once after a single increment, then DECR again.
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.DecrementMissionCount(ctx))
	assert.NoError(t, qm.DecrementMissionCount(ctx)) // already at floor
}

// ReadActiveCounters ----------------------------------------------------------

func TestQuotaManager_ReadActiveCounters_ZeroByDefault(t *testing.T) {
	qm, _ := newTestQuotaManager(t, "acme")
	missions, agents, err := qm.ReadActiveCounters(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, int64(0), missions)
	assert.Equal(t, int64(0), agents)
}

func TestQuotaManager_ReadActiveCounters_ReflectsIncrements(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementAgentCount(ctx))
	missions, agents, err := qm.ReadActiveCounters(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, int64(2), missions)
	assert.Equal(t, int64(1), agents)
}

// Key naming guard ------------------------------------------------------------

func TestQuotaManager_KeyNames(t *testing.T) {
	// Pin the renamed key conventions so any accidental rename trips this
	// test. The boot-time Redis sweep (Phase 3.13) relies on these exact
	// names.
	assert.Equal(t, "quota:missions:active", quotaMissionsActiveKey)
	assert.Equal(t, "quota:agents:active", quotaAgentsActiveKey)
}
