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
	"github.com/zeroroot-ai/gibson/pkg/billing/entitlements"
	"github.com/zeroroot-ai/sdk/auth"
)

// blockedEntitlementsProvider is an in-test Provider that always returns
// ErrEntitlementsRequired, simulating the BlockedProvider that New() installs
// in SaaS mode when ENTITLEMENTS_ENDPOINT is absent or wiring fails.
type blockedEntitlementsProvider struct{}

func (blockedEntitlementsProvider) Limits(_ context.Context, _ string) (entitlements.Limits, error) {
	return entitlements.Limits{}, entitlements.ErrEntitlementsRequired
}

// newQuotaManagerWithProvider creates a QuotaManager backed by miniredis and
// the given provider, with the given tenant injected into the returned context.
func newQuotaManagerWithProvider(t *testing.T, tenant string, p entitlements.Provider) (*QuotaManager, context.Context) {
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

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	qm := NewQuotaManager(store, p, logger)
	ctx := auth.ContextWithTenantString(context.Background(), tenant)
	return qm, ctx
}

// ---------------------------------------------------------------------------
// SaaS fail-closed: quota checks deny when entitlements are required but unavailable
// (Invariants 3 + 4, gibson#1097)
// ---------------------------------------------------------------------------

// TestCheckMissionQuota_SaaS_FailsClosed verifies that when the entitlements
// provider returns ErrEntitlementsRequired (SaaS mode, provider unavailable),
// CheckMissionQuota returns ResourceExhausted instead of nil (allow).
//
// Leak point #3 from the security assessment:
// "internal/.../quota.go:142 — CheckMissionQuota returns nil (allow) when
// GetQuota errors."
func TestCheckMissionQuota_SaaS_FailsClosed(t *testing.T) {
	qm, ctx := newQuotaManagerWithProvider(t, "acme", blockedEntitlementsProvider{})
	err := qm.CheckMissionQuota(ctx)
	require.Error(t, err, "SaaS fail-closed: CheckMissionQuota must deny when entitlements unavailable")
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, s.Code(),
		"SaaS fail-closed: must be ResourceExhausted, got %v", s.Code())
}

// TestCheckAgentQuota_SaaS_FailsClosed verifies the same for agent quota.
func TestCheckAgentQuota_SaaS_FailsClosed(t *testing.T) {
	qm, ctx := newQuotaManagerWithProvider(t, "acme", blockedEntitlementsProvider{})
	err := qm.CheckAgentQuota(ctx)
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, s.Code())
}

// TestCheckConnectorQuota_SaaS_FailsClosed verifies the same for connector quota.
func TestCheckConnectorQuota_SaaS_FailsClosed(t *testing.T) {
	qm, ctx := newQuotaManagerWithProvider(t, "acme", blockedEntitlementsProvider{})
	err := qm.CheckConnectorQuota(ctx, 0)
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.ResourceExhausted, s.Code())
}

// ---------------------------------------------------------------------------
// OSS unlimited-but-metered: error from a generic (non-required) provider
// still fails open (the pre-existing behaviour must not regress)
// ---------------------------------------------------------------------------

// transientErrorProvider simulates a provider that returns a transient
// backend error — NOT ErrEntitlementsRequired. This is the OSS / self-hosted
// case where a DB blip should still fail open.
type transientErrorProvider struct{}

func (transientErrorProvider) Limits(_ context.Context, _ string) (entitlements.Limits, error) {
	return entitlements.Limits{}, context.DeadlineExceeded
}

// TestCheckMissionQuota_OSS_TransientError_FailsOpen verifies that a generic
// (non-required) provider error still fails open (nil return).
// This guards the OSS unlimited-but-metered invariant: a DB blip on a
// self-hosted install must not block missions.
func TestCheckMissionQuota_OSS_TransientError_FailsOpen(t *testing.T) {
	qm, ctx := newQuotaManagerWithProvider(t, "acme", transientErrorProvider{})
	assert.NoError(t, qm.CheckMissionQuota(ctx),
		"OSS fail-open: transient provider error must not block missions")
}

func TestCheckAgentQuota_OSS_TransientError_FailsOpen(t *testing.T) {
	qm, ctx := newQuotaManagerWithProvider(t, "acme", transientErrorProvider{})
	assert.NoError(t, qm.CheckAgentQuota(ctx))
}

func TestCheckConnectorQuota_OSS_TransientError_FailsOpen(t *testing.T) {
	qm, ctx := newQuotaManagerWithProvider(t, "acme", transientErrorProvider{})
	assert.NoError(t, qm.CheckConnectorQuota(ctx, 0))
}

// ---------------------------------------------------------------------------
// OSS nil provider: unlimited-but-metered (entitlements OFF)
// Folded from gibson#1095/#1097 comment: usage recorded, nothing enforced.
// ---------------------------------------------------------------------------

// TestCheckMissionQuota_OSS_NilProvider_Unlimited verifies that with no
// entitlements provider (OSS default), quota checks always pass (unlimited).
func TestCheckMissionQuota_OSS_NilProvider_Unlimited(t *testing.T) {
	qm, ctx := newTestQuotaManager(t, "acme")
	// No limits set, nil provider → must pass regardless of counter.
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	require.NoError(t, qm.IncrementMissionCount(ctx))
	assert.NoError(t, qm.CheckMissionQuota(ctx),
		"OSS nil provider: mission quota must be unlimited (fail-open)")
}
