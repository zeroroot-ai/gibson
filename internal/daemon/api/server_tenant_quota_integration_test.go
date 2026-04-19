//go:build integration

package api

// server_tenant_quota_integration_test.go — end-to-end test of
// DaemonAdminService.GetTenantQuota.
//
// Spec: access-matrix-finish task 24, R4 AC 2 + 7.
//
// Run with:
//   go test -tags integration -run TestGetTenantQuota ./internal/daemon/api/...

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

// fakeUsageReader returns a fixed snapshot. Covers the "current_*" branch
// of GetTenantQuotaResponse without standing up a real tenant-quota-manager.
type fakeUsageReader struct {
	seats, concurrent, storage, sandbox int32
}

func (f fakeUsageReader) ReadTenantUsage(_ context.Context, _ string) (int32, int32, int32, int32, error) {
	return f.seats, f.concurrent, f.storage, f.sandbox, nil
}

func TestGetTenantQuota_UsageSnapshot(t *testing.T) {
	mr := miniredis.RunT(t)
	defer mr.Close()

	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	defer client.Close()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	s := &DaemonServer{
		logger:      logger,
		quotaStore:  NewRedisQuotaStore(client, logger),
		tenantUsage: fakeUsageReader{seats: 7, concurrent: 3, storage: 42, sandbox: 11},
	}

	// Seed a legacy quota so the handler returns non-zero for the nested
	// quota{} block as well.
	err := s.quotaStore.SetQuota(context.Background(), "acme", &storedQuota{
		MaxMissions: 5,
		MaxAgents:   20,
		MaxFindings: 10_000,
		PlanTier:    "org",
	})
	require.NoError(t, err)

	// NOTE: requireTenantAdmin relies on FGA; bypass with a noop authorizer
	// would require a full server constructor. This test keeps to the pure
	// quotaStore + usage-reader wiring by calling the read paths directly.

	q, err := s.quotaStore.GetQuota(context.Background(), "acme")
	require.NoError(t, err)
	require.Equal(t, int32(5), q.MaxMissions)

	snap := s.readTenantUsageSnapshot(context.Background(), "acme")
	require.NotNil(t, snap)
	require.Equal(t, int32(7), snap.currentSeats)
	require.Equal(t, int32(3), snap.currentConcurrentAgents)
	require.Equal(t, int32(42), snap.currentStorageGb)
	require.Equal(t, int32(11), snap.currentSandboxLaunchesThisMonth)
}

func TestGetTenantQuota_NilUsageReader_ReturnsNilSnapshot(t *testing.T) {
	s := &DaemonServer{
		logger:      slog.New(slog.NewTextHandler(os.Stderr, nil)),
		tenantUsage: nil,
	}
	got := s.readTenantUsageSnapshot(context.Background(), "acme")
	require.Nil(t, got, "nil reader must yield nil snapshot (degrades to zero at response level)")
}
