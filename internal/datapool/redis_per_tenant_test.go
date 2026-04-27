package datapool

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	redis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/auth"
)

// startMiniredis starts a miniredis server and returns it plus a cleanup func.
func startMiniredis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)
	return mr
}

func TestRedisPerTenant_ForTenant_HappyPath(t *testing.T) {
	mr := startMiniredis(t)

	// Seed the master index: HSET tenant:index acme 1
	adminClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), DB: 0})
	defer adminClient.Close()
	err := adminClient.HSet(context.Background(), redisMasterIndexKey, "acme", "1").Err()
	require.NoError(t, err)

	r, err := newRedisPerTenant(mr.Addr())
	require.NoError(t, err)
	defer r.Close()

	tenant := auth.MustNewTenantID("acme")
	client, err := r.ForTenant(context.Background(), tenant)
	require.NoError(t, err)
	require.NotNil(t, client)
}

func TestRedisPerTenant_ForTenant_NotProvisioned(t *testing.T) {
	mr := startMiniredis(t)

	r, err := newRedisPerTenant(mr.Addr())
	require.NoError(t, err)
	defer r.Close()

	tenant := auth.MustNewTenantID("unknown")
	_, err = r.ForTenant(context.Background(), tenant)
	require.Error(t, err)

	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Equal(t, "unknown", npErr.Tenant)
}

func TestRedisPerTenant_ForTenant_NeverReturnsDB0(t *testing.T) {
	mr := startMiniredis(t)

	// Seed: tenant → db 0 (admin DB) — should be rejected
	adminClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), DB: 0})
	defer adminClient.Close()
	err := adminClient.HSet(context.Background(), redisMasterIndexKey, "badtenant", "0").Err()
	require.NoError(t, err)

	r, err := newRedisPerTenant(mr.Addr())
	require.NoError(t, err)
	defer r.Close()

	tenant := auth.MustNewTenantID("badtenant")
	_, err = r.ForTenant(context.Background(), tenant)
	require.Error(t, err)

	var npErr *NotProvisionedError
	require.ErrorAs(t, err, &npErr)
	assert.Contains(t, npErr.Reason, "reserved")
}

func TestRedisPerTenant_ForTenant_DBIndexCached(t *testing.T) {
	mr := startMiniredis(t)

	adminClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), DB: 0})
	defer adminClient.Close()
	err := adminClient.HSet(context.Background(), redisMasterIndexKey, "cached", "2").Err()
	require.NoError(t, err)

	r, err := newRedisPerTenant(mr.Addr())
	require.NoError(t, err)
	defer r.Close()

	tenant := auth.MustNewTenantID("cached")
	ctx := context.Background()

	c1, err := r.ForTenant(ctx, tenant)
	require.NoError(t, err)

	// Remove from master index to verify cached path is used.
	err = adminClient.HDel(ctx, redisMasterIndexKey, "cached").Err()
	require.NoError(t, err)

	c2, err := r.ForTenant(ctx, tenant)
	require.NoError(t, err)

	// Should return the same client instance (cached).
	assert.Same(t, c1, c2)
}

func TestRedisPerTenant_ForTenant_TwoTenants_Isolated(t *testing.T) {
	mr := startMiniredis(t)

	adminClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), DB: 0})
	defer adminClient.Close()

	ctx := context.Background()
	err := adminClient.HSet(ctx, redisMasterIndexKey, "tenanta", "1", "tenantb", "2").Err()
	require.NoError(t, err)

	r, err := newRedisPerTenant(mr.Addr())
	require.NoError(t, err)
	defer r.Close()

	clientA, err := r.ForTenant(ctx, auth.MustNewTenantID("tenanta"))
	require.NoError(t, err)
	clientB, err := r.ForTenant(ctx, auth.MustNewTenantID("tenantb"))
	require.NoError(t, err)

	assert.NotSame(t, clientA, clientB)
}

func TestRedisPerTenant_ForTenant_EmptyAddr(t *testing.T) {
	_, err := newRedisPerTenant("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "addr is required")
}

func TestRedisPerTenant_Close(t *testing.T) {
	mr := startMiniredis(t)

	adminClient := redis.NewClient(&redis.Options{Addr: mr.Addr(), DB: 0})
	defer adminClient.Close()
	err := adminClient.HSet(context.Background(), redisMasterIndexKey, "closeme", "3").Err()
	require.NoError(t, err)

	r, err := newRedisPerTenant(mr.Addr())
	require.NoError(t, err)

	_, err = r.ForTenant(context.Background(), auth.MustNewTenantID("closeme"))
	require.NoError(t, err)

	r.Close()

	// After close, ForTenant should return an error.
	_, err = r.ForTenant(context.Background(), auth.MustNewTenantID("closeme"))
	require.Error(t, err)
}
