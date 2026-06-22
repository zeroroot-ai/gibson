package mission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestAuthzStore creates a MissionAuthzStore backed by miniredis for testing.
func newTestAuthzStore(t *testing.T) (MissionAuthzStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return NewRedisMissionAuthzStore(rdb), mr
}

func TestMissionAuthzStore_PutAndGet(t *testing.T) {
	store, _ := newTestAuthzStore(t)
	ctx := context.Background()

	err := store.Put(ctx, "run-01", "user-abc", "tenant-xyz")
	require.NoError(t, err)

	state, err := store.Get(ctx, "run-01")
	require.NoError(t, err)

	assert.Equal(t, "run-01", state.RunID)
	assert.Equal(t, "user-abc", state.UserID)
	assert.Equal(t, "tenant-xyz", state.TenantID)
	assert.Equal(t, authzStatusActive, state.Status)
	assert.WithinDuration(t, time.Now().UTC(), state.StartedAt, 5*time.Second)
}

func TestMissionAuthzStore_GetNotFound(t *testing.T) {
	store, _ := newTestAuthzStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "does-not-exist")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrMissionAuthzNotFound), "expected ErrMissionAuthzNotFound, got %v", err)
}

func TestMissionAuthzStore_MarkCompleted(t *testing.T) {
	store, mr := newTestAuthzStore(t)
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, "run-02", "user-abc", "tenant-xyz"))

	require.NoError(t, store.MarkCompleted(ctx, "run-02"))

	state, err := store.Get(ctx, "run-02")
	require.NoError(t, err)
	assert.Equal(t, authzStatusCompleted, state.Status)

	// Verify TTL is set (miniredis supports TTL inspection).
	ttl := mr.TTL(authzKey("run-02"))
	assert.Greater(t, ttl, time.Duration(0), "expected TTL to be set after completion")
	assert.LessOrEqual(t, ttl, authzStateTTLAfterDone)
}

func TestMissionAuthzStore_MarkCancelled(t *testing.T) {
	store, mr := newTestAuthzStore(t)
	ctx := context.Background()

	require.NoError(t, store.Put(ctx, "run-03", "user-abc", "tenant-xyz"))

	require.NoError(t, store.MarkCancelled(ctx, "run-03"))

	state, err := store.Get(ctx, "run-03")
	require.NoError(t, err)
	assert.Equal(t, authzStatusCancelled, state.Status)

	ttl := mr.TTL(authzKey("run-03"))
	assert.Greater(t, ttl, time.Duration(0), "expected TTL to be set after cancellation")
	assert.LessOrEqual(t, ttl, authzStateTTLAfterDone)
}

func TestMissionAuthzStore_MarkCompletedNotFound(t *testing.T) {
	store, _ := newTestAuthzStore(t)
	ctx := context.Background()

	// Marking a non-existent run is a no-op (not an error).
	err := store.MarkCompleted(ctx, "non-existent-run")
	require.NoError(t, err)
}

func TestMissionAuthzStore_MarkCancelledNotFound(t *testing.T) {
	store, _ := newTestAuthzStore(t)
	ctx := context.Background()

	err := store.MarkCancelled(ctx, "non-existent-run")
	require.NoError(t, err)
}

func TestMissionAuthzStore_PutEmptyRunID(t *testing.T) {
	store, _ := newTestAuthzStore(t)
	ctx := context.Background()

	err := store.Put(ctx, "", "user-abc", "tenant-xyz")
	require.Error(t, err)
}

func TestMissionAuthzStore_GetEmptyRunID(t *testing.T) {
	store, _ := newTestAuthzStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "")
	require.Error(t, err)
}

func TestMissionAuthzStore_ContextCancellation(t *testing.T) {
	store, _ := newTestAuthzStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Operations with a cancelled context should fail.
	_ = store.Put(ctx, "run-04", "user", "tenant")
	// No assertion needed — just shouldn't panic.
}
