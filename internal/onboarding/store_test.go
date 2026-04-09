package onboarding

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStore creates a RedisOnboardingStore backed by an in-process miniredis.
func newTestStore(t *testing.T) *RedisOnboardingStore {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return New(client, logger)
}

func TestGetState_EmptyTenant(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	step, steps, tasks, completedAt, err := store.GetState(ctx, "tenant-empty")

	require.NoError(t, err)
	assert.Equal(t, "", step)
	assert.Equal(t, []string{}, steps, "completedSteps should be empty slice, not nil")
	assert.Equal(t, map[string]string{}, tasks, "setupTasks should be empty map, not nil")
	assert.Equal(t, "", completedAt)
}

func TestGetState_EmptyTenantID_Error(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	_, _, _, _, err := store.GetState(ctx, "")
	assert.Error(t, err, "empty tenantID should return an error")
}

func TestUpdateState_RoundTrip(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tenantID := "tenant-roundtrip"
	wantStep := "configure_integrations"
	wantSteps := []string{"create_account", "verify_email"}
	wantTasks := map[string]string{"integrate_slack": "pending", "set_scope": "completed"}

	require.NoError(t, store.UpdateState(ctx, tenantID, wantStep, wantSteps, wantTasks))

	gotStep, gotSteps, gotTasks, completedAt, err := store.GetState(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, wantStep, gotStep)
	assert.Equal(t, wantSteps, gotSteps)
	assert.Equal(t, wantTasks, gotTasks)
	assert.Equal(t, "", completedAt, "not all tasks complete, so completedAt must be empty")
}

func TestUpdateState_AllTasksComplete_SetsCompletedAt(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tenantID := "tenant-done"
	tasks := map[string]string{"task_a": "completed", "task_b": "completed"}

	require.NoError(t, store.UpdateState(ctx, tenantID, "done", []string{"step_a"}, tasks))

	_, _, _, completedAt, err := store.GetState(ctx, tenantID)
	require.NoError(t, err)
	assert.NotEmpty(t, completedAt, "completedAt should be set when all tasks are completed")
}

func TestUpdateState_Overwrite(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	tenantID := "tenant-overwrite"

	require.NoError(t, store.UpdateState(ctx, tenantID, "step_1", []string{"a"}, map[string]string{"t": "pending"}))
	require.NoError(t, store.UpdateState(ctx, tenantID, "step_2", []string{"a", "b"}, map[string]string{"t": "completed"}))

	gotStep, gotSteps, gotTasks, _, err := store.GetState(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "step_2", gotStep)
	assert.Equal(t, []string{"a", "b"}, gotSteps)
	assert.Equal(t, map[string]string{"t": "completed"}, gotTasks)
}
