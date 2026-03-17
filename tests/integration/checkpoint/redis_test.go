package checkpoint_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zero-day-ai/gibson/internal/checkpoint"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

const (
	testKeyPrefix   = "gibson:test:checkpoint"
	redisStackImage = "redis/redis-stack-server:latest"
	testTimeout     = 30 * time.Second
)

// setupRedis starts a Redis Stack container for testing.
func setupRedis(t *testing.T) (*redis.Client, func()) {
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        redisStackImage,
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Skipf("Failed to start Redis container: %v (Docker required for integration tests)", err)
		return nil, func() {}
	}

	host, err := container.Host(ctx)
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get container host: %v", err)
		return nil, func() {}
	}

	port, err := container.MappedPort(ctx, "6379")
	if err != nil {
		container.Terminate(ctx)
		t.Skipf("Failed to get mapped port: %v", err)
		return nil, func() {}
	}

	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", host, port.Port()),
	})

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		container.Terminate(ctx)
		client.Close()
		t.Skipf("Failed to ping Redis: %v", err)
		return nil, func() {}
	}

	cleanup := func() {
		client.Close()
		container.Terminate(ctx)
	}

	t.Logf("Redis Stack container started at %s:%s", host, port.Port())
	return client, cleanup
}

// createTestStore creates a RedisCheckpointStore for testing.
func createTestStore(t *testing.T, client *redis.Client) *checkpoint.RedisCheckpointStore {
	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	cfg.Database = 0

	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	storeConfig := checkpoint.StoreConfig{
		KeyPrefix:  testKeyPrefix,
		DefaultTTL: 24 * time.Hour,
	}

	return checkpoint.NewRedisCheckpointStore(stateClient, storeConfig)
}

// createTestCheckpoints creates test checkpoints with known data.
func createTestCheckpoints(count int, missionID types.ID, threadID string) []*checkpoint.Checkpoint {
	checkpoints := make([]*checkpoint.Checkpoint, count)
	for i := 0; i < count; i++ {
		cp := checkpoint.NewCheckpoint(missionID, threadID)
		cp.CurrentNodeID = fmt.Sprintf("node-%d", i)
		cp.Label = fmt.Sprintf("checkpoint-%d", i)

		// Add some node states
		cp.NodeStates[fmt.Sprintf("node-%d", i)] = &checkpoint.NodeState{
			NodeID: fmt.Sprintf("node-%d", i),
			Status: checkpoint.NodeStatusRunning,
		}

		// Compute checksum
		checksum, _ := cp.ComputeChecksum()
		cp.Checksum = checksum

		// Add small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
		checkpoints[i] = cp
	}
	return checkpoints
}

// waitForExpiration waits for a checkpoint to expire with timeout.
func waitForExpiration(t *testing.T, store checkpoint.CheckpointStore, threadID, checkpointID string, timeout time.Duration) {
	ctx := context.Background()
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		_, err := store.GetLatest(ctx, threadID)
		if err == checkpoint.ErrCheckpointNotFound {
			return // Expired!
		}
		time.Sleep(100 * time.Millisecond)
	}

	t.Fatalf("Checkpoint %s did not expire within %v", checkpointID, timeout)
}

// cleanupKeys removes all test keys.
func cleanupKeys(ctx context.Context, client *redis.Client, pattern string) {
	var cursor uint64
	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return
		}
		if len(keys) > 0 {
			client.Del(ctx, keys...)
		}
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}
}

// TestRedisStore_SaveAndLoad tests basic save and load operations.
func TestRedisStore_SaveAndLoad(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread-1"

	// Create and save checkpoint
	cp := checkpoint.NewCheckpoint(missionID, threadID)
	cp.CurrentNodeID = "node-1"
	cp.NodeStates["node-1"] = &checkpoint.NodeState{
		NodeID: "node-1",
		Status: checkpoint.NodeStatusRunning,
	}

	checksum, err := cp.ComputeChecksum()
	require.NoError(t, err)
	cp.Checksum = checksum

	err = store.Save(ctx, cp)
	require.NoError(t, err, "Failed to save checkpoint")

	// Load checkpoint
	loaded, err := store.GetLatest(ctx, threadID)
	require.NoError(t, err, "Failed to load checkpoint")

	assert.Equal(t, cp.ID, loaded.ID)
	assert.Equal(t, cp.ThreadID, loaded.ThreadID)
	assert.Equal(t, cp.MissionID, loaded.MissionID)
	assert.Equal(t, cp.CurrentNodeID, loaded.CurrentNodeID)
	assert.Equal(t, cp.Checksum, loaded.Checksum)
}

// TestRedisStore_ThreadIsolation tests that checkpoints are isolated by thread.
func TestRedisStore_ThreadIsolation(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	thread1 := "thread-1"
	thread2 := "thread-2"

	// Create checkpoints for thread 1
	checkpoints1 := createTestCheckpoints(3, missionID, thread1)
	for _, cp := range checkpoints1 {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Create checkpoints for thread 2
	checkpoints2 := createTestCheckpoints(5, missionID, thread2)
	for _, cp := range checkpoints2 {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// List checkpoints for thread 1
	list1, err := store.ListByThread(ctx, thread1, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list1, 3, "Thread 1 should have 3 checkpoints")

	// List checkpoints for thread 2
	list2, err := store.ListByThread(ctx, thread2, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list2, 5, "Thread 2 should have 5 checkpoints")

	// Verify IDs don't overlap
	ids1 := make(map[string]bool)
	for _, cp := range list1 {
		ids1[cp.ID] = true
		assert.Equal(t, thread1, cp.ThreadID)
	}

	for _, cp := range list2 {
		assert.False(t, ids1[cp.ID], "Thread 2 checkpoint should not have thread 1 ID")
		assert.Equal(t, thread2, cp.ThreadID)
	}
}

// TestRedisStore_ListByThread tests checkpoint listing with pagination.
func TestRedisStore_ListByThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create 10 checkpoints
	checkpoints := createTestCheckpoints(10, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// List all checkpoints (descending - newest first)
	all, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, all, 10)

	// Verify descending order (newest first)
	for i := 0; i < len(all)-1; i++ {
		assert.True(t, all[i].CreatedAt.After(all[i+1].CreatedAt) || all[i].CreatedAt.Equal(all[i+1].CreatedAt))
	}

	// List with limit
	limited, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{Limit: 5})
	require.NoError(t, err)
	assert.Len(t, limited, 5)

	// List with offset
	offset, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{Offset: 5, Limit: 5})
	require.NoError(t, err)
	assert.Len(t, offset, 5)

	// List ascending (oldest first)
	ascending, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{Ascending: true})
	require.NoError(t, err)
	assert.Len(t, ascending, 10)

	// Verify ascending order (oldest first)
	for i := 0; i < len(ascending)-1; i++ {
		assert.True(t, ascending[i].CreatedAt.Before(ascending[i+1].CreatedAt) || ascending[i].CreatedAt.Equal(ascending[i+1].CreatedAt))
	}
}

// TestRedisStore_GetLatestByThread tests retrieving the latest checkpoint.
func TestRedisStore_GetLatestByThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create checkpoints with delays to ensure ordering
	checkpoints := createTestCheckpoints(5, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Get latest
	latest, err := store.GetLatestByThread(ctx, threadID)
	require.NoError(t, err)

	// Latest should be the last one we saved
	lastSaved := checkpoints[len(checkpoints)-1]
	assert.Equal(t, lastSaved.ID, latest.ID)
	assert.Equal(t, lastSaved.Label, latest.Label)
}

// TestRedisStore_DeleteCheckpoint tests checkpoint deletion.
func TestRedisStore_DeleteCheckpoint(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Note: DeleteCheckpoint by ID alone is not implemented in the current store
	// because it requires a thread ID for efficient key construction.
	// This test documents the current limitation.

	cp := checkpoint.NewCheckpoint(missionID, threadID)
	checksum, _ := cp.ComputeChecksum()
	cp.Checksum = checksum

	err := store.Save(ctx, cp)
	require.NoError(t, err)

	// Attempt to delete by ID alone should return an error
	err = store.DeleteCheckpoint(ctx, cp.ID)
	assert.Error(t, err, "DeleteCheckpoint by ID alone should require reverse index")
}

// TestRedisStore_DeleteByThread tests deleting all checkpoints for a thread.
func TestRedisStore_DeleteByThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create checkpoints
	checkpoints := createTestCheckpoints(5, missionID, threadID)
	for _, cp := range checkpoints {
		err := store.Save(ctx, cp)
		require.NoError(t, err)
	}

	// Verify checkpoints exist
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 5)

	// Delete all checkpoints for thread
	err = store.DeleteThreadCheckpoints(ctx, threadID)
	require.NoError(t, err)

	// Verify checkpoints are gone
	list, err = store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, 0)

	// Verify GetLatest returns not found
	_, err = store.GetLatestByThread(ctx, threadID)
	assert.ErrorIs(t, err, checkpoint.ErrCheckpointNotFound)
}

// TestRedisStore_TTLExpiration tests that checkpoints expire after TTL.
func TestRedisStore_TTLExpiration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping TTL test in short mode")
	}

	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create store with short TTL
	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	storeConfig := checkpoint.StoreConfig{
		KeyPrefix:  testKeyPrefix,
		DefaultTTL: 2 * time.Second, // Short TTL for testing
	}
	store := checkpoint.NewRedisCheckpointStore(stateClient, storeConfig)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Create checkpoint
	cp := checkpoint.NewCheckpoint(missionID, threadID)
	checksum, _ := cp.ComputeChecksum()
	cp.Checksum = checksum

	err = store.Save(ctx, cp)
	require.NoError(t, err)

	// Verify checkpoint exists
	_, err = store.GetLatest(ctx, threadID)
	require.NoError(t, err)

	// Wait for expiration
	t.Log("Waiting for checkpoint to expire...")
	waitForExpiration(t, store, threadID, cp.ID, 5*time.Second)

	t.Log("Checkpoint expired successfully")
}

// TestRedisStore_ConcurrentAccess tests concurrent checkpoint operations.
func TestRedisStore_ConcurrentAccess(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	store := createTestStore(t, client)
	defer cleanupKeys(ctx, client, testKeyPrefix+"*")

	missionID := types.NewID()
	threadID := "test-thread"

	// Concurrent writes
	concurrency := 50
	var wg sync.WaitGroup
	errors := make([]error, concurrency)
	checkpointIDs := make([]string, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			cp := checkpoint.NewCheckpoint(missionID, threadID)
			cp.CurrentNodeID = fmt.Sprintf("node-%d", idx)
			checksum, _ := cp.ComputeChecksum()
			cp.Checksum = checksum

			err := store.Save(ctx, cp)
			errors[idx] = err
			checkpointIDs[idx] = cp.ID
		}(i)
	}

	wg.Wait()

	// Verify no errors
	for i, err := range errors {
		require.NoError(t, err, "Goroutine %d failed", i)
	}

	// Verify all checkpoints were saved
	list, err := store.ListByThread(ctx, threadID, checkpoint.HistoryOptions{})
	require.NoError(t, err)
	assert.Len(t, list, concurrency, "All checkpoints should be saved")

	// Verify all IDs are unique
	seen := make(map[string]bool)
	for _, id := range checkpointIDs {
		assert.False(t, seen[id], "Duplicate checkpoint ID: %s", id)
		seen[id] = true
	}
}
