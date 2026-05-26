package checkpoint_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/checkpoint"
	"github.com/zeroroot-ai/gibson/internal/state"
)

// createTestBlobStore creates a RedisBlobStore for testing.
func createTestBlobStore(t *testing.T, stateClient *state.StateClient) *checkpoint.RedisBlobStore {
	config := checkpoint.BlobConfig{
		Threshold: 1024,      // 1KB threshold for testing
		TTL:       time.Hour, // 1 hour TTL
		KeyPrefix: testKeyPrefix + ":blob",
	}

	return checkpoint.NewRedisBlobStore(stateClient, config)
}

// TestBlobStore_StoreAndRetrieve tests basic blob storage and retrieval.
func TestBlobStore_StoreAndRetrieve(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	blobStore := createTestBlobStore(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	threadID := "test-thread"
	testData := []byte("This is test blob data for storage and retrieval")

	// Store blob
	blobID, err := blobStore.Store(ctx, threadID, testData)
	require.NoError(t, err)
	assert.NotEmpty(t, blobID)

	// Retrieve blob
	retrieved, err := blobStore.Get(ctx, threadID, blobID)
	require.NoError(t, err)
	assert.Equal(t, testData, retrieved)
}

// TestBlobStore_DeleteBlob tests blob deletion.
func TestBlobStore_DeleteBlob(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	blobStore := createTestBlobStore(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	threadID := "test-thread"
	testData := []byte("Blob to be deleted")

	// Store blob
	blobID, err := blobStore.Store(ctx, threadID, testData)
	require.NoError(t, err)

	// Verify blob exists
	_, err = blobStore.Get(ctx, threadID, blobID)
	require.NoError(t, err)

	// Delete blob
	err = blobStore.Delete(ctx, threadID, blobID)
	require.NoError(t, err)

	// Verify blob is gone
	_, err = blobStore.Get(ctx, threadID, blobID)
	assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)

	// Delete again should fail
	err = blobStore.Delete(ctx, threadID, blobID)
	assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)
}

// TestBlobStore_DeleteByThread tests deleting all blobs for a thread.
func TestBlobStore_DeleteByThread(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	blobStore := createTestBlobStore(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	threadID := "test-thread"

	// Store multiple blobs
	blobIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		data := []byte(fmt.Sprintf("Blob data %d", i))
		blobID, err := blobStore.Store(ctx, threadID, data)
		require.NoError(t, err)
		blobIDs[i] = blobID
	}

	// Verify all blobs exist
	for _, blobID := range blobIDs {
		_, err := blobStore.Get(ctx, threadID, blobID)
		require.NoError(t, err)
	}

	// Delete all blobs for thread
	err = blobStore.DeleteByThread(ctx, threadID)
	require.NoError(t, err)

	// Verify all blobs are gone
	for _, blobID := range blobIDs {
		_, err := blobStore.Get(ctx, threadID, blobID)
		assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)
	}
}

// TestBlobStore_LargeBlob tests storing and retrieving large blobs.
func TestBlobStore_LargeBlob(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	blobStore := createTestBlobStore(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	threadID := "test-thread"

	// Create large blob (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Store large blob
	blobID, err := blobStore.Store(ctx, threadID, largeData)
	require.NoError(t, err)

	// Retrieve and verify
	retrieved, err := blobStore.Get(ctx, threadID, blobID)
	require.NoError(t, err)
	assert.Equal(t, len(largeData), len(retrieved))
	assert.Equal(t, largeData, retrieved)
}

// TestBlobStore_TTL tests blob TTL expiration.
func TestBlobStore_TTL(t *testing.T) {
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

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	// Create blob store with short TTL
	config := checkpoint.BlobConfig{
		Threshold: 1024,
		TTL:       2 * time.Second, // Short TTL for testing
		KeyPrefix: testKeyPrefix + ":blob",
	}
	blobStore := checkpoint.NewRedisBlobStore(stateClient, config)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	threadID := "test-thread"
	testData := []byte("Data that should expire")

	// Store blob
	blobID, err := blobStore.Store(ctx, threadID, testData)
	require.NoError(t, err)

	// Verify blob exists
	_, err = blobStore.Get(ctx, threadID, blobID)
	require.NoError(t, err)

	// Wait for expiration
	t.Log("Waiting for blob to expire...")
	time.Sleep(3 * time.Second)

	// Verify blob is gone
	_, err = blobStore.Get(ctx, threadID, blobID)
	assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)

	t.Log("Blob expired successfully")
}

// TestBlobStore_ShouldStoreAsBlob tests threshold detection.
func TestBlobStore_ShouldStoreAsBlob(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	config := checkpoint.BlobConfig{
		Threshold: 1024, // 1KB threshold
		TTL:       time.Hour,
		KeyPrefix: testKeyPrefix + ":blob",
	}
	blobStore := checkpoint.NewRedisBlobStore(stateClient, config)

	// Small data should not be stored as blob
	assert.False(t, blobStore.ShouldStoreAsBlob(512))
	assert.False(t, blobStore.ShouldStoreAsBlob(1023))

	// Data at threshold should be stored as blob
	assert.True(t, blobStore.ShouldStoreAsBlob(1024))

	// Large data should be stored as blob
	assert.True(t, blobStore.ShouldStoreAsBlob(2048))
	assert.True(t, blobStore.ShouldStoreAsBlob(1024*1024))
}

// TestBlobStore_ThreadIsolation tests that blobs are isolated by thread.
func TestBlobStore_ThreadIsolation(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	blobStore := createTestBlobStore(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	thread1 := "thread-1"
	thread2 := "thread-2"

	// Store blob in thread 1
	data1 := []byte("Thread 1 data")
	blobID1, err := blobStore.Store(ctx, thread1, data1)
	require.NoError(t, err)

	// Store blob in thread 2
	data2 := []byte("Thread 2 data")
	blobID2, err := blobStore.Store(ctx, thread2, data2)
	require.NoError(t, err)

	// Retrieve from correct threads
	retrieved1, err := blobStore.Get(ctx, thread1, blobID1)
	require.NoError(t, err)
	assert.Equal(t, data1, retrieved1)

	retrieved2, err := blobStore.Get(ctx, thread2, blobID2)
	require.NoError(t, err)
	assert.Equal(t, data2, retrieved2)

	// Cross-thread access should fail
	_, err = blobStore.Get(ctx, thread1, blobID2)
	assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)

	_, err = blobStore.Get(ctx, thread2, blobID1)
	assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)

	// Delete thread 1 blobs
	err = blobStore.DeleteByThread(ctx, thread1)
	require.NoError(t, err)

	// Thread 1 blob should be gone
	_, err = blobStore.Get(ctx, thread1, blobID1)
	assert.ErrorIs(t, err, checkpoint.ErrBlobNotFound)

	// Thread 2 blob should still exist
	_, err = blobStore.Get(ctx, thread2, blobID2)
	require.NoError(t, err)
}

// TestBlobStore_EmptyData tests handling of edge cases.
func TestBlobStore_EmptyData(t *testing.T) {
	client, cleanup := setupRedis(t)
	if client == nil {
		return
	}
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	cfg := state.DefaultConfig()
	cfg.URL = fmt.Sprintf("redis://%s", client.Options().Addr)
	stateClient, err := state.NewStateClient(cfg)
	require.NoError(t, err)

	blobStore := createTestBlobStore(t, stateClient)
	defer cleanupKeys(ctx, client, testKeyPrefix+":blob*")

	threadID := "test-thread"

	// Storing empty data should fail
	_, err = blobStore.Store(ctx, threadID, []byte{})
	assert.Error(t, err)

	// Storing nil data should fail
	_, err = blobStore.Store(ctx, threadID, nil)
	assert.Error(t, err)
}
