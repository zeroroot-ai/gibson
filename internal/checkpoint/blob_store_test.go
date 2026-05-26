package checkpoint

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/state"
)

func TestBlobConfig_ApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		config   BlobConfig
		expected BlobConfig
	}{
		{
			name:   "empty config gets all defaults",
			config: BlobConfig{},
			expected: BlobConfig{
				Threshold: 1048576,
				TTL:       7 * 24 * time.Hour,
				KeyPrefix: "gibson:checkpoint:blob",
			},
		},
		{
			name: "partial config preserves custom values",
			config: BlobConfig{
				Threshold: 2097152,
				KeyPrefix: "custom:prefix",
			},
			expected: BlobConfig{
				Threshold: 2097152,
				TTL:       7 * 24 * time.Hour,
				KeyPrefix: "custom:prefix",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config
			config.ApplyDefaults()
			assert.Equal(t, tt.expected, config)
		})
	}
}

func TestRedisBlobStore_ShouldStoreAsBlob(t *testing.T) {
	config := BlobConfig{Threshold: 1024}
	config.ApplyDefaults()

	store := &RedisBlobStore{
		config: config,
	}

	tests := []struct {
		name     string
		size     int
		expected bool
	}{
		{
			name:     "size below threshold",
			size:     512,
			expected: false,
		},
		{
			name:     "size at threshold",
			size:     1024,
			expected: true,
		},
		{
			name:     "size above threshold",
			size:     2048,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := store.ShouldStoreAsBlob(tt.size)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestRedisBlobStore_buildKey(t *testing.T) {
	config := DefaultBlobConfig()
	store := &RedisBlobStore{
		config: config,
	}

	threadID := "thread_123"
	blobID := "blob_456"

	key := store.buildKey(threadID, blobID)
	expected := "gibson:checkpoint:blob:thread_123:blob_456"

	assert.Equal(t, expected, key)
}

func TestBlobReference(t *testing.T) {
	ref := BlobReference{
		BlobID:    "01HQ7ZABCDEF",
		Size:      1048576,
		CreatedAt: time.Now(),
		Type:      "working_memory",
	}

	assert.NotEmpty(t, ref.BlobID)
	assert.Equal(t, int64(1048576), ref.Size)
	assert.Equal(t, "working_memory", ref.Type)
}

func TestParseBlobReference(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name: "valid BlobReference struct",
			input: BlobReference{
				BlobID:    "01HQ7Z",
				Size:      1024,
				CreatedAt: time.Now(),
				Type:      "test",
			},
			wantErr: false,
		},
		{
			name: "valid map",
			input: map[string]any{
				"blob_id":    "01HQ7Z",
				"size":       float64(1024),
				"created_at": time.Now().Format(time.RFC3339),
				"type":       "test",
			},
			wantErr: false,
		},
		{
			name:    "invalid type",
			input:   "invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := parseBlobReference(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, ref)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ref)
				assert.NotEmpty(t, ref.BlobID)
			}
		})
	}
}

// Integration tests require a live Redis connection
// These are skipped in CI unless REDIS_URL is set

func getTestStateClient(t *testing.T) *state.StateClient {
	t.Helper()

	cfg := state.DefaultConfig()
	// Try to use Redis from environment or skip test
	if cfg.URL == "" {
		cfg.URL = "redis://localhost:6379"
	}

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
	})

	return client
}

func TestRedisBlobStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	client := getTestStateClient(t)
	ctx := context.Background()

	config := DefaultBlobConfig()
	config.TTL = 1 * time.Minute // Short TTL for testing
	config.KeyPrefix = "test:blob"

	store := NewRedisBlobStore(client, config)

	t.Run("Store and Get blob", func(t *testing.T) {
		threadID := "test_thread_1"
		data := []byte("test blob data with some content")

		// Store blob
		blobID, err := store.Store(ctx, threadID, data)
		require.NoError(t, err)
		assert.NotEmpty(t, blobID)

		// Get blob
		retrieved, err := store.Get(ctx, threadID, blobID)
		require.NoError(t, err)
		assert.Equal(t, data, retrieved)

		// Cleanup
		err = store.Delete(ctx, threadID, blobID)
		require.NoError(t, err)
	})

	t.Run("Get nonexistent blob returns error", func(t *testing.T) {
		threadID := "test_thread_2"
		blobID := "nonexistent"

		_, err := store.Get(ctx, threadID, blobID)
		assert.ErrorIs(t, err, ErrBlobNotFound)
	})

	t.Run("Delete nonexistent blob returns error", func(t *testing.T) {
		threadID := "test_thread_3"
		blobID := "nonexistent"

		err := store.Delete(ctx, threadID, blobID)
		assert.ErrorIs(t, err, ErrBlobNotFound)
	})

	t.Run("DeleteByThread removes all thread blobs", func(t *testing.T) {
		threadID := "test_thread_4"

		// Store multiple blobs
		blobIDs := make([]string, 3)
		for i := 0; i < 3; i++ {
			data := []byte("test data")
			blobID, err := store.Store(ctx, threadID, data)
			require.NoError(t, err)
			blobIDs[i] = blobID
		}

		// Delete all blobs for thread
		err := store.DeleteByThread(ctx, threadID)
		require.NoError(t, err)

		// Verify all blobs are gone
		for _, blobID := range blobIDs {
			_, err := store.Get(ctx, threadID, blobID)
			assert.ErrorIs(t, err, ErrBlobNotFound)
		}
	})

	t.Run("Store empty data returns error", func(t *testing.T) {
		threadID := "test_thread_5"
		data := []byte{}

		_, err := store.Store(ctx, threadID, data)
		assert.Error(t, err)
	})
}

func TestExtractLargeObjects(t *testing.T) {
	threshold := int64(100) // Small threshold for testing

	t.Run("extracts large working memory", func(t *testing.T) {
		state := NewExecutionState("mission_123", "thread_123")

		// Add large working memory
		largeData := make([]byte, 150)
		for i := range largeData {
			largeData[i] = byte(i % 256)
		}
		state.WorkingMemory["large_data"] = string(largeData)

		// Extract large objects
		modifiedState, blobs, err := ExtractLargeObjects(state, threshold)
		require.NoError(t, err)
		assert.NotNil(t, modifiedState)
		assert.Len(t, blobs, 1)

		// Verify working memory was cleared
		assert.Empty(t, modifiedState.WorkingMemory)

		// Verify blob reference was added to metadata
		assert.Contains(t, modifiedState.Metadata, "working_memory_blob")
	})

	t.Run("does not extract small data", func(t *testing.T) {
		state := NewExecutionState("mission_123", "thread_123")

		// Add small working memory
		state.WorkingMemory["small_data"] = "tiny"

		// Extract large objects
		modifiedState, blobs, err := ExtractLargeObjects(state, threshold)
		require.NoError(t, err)
		assert.NotNil(t, modifiedState)
		assert.Empty(t, blobs)

		// Verify working memory was not modified
		assert.NotEmpty(t, modifiedState.WorkingMemory)
	})

	t.Run("handles empty state", func(t *testing.T) {
		state := NewExecutionState("mission_123", "thread_123")

		modifiedState, blobs, err := ExtractLargeObjects(state, threshold)
		require.NoError(t, err)
		assert.NotNil(t, modifiedState)
		assert.Empty(t, blobs)
	})
}
