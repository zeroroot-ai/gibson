package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/state"
	testutil "github.com/zeroroot-ai/gibson/internal/testing"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// setupTestRedisClient creates a test Redis client for integration tests.
// Skips the test if Redis is not available.
func setupTestRedisClient(t *testing.T) *state.StateClient {
	t.Helper()

	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379"

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Redis not available, skipping test: %v", err)
	}

	// Ensure indexes are created
	ctx := context.Background()
	if err := client.EnsureIndexes(ctx); err != nil {
		t.Fatalf("failed to create indexes: %v", err)
	}

	return client
}

// cleanupTestRedisMemory removes all test data for a mission.
func cleanupTestRedisMemory(t *testing.T, memory *RedisMissionMemory) {
	t.Helper()

	ctx := context.Background()
	if err := memory.Clear(ctx); err != nil {
		t.Logf("warning: failed to cleanup test data: %v", err)
	}
}

func TestRedisMissionMemory_Store(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("store simple value", func(t *testing.T) {
		err := memory.Store(ctx, "test_key", "test_value", nil)
		require.NoError(t, err)

		// Verify storage
		item, err := memory.Retrieve(ctx, "test_key")
		require.NoError(t, err)
		assert.Equal(t, "test_key", item.Key)
		assert.Equal(t, "test_value", item.Value)
	})

	t.Run("store complex value", func(t *testing.T) {
		complexValue := map[string]any{
			"name":  "alice",
			"age":   30,
			"roles": []string{"admin", "user"},
		}

		err := memory.Store(ctx, "complex_key", complexValue, nil)
		require.NoError(t, err)

		// Verify storage
		item, err := memory.Retrieve(ctx, "complex_key")
		require.NoError(t, err)
		assert.Equal(t, "complex_key", item.Key)

		// Compare as JSON to handle map ordering
		expected, _ := json.Marshal(complexValue)
		actual, _ := json.Marshal(item.Value)
		assert.JSONEq(t, string(expected), string(actual))
	})

	t.Run("store with metadata", func(t *testing.T) {
		metadata := map[string]any{
			"source":   "api",
			"priority": 1,
		}

		err := memory.Store(ctx, "metadata_key", "value", metadata)
		require.NoError(t, err)

		// Verify metadata
		item, err := memory.Retrieve(ctx, "metadata_key")
		require.NoError(t, err)
		assert.Equal(t, metadata["source"], item.Metadata["source"])
		assert.Equal(t, float64(1), item.Metadata["priority"]) // JSON numbers are float64
	})

	t.Run("update existing key", func(t *testing.T) {
		// Store initial value
		err := memory.Store(ctx, "update_key", "initial", nil)
		require.NoError(t, err)

		// Update value
		err = memory.Store(ctx, "update_key", "updated", nil)
		require.NoError(t, err)

		// Verify update
		item, err := memory.Retrieve(ctx, "update_key")
		require.NoError(t, err)
		assert.Equal(t, "updated", item.Value)
	})

	t.Run("empty key error", func(t *testing.T) {
		err := memory.Store(ctx, "", "value", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key cannot be empty")
	})
}

func TestRedisMissionMemory_Retrieve(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("retrieve existing key", func(t *testing.T) {
		// Store a value
		err := memory.Store(ctx, "retrieve_key", "retrieve_value", nil)
		require.NoError(t, err)

		// Retrieve it
		item, err := memory.Retrieve(ctx, "retrieve_key")
		require.NoError(t, err)
		assert.Equal(t, "retrieve_key", item.Key)
		assert.Equal(t, "retrieve_value", item.Value)
		assert.NotZero(t, item.CreatedAt)
		assert.NotZero(t, item.UpdatedAt)
	})

	t.Run("retrieve non-existent key", func(t *testing.T) {
		_, err := memory.Retrieve(ctx, "non_existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission memory item not found")
	})

	t.Run("retrieve with timestamps", func(t *testing.T) {
		// MemoryEntry timestamps are stored as Unix milliseconds (documented
		// on the struct), so the lower bound must be ms-truncated too —
		// otherwise a store landing in the same millisecond reads as
		// "before" the ns-precision bound and the assertion races.
		beforeStore := time.Now().Truncate(time.Millisecond)
		err := memory.Store(ctx, "timestamp_key", "value", nil)
		require.NoError(t, err)
		afterStore := time.Now()

		item, err := memory.Retrieve(ctx, "timestamp_key")
		require.NoError(t, err)

		// Verify timestamps are within reasonable range
		assert.True(t, item.CreatedAt.After(beforeStore) || item.CreatedAt.Equal(beforeStore))
		assert.True(t, item.CreatedAt.Before(afterStore) || item.CreatedAt.Equal(afterStore))
		assert.Equal(t, item.CreatedAt, item.UpdatedAt)
	})
}

func TestRedisMissionMemory_Delete(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("delete existing key", func(t *testing.T) {
		// Store a value
		err := memory.Store(ctx, "delete_key", "delete_value", nil)
		require.NoError(t, err)

		// Delete it
		err = memory.Delete(ctx, "delete_key")
		require.NoError(t, err)

		// Verify deletion
		_, err = memory.Retrieve(ctx, "delete_key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission memory item not found")
	})

	t.Run("delete non-existent key", func(t *testing.T) {
		err := memory.Delete(ctx, "non_existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "mission memory item not found")
	})

	t.Run("delete removes from index", func(t *testing.T) {
		// Store a value
		err := memory.Store(ctx, "index_key", "value", nil)
		require.NoError(t, err)

		// Verify it's in keys list
		keys, err := memory.Keys(ctx)
		require.NoError(t, err)
		assert.Contains(t, keys, "index_key")

		// Delete it
		err = memory.Delete(ctx, "index_key")
		require.NoError(t, err)

		// Verify it's removed from keys list
		keys, err = memory.Keys(ctx)
		require.NoError(t, err)
		assert.NotContains(t, keys, "index_key")
	})
}

func TestRedisMissionMemory_Search(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	// Store test data
	testData := []struct {
		key   string
		value string
	}{
		{"api_key", "secret API key for authentication"},
		{"database_url", "postgresql://localhost/mydb with credentials"},
		{"session_token", "JWT token for API access"},
		{"config", "application configuration settings"},
	}

	for _, td := range testData {
		err := memory.Store(ctx, td.key, td.value, nil)
		require.NoError(t, err)
	}

	// Wait a moment for indexing (RediSearch is near real-time)
	time.Sleep(100 * time.Millisecond)

	t.Run("search by keyword", func(t *testing.T) {
		results, err := memory.Search(ctx, "API", 10)
		require.NoError(t, err)

		// Should find entries containing "API"
		assert.GreaterOrEqual(t, len(results), 1)

		// Verify results contain the search term
		found := false
		for _, result := range results {
			if result.Item.Key == "api_key" || result.Item.Key == "session_token" {
				found = true
				break
			}
		}
		assert.True(t, found, "expected to find API-related entries")
	})

	t.Run("search with limit", func(t *testing.T) {
		results, err := memory.Search(ctx, "API", 1)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(results), 1)
	})

	t.Run("search with scores", func(t *testing.T) {
		results, err := memory.Search(ctx, "API", 10)
		require.NoError(t, err)

		// Verify all results have scores
		for _, result := range results {
			assert.NotZero(t, result.Score)
		}
	})

	t.Run("search no results", func(t *testing.T) {
		results, err := memory.Search(ctx, "nonexistent_term_xyz", 10)
		require.NoError(t, err)
		assert.Empty(t, results)
	})

	t.Run("empty query error", func(t *testing.T) {
		_, err := memory.Search(ctx, "", 10)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "query cannot be empty")
	})

	t.Run("mission isolation", func(t *testing.T) {
		// Create another mission's memory
		otherMissionID := types.NewID()
		otherMemory := NewRedisMissionMemory(client, otherMissionID, "")
		defer cleanupTestRedisMemory(t, otherMemory)

		// Store data in other mission
		err := otherMemory.Store(ctx, "isolated_key", "isolated API data", nil)
		require.NoError(t, err)

		time.Sleep(100 * time.Millisecond)

		// Search in original mission - should not find other mission's data
		results, err := memory.Search(ctx, "isolated", 10)
		require.NoError(t, err)
		assert.Empty(t, results, "should not find data from other missions")
	})
}

func TestRedisMissionMemory_History(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("history ordered by time", func(t *testing.T) {
		// Store entries with slight delays
		for i := 0; i < 3; i++ {
			key := fmt.Sprintf("history_key_%d", i)
			value := fmt.Sprintf("value_%d", i)
			err := memory.Store(ctx, key, value, nil)
			require.NoError(t, err)
			time.Sleep(10 * time.Millisecond)
		}

		// Wait for indexing
		time.Sleep(100 * time.Millisecond)

		// Get history
		items, err := memory.History(ctx, 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(items), 3)

		// Verify ordering (most recent first)
		for i := 0; i < len(items)-1; i++ {
			assert.True(t, items[i].CreatedAt.After(items[i+1].CreatedAt) ||
				items[i].CreatedAt.Equal(items[i+1].CreatedAt),
				"history should be ordered by created_at descending")
		}
	})

	t.Run("history with limit", func(t *testing.T) {
		items, err := memory.History(ctx, 2)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(items), 2)
	})

	t.Run("empty history", func(t *testing.T) {
		emptyMissionID := types.NewID()
		emptyMemory := NewRedisMissionMemory(client, emptyMissionID, "")
		defer cleanupTestRedisMemory(t, emptyMemory)

		items, err := emptyMemory.History(ctx, 10)
		require.NoError(t, err)
		assert.Empty(t, items)
	})
}

func TestRedisMissionMemory_Keys(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("list all keys", func(t *testing.T) {
		// Store multiple entries
		expectedKeys := []string{"key1", "key2", "key3"}
		for _, key := range expectedKeys {
			err := memory.Store(ctx, key, "value", nil)
			require.NoError(t, err)
		}

		// Get keys
		keys, err := memory.Keys(ctx)
		require.NoError(t, err)

		// Verify all expected keys are present
		assert.Len(t, keys, len(expectedKeys))
		for _, expected := range expectedKeys {
			assert.Contains(t, keys, expected)
		}
	})

	t.Run("empty keys list", func(t *testing.T) {
		emptyMissionID := types.NewID()
		emptyMemory := NewRedisMissionMemory(client, emptyMissionID, "")
		defer cleanupTestRedisMemory(t, emptyMemory)

		keys, err := emptyMemory.Keys(ctx)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

func TestRedisMissionMemory_Clear(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("clear all entries", func(t *testing.T) {
		// Store multiple entries
		for i := 0; i < 5; i++ {
			key := fmt.Sprintf("clear_key_%d", i)
			err := memory.Store(ctx, key, "value", nil)
			require.NoError(t, err)
		}

		// Verify entries exist
		keys, err := memory.Keys(ctx)
		require.NoError(t, err)
		assert.Len(t, keys, 5)

		// Clear all
		err = memory.Clear(ctx)
		require.NoError(t, err)

		// Verify all cleared
		keys, err = memory.Keys(ctx)
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("clear empty memory", func(t *testing.T) {
		emptyMissionID := types.NewID()
		emptyMemory := NewRedisMissionMemory(client, emptyMissionID, "")

		// Clear should not error on empty memory
		err := emptyMemory.Clear(ctx)
		require.NoError(t, err)
	})
}

func TestRedisMissionMemory_MissionID(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")

	assert.Equal(t, missionID, memory.MissionID())
}

func TestRedisMissionMemory_ContinuityMode(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")

	// Should default to isolated mode
	assert.Equal(t, MemoryIsolated, memory.ContinuityMode())
}

func TestRedisMissionMemory_Continuity_NotImplemented(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")

	ctx := testutil.WithTestTenant()

	t.Run("GetPreviousRunValue not supported", func(t *testing.T) {
		_, err := memory.GetPreviousRunValue(ctx, "key")
		require.Error(t, err)
		assert.Equal(t, ErrContinuityNotSupported, err)
	})

	t.Run("GetValueHistory returns empty", func(t *testing.T) {
		history, err := memory.GetValueHistory(ctx, "key")
		require.NoError(t, err)
		assert.Empty(t, history)
	})
}

func TestRedisMissionMemory_MultiTenantIsolation(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	// Create two separate missions
	missionID1 := types.NewID()
	missionID2 := types.NewID()

	memory1 := NewRedisMissionMemory(client, missionID1, "")
	memory2 := NewRedisMissionMemory(client, missionID2, "")

	defer cleanupTestRedisMemory(t, memory1)
	defer cleanupTestRedisMemory(t, memory2)

	ctx := testutil.WithTestTenant()

	// Store data in both missions with same key
	err := memory1.Store(ctx, "shared_key", "mission1_value", nil)
	require.NoError(t, err)

	err = memory2.Store(ctx, "shared_key", "mission2_value", nil)
	require.NoError(t, err)

	// Verify isolation in retrieval
	item1, err := memory1.Retrieve(ctx, "shared_key")
	require.NoError(t, err)
	assert.Equal(t, "mission1_value", item1.Value)

	item2, err := memory2.Retrieve(ctx, "shared_key")
	require.NoError(t, err)
	assert.Equal(t, "mission2_value", item2.Value)

	// Verify isolation in keys listing
	keys1, err := memory1.Keys(ctx)
	require.NoError(t, err)
	assert.Contains(t, keys1, "shared_key")

	keys2, err := memory2.Keys(ctx)
	require.NoError(t, err)
	assert.Contains(t, keys2, "shared_key")

	// Verify deletion isolation
	err = memory1.Delete(ctx, "shared_key")
	require.NoError(t, err)

	// Mission 1 should not have the key
	_, err = memory1.Retrieve(ctx, "shared_key")
	require.Error(t, err)

	// Mission 2 should still have the key
	item2, err = memory2.Retrieve(ctx, "shared_key")
	require.NoError(t, err)
	assert.Equal(t, "mission2_value", item2.Value)
}

func TestRedisMissionMemory_KeyNaming(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("verify document key format", func(t *testing.T) {
		key := "test_key"
		expectedDocKey := fmt.Sprintf("gibson:memory:%s:%s", missionID, key)

		// Store a value
		err := memory.Store(ctx, key, "value", nil)
		require.NoError(t, err)

		// Verify the key exists in Redis with correct format
		exists, err := client.Client().Exists(ctx, expectedDocKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists)
	})

	t.Run("verify index key format", func(t *testing.T) {
		expectedIndexKey := fmt.Sprintf("gibson:memory:idx:%s", missionID)

		// Store a value
		err := memory.Store(ctx, "index_test", "value", nil)
		require.NoError(t, err)

		// Verify the index set exists
		exists, err := client.Client().Exists(ctx, expectedIndexKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists)

		// Verify the key is in the set
		isMember, err := client.Client().SIsMember(ctx, expectedIndexKey, "index_test").Result()
		require.NoError(t, err)
		assert.True(t, isMember)
	})
}

func TestRedisMissionMemory_SpecialCharacters(t *testing.T) {
	client := setupTestRedisClient(t)
	defer client.Close()

	missionID := types.NewID()
	memory := NewRedisMissionMemory(client, missionID, "")
	defer cleanupTestRedisMemory(t, memory)

	ctx := testutil.WithTestTenant()

	t.Run("keys with special characters", func(t *testing.T) {
		specialKeys := []string{
			"key-with-dashes",
			"key_with_underscores",
			"key.with.dots",
			"key:with:colons",
		}

		for _, key := range specialKeys {
			err := memory.Store(ctx, key, "value", nil)
			require.NoError(t, err, "failed to store key: %s", key)

			item, err := memory.Retrieve(ctx, key)
			require.NoError(t, err, "failed to retrieve key: %s", key)
			assert.Equal(t, key, item.Key)
		}
	})

	t.Run("values with special characters", func(t *testing.T) {
		specialValues := []string{
			"value with spaces",
			"value\nwith\nnewlines",
			"value\twith\ttabs",
			`value "with" quotes`,
			"value with émojis 🚀",
		}

		for i, value := range specialValues {
			key := fmt.Sprintf("special_value_%d", i)
			err := memory.Store(ctx, key, value, nil)
			require.NoError(t, err)

			item, err := memory.Retrieve(ctx, key)
			require.NoError(t, err)
			assert.Equal(t, value, item.Value)
		}
	})
}
