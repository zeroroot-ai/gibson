package redis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupRedisTargetDAO creates a test Redis client and DAO for testing.
// Skips the test if Redis is not available.
func setupRedisTargetDAO(t *testing.T) (*RedisTargetDAO, context.Context, func()) {
	t.Helper()

	// Use test Redis configuration
	// Database must be 0: RediSearch (FT.CREATE) rejects non-zero databases.
	cfg := &state.Config{
		URL:      "redis://localhost:6379",
		Database: 0,
	}

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
		return nil, nil, nil
	}

	ctx := context.Background()

	// Ensure indexes are created
	if err := client.EnsureIndexes(ctx); err != nil {
		client.Close()
		t.Fatalf("Failed to create indexes: %v", err)
	}

	dao := NewRedisTargetDAO(client)

	// Cleanup function
	cleanup := func() {
		// Clean up test data by deleting all target keys
		keys, _ := client.Client().Keys(ctx, "gibson:target:*").Result()
		if len(keys) > 0 {
			client.Client().Del(ctx, keys...)
		}
		client.Close()
	}

	return dao, ctx, cleanup
}

// createTestTarget creates a test target with sensible defaults.
func createTestTarget(name string) *types.Target {
	target := types.NewTargetWithConnection(name, "http_api", map[string]any{
		"url": "https://api.example.com/v1/chat",
	})
	target.Provider = types.ProviderOpenAI
	target.Model = "gpt-4"
	target.Description = "Test target"
	target.Tags = []string{"test", "api"}
	target.Timeout = 30
	target.AuthType = types.AuthTypeAPIKey
	target.Status = types.TargetStatusActive

	// Add config — use float64 for numeric values: JSON round-trip through
	// Redis always decodes numbers into interface{} as float64.
	target.Config = map[string]interface{}{
		"temperature": 0.7,
		"max_tokens":  float64(1000),
	}

	// Add capabilities
	target.Capabilities = []string{"chat", "completion"}

	// Add headers for backward compatibility
	target.Headers = map[string]string{
		"Content-Type": "application/json",
	}

	return target
}

func TestRedisTargetDAO_Create(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("create_valid_target", func(t *testing.T) {
		target := createTestTarget("test-target-1")

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// Verify target was created
		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, target.ID, retrieved.ID)
		assert.Equal(t, target.Name, retrieved.Name)
		assert.Equal(t, target.Type, retrieved.Type)
		assert.Equal(t, target.Provider, retrieved.Provider)
		assert.Equal(t, target.Model, retrieved.Model)
		assert.Equal(t, target.Status, retrieved.Status)
		assert.Equal(t, target.Description, retrieved.Description)
		assert.Equal(t, target.Tags, retrieved.Tags)
		assert.Equal(t, target.Timeout, retrieved.Timeout)
		assert.Equal(t, target.AuthType, retrieved.AuthType)

		// Verify JSON fields
		assert.Equal(t, target.Config, retrieved.Config)
		assert.Equal(t, target.Capabilities, retrieved.Capabilities)
		assert.Equal(t, target.Connection, retrieved.Connection)
		assert.Equal(t, target.Headers, retrieved.Headers)
	})

	t.Run("create_duplicate_name", func(t *testing.T) {
		target1 := createTestTarget("duplicate-name")
		err := dao.Create(ctx, target1)
		require.NoError(t, err)

		// Try to create another with same name
		target2 := createTestTarget("duplicate-name")
		err = dao.Create(ctx, target2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("create_with_empty_name", func(t *testing.T) {
		target := createTestTarget("")
		err := dao.Create(ctx, target)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("create_with_credential_id", func(t *testing.T) {
		target := createTestTarget("target-with-cred")
		credID := types.NewID()
		target.CredentialID = &credID

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// Verify credential ID was stored
		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved.CredentialID)
		assert.Equal(t, credID, *retrieved.CredentialID)
	})

	t.Run("create_with_complex_connection", func(t *testing.T) {
		target := createTestTarget("complex-connection")
		// JSON round-trip: numbers in interface{} decode as float64; nested
		// map[string]string decodes as map[string]interface{}.
		target.Connection = map[string]any{
			"host":     "example.com",
			"port":     float64(8443),
			"protocol": "https",
			"headers": map[string]interface{}{
				"X-API-Key": "secret",
			},
		}

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, target.Connection, retrieved.Connection)
	})
}

func TestRedisTargetDAO_Get(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_existing_target", func(t *testing.T) {
		target := createTestTarget("get-test")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, target.ID, retrieved.ID)
		assert.Equal(t, target.Name, retrieved.Name)
	})

	t.Run("get_nonexistent_target", func(t *testing.T) {
		id := types.NewID()
		_, err := dao.Get(ctx, id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisTargetDAO_GetByName(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_by_name_existing", func(t *testing.T) {
		target := createTestTarget("name-lookup-test")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.GetByName(ctx, "name-lookup-test")
		require.NoError(t, err)
		assert.Equal(t, target.ID, retrieved.ID)
		assert.Equal(t, target.Name, retrieved.Name)
	})

	t.Run("get_by_name_nonexistent", func(t *testing.T) {
		_, err := dao.GetByName(ctx, "nonexistent-name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisTargetDAO_List(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	// Create test targets with different attributes
	target1 := createTestTarget("list-test-1")
	target1.Provider = types.ProviderOpenAI
	target1.Type = "http_api"
	target1.Status = types.TargetStatusActive
	target1.Tags = []string{"production", "ai"}
	err := dao.Create(ctx, target1)
	require.NoError(t, err)

	target2 := createTestTarget("list-test-2")
	target2.Provider = types.ProviderAnthropic
	target2.Type = "http_api"
	target2.Status = types.TargetStatusActive
	target2.Tags = []string{"production"}
	err = dao.Create(ctx, target2)
	require.NoError(t, err)

	target3 := createTestTarget("list-test-3")
	target3.Provider = types.ProviderOpenAI
	target3.Type = "kubernetes"
	target3.Status = types.TargetStatusInactive
	target3.Tags = []string{"test"}
	err = dao.Create(ctx, target3)
	require.NoError(t, err)

	// Wait for indexing to complete
	time.Sleep(100 * time.Millisecond)

	t.Run("list_all", func(t *testing.T) {
		targets, err := dao.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), 3)
	})

	t.Run("filter_by_provider", func(t *testing.T) {
		provider := types.ProviderOpenAI
		filter := &types.TargetFilter{
			Provider: &provider,
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), 2)
		for _, tgt := range targets {
			assert.Equal(t, types.ProviderOpenAI, tgt.Provider)
		}
	})

	t.Run("filter_by_type", func(t *testing.T) {
		targetType := "http_api"
		filter := &types.TargetFilter{
			Type: &targetType,
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), 2)
		for _, tgt := range targets {
			assert.Equal(t, "http_api", tgt.Type)
		}
	})

	t.Run("filter_by_status", func(t *testing.T) {
		status := types.TargetStatusActive
		filter := &types.TargetFilter{
			Status: &status,
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), 2)
		for _, tgt := range targets {
			assert.Equal(t, types.TargetStatusActive, tgt.Status)
		}
	})

	t.Run("filter_by_tags", func(t *testing.T) {
		filter := &types.TargetFilter{
			Tags: []string{"production"},
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), 2)
		for _, tgt := range targets {
			assert.Contains(t, tgt.Tags, "production")
		}
	})

	t.Run("filter_with_limit", func(t *testing.T) {
		filter := &types.TargetFilter{
			Limit: 2,
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(targets), 2)
	})

	t.Run("filter_with_offset", func(t *testing.T) {
		filter := &types.TargetFilter{
			Limit:  10,
			Offset: 1,
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		// Should return fewer results due to offset
		assert.GreaterOrEqual(t, len(targets), 0)
	})

	t.Run("combined_filters", func(t *testing.T) {
		provider := types.ProviderOpenAI
		status := types.TargetStatusActive
		filter := &types.TargetFilter{
			Provider: &provider,
			Status:   &status,
		}
		targets, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(targets), 1)
		for _, tgt := range targets {
			assert.Equal(t, types.ProviderOpenAI, tgt.Provider)
			assert.Equal(t, types.TargetStatusActive, tgt.Status)
		}
	})
}

func TestRedisTargetDAO_Update(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("update_target_fields", func(t *testing.T) {
		target := createTestTarget("update-test-1")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// Update fields
		target.Description = "Updated description"
		target.Provider = types.ProviderAnthropic
		target.Status = types.TargetStatusInactive
		target.Model = "claude-3-opus"
		target.Config = map[string]interface{}{
			"temperature": 0.9,
		}

		err = dao.Update(ctx, target)
		require.NoError(t, err)

		// Verify updates
		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated description", retrieved.Description)
		assert.Equal(t, types.ProviderAnthropic, retrieved.Provider)
		assert.Equal(t, types.TargetStatusInactive, retrieved.Status)
		assert.Equal(t, "claude-3-opus", retrieved.Model)
		assert.Equal(t, target.Config, retrieved.Config)
	})

	t.Run("update_target_name", func(t *testing.T) {
		target := createTestTarget("old-target-name")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// Update name
		oldName := target.Name
		target.Name = "new-target-name"

		err = dao.Update(ctx, target)
		require.NoError(t, err)

		// Verify new name works
		retrieved, err := dao.GetByName(ctx, "new-target-name")
		require.NoError(t, err)
		assert.Equal(t, target.ID, retrieved.ID)

		// Verify old name doesn't work
		_, err = dao.GetByName(ctx, oldName)
		assert.Error(t, err)
	})

	t.Run("update_to_duplicate_name", func(t *testing.T) {
		target1 := createTestTarget("update-dup-1")
		err := dao.Create(ctx, target1)
		require.NoError(t, err)

		target2 := createTestTarget("update-dup-2")
		err = dao.Create(ctx, target2)
		require.NoError(t, err)

		// Try to update target2 to have same name as target1
		target2.Name = "update-dup-1"
		err = dao.Update(ctx, target2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("update_nonexistent_target", func(t *testing.T) {
		target := createTestTarget("nonexistent")
		target.ID = types.NewID() // Use a new ID that doesn't exist

		err := dao.Update(ctx, target)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("update_credential_id", func(t *testing.T) {
		target := createTestTarget("update-cred-id")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// Add credential ID
		credID := types.NewID()
		target.CredentialID = &credID

		err = dao.Update(ctx, target)
		require.NoError(t, err)

		// Verify update
		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved.CredentialID)
		assert.Equal(t, credID, *retrieved.CredentialID)

		// Remove credential ID
		target.CredentialID = nil
		err = dao.Update(ctx, target)
		require.NoError(t, err)

		retrieved, err = dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Nil(t, retrieved.CredentialID)
	})

	t.Run("update_connection_parameters", func(t *testing.T) {
		target := createTestTarget("update-connection")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// JSON round-trip: port (number) in interface{} decodes as float64.
		target.Connection = map[string]any{
			"host":     "newhost.example.com",
			"port":     float64(9000),
			"protocol": "grpc",
		}

		err = dao.Update(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, target.Connection, retrieved.Connection)
	})
}

func TestRedisTargetDAO_Delete(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("delete_existing_target", func(t *testing.T) {
		target := createTestTarget("delete-test-1")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		err = dao.Delete(ctx, target.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = dao.Get(ctx, target.ID)
		assert.Error(t, err)

		// Verify name lookup also deleted
		exists, err := dao.Exists(ctx, target.Name)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("delete_nonexistent_target", func(t *testing.T) {
		id := types.NewID()
		err := dao.Delete(ctx, id)
		assert.Error(t, err)
	})
}

func TestRedisTargetDAO_Exists(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("exists_by_id_true", func(t *testing.T) {
		target := createTestTarget("exists-test")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		exists, err := dao.ExistsByID(ctx, target.ID)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("exists_by_id_false", func(t *testing.T) {
		id := types.NewID()
		exists, err := dao.ExistsByID(ctx, id)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestRedisTargetDAO_ExistsByName(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	// Note: `Exists` takes a name string; `ExistsByID` takes a types.ID.
	// This test covers the by-name lookup surface.
	t.Run("exists_by_name_true", func(t *testing.T) {
		target := createTestTarget("exists-by-name-test")
		err := dao.Create(ctx, target)
		require.NoError(t, err)

		exists, err := dao.Exists(ctx, "exists-by-name-test")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("exists_by_name_false", func(t *testing.T) {
		exists, err := dao.Exists(ctx, "nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestRedisTargetDAO_JSONFieldsPreserved(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("json_fields_preserved", func(t *testing.T) {
		target := createTestTarget("json-test")

		// Set complex JSON fields — use float64 for all integer literals:
		// JSON round-trip through Redis decodes numbers in interface{} as float64.
		target.Config = map[string]interface{}{
			"temperature":       0.7,
			"max_tokens":        float64(1000),
			"top_p":             0.9,
			"frequency_penalty": 0.5,
			"nested": map[string]interface{}{
				"key1": "value1",
				"key2": float64(42),
			},
		}

		target.Connection = map[string]any{
			"host":     "api.example.com",
			"port":     float64(443),
			"protocol": "https",
			"tls": map[string]any{
				"enabled": true,
				"verify":  true,
			},
		}

		target.Headers = map[string]string{
			"Authorization": "Bearer token",
			"Content-Type":  "application/json",
			"X-Custom":      "header-value",
		}

		target.Capabilities = []string{"chat", "completion", "embedding", "vision"}

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		// Retrieve and verify JSON data is preserved
		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)

		assert.Equal(t, target.Config, retrieved.Config)
		assert.Equal(t, target.Connection, retrieved.Connection)
		assert.Equal(t, target.Headers, retrieved.Headers)
		assert.Equal(t, target.Capabilities, retrieved.Capabilities)
	})
}

func TestRedisTargetDAO_ConcurrentOperations(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("concurrent_creates", func(t *testing.T) {
		const numConcurrent = 10

		errChan := make(chan error, numConcurrent)
		for i := 0; i < numConcurrent; i++ {
			go func(idx int) {
				target := createTestTarget(fmt.Sprintf("concurrent-%d", idx))
				errChan <- dao.Create(ctx, target)
			}(i)
		}

		// Collect results
		successCount := 0
		for i := 0; i < numConcurrent; i++ {
			if err := <-errChan; err == nil {
				successCount++
			}
		}

		assert.Equal(t, numConcurrent, successCount)
	})
}

func TestRedisTargetDAO_TimestampPrecision(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("millisecond_precision_preserved", func(t *testing.T) {
		target := createTestTarget("timestamp-test")

		// Set specific timestamps
		now := time.Now()
		target.CreatedAt = now
		target.UpdatedAt = now

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)

		// Timestamps should be within 1 millisecond (Unix milli precision)
		assert.WithinDuration(t, target.CreatedAt, retrieved.CreatedAt, time.Millisecond)
		assert.WithinDuration(t, target.UpdatedAt, retrieved.UpdatedAt, time.Millisecond)
	})
}

func TestRedisTargetDAO_BackwardCompatibility(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("deprecated_url_field", func(t *testing.T) {
		target := createTestTarget("backward-compat")
		target.URL = "https://legacy-api.example.com/v1"

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, target.URL, retrieved.URL)
	})

	t.Run("deprecated_headers_field", func(t *testing.T) {
		target := createTestTarget("headers-compat")
		target.Headers = map[string]string{
			"Authorization": "Bearer legacy-token",
			"X-API-Version": "v1",
		}

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)
		assert.Equal(t, target.Headers, retrieved.Headers)
	})
}

func TestRedisTargetDAO_EmptyCollections(t *testing.T) {
	dao, ctx, cleanup := setupRedisTargetDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("empty_collections_preserved", func(t *testing.T) {
		target := createTestTarget("empty-collections")
		target.Tags = []string{}
		target.Capabilities = []string{}
		target.Config = map[string]interface{}{}
		target.Headers = map[string]string{}

		err := dao.Create(ctx, target)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, target.ID)
		require.NoError(t, err)

		// Empty collections should be preserved as empty, not nil
		assert.NotNil(t, retrieved.Tags)
		assert.Len(t, retrieved.Tags, 0)
		assert.NotNil(t, retrieved.Capabilities)
		assert.Len(t, retrieved.Capabilities, 0)
		assert.NotNil(t, retrieved.Config)
		assert.Len(t, retrieved.Config, 0)
		assert.NotNil(t, retrieved.Headers)
		assert.Len(t, retrieved.Headers, 0)
	})
}
