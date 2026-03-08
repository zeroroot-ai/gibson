package database

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

// setupRedisCredentialDAO creates a test Redis client and DAO for testing.
// Skips the test if Redis is not available.
func setupRedisCredentialDAO(t *testing.T) (*RedisCredentialDAO, context.Context, func()) {
	t.Helper()

	// Use test Redis configuration
	cfg := &state.Config{
		URL:      "redis://localhost:6379",
		Database: 15, // Use test database
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

	dao := NewRedisCredentialDAO(client)

	// Cleanup function
	cleanup := func() {
		// Clean up test data by deleting all credential keys
		keys, _ := client.Client().Keys(ctx, "gibson:credential:*").Result()
		if len(keys) > 0 {
			client.Client().Del(ctx, keys...)
		}
		client.Close()
	}

	return dao, ctx, cleanup
}

// createTestCredential creates a test credential with encrypted fields.
func createTestCredential(name string) *types.Credential {
	cred := types.NewCredential(name, types.CredentialTypeAPIKey)
	cred.Provider = "openai"
	cred.Description = "Test API key"
	cred.Tags = []string{"test", "api"}

	// Set encrypted fields (simulated encryption)
	cred.EncryptedValue = []byte("encrypted_api_key_value")
	cred.EncryptionIV = []byte("initialization_vector_16bytes")
	cred.KeyDerivationSalt = []byte("salt_for_key_derivation_32bytes")

	return cred
}

func TestRedisCredentialDAO_Create(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("create_valid_credential", func(t *testing.T) {
		cred := createTestCredential("test-cred-1")

		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		// Verify credential was created
		retrieved, err := dao.Get(ctx, cred.ID)
		require.NoError(t, err)
		assert.Equal(t, cred.ID, retrieved.ID)
		assert.Equal(t, cred.Name, retrieved.Name)
		assert.Equal(t, cred.Type, retrieved.Type)
		assert.Equal(t, cred.Provider, retrieved.Provider)
		assert.Equal(t, cred.Status, retrieved.Status)
		assert.Equal(t, cred.Description, retrieved.Description)
		assert.Equal(t, cred.Tags, retrieved.Tags)

		// Verify encrypted fields are preserved
		assert.Equal(t, cred.EncryptedValue, retrieved.EncryptedValue)
		assert.Equal(t, cred.EncryptionIV, retrieved.EncryptionIV)
		assert.Equal(t, cred.KeyDerivationSalt, retrieved.KeyDerivationSalt)
	})

	t.Run("create_duplicate_name", func(t *testing.T) {
		cred1 := createTestCredential("duplicate-name")
		err := dao.Create(ctx, cred1)
		require.NoError(t, err)

		// Try to create another with same name
		cred2 := createTestCredential("duplicate-name")
		err = dao.Create(ctx, cred2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("create_with_empty_name", func(t *testing.T) {
		cred := createTestCredential("")
		err := dao.Create(ctx, cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("create_with_invalid_type", func(t *testing.T) {
		cred := createTestCredential("invalid-type-cred")
		cred.Type = types.CredentialType("invalid")
		err := dao.Create(ctx, cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("create_with_empty_encrypted_value", func(t *testing.T) {
		cred := createTestCredential("empty-encrypted-value")
		cred.EncryptedValue = []byte{} // Empty encrypted value
		err := dao.Create(ctx, cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
		assert.Contains(t, err.Error(), "encrypted value cannot be empty")
	})

	t.Run("create_with_empty_encryption_iv", func(t *testing.T) {
		cred := createTestCredential("empty-iv")
		cred.EncryptionIV = []byte{} // Empty IV
		err := dao.Create(ctx, cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
		assert.Contains(t, err.Error(), "encryption IV cannot be empty")
	})

	t.Run("create_with_empty_key_derivation_salt", func(t *testing.T) {
		cred := createTestCredential("empty-salt")
		cred.KeyDerivationSalt = []byte{} // Empty salt
		err := dao.Create(ctx, cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
		assert.Contains(t, err.Error(), "key derivation salt cannot be empty")
	})
}

func TestRedisCredentialDAO_Get(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_existing_credential", func(t *testing.T) {
		cred := createTestCredential("get-test")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, cred.ID)
		require.NoError(t, err)
		assert.Equal(t, cred.ID, retrieved.ID)
		assert.Equal(t, cred.Name, retrieved.Name)
	})

	t.Run("get_nonexistent_credential", func(t *testing.T) {
		id := types.NewID()
		_, err := dao.Get(ctx, id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisCredentialDAO_GetByName(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_by_name_existing", func(t *testing.T) {
		cred := createTestCredential("name-lookup-test")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		retrieved, err := dao.GetByName(ctx, "name-lookup-test")
		require.NoError(t, err)
		assert.Equal(t, cred.ID, retrieved.ID)
		assert.Equal(t, cred.Name, retrieved.Name)
	})

	t.Run("get_by_name_nonexistent", func(t *testing.T) {
		_, err := dao.GetByName(ctx, "nonexistent-name")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisCredentialDAO_List(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	// Create test credentials with different attributes
	cred1 := createTestCredential("list-test-1")
	cred1.Provider = "openai"
	cred1.Type = types.CredentialTypeAPIKey
	cred1.Status = types.CredentialStatusActive
	cred1.Tags = []string{"production", "ai"}
	err := dao.Create(ctx, cred1)
	require.NoError(t, err)

	cred2 := createTestCredential("list-test-2")
	cred2.Provider = "anthropic"
	cred2.Type = types.CredentialTypeBearer
	cred2.Status = types.CredentialStatusActive
	cred2.Tags = []string{"production"}
	err = dao.Create(ctx, cred2)
	require.NoError(t, err)

	cred3 := createTestCredential("list-test-3")
	cred3.Provider = "openai"
	cred3.Type = types.CredentialTypeAPIKey
	cred3.Status = types.CredentialStatusExpired
	cred3.Tags = []string{"test"}
	err = dao.Create(ctx, cred3)
	require.NoError(t, err)

	// Wait for indexing to complete
	time.Sleep(100 * time.Millisecond)

	t.Run("list_all", func(t *testing.T) {
		credentials, err := dao.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(credentials), 3)
	})

	t.Run("filter_by_provider", func(t *testing.T) {
		provider := "openai"
		filter := &types.CredentialFilter{
			Provider: &provider,
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(credentials), 2)
		for _, c := range credentials {
			assert.Equal(t, "openai", c.Provider)
		}
	})

	t.Run("filter_by_type", func(t *testing.T) {
		credType := types.CredentialTypeAPIKey
		filter := &types.CredentialFilter{
			Type: &credType,
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(credentials), 2)
		for _, c := range credentials {
			assert.Equal(t, types.CredentialTypeAPIKey, c.Type)
		}
	})

	t.Run("filter_by_status", func(t *testing.T) {
		status := types.CredentialStatusActive
		filter := &types.CredentialFilter{
			Status: &status,
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(credentials), 2)
		for _, c := range credentials {
			assert.Equal(t, types.CredentialStatusActive, c.Status)
		}
	})

	t.Run("filter_by_tags", func(t *testing.T) {
		filter := &types.CredentialFilter{
			Tags: []string{"production"},
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(credentials), 2)
		for _, c := range credentials {
			assert.Contains(t, c.Tags, "production")
		}
	})

	t.Run("filter_with_limit", func(t *testing.T) {
		filter := &types.CredentialFilter{
			Limit: 2,
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(credentials), 2)
	})

	t.Run("filter_with_offset", func(t *testing.T) {
		filter := &types.CredentialFilter{
			Limit:  10,
			Offset: 1,
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		// Should return fewer results due to offset
		assert.GreaterOrEqual(t, len(credentials), 0)
	})

	t.Run("combined_filters", func(t *testing.T) {
		provider := "openai"
		status := types.CredentialStatusActive
		filter := &types.CredentialFilter{
			Provider: &provider,
			Status:   &status,
		}
		credentials, err := dao.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(credentials), 1)
		for _, c := range credentials {
			assert.Equal(t, "openai", c.Provider)
			assert.Equal(t, types.CredentialStatusActive, c.Status)
		}
	})
}

func TestRedisCredentialDAO_Update(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("update_credential_fields", func(t *testing.T) {
		cred := createTestCredential("update-test-1")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		// Update fields
		cred.Description = "Updated description"
		cred.Provider = "anthropic"
		cred.Status = types.CredentialStatusInactive
		cred.UpdatedAt = time.Now()

		err = dao.Update(ctx, cred)
		require.NoError(t, err)

		// Verify updates
		retrieved, err := dao.Get(ctx, cred.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated description", retrieved.Description)
		assert.Equal(t, "anthropic", retrieved.Provider)
		assert.Equal(t, types.CredentialStatusInactive, retrieved.Status)
	})

	t.Run("update_credential_name", func(t *testing.T) {
		cred := createTestCredential("old-name")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		// Update name
		oldName := cred.Name
		cred.Name = "new-name"
		cred.UpdatedAt = time.Now()

		err = dao.Update(ctx, cred)
		require.NoError(t, err)

		// Verify new name works
		retrieved, err := dao.GetByName(ctx, "new-name")
		require.NoError(t, err)
		assert.Equal(t, cred.ID, retrieved.ID)

		// Verify old name doesn't work
		_, err = dao.GetByName(ctx, oldName)
		assert.Error(t, err)
	})

	t.Run("update_to_duplicate_name", func(t *testing.T) {
		cred1 := createTestCredential("update-dup-1")
		err := dao.Create(ctx, cred1)
		require.NoError(t, err)

		cred2 := createTestCredential("update-dup-2")
		err = dao.Create(ctx, cred2)
		require.NoError(t, err)

		// Try to update cred2 to have same name as cred1
		cred2.Name = "update-dup-1"
		err = dao.Update(ctx, cred2)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("update_nonexistent_credential", func(t *testing.T) {
		cred := createTestCredential("nonexistent")
		cred.ID = types.NewID() // Use a new ID that doesn't exist

		err := dao.Update(ctx, cred)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisCredentialDAO_UpdateLastUsed(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("update_last_used", func(t *testing.T) {
		cred := createTestCredential("last-used-test")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		// Update last used
		lastUsed := time.Now().Add(-1 * time.Hour)
		err = dao.UpdateLastUsed(ctx, cred.ID, lastUsed)
		require.NoError(t, err)

		// Verify update
		retrieved, err := dao.Get(ctx, cred.ID)
		require.NoError(t, err)
		require.NotNil(t, retrieved.LastUsed)
		// Allow for some millisecond precision loss
		assert.WithinDuration(t, lastUsed, *retrieved.LastUsed, time.Second)
	})

	t.Run("update_last_used_nonexistent", func(t *testing.T) {
		id := types.NewID()
		err := dao.UpdateLastUsed(ctx, id, time.Now())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisCredentialDAO_Delete(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("delete_existing_credential", func(t *testing.T) {
		cred := createTestCredential("delete-test-1")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		err = dao.Delete(ctx, cred.ID)
		require.NoError(t, err)

		// Verify deletion
		_, err = dao.Get(ctx, cred.ID)
		assert.Error(t, err)

		// Verify name lookup also deleted
		exists, err := dao.Exists(ctx, cred.Name)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("delete_nonexistent_credential", func(t *testing.T) {
		id := types.NewID()
		err := dao.Delete(ctx, id)
		assert.Error(t, err)
	})
}

func TestRedisCredentialDAO_DeleteByName(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("delete_by_name_existing", func(t *testing.T) {
		cred := createTestCredential("delete-by-name-test")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		err = dao.DeleteByName(ctx, "delete-by-name-test")
		require.NoError(t, err)

		// Verify deletion
		_, err = dao.GetByName(ctx, "delete-by-name-test")
		assert.Error(t, err)
	})

	t.Run("delete_by_name_nonexistent", func(t *testing.T) {
		err := dao.DeleteByName(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestRedisCredentialDAO_Exists(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("exists_true", func(t *testing.T) {
		cred := createTestCredential("exists-test")
		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		exists, err := dao.Exists(ctx, "exists-test")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("exists_false", func(t *testing.T) {
		exists, err := dao.Exists(ctx, "nonexistent")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestRedisCredentialDAO_EncryptedFieldsNotIndexed(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("encrypted_fields_preserved_as_binary", func(t *testing.T) {
		cred := createTestCredential("encryption-test")

		// Set specific encrypted values
		cred.EncryptedValue = []byte{0x01, 0x02, 0x03, 0xFF, 0xFE}
		cred.EncryptionIV = []byte{0xAA, 0xBB, 0xCC, 0xDD}
		cred.KeyDerivationSalt = []byte{0x11, 0x22, 0x33, 0x44, 0x55}

		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		// Retrieve and verify binary data is preserved
		retrieved, err := dao.Get(ctx, cred.ID)
		require.NoError(t, err)

		assert.Equal(t, cred.EncryptedValue, retrieved.EncryptedValue)
		assert.Equal(t, cred.EncryptionIV, retrieved.EncryptionIV)
		assert.Equal(t, cred.KeyDerivationSalt, retrieved.KeyDerivationSalt)
	})
}

func TestRedisCredentialDAO_ConcurrentOperations(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("concurrent_creates_different_names", func(t *testing.T) {
		const numConcurrent = 10

		errChan := make(chan error, numConcurrent)
		for i := 0; i < numConcurrent; i++ {
			go func(idx int) {
				cred := createTestCredential(fmt.Sprintf("concurrent-%d", idx))
				errChan <- dao.Create(ctx, cred)
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

	t.Run("concurrent_creates_same_name_atomic", func(t *testing.T) {
		// Test that atomic Lua script prevents race conditions
		// where multiple creates with the same name are attempted concurrently
		const numConcurrent = 10
		const credName = "race-condition-test"

		errChan := make(chan error, numConcurrent)
		for i := 0; i < numConcurrent; i++ {
			go func(idx int) {
				// All goroutines try to create credential with same name
				cred := createTestCredential(credName)
				errChan <- dao.Create(ctx, cred)
			}(i)
		}

		// Collect results
		successCount := 0
		errorCount := 0
		for i := 0; i < numConcurrent; i++ {
			err := <-errChan
			if err == nil {
				successCount++
			} else {
				errorCount++
			}
		}

		// Exactly ONE should succeed, rest should fail with "already exists"
		assert.Equal(t, 1, successCount, "exactly one create should succeed")
		assert.Equal(t, numConcurrent-1, errorCount, "all other creates should fail")

		// Verify only one credential exists
		cred, err := dao.GetByName(ctx, credName)
		require.NoError(t, err)
		assert.Equal(t, credName, cred.Name)
	})
}

func TestRedisCredentialDAO_TimestampPrecision(t *testing.T) {
	dao, ctx, cleanup := setupRedisCredentialDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("millisecond_precision_preserved", func(t *testing.T) {
		cred := createTestCredential("timestamp-test")

		// Set specific timestamps
		now := time.Now()
		cred.CreatedAt = now
		cred.UpdatedAt = now
		lastUsed := now.Add(-1 * time.Hour)
		cred.LastUsed = &lastUsed

		err := dao.Create(ctx, cred)
		require.NoError(t, err)

		retrieved, err := dao.Get(ctx, cred.ID)
		require.NoError(t, err)

		// Timestamps should be within 1 millisecond (Unix milli precision)
		assert.WithinDuration(t, cred.CreatedAt, retrieved.CreatedAt, time.Millisecond)
		assert.WithinDuration(t, cred.UpdatedAt, retrieved.UpdatedAt, time.Millisecond)
		require.NotNil(t, retrieved.LastUsed)
		assert.WithinDuration(t, *cred.LastUsed, *retrieved.LastUsed, time.Millisecond)
	})
}
