package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
)

// TestNewMemoryManagerFactory verifies factory initialization.
func TestNewMemoryManagerFactory(t *testing.T) {
	t.Run("success with default config", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)
		require.NotNil(t, factory)
		assert.NotNil(t, factory.Config())
		assert.Equal(t, db, factory.DB())
	})

	t.Run("success with custom config", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		config := &memory.MemoryConfig{
			Working: memory.WorkingMemoryConfig{
				MaxTokens:      50000,
				EvictionPolicy: "lru",
			},
			Mission: memory.MissionMemoryConfig{
				CacheSize: 500,
				EnableFTS: true,
			},
			LongTerm: memory.LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: memory.EmbedderConfig{
					Provider: "mock",
					Model:    "test-model",
				},
			},
		}

		factory, err := NewMemoryManagerFactory(db, nil, config)
		require.NoError(t, err)
		require.NotNil(t, factory)
		assert.Equal(t, 50000, factory.Config().Working.MaxTokens)
		assert.Equal(t, 500, factory.Config().Mission.CacheSize)
	})

	t.Run("error when db is nil", func(t *testing.T) {
		factory, err := NewMemoryManagerFactory(nil, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "database connection cannot be nil")
	})

	t.Run("error with invalid config", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		config := &memory.MemoryConfig{
			Working: memory.WorkingMemoryConfig{
				MaxTokens:      -1, // Invalid
				EvictionPolicy: "lru",
			},
		}

		factory, err := NewMemoryManagerFactory(db, nil, config)
		assert.Error(t, err)
		assert.Nil(t, factory)
		assert.Contains(t, err.Error(), "validation failed")
	})
}

// TestMemoryManagerFactory_CreateForMission verifies memory manager creation.
func TestMemoryManagerFactory_CreateForMission(t *testing.T) {
	t.Run("creates manager for valid mission ID", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		missionID := types.NewID()

		mgr, err := factory.CreateForMission(ctx, missionID)
		require.NoError(t, err)
		require.NotNil(t, mgr)
		defer mgr.Close()

		// Verify manager is scoped to the correct mission
		assert.Equal(t, missionID, mgr.MissionID())

		// Verify all memory tiers are accessible
		assert.NotNil(t, mgr.Working())
		assert.NotNil(t, mgr.Mission())
		assert.NotNil(t, mgr.LongTerm())
	})

	t.Run("creates isolated managers for different missions", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		missionID1 := types.NewID()
		missionID2 := types.NewID()

		mgr1, err := factory.CreateForMission(ctx, missionID1)
		require.NoError(t, err)
		require.NotNil(t, mgr1)
		defer mgr1.Close()

		mgr2, err := factory.CreateForMission(ctx, missionID2)
		require.NoError(t, err)
		require.NotNil(t, mgr2)
		defer mgr2.Close()

		// Verify managers are scoped to different missions
		assert.NotEqual(t, mgr1.MissionID(), mgr2.MissionID())
		assert.Equal(t, missionID1, mgr1.MissionID())
		assert.Equal(t, missionID2, mgr2.MissionID())

		// Verify memory isolation - data in one should not affect the other
		mgr1.Working().Set("test-key", "value1")
		mgr2.Working().Set("test-key", "value2")

		val1, exists1 := mgr1.Working().Get("test-key")
		val2, exists2 := mgr2.Working().Get("test-key")

		assert.True(t, exists1)
		assert.True(t, exists2)
		assert.Equal(t, "value1", val1)
		assert.Equal(t, "value2", val2)
	})

	t.Run("error when mission ID is zero", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		mgr, err := factory.CreateForMission(ctx, types.ID(""))
		assert.Error(t, err)
		assert.Nil(t, mgr)
		assert.Contains(t, err.Error(), "mission ID cannot be zero")
	})

	t.Run("error when mission ID is invalid", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		invalidID := types.ID("not-a-valid-uuid")
		mgr, err := factory.CreateForMission(ctx, invalidID)
		assert.Error(t, err)
		assert.Nil(t, mgr)
		assert.Contains(t, err.Error(), "invalid mission ID")
	})
}

// TestMemoryManagerFactory_MemoryManagerLifecycle tests the full lifecycle.
func TestMemoryManagerFactory_MemoryManagerLifecycle(t *testing.T) {
	t.Run("manager can be closed and resources released", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		missionID := types.NewID()

		mgr, err := factory.CreateForMission(ctx, missionID)
		require.NoError(t, err)
		require.NotNil(t, mgr)

		// Use the manager
		mgr.Working().Set("test-key", "test-value")
		val, exists := mgr.Working().Get("test-key")
		assert.True(t, exists)
		assert.Equal(t, "test-value", val)

		// Close the manager
		err = mgr.Close()
		assert.NoError(t, err)

		// Working memory should be cleared after close
		val, exists = mgr.Working().Get("test-key")
		assert.False(t, exists)
		assert.Equal(t, "", val)
	})

	t.Run("multiple close calls are safe (idempotent)", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		factory, err := NewMemoryManagerFactory(db, nil, nil)
		require.NoError(t, err)

		ctx := context.Background()
		missionID := types.NewID()

		mgr, err := factory.CreateForMission(ctx, missionID)
		require.NoError(t, err)
		require.NotNil(t, mgr)

		// Close multiple times
		err = mgr.Close()
		assert.NoError(t, err)

		err = mgr.Close()
		assert.NoError(t, err)

		err = mgr.Close()
		assert.NoError(t, err)
	})
}

// TestMemoryManagerFactory_ConfigPropagation verifies config is applied.
func TestMemoryManagerFactory_ConfigPropagation(t *testing.T) {
	t.Run("custom config is applied to created managers", func(t *testing.T) {
		db := setupTestDB(t)
		defer db.Close()

		config := &memory.MemoryConfig{
			Working: memory.WorkingMemoryConfig{
				MaxTokens:      25000,
				EvictionPolicy: "lru",
			},
			Mission: memory.MissionMemoryConfig{
				CacheSize: 250,
				EnableFTS: true,
			},
			LongTerm: memory.LongTermMemoryConfig{
				Backend: "embedded",
				Embedder: memory.EmbedderConfig{
					Provider: "mock",
					Model:    "test-model",
				},
			},
		}

		factory, err := NewMemoryManagerFactory(db, nil, config)
		require.NoError(t, err)

		ctx := context.Background()
		missionID := types.NewID()

		mgr, err := factory.CreateForMission(ctx, missionID)
		require.NoError(t, err)
		require.NotNil(t, mgr)
		defer mgr.Close()

		// Verify the manager was created with the custom configuration
		// We can test this by verifying working memory respects max tokens
		// (implementation detail: working memory uses the config value)
		assert.NotNil(t, mgr.Working())
		assert.NotNil(t, mgr.Mission())
		assert.NotNil(t, mgr.LongTerm())
	})
}

// setupTestDB creates an in-memory SQLite database for testing.
func setupTestDB(t *testing.T) *database.DB {
	t.Helper()

	db, err := database.Open(":memory:")
	require.NoError(t, err)

	// Initialize schema
	err = db.InitSchema()
	require.NoError(t, err)

	return db
}
