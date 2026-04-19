package memory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupManagerTestDB creates a temp file SQLite database for manager testing.
// We use a temp file instead of :memory: because WAL mode doesn't work with in-memory databases.
func setupManagerTestDB(t *testing.T) (*database.DB, func()) {
	t.Helper()

	// Create temp directory for test database
	tmpDir, err := os.MkdirTemp("", "gibson-manager-test-*")
	require.NoError(t, err, "failed to create temp dir")

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.Open(dbPath)
	require.NoError(t, err, "failed to open test database")

	// Initialize schema
	err = db.InitSchema()
	require.NoError(t, err, "failed to initialize schema")

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

// TestNewMemoryManager_Success tests successful creation of a MemoryManager.
func TestNewMemoryManager_Success(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	config := NewDefaultMemoryConfig()

	manager, err := NewMemoryManager(missionID, db, config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	// Verify MissionID is set correctly
	assert.Equal(t, missionID, manager.MissionID())

	// Clean up
	err = manager.Close()
	assert.NoError(t, err)
}

// TestNewMemoryManager_WithNilConfig tests creation with nil config (should use defaults).
func TestNewMemoryManager_WithNilConfig(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()

	// Pass nil config - should apply defaults
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	require.NotNil(t, manager)

	assert.Equal(t, missionID, manager.MissionID())

	err = manager.Close()
	assert.NoError(t, err)
}

// TestNewMemoryManager_WithCustomConfig tests creation with custom configuration.
func TestNewMemoryManager_WithCustomConfig(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()

	// Create custom config
	config := &MemoryConfig{
		Working: WorkingMemoryConfig{
			MaxTokens:      50000,
			EvictionPolicy: "lru",
		},
		Mission: MissionMemoryConfig{
			CacheSize: 500,
			EnableFTS: true,
		},
		LongTerm: LongTermMemoryConfig{
			Backend: "embedded",
			Embedder: EmbedderConfig{
				Provider: "native",
			},
		},
	}

	manager, err := NewMemoryManager(missionID, db, config)
	require.NoError(t, err)
	require.NotNil(t, manager)

	assert.Equal(t, missionID, manager.MissionID())

	err = manager.Close()
	assert.NoError(t, err)
}

// TestNewMemoryManager_InvalidConfig tests creation with invalid configuration.
func TestNewMemoryManager_InvalidConfig(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()

	// Create invalid config (negative max tokens)
	config := &MemoryConfig{
		Working: WorkingMemoryConfig{
			MaxTokens:      -1000,
			EvictionPolicy: "lru",
		},
	}

	manager, err := NewMemoryManager(missionID, db, config)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "memory configuration validation failed")
}

// TestMemoryManager_Working tests the Working() accessor.
func TestMemoryManager_Working(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	// Get working memory
	working := manager.Working()
	require.NotNil(t, working)

	// Test that it's functional
	err = working.Set("test-key", "test-value")
	assert.NoError(t, err)

	value, ok := working.Get("test-key")
	assert.True(t, ok)
	assert.Equal(t, "test-value", value)
}

// TestMemoryManager_Mission tests the Mission() accessor.
func TestMemoryManager_Mission(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	// Get mission memory
	mission := manager.Mission()
	require.NotNil(t, mission)

	// Verify it's scoped to the correct mission
	assert.Equal(t, missionID, mission.MissionID())

	// Test that it's functional
	ctx := context.Background()
	err = mission.Store(ctx, "test-key", "test-value", nil)
	assert.NoError(t, err)

	item, err := mission.Retrieve(ctx, "test-key")
	assert.NoError(t, err)
	assert.Equal(t, "test-key", item.Key)
	assert.Equal(t, "test-value", item.Value)
}

// TestMemoryManager_LongTerm tests the LongTerm() accessor.
func TestMemoryManager_LongTerm(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	// Get long-term memory
	longTerm := manager.LongTerm()
	require.NotNil(t, longTerm)

	// Test that it's functional
	ctx := context.Background()
	err = longTerm.Store(ctx, "test-id", "test content", nil)
	assert.NoError(t, err)

	// Note: We can't easily test search without setting up mock results,
	// but we've verified the instance is returned correctly
}

// TestMemoryManager_MemoryStore tests that MemoryManager implements MemoryStore.
func TestMemoryManager_MemoryStore(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	// Verify manager implements MemoryStore interface
	var _ MemoryStore = manager

	// Test all MemoryStore methods are accessible
	assert.NotNil(t, manager.Working())
	assert.NotNil(t, manager.Mission())
	assert.NotNil(t, manager.LongTerm())
}

// TestMemoryManager_Close tests resource cleanup.
func TestMemoryManager_Close(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)

	// Add some data to working memory
	working := manager.Working()
	err = working.Set("key1", "value1")
	require.NoError(t, err)
	err = working.Set("key2", "value2")
	require.NoError(t, err)

	// Verify data exists
	keys := working.List()
	assert.Len(t, keys, 2)

	// Close the manager
	err = manager.Close()
	assert.NoError(t, err)

	// Verify working memory was cleared
	keys = working.List()
	assert.Len(t, keys, 0)
}

// TestMemoryManager_Close_Idempotent tests that Close is idempotent.
func TestMemoryManager_Close_Idempotent(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)

	// Close multiple times - should not error
	err = manager.Close()
	assert.NoError(t, err)

	err = manager.Close()
	assert.NoError(t, err)

	err = manager.Close()
	assert.NoError(t, err)
}

// TestMemoryManager_MultipleMissions tests that multiple managers can coexist.
func TestMemoryManager_MultipleMissions(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	// Create managers for two different missions
	mission1ID := types.NewID()
	mission2ID := types.NewID()

	manager1, err := NewMemoryManager(mission1ID, db, nil)
	require.NoError(t, err)
	defer manager1.Close()

	manager2, err := NewMemoryManager(mission2ID, db, nil)
	require.NoError(t, err)
	defer manager2.Close()

	// Verify they have different mission IDs
	assert.NotEqual(t, manager1.MissionID(), manager2.MissionID())
	assert.Equal(t, mission1ID, manager1.MissionID())
	assert.Equal(t, mission2ID, manager2.MissionID())

	// Store data in each mission's memory
	ctx := context.Background()

	err = manager1.Mission().Store(ctx, "key", "value1", nil)
	require.NoError(t, err)

	err = manager2.Mission().Store(ctx, "key", "value2", nil)
	require.NoError(t, err)

	// Verify data is isolated between missions
	item1, err := manager1.Mission().Retrieve(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, "value1", item1.Value)

	item2, err := manager2.Mission().Retrieve(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, "value2", item2.Value)
}

// TestMemoryManager_Integration tests a complete mission across all memory tiers.
func TestMemoryManager_Integration(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()
	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Step 1: Use working memory for immediate context
	working := manager.Working()
	err = working.Set("current-finding", map[string]string{
		"type":     "sql-injection",
		"severity": "high",
	})
	require.NoError(t, err)

	// Step 2: Persist important findings to mission memory
	mission := manager.Mission()
	err = mission.Store(ctx, "finding-001", map[string]any{
		"type":        "sql-injection",
		"description": "SQL injection in login form",
		"severity":    "high",
	}, map[string]any{"status": "confirmed"})
	require.NoError(t, err)

	// Step 3: Store to long-term memory for semantic search
	longTerm := manager.LongTerm()
	err = longTerm.Store(ctx, "finding-001", "SQL injection vulnerability in login form allows authentication bypass", map[string]any{
		"type":     "finding",
		"severity": "high",
	})
	require.NoError(t, err)

	// Verify all tiers have the data
	// Working memory
	value, ok := working.Get("current-finding")
	assert.True(t, ok)
	assert.NotNil(t, value)

	// Mission memory
	item, err := mission.Retrieve(ctx, "finding-001")
	assert.NoError(t, err)
	assert.Equal(t, "finding-001", item.Key)

	// Long-term memory - just verify store didn't error (search requires mock setup)
	// Already verified above with require.NoError
}

// TestMemoryManager_TokenBudgetManagement tests token budget across working memory.
func TestMemoryManager_TokenBudgetManagement(t *testing.T) {
	db, cleanup := setupManagerTestDB(t)
	defer cleanup()

	missionID := types.NewID()

	// Create manager with small token budget for testing
	config := &MemoryConfig{
		Working: WorkingMemoryConfig{
			MaxTokens:      1000,
			EvictionPolicy: "lru",
		},
	}
	config.ApplyDefaults()

	manager, err := NewMemoryManager(missionID, db, config)
	require.NoError(t, err)
	defer manager.Close()

	working := manager.Working()

	// Verify max tokens is set correctly
	assert.Equal(t, 1000, working.MaxTokens())

	// Add some data and verify token counting
	err = working.Set("key1", "some data")
	assert.NoError(t, err)

	tokenCount := working.TokenCount()
	assert.Greater(t, tokenCount, 0)
	assert.LessOrEqual(t, tokenCount, 1000)
}
