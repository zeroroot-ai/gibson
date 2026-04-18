package memory

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/memory/embedder"
	"github.com/zero-day-ai/gibson/internal/memory/vector"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupIntegrationDB creates a temp file SQLite database for integration testing.
func setupIntegrationDB(t *testing.T) (*database.DB, func()) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "gibson-integration-test-*")
	require.NoError(t, err, "failed to create temp dir")

	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := database.Open(dbPath)
	require.NoError(t, err, "failed to open test database")

	err = db.InitSchema()
	require.NoError(t, err, "failed to initialize schema")

	cleanup := func() {
		db.Close()
		os.RemoveAll(tmpDir)
	}

	return db, cleanup
}

// TestMemoryIntegration_FullMission tests the complete memory system mission.
func TestMemoryIntegration_FullMission(t *testing.T) {
	db, cleanup := setupIntegrationDB(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	// Create memory manager with default config
	config := NewDefaultMemoryConfig()
	manager, err := NewMemoryManager(missionID, db, config)
	require.NoError(t, err)
	defer manager.Close()

	// Verify all memory tiers are accessible
	assert.NotNil(t, manager.Working())
	assert.NotNil(t, manager.Mission())
	assert.NotNil(t, manager.LongTerm())
	assert.Equal(t, missionID, manager.MissionID())

	// Step 1: Use working memory for immediate context
	working := manager.Working()
	err = working.Set("current-target", map[string]string{
		"host": "192.168.1.100",
		"port": "443",
	})
	require.NoError(t, err)

	err = working.Set("scan-state", "in-progress")
	require.NoError(t, err)

	// Verify working memory
	value, ok := working.Get("current-target")
	assert.True(t, ok)
	assert.NotNil(t, value)

	keys := working.List()
	assert.Len(t, keys, 2)

	tokenCount := working.TokenCount()
	assert.Greater(t, tokenCount, 0)

	// Step 2: Store findings in mission memory
	mission := manager.Mission()
	err = mission.Store(ctx, "finding-001", map[string]any{
		"type":        "sql-injection",
		"description": "SQL injection vulnerability in login form",
		"severity":    "high",
		"endpoint":    "/api/login",
	}, map[string]any{
		"status":     "confirmed",
		"exploited":  false,
		"confidence": 0.95,
	})
	require.NoError(t, err)

	err = mission.Store(ctx, "finding-002", map[string]any{
		"type":        "xss",
		"description": "Cross-site scripting in user profile",
		"severity":    "medium",
		"endpoint":    "/api/profile",
	}, map[string]any{
		"status":     "pending",
		"confidence": 0.85,
	})
	require.NoError(t, err)

	// Verify mission memory retrieval
	item, err := mission.Retrieve(ctx, "finding-001")
	require.NoError(t, err)
	assert.Equal(t, "finding-001", item.Key)

	// Verify FTS search
	results, err := mission.Search(ctx, "SQL injection", 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1)

	// Verify history
	history, err := mission.History(ctx, 10)
	require.NoError(t, err)
	assert.Len(t, history, 2)

	// Verify keys
	missionKeys, err := mission.Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, missionKeys, 2)

	// Step 3: Store to long-term memory
	longTerm := manager.LongTerm()
	err = longTerm.Store(ctx, "finding-001", "SQL injection vulnerability in login form allows authentication bypass", map[string]any{
		"type":     "finding",
		"severity": "high",
	})
	require.NoError(t, err)

	// Clean up
	err = manager.Close()
	assert.NoError(t, err)
}

// TestMemoryIntegration_CrossTierOperations tests operations that span memory tiers.
func TestMemoryIntegration_CrossTierOperations(t *testing.T) {
	db, cleanup := setupIntegrationDB(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	// Scenario: Promote data from working memory to mission memory
	working := manager.Working()
	mission := manager.Mission()

	// Store temporary finding in working memory
	findingData := map[string]any{
		"type":     "potential-vuln",
		"severity": "unknown",
		"endpoint": "/api/test",
	}
	err = working.Set("temp-finding", findingData)
	require.NoError(t, err)

	// Retrieve from working memory
	tempValue, ok := working.Get("temp-finding")
	require.True(t, ok)

	// Promote to mission memory
	err = mission.Store(ctx, "confirmed-finding", tempValue, map[string]any{
		"promoted_from": "working",
	})
	require.NoError(t, err)

	// Remove from working memory
	deleted := working.Delete("temp-finding")
	assert.True(t, deleted)

	// Verify in mission memory
	item, err := mission.Retrieve(ctx, "confirmed-finding")
	require.NoError(t, err)
	assert.Equal(t, "confirmed-finding", item.Key)

	// Verify removed from working memory
	_, ok = working.Get("temp-finding")
	assert.False(t, ok)
}

// TestMemoryIntegration_MissionIsolation tests that multiple missions are isolated.
func TestMemoryIntegration_MissionIsolation(t *testing.T) {
	db, cleanup := setupIntegrationDB(t)
	defer cleanup()

	ctx := context.Background()
	mission1ID := types.NewID()
	mission2ID := types.NewID()

	manager1, err := NewMemoryManager(mission1ID, db, nil)
	require.NoError(t, err)
	defer manager1.Close()

	manager2, err := NewMemoryManager(mission2ID, db, nil)
	require.NoError(t, err)
	defer manager2.Close()

	// Store in mission 1
	err = manager1.Mission().Store(ctx, "shared-key", "mission1-data", nil)
	require.NoError(t, err)

	// Store in mission 2
	err = manager2.Mission().Store(ctx, "shared-key", "mission2-data", nil)
	require.NoError(t, err)

	// Verify isolation
	item1, err := manager1.Mission().Retrieve(ctx, "shared-key")
	require.NoError(t, err)
	assert.Equal(t, "mission1-data", item1.Value)

	item2, err := manager2.Mission().Retrieve(ctx, "shared-key")
	require.NoError(t, err)
	assert.Equal(t, "mission2-data", item2.Value)

	// Verify keys are isolated
	keys1, err := manager1.Mission().Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys1, 1)

	keys2, err := manager2.Mission().Keys(ctx)
	require.NoError(t, err)
	assert.Len(t, keys2, 1)
}

// TestMemoryIntegration_WorkingMemoryEviction tests token-based eviction.
func TestMemoryIntegration_WorkingMemoryEviction(t *testing.T) {
	db, cleanup := setupIntegrationDB(t)
	defer cleanup()

	missionID := types.NewID()

	// Create manager with small token budget
	// Each key-value pair is approximately 25-30 tokens, so 100 tokens can hold ~3 items
	config := &MemoryConfig{
		Working: WorkingMemoryConfig{
			MaxTokens:      100, // Very small - will force eviction with ~3 items
			EvictionPolicy: "lru",
		},
	}
	config.ApplyDefaults()

	manager, err := NewMemoryManager(missionID, db, config)
	require.NoError(t, err)
	defer manager.Close()

	working := manager.Working()

	// Fill up working memory with larger data values
	for i := 0; i < 10; i++ {
		err = working.Set("key-"+string(rune('A'+i)), "some data value that is fairly long to ensure token counting works")
		require.NoError(t, err)
	}

	// Verify token count is within budget
	tokenCount := working.TokenCount()
	assert.LessOrEqual(t, tokenCount, 100)

	// Verify some keys were evicted (10 items should not all fit in 100 tokens)
	keys := working.List()
	t.Logf("After eviction: %d keys remain, token count: %d", len(keys), tokenCount)
	assert.Less(t, len(keys), 10, "some keys should have been evicted")
}

// TestMemoryIntegration_LongTermMemoryWithMockEmbedder tests long-term memory with mock.
func TestMemoryIntegration_LongTermMemoryWithMockEmbedder(t *testing.T) {
	ctx := context.Background()

	// Create mock embedder and vector store
	mockEmbedder := embedder.NewMockEmbedder()
	mockStore := vector.NewEmbeddedVectorStore(1536)

	// Create long-term memory
	longTerm := NewLongTermMemory(mockStore, mockEmbedder)

	// Store findings
	err := longTerm.Store(ctx, "vuln-001", "SQL injection vulnerability found in login form", map[string]any{
		"type":     "finding",
		"severity": "high",
	})
	require.NoError(t, err)

	err = longTerm.Store(ctx, "vuln-002", "Cross-site scripting in user profile page", map[string]any{
		"type":     "finding",
		"severity": "medium",
	})
	require.NoError(t, err)

	// Search for similar content
	results, err := longTerm.Search(ctx, "SQL injection", 5, nil)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1)

	// Test SimilarFindings
	similarResults, err := longTerm.SimilarFindings(ctx, "login form vulnerability", 5)
	require.NoError(t, err)
	// Results depend on mock embedder - just verify no error

	// Delete
	err = longTerm.Delete(ctx, "vuln-001")
	require.NoError(t, err)

	// Health check
	health := longTerm.Health(ctx)
	assert.Equal(t, types.HealthStateHealthy, health.State)

	// Verify embedder was called
	calls := mockEmbedder.GetCalls()
	assert.Greater(t, len(calls), 0)
	_ = similarResults // silence unused variable if no assertions on it
}

// TestMemoryIntegration_FTSSearchAccuracy tests FTS5 search accuracy.
func TestMemoryIntegration_FTSSearchAccuracy(t *testing.T) {
	db, cleanup := setupIntegrationDB(t)
	defer cleanup()

	ctx := context.Background()
	missionID := types.NewID()

	manager, err := NewMemoryManager(missionID, db, nil)
	require.NoError(t, err)
	defer manager.Close()

	mission := manager.Mission()

	// Store various findings
	findings := []struct {
		key   string
		value string
	}{
		{"finding-sql-1", "SQL injection in user authentication endpoint"},
		{"finding-sql-2", "SQL error message disclosure in API response"},
		{"finding-xss-1", "Cross-site scripting vulnerability in search form"},
		{"finding-csrf-1", "CSRF token missing on admin panel"},
		{"finding-auth-1", "Weak password policy allows dictionary attacks"},
	}

	for _, f := range findings {
		err = mission.Store(ctx, f.key, f.value, nil)
		require.NoError(t, err)
	}

	// Search for SQL-related findings
	results, err := mission.Search(ctx, "SQL", 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 2)

	// Verify SQL findings are in results
	foundSQL := 0
	for _, r := range results {
		if r.Item.Key == "finding-sql-1" || r.Item.Key == "finding-sql-2" {
			foundSQL++
		}
	}
	assert.GreaterOrEqual(t, foundSQL, 1)

	// Search for cross-site scripting
	results, err = mission.Search(ctx, "cross-site scripting", 10)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(results), 1)

	// Search with no matches
	results, err = mission.Search(ctx, "nonexistentterm12345", 10)
	require.NoError(t, err)
	assert.Empty(t, results)
}
