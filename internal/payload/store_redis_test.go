package payload

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupRedisTestStore creates a test Redis store with a clean state.
// It requires a running Redis instance with RedisJSON and RediSearch modules.
func setupRedisTestStore(t *testing.T) (*RedisPayloadStore, context.Context, func()) {
	t.Helper()

	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379/15" // Use database 15 for tests
	cfg.Database = 15

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Redis not available or modules not loaded: %v", err)
		return nil, nil, nil
	}

	ctx := context.Background()

	// Ensure indexes are created
	if err := client.EnsureIndexes(ctx); err != nil {
		t.Skipf("Failed to create indexes: %v", err)
		return nil, nil, nil
	}

	store := NewRedisPayloadStore(client)

	// Cleanup function to flush the test database
	cleanup := func() {
		rdb := client.Client()
		rdb.FlushDB(ctx)
		client.Close()
	}

	return store, ctx, cleanup
}

func TestRedisPayloadStore_Save(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("saves payload successfully", func(t *testing.T) {
		payload := NewPayload("test-payload", "Test template {{param}}", CategoryJailbreak)
		payload.Description = "Test payload description"
		payload.Severity = agent.SeverityHigh
		payload.SuccessIndicators = []SuccessIndicator{
			{Type: IndicatorContains, Value: "success"},
		}

		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Verify payload was saved
		retrieved, err := store.Get(ctx, payload.ID)
		require.NoError(t, err)
		assert.Equal(t, payload.ID, retrieved.ID)
		assert.Equal(t, payload.Name, retrieved.Name)
		assert.Equal(t, payload.Description, retrieved.Description)
	})

	t.Run("creates version history", func(t *testing.T) {
		payload := NewPayload("versioned-payload", "Template", CategoryDataExtraction)
		payload.SuccessIndicators = []SuccessIndicator{
			{Type: IndicatorContains, Value: "test"},
		}

		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Check version history
		versions, err := store.GetVersionHistory(ctx, payload.ID)
		require.NoError(t, err)
		assert.Len(t, versions, 1)
		assert.Equal(t, "v1", versions[0].Version)
		assert.Equal(t, "created", versions[0].ChangeType)
	})

	t.Run("creates name lookup", func(t *testing.T) {
		payload := NewPayload("named-payload", "Template", CategoryPromptInjection)
		payload.SuccessIndicators = []SuccessIndicator{
			{Type: IndicatorContains, Value: "test"},
		}

		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Verify name lookup works
		retrieved, err := store.GetByName(ctx, "named-payload")
		require.NoError(t, err)
		assert.Equal(t, payload.ID, retrieved.ID)
	})

	t.Run("validates payload before save", func(t *testing.T) {
		payload := NewPayload("", "Template", CategoryJailbreak)
		payload.SuccessIndicators = []SuccessIndicator{
			{Type: IndicatorContains, Value: "test"},
		}

		err := store.Save(ctx, &payload)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "validation failed")
	})

	t.Run("rejects nil payload", func(t *testing.T) {
		err := store.Save(ctx, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cannot be nil")
	})
}

func TestRedisPayloadStore_Get(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("retrieves existing payload", func(t *testing.T) {
		payload := createRedisTestPayload("get-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, payload.ID)
		require.NoError(t, err)
		assert.Equal(t, payload.ID, retrieved.ID)
		assert.Equal(t, payload.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent payload", func(t *testing.T) {
		id := types.NewID()
		_, err := store.Get(ctx, id)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisPayloadStore_GetByName(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("retrieves payload by name", func(t *testing.T) {
		payload := createRedisTestPayload("name-lookup-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		retrieved, err := store.GetByName(ctx, "name-lookup-test")
		require.NoError(t, err)
		assert.Equal(t, payload.ID, retrieved.ID)
		assert.Equal(t, payload.Name, retrieved.Name)
	})

	t.Run("returns error for non-existent name", func(t *testing.T) {
		_, err := store.GetByName(ctx, "non-existent-payload")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisPayloadStore_List(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	// Create test payloads with different attributes
	payloads := []Payload{
		createRedisTestPayloadWithAttrs("list-1", CategoryJailbreak, agent.SeverityHigh, true, false),
		createRedisTestPayloadWithAttrs("list-2", CategoryPromptInjection, agent.SeverityMedium, true, true),
		createRedisTestPayloadWithAttrs("list-3", CategoryDataExtraction, agent.SeverityHigh, false, false),
		createRedisTestPayloadWithAttrs("list-4", CategoryJailbreak, agent.SeverityCritical, true, true),
	}

	for i := range payloads {
		err := store.Save(ctx, &payloads[i])
		require.NoError(t, err)
	}

	// Wait for indexes to update
	time.Sleep(100 * time.Millisecond)

	t.Run("lists all payloads with no filter", func(t *testing.T) {
		result, err := store.List(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result), 4)
	})

	t.Run("filters by category", func(t *testing.T) {
		filter := &PayloadFilter{
			Categories: []PayloadCategory{CategoryJailbreak},
			Limit:      100,
		}
		result, err := store.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result), 2) // list-1 and list-4
		for _, p := range result {
			assert.Contains(t, p.Categories, CategoryJailbreak)
		}
	})

	t.Run("filters by severity", func(t *testing.T) {
		filter := &PayloadFilter{
			Severities: []agent.FindingSeverity{agent.SeverityHigh},
			Limit:      100,
		}
		result, err := store.List(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result), 2) // list-1 and list-3
	})

	t.Run("filters by enabled", func(t *testing.T) {
		enabled := true
		filter := &PayloadFilter{
			Enabled: &enabled,
			Limit:   100,
		}
		result, err := store.List(ctx, filter)
		require.NoError(t, err)
		for _, p := range result {
			assert.True(t, p.Enabled)
		}
	})

	t.Run("filters by built_in", func(t *testing.T) {
		builtIn := true
		filter := &PayloadFilter{
			BuiltIn: &builtIn,
			Limit:   100,
		}
		result, err := store.List(ctx, filter)
		require.NoError(t, err)
		for _, p := range result {
			assert.True(t, p.BuiltIn)
		}
	})

	t.Run("respects pagination", func(t *testing.T) {
		filter := &PayloadFilter{
			Limit:  2,
			Offset: 0,
		}
		result, err := store.List(ctx, filter)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(result), 2)
	})
}

func TestRedisPayloadStore_Search(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	// Create test payloads with searchable content
	payloads := []Payload{
		createRedisTestPayload("sql-injection"),
		createRedisTestPayload("xss-attack"),
		createRedisTestPayload("jailbreak-attempt"),
	}
	payloads[0].Description = "SQL injection payload for database testing"
	payloads[1].Description = "Cross-site scripting attack vector"
	payloads[2].Description = "Jailbreak prompt for LLM testing"

	for i := range payloads {
		err := store.Save(ctx, &payloads[i])
		require.NoError(t, err)
	}

	// Wait for indexes to update
	time.Sleep(100 * time.Millisecond)

	t.Run("full-text search on description", func(t *testing.T) {
		result, err := store.Search(ctx, "SQL database", nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result), 1)
	})

	t.Run("search with filter", func(t *testing.T) {
		filter := &PayloadFilter{
			Categories: []PayloadCategory{CategoryJailbreak},
			Limit:      100,
		}
		result, err := store.Search(ctx, "jailbreak", filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result), 1)
	})

	t.Run("empty search query returns all", func(t *testing.T) {
		result, err := store.Search(ctx, "", nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result), 3)
	})
}

func TestRedisPayloadStore_Update(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("updates payload successfully", func(t *testing.T) {
		payload := createRedisTestPayload("update-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Update payload
		payload.Description = "Updated description"
		payload.Severity = agent.SeverityCritical
		err = store.Update(ctx, &payload)
		require.NoError(t, err)

		// Verify update
		retrieved, err := store.Get(ctx, payload.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated description", retrieved.Description)
		assert.Equal(t, agent.SeverityCritical, retrieved.Severity)
	})

	t.Run("creates version snapshot", func(t *testing.T) {
		payload := createRedisTestPayload("version-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Update payload
		payload.Description = "First update"
		err = store.Update(ctx, &payload)
		require.NoError(t, err)

		// Check version history
		versions, err := store.GetVersionHistory(ctx, payload.ID)
		require.NoError(t, err)
		assert.Len(t, versions, 2)
		assert.Equal(t, "v2", versions[0].Version) // Most recent first
		assert.Equal(t, "v1", versions[1].Version)
	})

	t.Run("updates name lookup on name change", func(t *testing.T) {
		payload := createRedisTestPayload("original-name")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Update name
		payload.Name = "new-name"
		err = store.Update(ctx, &payload)
		require.NoError(t, err)

		// Old name should not work
		_, err = store.GetByName(ctx, "original-name")
		assert.Error(t, err)

		// New name should work
		retrieved, err := store.GetByName(ctx, "new-name")
		require.NoError(t, err)
		assert.Equal(t, payload.ID, retrieved.ID)
	})

	t.Run("returns error for non-existent payload", func(t *testing.T) {
		payload := createRedisTestPayload("non-existent")
		payload.ID = types.NewID() // New ID that doesn't exist
		err := store.Update(ctx, &payload)
		assert.Error(t, err)
	})
}

func TestRedisPayloadStore_Delete(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("soft deletes payload", func(t *testing.T) {
		payload := createRedisTestPayload("delete-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Delete payload
		err = store.Delete(ctx, payload.ID)
		require.NoError(t, err)

		// Payload should still exist but be disabled
		retrieved, err := store.Get(ctx, payload.ID)
		require.NoError(t, err)
		assert.False(t, retrieved.Enabled)
	})

	t.Run("returns error for non-existent payload", func(t *testing.T) {
		id := types.NewID()
		err := store.Delete(ctx, id)
		assert.Error(t, err)
	})
}

func TestRedisPayloadStore_HardDelete(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("permanently deletes payload", func(t *testing.T) {
		payload := createRedisTestPayload("hard-delete-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Hard delete payload
		err = store.HardDelete(ctx, payload.ID)
		require.NoError(t, err)

		// Payload should not exist
		_, err = store.Get(ctx, payload.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		// Name lookup should be gone
		_, err = store.GetByName(ctx, payload.Name)
		assert.Error(t, err)

		// Version history should be gone
		versions, err := store.GetVersionHistory(ctx, payload.ID)
		require.NoError(t, err)
		assert.Len(t, versions, 0)
	})
}

func TestRedisPayloadStore_GetVersionHistory(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("returns version history in reverse order", func(t *testing.T) {
		payload := createRedisTestPayload("version-history-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		// Make several updates
		for i := 1; i <= 3; i++ {
			payload.Description = fmt.Sprintf("Update %d", i)
			err = store.Update(ctx, &payload)
			require.NoError(t, err)
		}

		// Get version history
		versions, err := store.GetVersionHistory(ctx, payload.ID)
		require.NoError(t, err)
		assert.Len(t, versions, 4) // v1 (created) + 3 updates (v2, v3, v4)

		// Verify order (most recent first)
		assert.Equal(t, "v4", versions[0].Version)
		assert.Equal(t, "v3", versions[1].Version)
		assert.Equal(t, "v2", versions[2].Version)
		assert.Equal(t, "v1", versions[3].Version)
	})

	t.Run("returns empty for non-existent payload", func(t *testing.T) {
		id := types.NewID()
		versions, err := store.GetVersionHistory(ctx, id)
		require.NoError(t, err)
		assert.Len(t, versions, 0)
	})
}

func TestRedisPayloadStore_Exists(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("returns true for existing payload", func(t *testing.T) {
		payload := createRedisTestPayload("exists-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		exists, err := store.Exists(ctx, payload.ID)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent payload", func(t *testing.T) {
		id := types.NewID()
		exists, err := store.Exists(ctx, id)
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestRedisPayloadStore_ExistsByName(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("returns true for existing name", func(t *testing.T) {
		payload := createRedisTestPayload("name-exists-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		exists, err := store.ExistsByName(ctx, "name-exists-test")
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("returns false for non-existent name", func(t *testing.T) {
		exists, err := store.ExistsByName(ctx, "non-existent-name")
		require.NoError(t, err)
		assert.False(t, exists)
	})
}

func TestRedisPayloadStore_Count(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	// Create test payloads
	for i := 0; i < 5; i++ {
		payload := createRedisTestPayload(fmt.Sprintf("count-test-%d", i))
		err := store.Save(ctx, &payload)
		require.NoError(t, err)
	}

	// Wait for indexes to update
	time.Sleep(100 * time.Millisecond)

	t.Run("counts all payloads", func(t *testing.T) {
		count, err := store.Count(ctx, nil)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, 5)
	})

	t.Run("counts with filter", func(t *testing.T) {
		enabled := true
		filter := &PayloadFilter{
			Enabled: &enabled,
		}
		count, err := store.Count(ctx, filter)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, count, 5)
	})
}

func TestRedisPayloadStore_ImportBatch(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("imports valid payloads", func(t *testing.T) {
		payloads := []*Payload{
			createRedisTestPayloadPtr("import-1"),
			createRedisTestPayloadPtr("import-2"),
			createRedisTestPayloadPtr("import-3"),
		}

		result, err := store.ImportBatch(ctx, payloads)
		require.NoError(t, err)
		assert.Equal(t, 3, result.Total)
		assert.Equal(t, 3, result.Imported)
		assert.Equal(t, 0, result.Failed)
		assert.Equal(t, 0, result.Skipped)
	})

	t.Run("skips duplicates", func(t *testing.T) {
		payload := createRedisTestPayload("duplicate-test")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		payloads := []*Payload{&payload}
		result, err := store.ImportBatch(ctx, payloads)
		require.NoError(t, err)
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, 0, result.Imported)
		assert.Equal(t, 1, result.Skipped)
	})

	t.Run("handles validation errors", func(t *testing.T) {
		invalid := createRedisTestPayload("")
		payloads := []*Payload{&invalid}

		result, err := store.ImportBatch(ctx, payloads)
		require.NoError(t, err)
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, 0, result.Imported)
		assert.Equal(t, 1, result.Failed)
	})
}

func TestRedisPayloadStore_Chains(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("creates and retrieves chain", func(t *testing.T) {
		payload := createRedisTestPayload("chain-payload")
		err := store.Save(ctx, &payload)
		require.NoError(t, err)

		chain := &PayloadChain{
			ID:          types.NewID(),
			Name:        "Test Chain",
			Description: "A test attack chain",
			Steps: []ChainStep{
				{
					ID:        "step1",
					PayloadID: payload.ID,
					OnSuccess: StepActionContinue,
					OnFailure: StepActionAbort,
				},
			},
		}

		err = store.CreateChain(ctx, chain)
		require.NoError(t, err)

		retrieved, err := store.GetChain(ctx, chain.ID)
		require.NoError(t, err)
		assert.Equal(t, chain.ID, retrieved.ID)
		assert.Equal(t, chain.Name, retrieved.Name)
		assert.Len(t, retrieved.Steps, 1)
	})

	t.Run("lists all chains", func(t *testing.T) {
		// Create a few chains
		for i := 0; i < 3; i++ {
			chain := &PayloadChain{
				ID:          types.NewID(),
				Name:        fmt.Sprintf("Chain %d", i),
				Description: "Test chain",
				Steps:       []ChainStep{},
			}
			err := store.CreateChain(ctx, chain)
			require.NoError(t, err)
		}

		chains, err := store.ListChains(ctx)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(chains), 3)
	})

	t.Run("updates chain", func(t *testing.T) {
		chain := &PayloadChain{
			ID:          types.NewID(),
			Name:        "Original Name",
			Description: "Original description",
			Steps:       []ChainStep{},
		}
		err := store.CreateChain(ctx, chain)
		require.NoError(t, err)

		chain.Name = "Updated Name"
		chain.Description = "Updated description"
		err = store.UpdateChain(ctx, chain)
		require.NoError(t, err)

		retrieved, err := store.GetChain(ctx, chain.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Name", retrieved.Name)
		assert.Equal(t, "Updated description", retrieved.Description)
	})

	t.Run("deletes chain", func(t *testing.T) {
		chain := &PayloadChain{
			ID:          types.NewID(),
			Name:        "Delete Me",
			Description: "This chain will be deleted",
			Steps:       []ChainStep{},
		}
		err := store.CreateChain(ctx, chain)
		require.NoError(t, err)

		err = store.DeleteChain(ctx, chain.ID)
		require.NoError(t, err)

		_, err = store.GetChain(ctx, chain.ID)
		assert.Error(t, err)
	})
}

func TestRedisPayloadStore_Executions(t *testing.T) {
	store, ctx, cleanup := setupRedisTestStore(t)
	if store == nil {
		return
	}
	defer cleanup()

	t.Run("saves and retrieves execution", func(t *testing.T) {
		execution := &Execution{
			ID:        types.NewID(),
			PayloadID: types.NewID(),
			TargetID:  types.NewID(),
			AgentID:   types.NewID(),
			Status:    ExecutionStatusCompleted,
			Success:   true,
			CreatedAt: time.Now(),
		}

		err := store.SaveExecution(ctx, execution)
		require.NoError(t, err)

		retrieved, err := store.GetExecution(ctx, execution.ID)
		require.NoError(t, err)
		assert.Equal(t, execution.ID, retrieved.ID)
		assert.Equal(t, execution.Status, retrieved.Status)
		assert.True(t, retrieved.Success)
	})

	t.Run("lists executions by payload", func(t *testing.T) {
		payloadID := types.NewID()

		// Create multiple executions for the same payload
		for i := 0; i < 3; i++ {
			execution := &Execution{
				ID:        types.NewID(),
				PayloadID: payloadID,
				TargetID:  types.NewID(),
				AgentID:   types.NewID(),
				Status:    ExecutionStatusCompleted,
				CreatedAt: time.Now(),
			}
			err := store.SaveExecution(ctx, execution)
			require.NoError(t, err)
		}

		executions, err := store.ListExecutionsByPayload(ctx, payloadID, 10)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(executions), 3)
		for _, exec := range executions {
			assert.Equal(t, payloadID, exec.PayloadID)
		}
	})
}

// Helper functions for Redis tests

func createRedisTestPayload(name string) Payload {
	payload := NewPayload(name, "Test template", CategoryJailbreak)
	payload.Description = "Test payload"
	payload.Severity = agent.SeverityMedium
	payload.SuccessIndicators = []SuccessIndicator{
		{Type: IndicatorContains, Value: "success"},
	}
	return payload
}

func createRedisTestPayloadPtr(name string) *Payload {
	p := createRedisTestPayload(name)
	return &p
}

func createRedisTestPayloadWithAttrs(name string, category PayloadCategory, severity agent.FindingSeverity, enabled, builtIn bool) Payload {
	payload := NewPayload(name, "Test template", category)
	payload.Description = "Test payload with attributes"
	payload.Severity = severity
	payload.Enabled = enabled
	payload.BuiltIn = builtIn
	payload.SuccessIndicators = []SuccessIndicator{
		{Type: IndicatorContains, Value: "test"},
	}
	return payload
}
