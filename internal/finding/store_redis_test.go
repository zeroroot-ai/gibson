package finding

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/state"
	testutil "github.com/zero-day-ai/gibson/internal/testing"
	"github.com/zero-day-ai/gibson/internal/types"
)

// getTestStateClient creates a StateClient for testing.
// Set REDIS_URL env var to use a real Redis instance, otherwise tests will be skipped.
func getTestStateClient(t *testing.T) *state.StateClient {
	t.Helper()

	cfg := state.DefaultConfig()
	cfg.URL = "redis://localhost:6379/15" // Use DB 15 for tests

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Skipping Redis tests: %v", err)
		return nil
	}

	// Ensure indexes are created
	ctx := context.Background()
	if err := client.EnsureIndexes(ctx); err != nil {
		t.Skipf("Skipping Redis tests: failed to create indexes: %v", err)
		return nil
	}

	return client
}

// cleanupTestData removes all test data from Redis.
func cleanupTestData(t *testing.T, client *state.StateClient) {
	t.Helper()

	ctx := context.Background()
	rdb := client.Client()

	// Delete all test keys
	keys, err := rdb.Keys(ctx, "gibson:finding:*").Result()
	if err != nil {
		t.Logf("Warning: failed to list keys: %v", err)
		return
	}

	if len(keys) > 0 {
		if err := rdb.Del(ctx, keys...).Err(); err != nil {
			t.Logf("Warning: failed to delete keys: %v", err)
		}
	}
}

// createRedisTestFinding creates a test EnhancedFinding for Redis store tests.
func createRedisTestFinding(missionID types.ID, severity agent.FindingSeverity) EnhancedFinding {
	now := time.Now()
	return EnhancedFinding{
		Finding: agent.Finding{
			ID:          types.NewID(),
			Title:       "SQL Injection in Login Form",
			Description: "Found SQL injection vulnerability in user authentication endpoint",
			Severity:    severity,
			Category:    string(CategoryPromptInjection),
			Confidence:  0.95,
			CWE:         []string{"CWE-89"},
			CreatedAt:   now,
		},
		MissionID:       missionID,
		AgentName:       "sql-agent",
		Status:          StatusOpen,
		RiskScore:       8.5,
		Remediation:     "Use parameterized queries instead of string concatenation",
		References:      []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
		OccurrenceCount: 1,
		UpdatedAt:       now,
	}
}

func TestRedisFindingStore_Store(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("store new finding", func(t *testing.T) {
		missionID := types.NewID()
		finding := createRedisTestFinding(missionID, agent.SeverityCritical)

		err := store.Store(ctx, finding)
		require.NoError(t, err)

		// Verify finding can be retrieved
		retrieved, err := store.Get(ctx, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, finding.ID, retrieved.ID)
		assert.Equal(t, finding.Title, retrieved.Title)
		assert.Equal(t, finding.Severity, retrieved.Severity)

		// Verify secondary indexes
		count, err := store.Count(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		findings, err := store.ListBySeverity(ctx, agent.SeverityCritical)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, finding.ID, findings[0].ID)
	})

	t.Run("store duplicate finding", func(t *testing.T) {
		missionID := types.NewID()
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)

		// Store first time
		err := store.Store(ctx, finding)
		require.NoError(t, err)

		// Store again (should succeed, acts as update)
		finding.Title = "Updated Title"
		err = store.Store(ctx, finding)
		require.NoError(t, err)

		// Verify updated title
		retrieved, err := store.Get(ctx, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Title", retrieved.Title)

		// Verify count is still 1
		count, err := store.Count(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 1, count)
	})

	t.Run("store multiple findings for same mission", func(t *testing.T) {
		missionID := types.NewID()

		finding1 := createRedisTestFinding(missionID, agent.SeverityCritical)
		finding2 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding3 := createRedisTestFinding(missionID, agent.SeverityMedium)

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))
		require.NoError(t, store.Store(ctx, finding3))

		// Verify count
		count, err := store.Count(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 3, count)

		// Verify all can be listed
		findings, err := store.List(ctx, missionID, nil)
		require.NoError(t, err)
		assert.Len(t, findings, 3)
	})
}

func TestRedisFindingStore_Get(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("get existing finding", func(t *testing.T) {
		missionID := types.NewID()
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)

		err := store.Store(ctx, finding)
		require.NoError(t, err)

		retrieved, err := store.Get(ctx, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, finding.ID, retrieved.ID)
		assert.Equal(t, finding.Title, retrieved.Title)
		assert.Equal(t, finding.Description, retrieved.Description)
		assert.Equal(t, finding.Severity, retrieved.Severity)
		assert.Equal(t, finding.RiskScore, retrieved.RiskScore)
	})

	t.Run("get non-existent finding", func(t *testing.T) {
		nonExistentID := types.NewID()

		_, err := store.Get(ctx, nonExistentID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisFindingStore_List(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("list without filter", func(t *testing.T) {
		missionID := types.NewID()

		// Create test findings
		finding1 := createRedisTestFinding(missionID, agent.SeverityCritical)
		finding2 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding3 := createRedisTestFinding(missionID, agent.SeverityMedium)

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))
		require.NoError(t, store.Store(ctx, finding3))

		findings, err := store.List(ctx, missionID, nil)
		require.NoError(t, err)
		assert.Len(t, findings, 3)
	})

	t.Run("list with severity filter", func(t *testing.T) {
		missionID := types.NewID()

		// Create test findings
		finding1 := createRedisTestFinding(missionID, agent.SeverityCritical)
		finding2 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding3 := createRedisTestFinding(missionID, agent.SeverityCritical)

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))
		require.NoError(t, store.Store(ctx, finding3))

		// Filter by critical severity
		severity := agent.SeverityCritical
		filter := &FindingFilter{Severity: &severity}

		findings, err := store.List(ctx, missionID, filter)
		require.NoError(t, err)
		assert.Len(t, findings, 2)

		for _, f := range findings {
			assert.Equal(t, agent.SeverityCritical, f.Severity)
		}
	})

	t.Run("list with status filter", func(t *testing.T) {
		missionID := types.NewID()

		finding1 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding1.Status = StatusOpen

		finding2 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding2.Status = StatusConfirmed

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))

		// Filter by open status
		status := StatusOpen
		filter := &FindingFilter{Status: &status}

		findings, err := store.List(ctx, missionID, filter)
		require.NoError(t, err)
		assert.Len(t, findings, 1)
		assert.Equal(t, StatusOpen, findings[0].Status)
	})

	t.Run("list with risk range filter", func(t *testing.T) {
		missionID := types.NewID()

		finding1 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding1.RiskScore = 9.0

		finding2 := createRedisTestFinding(missionID, agent.SeverityMedium)
		finding2.RiskScore = 5.0

		finding3 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding3.RiskScore = 7.5

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))
		require.NoError(t, store.Store(ctx, finding3))

		// Filter by risk score >= 7.0
		minRisk := 7.0
		maxRisk := 10.0
		filter := &FindingFilter{MinRisk: &minRisk, MaxRisk: &maxRisk}

		findings, err := store.List(ctx, missionID, filter)
		require.NoError(t, err)
		assert.Len(t, findings, 2)

		for _, f := range findings {
			assert.GreaterOrEqual(t, f.RiskScore, 7.0)
			assert.LessOrEqual(t, f.RiskScore, 10.0)
		}
	})
}

func TestRedisFindingStore_Update(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("update finding fields", func(t *testing.T) {
		missionID := types.NewID()
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)

		err := store.Store(ctx, finding)
		require.NoError(t, err)

		// Update fields
		finding.Title = "Updated Title"
		finding.RiskScore = 9.5
		finding.Status = StatusConfirmed

		err = store.Update(ctx, finding)
		require.NoError(t, err)

		// Verify updates
		retrieved, err := store.Get(ctx, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated Title", retrieved.Title)
		assert.Equal(t, 9.5, retrieved.RiskScore)
		assert.Equal(t, StatusConfirmed, retrieved.Status)
	})

	t.Run("update severity maintains indexes", func(t *testing.T) {
		missionID := types.NewID()
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)

		err := store.Store(ctx, finding)
		require.NoError(t, err)

		// Verify in high severity index
		highFindings, err := store.ListBySeverity(ctx, agent.SeverityHigh)
		require.NoError(t, err)
		assert.Len(t, highFindings, 1)

		// Update severity to critical
		finding.Severity = agent.SeverityCritical
		err = store.Update(ctx, finding)
		require.NoError(t, err)

		// Verify moved to critical severity index
		criticalFindings, err := store.ListBySeverity(ctx, agent.SeverityCritical)
		require.NoError(t, err)
		assert.Len(t, criticalFindings, 1)

		// Verify removed from high severity index
		highFindings, err = store.ListBySeverity(ctx, agent.SeverityHigh)
		require.NoError(t, err)
		assert.Len(t, highFindings, 0)
	})

	t.Run("update non-existent finding", func(t *testing.T) {
		finding := createRedisTestFinding(types.NewID(), agent.SeverityHigh)

		err := store.Update(ctx, finding)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisFindingStore_Delete(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("delete existing finding", func(t *testing.T) {
		missionID := types.NewID()
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)

		err := store.Store(ctx, finding)
		require.NoError(t, err)

		// Verify exists
		_, err = store.Get(ctx, finding.ID)
		require.NoError(t, err)

		// Delete
		err = store.Delete(ctx, finding.ID)
		require.NoError(t, err)

		// Verify deleted
		_, err = store.Get(ctx, finding.ID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")

		// Verify removed from mission index
		count, err := store.Count(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 0, count)

		// Verify removed from severity index
		findings, err := store.ListBySeverity(ctx, agent.SeverityHigh)
		require.NoError(t, err)
		assert.Len(t, findings, 0)
	})

	t.Run("delete non-existent finding", func(t *testing.T) {
		nonExistentID := types.NewID()

		err := store.Delete(ctx, nonExistentID)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisFindingStore_Count(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("count findings for mission", func(t *testing.T) {
		missionID := types.NewID()

		// Initially zero
		count, err := store.Count(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 0, count)

		// Add findings
		for i := 0; i < 5; i++ {
			finding := createRedisTestFinding(missionID, agent.SeverityHigh)
			require.NoError(t, store.Store(ctx, finding))
		}

		// Count should be 5
		count, err = store.Count(ctx, missionID)
		require.NoError(t, err)
		assert.Equal(t, 5, count)
	})

	t.Run("count isolated by mission", func(t *testing.T) {
		mission1 := types.NewID()
		mission2 := types.NewID()

		// Add findings to mission 1
		for i := 0; i < 3; i++ {
			finding := createRedisTestFinding(mission1, agent.SeverityHigh)
			require.NoError(t, store.Store(ctx, finding))
		}

		// Add findings to mission 2
		for i := 0; i < 2; i++ {
			finding := createRedisTestFinding(mission2, agent.SeverityMedium)
			require.NoError(t, store.Store(ctx, finding))
		}

		// Verify counts are isolated
		count1, err := store.Count(ctx, mission1)
		require.NoError(t, err)
		assert.Equal(t, 3, count1)

		count2, err := store.Count(ctx, mission2)
		require.NoError(t, err)
		assert.Equal(t, 2, count2)
	})
}

func TestRedisFindingStore_ListBySeverity(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	t.Run("list by severity", func(t *testing.T) {
		missionID := types.NewID()

		// Create findings with different severities
		critical1 := createRedisTestFinding(missionID, agent.SeverityCritical)
		critical2 := createRedisTestFinding(missionID, agent.SeverityCritical)
		high := createRedisTestFinding(missionID, agent.SeverityHigh)
		medium := createRedisTestFinding(missionID, agent.SeverityMedium)

		require.NoError(t, store.Store(ctx, critical1))
		require.NoError(t, store.Store(ctx, critical2))
		require.NoError(t, store.Store(ctx, high))
		require.NoError(t, store.Store(ctx, medium))

		// List critical findings
		criticalFindings, err := store.ListBySeverity(ctx, agent.SeverityCritical)
		require.NoError(t, err)
		assert.Len(t, criticalFindings, 2)

		// List high findings
		highFindings, err := store.ListBySeverity(ctx, agent.SeverityHigh)
		require.NoError(t, err)
		assert.Len(t, highFindings, 1)

		// List low findings (none)
		lowFindings, err := store.ListBySeverity(ctx, agent.SeverityLow)
		require.NoError(t, err)
		assert.Len(t, lowFindings, 0)
	})
}

func TestRedisFindingStore_Search(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	// Wait for index to be ready
	time.Sleep(100 * time.Millisecond)

	t.Run("full-text search", func(t *testing.T) {
		missionID := types.NewID()

		// Create findings with distinct content
		finding1 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding1.Title = "SQL Injection Vulnerability"
		finding1.Description = "SQL injection found in login form"

		finding2 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding2.Title = "XSS Vulnerability"
		finding2.Description = "Cross-site scripting in user profile"

		finding3 := createRedisTestFinding(missionID, agent.SeverityMedium)
		finding3.Title = "SQL Stored Procedure Issue"
		finding3.Description = "Unsafe SQL stored procedure found"

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))
		require.NoError(t, store.Store(ctx, finding3))

		// Wait for indexing
		time.Sleep(200 * time.Millisecond)

		// Search for "SQL"
		opts := &state.SearchOptions{
			Limit:      10,
			Offset:     0,
			WithScores: true,
		}

		result, err := store.Search(ctx, "SQL", opts)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result.Documents), 2) // Should find at least 2 SQL-related findings
	})

	t.Run("search with tag filter", func(t *testing.T) {
		missionID := types.NewID()

		critical := createRedisTestFinding(missionID, agent.SeverityCritical)
		high := createRedisTestFinding(missionID, agent.SeverityHigh)

		require.NoError(t, store.Store(ctx, critical))
		require.NoError(t, store.Store(ctx, high))

		// Wait for indexing
		time.Sleep(200 * time.Millisecond)

		// Search for critical severity
		query := "@severity:{critical}"
		opts := &state.SearchOptions{Limit: 10}

		result, err := store.Search(ctx, query, opts)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result.Documents), 1)
	})

	t.Run("search with combined filters", func(t *testing.T) {
		missionID := types.NewID()

		finding := createRedisTestFinding(missionID, agent.SeverityCritical)
		finding.Title = "Authentication Bypass"
		finding.AgentName = "auth-tester"

		require.NoError(t, store.Store(ctx, finding))

		// Wait for indexing
		time.Sleep(200 * time.Millisecond)

		// Search with text and tag filters
		query := "authentication @severity:{critical}"
		opts := &state.SearchOptions{Limit: 10}

		result, err := store.Search(ctx, query, opts)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(result.Documents), 1)
	})
}

func TestRedisFindingStore_SearchWithFilter(t *testing.T) {
	client := getTestStateClient(t)
	if client == nil {
		return
	}
	defer client.Close()
	defer cleanupTestData(t, client)

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()

	// Wait for index to be ready
	time.Sleep(100 * time.Millisecond)

	t.Run("search with filter object", func(t *testing.T) {
		missionID := types.NewID()

		finding1 := createRedisTestFinding(missionID, agent.SeverityCritical)
		finding1.Title = "SQL Injection in API"
		finding1.Status = StatusOpen

		finding2 := createRedisTestFinding(missionID, agent.SeverityHigh)
		finding2.Title = "XSS in Dashboard"
		finding2.Status = StatusConfirmed

		require.NoError(t, store.Store(ctx, finding1))
		require.NoError(t, store.Store(ctx, finding2))

		// Wait for indexing
		time.Sleep(200 * time.Millisecond)

		// Search with filter
		severity := agent.SeverityCritical
		status := StatusOpen
		filter := &FindingFilter{
			Severity: &severity,
			Status:   &status,
		}

		opts := &state.SearchOptions{Limit: 10}
		findings, err := store.SearchWithFilter(ctx, "SQL", filter, opts)
		require.NoError(t, err)

		// Should find the critical/open SQL finding
		if len(findings) > 0 {
			assert.Equal(t, agent.SeverityCritical, findings[0].Severity)
			assert.Equal(t, StatusOpen, findings[0].Status)
		}
	})
}

func TestRedisFindingStore_KeyGeneration(t *testing.T) {
	store := NewRedisFindingStore(nil)

	t.Run("finding key format", func(t *testing.T) {
		id := types.NewID()
		key := store.findingKey(id)
		assert.Equal(t, fmt.Sprintf("gibson:finding:%s", id.String()), key)
	})

	t.Run("mission set key format", func(t *testing.T) {
		missionID := types.NewID()
		key := store.missionSetKey(missionID)
		assert.Equal(t, fmt.Sprintf("gibson:finding:by_mission:%s", missionID.String()), key)
	})

	t.Run("severity set key format", func(t *testing.T) {
		key := store.severitySetKey(agent.SeverityCritical)
		assert.Equal(t, "gibson:finding:by_severity:critical", key)
	})
}

func TestRedisFindingStore_FilterHelpers(t *testing.T) {
	store := NewRedisFindingStore(nil)

	t.Run("empty filter detection", func(t *testing.T) {
		emptyFilter := &FindingFilter{}
		assert.True(t, store.isEmptyFilter(emptyFilter))

		severity := agent.SeverityHigh
		nonEmptyFilter := &FindingFilter{Severity: &severity}
		assert.False(t, store.isEmptyFilter(nonEmptyFilter))
	})

	t.Run("structured query detection", func(t *testing.T) {
		assert.True(t, store.isStructuredQuery("@severity:{critical}"))
		assert.True(t, store.isStructuredQuery("@risk_score:[7.0 10.0]"))
		assert.False(t, store.isStructuredQuery("simple text query"))
	})

	t.Run("build filter clauses", func(t *testing.T) {
		severity := agent.SeverityCritical
		status := StatusOpen
		agentName := "test-agent"
		minRisk := 7.0
		maxRisk := 10.0

		filter := &FindingFilter{
			Severity:  &severity,
			Status:    &status,
			AgentName: &agentName,
			MinRisk:   &minRisk,
			MaxRisk:   &maxRisk,
		}

		clauses := store.buildFilterClauses(filter)
		assert.NotEmpty(t, clauses)
		assert.Contains(t, clauses, "@severity:{critical}")
		assert.Contains(t, clauses, "@status:{open}")
	})
}

// Benchmark tests for performance evaluation

func BenchmarkRedisFindingStore_Store(b *testing.B) {
	client := getTestStateClient(&testing.T{})
	if client == nil {
		b.Skip("Redis not available")
	}
	defer client.Close()

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()
	missionID := types.NewID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)
		_ = store.Store(ctx, finding)
	}
}

func BenchmarkRedisFindingStore_Get(b *testing.B) {
	client := getTestStateClient(&testing.T{})
	if client == nil {
		b.Skip("Redis not available")
	}
	defer client.Close()

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()
	missionID := types.NewID()

	// Prepare test data
	finding := createRedisTestFinding(missionID, agent.SeverityHigh)
	_ = store.Store(ctx, finding)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.Get(ctx, finding.ID)
	}
}

func BenchmarkRedisFindingStore_Search(b *testing.B) {
	client := getTestStateClient(&testing.T{})
	if client == nil {
		b.Skip("Redis not available")
	}
	defer client.Close()

	store := NewRedisFindingStore(client)
	ctx := testutil.WithTestTenant()
	missionID := types.NewID()

	// Prepare test data
	for i := 0; i < 100; i++ {
		finding := createRedisTestFinding(missionID, agent.SeverityHigh)
		_ = store.Store(ctx, finding)
	}

	time.Sleep(500 * time.Millisecond) // Wait for indexing

	opts := &state.SearchOptions{Limit: 20}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = store.Search(ctx, "SQL injection", opts)
	}
}
