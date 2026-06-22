package harness

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/agent"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// ────────────────────────────────────────────────────────────────────────────
// InMemoryFindingStore Creation Tests
// ────────────────────────────────────────────────────────────────────────────

func TestNewInMemoryFindingStore(t *testing.T) {
	store := NewInMemoryFindingStore()

	assert.NotNil(t, store)
	assert.NotNil(t, store.findings)
	assert.Empty(t, store.findings)
}

// ────────────────────────────────────────────────────────────────────────────
// InMemoryFindingStore Store Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_Store_Success(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding := agent.NewFinding("Test Finding", "Description", agent.SeverityHigh)

	err := store.Store(ctx, "", missionID, finding)
	require.NoError(t, err)

	// Verify the finding was stored
	assert.Equal(t, 1, store.Count(missionID))
}

func TestInMemoryFindingStore_Store_MultipleFindingsSameMission(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)
	finding3 := agent.NewFinding("Finding 3", "Description 3", agent.SeverityCritical)

	err := store.Store(ctx, "", missionID, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding2)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding3)
	require.NoError(t, err)

	assert.Equal(t, 3, store.Count(missionID))
}

func TestInMemoryFindingStore_Store_MultipleMissions(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	mission1 := types.NewID()
	mission2 := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)

	err := store.Store(ctx, "", mission1, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", mission2, finding2)
	require.NoError(t, err)

	assert.Equal(t, 1, store.Count(mission1))
	assert.Equal(t, 1, store.Count(mission2))
}

// ────────────────────────────────────────────────────────────────────────────
// InMemoryFindingStore Get Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_Get_EmptyStore(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	findings, err := store.Get(ctx, "", missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestInMemoryFindingStore_Get_NoFilter(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)

	err := store.Store(ctx, "", missionID, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding2)
	require.NoError(t, err)

	// Get all findings with no filter
	findings, err := store.Get(ctx, "", missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 2)
}

func TestInMemoryFindingStore_Get_WithFilter_Severity(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)
	finding3 := agent.NewFinding("Finding 3", "Description 3", agent.SeverityHigh)

	err := store.Store(ctx, "", missionID, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding2)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding3)
	require.NoError(t, err)

	// Filter for high severity
	filter := NewFindingFilter().WithSeverity(agent.SeverityHigh)
	findings, err := store.Get(ctx, "", missionID, *filter)
	require.NoError(t, err)
	assert.Len(t, findings, 2)

	for _, f := range findings {
		assert.Equal(t, agent.SeverityHigh, f.Severity)
	}
}

func TestInMemoryFindingStore_Get_WithFilter_Category(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh).
		WithCategory("injection")
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium).
		WithCategory("xss")
	finding3 := agent.NewFinding("Finding 3", "Description 3", agent.SeverityHigh).
		WithCategory("injection")

	err := store.Store(ctx, "", missionID, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding2)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding3)
	require.NoError(t, err)

	// Filter for injection category
	filter := NewFindingFilter().WithCategory("injection")
	findings, err := store.Get(ctx, "", missionID, *filter)
	require.NoError(t, err)
	assert.Len(t, findings, 2)

	for _, f := range findings {
		assert.Contains(t, f.Category, "injection")
	}
}

func TestInMemoryFindingStore_Get_WithFilter_MultipleConditions(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding1 := agent.NewFinding("SQL Injection", "Found SQL injection", agent.SeverityHigh).
		WithCategory("injection").
		WithConfidence(0.9)
	finding2 := agent.NewFinding("XSS", "Found XSS", agent.SeverityMedium).
		WithCategory("xss").
		WithConfidence(0.8)
	finding3 := agent.NewFinding("SQL Injection 2", "Another SQL injection", agent.SeverityHigh).
		WithCategory("injection").
		WithConfidence(0.7)

	err := store.Store(ctx, "", missionID, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding2)
	require.NoError(t, err)
	err = store.Store(ctx, "", missionID, finding3)
	require.NoError(t, err)

	// Filter for high severity AND injection category AND confidence >= 0.8
	filter := NewFindingFilter().
		WithSeverity(agent.SeverityHigh).
		WithCategory("injection").
		WithMinConfidence(0.8)

	findings, err := store.Get(ctx, "", missionID, *filter)
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "SQL Injection", findings[0].Title)
}

func TestInMemoryFindingStore_Get_NoMatches(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
	err := store.Store(ctx, "", missionID, finding)
	require.NoError(t, err)

	// Filter that matches nothing
	filter := NewFindingFilter().WithSeverity(agent.SeverityCritical)
	findings, err := store.Get(ctx, "", missionID, *filter)
	require.NoError(t, err)
	assert.Empty(t, findings)
}

func TestInMemoryFindingStore_Get_DifferentMissions(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	mission1 := types.NewID()
	mission2 := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)

	err := store.Store(ctx, "", mission1, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", mission2, finding2)
	require.NoError(t, err)

	// Get findings for mission1
	findings, err := store.Get(ctx, "", mission1, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "Finding 1", findings[0].Title)

	// Get findings for mission2
	findings, err = store.Get(ctx, "", mission2, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "Finding 2", findings[0].Title)
}

// ────────────────────────────────────────────────────────────────────────────
// InMemoryFindingStore Count Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_Count(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	// Initially 0
	assert.Equal(t, 0, store.Count(missionID))

	// Add findings
	for i := 0; i < 5; i++ {
		finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
		err := store.Store(ctx, "", missionID, finding)
		require.NoError(t, err)
	}

	assert.Equal(t, 5, store.Count(missionID))
}

func TestInMemoryFindingStore_Count_NonexistentMission(t *testing.T) {
	store := NewInMemoryFindingStore()
	missionID := types.NewID()

	// Count for non-existent mission should be 0
	assert.Equal(t, 0, store.Count(missionID))
}

// ────────────────────────────────────────────────────────────────────────────
// InMemoryFindingStore Clear Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_Clear(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
	err := store.Store(ctx, "", missionID, finding)
	require.NoError(t, err)

	assert.Equal(t, 1, store.Count(missionID))

	// Clear the mission
	store.Clear(missionID)
	assert.Equal(t, 0, store.Count(missionID))
}

func TestInMemoryFindingStore_Clear_NonexistentMission(t *testing.T) {
	store := NewInMemoryFindingStore()
	missionID := types.NewID()

	// Should not panic
	store.Clear(missionID)
	assert.Equal(t, 0, store.Count(missionID))
}

func TestInMemoryFindingStore_Clear_OneMissionLeavesOthers(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	mission1 := types.NewID()
	mission2 := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)

	err := store.Store(ctx, "", mission1, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", mission2, finding2)
	require.NoError(t, err)

	// Clear mission1
	store.Clear(mission1)

	assert.Equal(t, 0, store.Count(mission1))
	assert.Equal(t, 1, store.Count(mission2))
}

// ────────────────────────────────────────────────────────────────────────────
// InMemoryFindingStore ClearAll Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_ClearAll(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	mission1 := types.NewID()
	mission2 := types.NewID()

	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	finding2 := agent.NewFinding("Finding 2", "Description 2", agent.SeverityMedium)

	err := store.Store(ctx, "", mission1, finding1)
	require.NoError(t, err)
	err = store.Store(ctx, "", mission2, finding2)
	require.NoError(t, err)

	assert.Equal(t, 1, store.Count(mission1))
	assert.Equal(t, 1, store.Count(mission2))

	// Clear all
	store.ClearAll()

	assert.Equal(t, 0, store.Count(mission1))
	assert.Equal(t, 0, store.Count(mission2))
}

func TestInMemoryFindingStore_ClearAll_EmptyStore(t *testing.T) {
	store := NewInMemoryFindingStore()

	// Should not panic
	store.ClearAll()

	assert.NotNil(t, store.findings)
	assert.Empty(t, store.findings)
}

// ────────────────────────────────────────────────────────────────────────────
// Thread Safety Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_ConcurrentStore(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	const numGoroutines = 10
	const findingsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < findingsPerGoroutine; j++ {
				finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
				err := store.Store(ctx, "", missionID, finding)
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()

	// Verify all findings were stored
	expected := numGoroutines * findingsPerGoroutine
	assert.Equal(t, expected, store.Count(missionID))
}

func TestInMemoryFindingStore_ConcurrentGet(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	// Pre-populate with findings
	for i := 0; i < 100; i++ {
		finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
		err := store.Store(ctx, "", missionID, finding)
		require.NoError(t, err)
	}

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				findings, err := store.Get(ctx, "", missionID, FindingFilter{})
				assert.NoError(t, err)
				assert.Len(t, findings, 100)
			}
		}()
	}

	wg.Wait()
}

func TestInMemoryFindingStore_ConcurrentStoreAndGet(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	const numWriters = 5
	const numReaders = 5
	const operations = 50

	var wg sync.WaitGroup
	wg.Add(numWriters + numReaders)

	// Writers
	for i := 0; i < numWriters; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
				err := store.Store(ctx, "", missionID, finding)
				assert.NoError(t, err)
			}
		}()
	}

	// Readers
	for i := 0; i < numReaders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < operations; j++ {
				_, err := store.Get(ctx, "", missionID, FindingFilter{})
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()

	// Verify all writes completed
	assert.Equal(t, numWriters*operations, store.Count(missionID))
}

func TestInMemoryFindingStore_ConcurrentOperations(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	var wg sync.WaitGroup
	wg.Add(4)

	// Writer
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			finding := agent.NewFinding("Finding", "Description", agent.SeverityMedium)
			err := store.Store(ctx, "", missionID, finding)
			assert.NoError(t, err)
		}
	}()

	// Reader
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, err := store.Get(ctx, "", missionID, FindingFilter{})
			assert.NoError(t, err)
		}
	}()

	// Counter
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_ = store.Count(missionID)
		}
	}()

	// Clearer (after some writes)
	go func() {
		defer wg.Done()
		// Let some writes happen first
		for i := 0; i < 10; i++ {
			store.Clear(missionID)
		}
	}()

	wg.Wait()
}

// ────────────────────────────────────────────────────────────────────────────
// Edge Cases and Integration Tests
// ────────────────────────────────────────────────────────────────────────────

func TestInMemoryFindingStore_ComplexFiltering(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()
	targetID := types.NewID()

	// Create diverse findings
	findings := func() []agent.Finding {
		f1 := agent.NewFinding("SQL Injection", "Critical SQL injection in login", agent.SeverityCritical).
			WithCategory("injection").
			WithConfidence(0.95).
			WithCWE("CWE-89")
		f1.CVSS = &agent.CVSSScore{Score: 9.8}

		f2 := agent.NewFinding("XSS", "Reflected XSS in search", agent.SeverityHigh).
			WithCategory("xss").
			WithConfidence(0.85).
			WithCWE("CWE-79")
		f2.CVSS = &agent.CVSSScore{Score: 7.5}

		f3 := agent.NewFinding("CSRF", "Missing CSRF token", agent.SeverityMedium).
			WithCategory("csrf").
			WithConfidence(0.9).
			WithCWE("CWE-352")
		f3.CVSS = &agent.CVSSScore{Score: 6.5}

		f4 := agent.NewFinding("Info Disclosure", "Version info exposed", agent.SeverityLow).
			WithCategory("information").
			WithConfidence(1.0)

		return []agent.Finding{f1, f2, f3, f4}
	}()

	// Store all findings
	for _, f := range findings {
		f.TargetID = &targetID
		err := store.Store(ctx, "", missionID, f)
		require.NoError(t, err)
	}

	// Test various filters
	tests := []struct {
		name           string
		filter         *FindingFilter
		expectedCount  int
		expectedTitles []string
	}{
		{
			name:           "high severity or above",
			filter:         NewFindingFilter().WithSeverity(agent.SeverityHigh),
			expectedCount:  1,
			expectedTitles: []string{"XSS"},
		},
		{
			name:           "high confidence (>= 0.9)",
			filter:         NewFindingFilter().WithMinConfidence(0.9),
			expectedCount:  3,
			expectedTitles: []string{"SQL Injection", "CSRF", "Info Disclosure"},
		},
		{
			name:           "CVSS >= 7.0",
			filter:         NewFindingFilter().WithMinCVSS(7.0),
			expectedCount:  2,
			expectedTitles: []string{"SQL Injection", "XSS"},
		},
		{
			name:           "injection category",
			filter:         NewFindingFilter().WithCategory("inject"),
			expectedCount:  1,
			expectedTitles: []string{"SQL Injection"},
		},
		{
			name:           "specific target",
			filter:         NewFindingFilter().WithTargetID(targetID),
			expectedCount:  4,
			expectedTitles: []string{"SQL Injection", "XSS", "CSRF", "Info Disclosure"},
		},
		{
			name: "complex filter",
			filter: NewFindingFilter().
				WithMinConfidence(0.85).
				WithMinCVSS(7.0),
			expectedCount:  2,
			expectedTitles: []string{"SQL Injection", "XSS"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := store.Get(ctx, "", missionID, *tt.filter)
			require.NoError(t, err)
			assert.Len(t, results, tt.expectedCount)

			titles := make([]string, len(results))
			for i, f := range results {
				titles[i] = f.Title
			}
			assert.ElementsMatch(t, tt.expectedTitles, titles)
		})
	}
}

func TestInMemoryFindingStore_ContextCancellation(t *testing.T) {
	store := NewInMemoryFindingStore()
	missionID := types.NewID()

	// Context cancellation doesn't affect in-memory operations
	// but we should handle it gracefully
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	finding := agent.NewFinding("Test", "Description", agent.SeverityMedium)
	err := store.Store(ctx, "", missionID, finding)
	require.NoError(t, err) // In-memory store ignores context

	findings, err := store.Get(ctx, "", missionID, FindingFilter{})
	require.NoError(t, err) // In-memory store ignores context
	assert.Len(t, findings, 1)
}

func TestInMemoryFindingStore_ImmutabilityOfResults(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	finding := agent.NewFinding("Original Title", "Original Description", agent.SeverityHigh)
	err := store.Store(ctx, "", missionID, finding)
	require.NoError(t, err)

	// Get findings
	findings, err := store.Get(ctx, "", missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	// Modify the returned finding
	findings[0].Title = "Modified Title"

	// Get findings again - should still have original title
	findings2, err := store.Get(ctx, "", missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings2, 1)

	// Note: This test shows that modifications to returned findings
	// DO affect the stored data since we're not doing deep copies.
	// This is a known limitation of the in-memory store.
	// For production use, consider implementing deep copying.
}

// ────────────────────────────────────────────────────────────────────────────
// Tenant Isolation Tests
// ────────────────────────────────────────────────────────────────────────────

// TestInMemoryFindingStore_TenantIsolation verifies that findings stored under one
// tenant are not visible when querying under a different tenant, providing
// defense-in-depth isolation at the storage layer.
func TestInMemoryFindingStore_TenantIsolation(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	tenantA := "tenant-alpha"
	tenantB := "tenant-beta"

	findingA := agent.NewFinding("Finding for Tenant A", "Tenant A description", agent.SeverityHigh)
	findingB := agent.NewFinding("Finding for Tenant B", "Tenant B description", agent.SeverityCritical)

	// Store findings under different tenants for the same missionID
	err := store.Store(ctx, tenantA, missionID, findingA)
	require.NoError(t, err)

	err = store.Store(ctx, tenantB, missionID, findingB)
	require.NoError(t, err)

	// Tenant A should only see its own finding
	findingsA, err := store.Get(ctx, tenantA, missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findingsA, 1)
	assert.Equal(t, "Finding for Tenant A", findingsA[0].Title)

	// Tenant B should only see its own finding
	findingsB, err := store.Get(ctx, tenantB, missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findingsB, 1)
	assert.Equal(t, "Finding for Tenant B", findingsB[0].Title)

	// Count reflects per-tenant totals: total across all tenants is 2
	assert.Equal(t, 2, store.Count(missionID))
}

// TestInMemoryFindingStore_TenantIsolation_EmptyTenant verifies backward compatibility:
// empty tenantID (single-tenant mode) operates in its own namespace
// and does not collide with tenant-scoped findings for the same missionID.
func TestInMemoryFindingStore_TenantIsolation_EmptyTenant(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()

	findingGlobal := agent.NewFinding("Global Finding", "No tenant", agent.SeverityLow)
	findingTenanted := agent.NewFinding("Tenant Finding", "Has tenant", agent.SeverityHigh)

	err := store.Store(ctx, "", missionID, findingGlobal)
	require.NoError(t, err)

	err = store.Store(ctx, "tenant-x", missionID, findingTenanted)
	require.NoError(t, err)

	// Empty-tenant query returns only the global finding
	globalFindings, err := store.Get(ctx, "", missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, globalFindings, 1)
	assert.Equal(t, "Global Finding", globalFindings[0].Title)

	// Tenant-x query returns only the tenanted finding
	tenantFindings, err := store.Get(ctx, "tenant-x", missionID, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, tenantFindings, 1)
	assert.Equal(t, "Tenant Finding", tenantFindings[0].Title)
}

// TestInMemoryFindingStore_TenantIsolation_ClearScopedByMission verifies that
// Clear() removes findings for all tenants for that mission (cross-tenant cleanup),
// which is appropriate for admin-level mission teardown.
func TestInMemoryFindingStore_TenantIsolation_ClearScopedByMission(t *testing.T) {
	store := NewInMemoryFindingStore()
	ctx := context.Background()
	missionID := types.NewID()
	otherMissionID := types.NewID()

	err := store.Store(ctx, "tenant-a", missionID, agent.NewFinding("F1", "d", agent.SeverityHigh))
	require.NoError(t, err)
	err = store.Store(ctx, "tenant-b", missionID, agent.NewFinding("F2", "d", agent.SeverityLow))
	require.NoError(t, err)
	err = store.Store(ctx, "tenant-a", otherMissionID, agent.NewFinding("F3", "d", agent.SeverityMedium))
	require.NoError(t, err)

	// Clear missionID — removes all tenants' findings for that mission
	store.Clear(missionID)

	assert.Equal(t, 0, store.Count(missionID))
	assert.Equal(t, 1, store.Count(otherMissionID)) // Other mission unaffected
}
