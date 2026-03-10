package finding

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupTestAnalytics creates an in-memory store and analytics instance
func setupTestAnalytics(t *testing.T) (*FindingAnalytics, *InMemoryFindingStore, types.ID) {
	t.Helper()

	// Create in-memory store and analytics
	store := NewInMemoryFindingStore()
	analytics := NewFindingAnalytics(store)

	// Create test mission ID
	missionID := types.NewID()

	return analytics, store, missionID
}

// createTestFinding creates a test finding with specified attributes
func createTestFinding(missionID types.ID, severity agent.FindingSeverity, category FindingCategory, status FindingStatus, riskScore float64) EnhancedFinding {
	baseFinding := agent.NewFinding(
		"Test Finding",
		"Test Description",
		severity,
	)

	finding := NewEnhancedFinding(baseFinding, missionID, "test-agent")
	finding.Category = string(category)
	finding.Status = status
	finding.RiskScore = riskScore
	finding.Subcategory = "test_subcategory"

	// Add MITRE mappings via Metadata
	if finding.Metadata == nil {
		finding.Metadata = make(map[string]any)
	}
	finding.Metadata["mitre_attack"] = []SimpleMitreMapping{
		{
			TechniqueID:   "T1059",
			TechniqueName: "Command and Scripting Interpreter",
			Tactic:        "Execution",
		},
	}

	return finding
}

func TestNewFindingAnalytics(t *testing.T) {
	_, store, _ := setupTestAnalytics(t)
	analytics := NewFindingAnalytics(store)

	assert.NotNil(t, analytics)
	assert.NotNil(t, analytics.store)
}

func TestGetStatistics_Empty(t *testing.T) {
	analytics, _, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	stats, err := analytics.GetStatistics(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.Equal(t, 0, stats.Total)
	assert.Equal(t, 0, len(stats.BySeverity))
	assert.Equal(t, 0, len(stats.ByCategory))
	assert.Equal(t, 0, len(stats.ByStatus))
	assert.Equal(t, 0.0, stats.AverageRiskScore)
	assert.Equal(t, 0, len(stats.TopMitreTechniques))
}

func TestGetStatistics_WithFindings(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create test findings with various attributes
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityCritical, CategoryJailbreak, StatusOpen, 9.5),
		createTestFinding(missionID, agent.SeverityHigh, CategoryPromptInjection, StatusOpen, 7.5),
		createTestFinding(missionID, agent.SeverityHigh, CategoryPromptInjection, StatusConfirmed, 7.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryDataExtraction, StatusResolved, 4.5),
		createTestFinding(missionID, agent.SeverityLow, CategoryInformationDisclosure, StatusFalsePositive, 2.0),
	}

	// Store findings
	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	// Get statistics
	stats, err := analytics.GetStatistics(ctx, missionID)
	require.NoError(t, err)
	require.NotNil(t, stats)

	// Verify total
	assert.Equal(t, 5, stats.Total)

	// Verify by severity
	assert.Equal(t, 1, stats.BySeverity[agent.SeverityCritical])
	assert.Equal(t, 2, stats.BySeverity[agent.SeverityHigh])
	assert.Equal(t, 1, stats.BySeverity[agent.SeverityMedium])
	assert.Equal(t, 1, stats.BySeverity[agent.SeverityLow])

	// Verify by category
	assert.Equal(t, 1, stats.ByCategory[CategoryJailbreak])
	assert.Equal(t, 2, stats.ByCategory[CategoryPromptInjection])
	assert.Equal(t, 1, stats.ByCategory[CategoryDataExtraction])
	assert.Equal(t, 1, stats.ByCategory[CategoryInformationDisclosure])

	// Verify by status
	assert.Equal(t, 2, stats.ByStatus[StatusOpen])
	assert.Equal(t, 1, stats.ByStatus[StatusConfirmed])
	assert.Equal(t, 1, stats.ByStatus[StatusResolved])
	assert.Equal(t, 1, stats.ByStatus[StatusFalsePositive])

	// Verify average risk score (9.5 + 7.5 + 7.0 + 4.5 + 2.0) / 5 = 6.1
	assert.InDelta(t, 6.1, stats.AverageRiskScore, 0.01)

	// Verify MITRE techniques
	assert.Greater(t, len(stats.TopMitreTechniques), 0)
	if len(stats.TopMitreTechniques) > 0 {
		assert.Equal(t, "T1059", stats.TopMitreTechniques[0].TechniqueID)
		assert.Equal(t, 5, stats.TopMitreTechniques[0].Count) // All findings have this technique
	}
}

func TestGetStatistics_TopMitreTechniques(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with different MITRE techniques
	for i := 0; i < 15; i++ {
		finding := createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 7.0)

		// Add multiple different techniques to test top 10 limit via Metadata
		if finding.Metadata == nil {
			finding.Metadata = make(map[string]any)
		}
		finding.Metadata["mitre_attack"] = []SimpleMitreMapping{
			{
				TechniqueID:   "T1059",
				TechniqueName: "Command and Scripting Interpreter",
				Tactic:        "Execution",
			},
		}

		// Add unique technique for some findings
		if i < 12 {
			finding.Metadata["mitre_atlas"] = []SimpleMitreMapping{
				{
					TechniqueID:   "AML.T0043",
					TechniqueName: "Craft Adversarial Data",
					Tactic:        "ML Model Access",
				},
			}
		}

		err := store.Store(ctx, finding)
		require.NoError(t, err)
	}

	stats, err := analytics.GetStatistics(ctx, missionID)
	require.NoError(t, err)

	// Should have techniques sorted by count
	assert.Greater(t, len(stats.TopMitreTechniques), 0)
	assert.LessOrEqual(t, len(stats.TopMitreTechniques), 10) // Max 10 techniques

	// T1059 should be first (15 occurrences)
	if len(stats.TopMitreTechniques) > 0 {
		assert.Equal(t, "T1059", stats.TopMitreTechniques[0].TechniqueID)
		assert.Equal(t, 15, stats.TopMitreTechniques[0].Count)
	}

	// AML.T0043 should be second (12 occurrences)
	if len(stats.TopMitreTechniques) > 1 {
		assert.Equal(t, "AML.T0043", stats.TopMitreTechniques[1].TechniqueID)
		assert.Equal(t, 12, stats.TopMitreTechniques[1].Count)
	}
}

func TestGetTrends_Empty(t *testing.T) {
	analytics, _, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	trends, err := analytics.GetTrends(ctx, missionID, 24*time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, len(trends))
}

func TestGetTrends_WithFindings(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings at different times
	now := time.Now()
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryPromptInjection, StatusOpen, 5.0),
		createTestFinding(missionID, agent.SeverityLow, CategoryDataExtraction, StatusOpen, 2.0),
	}

	// Set different creation times
	findings[0].CreatedAt = now.Add(-3 * time.Hour)
	findings[1].CreatedAt = now.Add(-2 * time.Hour)
	findings[2].CreatedAt = now.Add(-1 * time.Hour)

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	// Get trends for last 24 hours
	trends, err := analytics.GetTrends(ctx, missionID, 24*time.Hour)
	require.NoError(t, err)

	// Should have trend points
	assert.Greater(t, len(trends), 0)

	// Verify trend points are ordered by time
	for i := 1; i < len(trends); i++ {
		assert.True(t, trends[i].Timestamp.After(trends[i-1].Timestamp) || trends[i].Timestamp.Equal(trends[i-1].Timestamp))
	}
}

func TestGetTrends_HourlyBucketing(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings within a single day (should use hourly buckets)
	now := time.Now().Truncate(time.Hour)
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0),
		createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 9.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryPromptInjection, StatusOpen, 5.0),
	}

	// Two findings in first hour, one in second hour
	findings[0].CreatedAt = now.Add(-2 * time.Hour)
	findings[1].CreatedAt = now.Add(-2*time.Hour + 30*time.Minute)
	findings[2].CreatedAt = now.Add(-1 * time.Hour)

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	trends, err := analytics.GetTrends(ctx, missionID, 24*time.Hour)
	require.NoError(t, err)

	// Should have 2 buckets
	assert.Equal(t, 2, len(trends))

	// First bucket should have 2 findings
	assert.Equal(t, 2, trends[0].Count)
	assert.InDelta(t, 8.5, trends[0].RiskScore, 0.01) // Average of 8.0 and 9.0

	// Second bucket should have 1 finding
	assert.Equal(t, 1, trends[1].Count)
	assert.Equal(t, 5.0, trends[1].RiskScore)
}

func TestGetTrends_DailyBucketing(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings over multiple days (should use 6-hour buckets for week view)
	now := time.Now().Truncate(24 * time.Hour)
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryPromptInjection, StatusOpen, 5.0),
		createTestFinding(missionID, agent.SeverityLow, CategoryDataExtraction, StatusOpen, 2.0),
	}

	// Spread findings over 3 days
	findings[0].CreatedAt = now.Add(-5 * 24 * time.Hour)
	findings[1].CreatedAt = now.Add(-3 * 24 * time.Hour)
	findings[2].CreatedAt = now.Add(-1 * 24 * time.Hour)

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	trends, err := analytics.GetTrends(ctx, missionID, 7*24*time.Hour)
	require.NoError(t, err)

	// Should have 3 buckets
	assert.Equal(t, 3, len(trends))

	// Each bucket should have 1 finding
	for _, trend := range trends {
		assert.Equal(t, 1, trend.Count)
	}
}

func TestGetTrends_WeeklyBucketing(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings over multiple weeks (should use weekly buckets)
	now := time.Now().Truncate(24 * time.Hour)
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryPromptInjection, StatusOpen, 5.0),
	}

	// Spread findings over 2 weeks
	findings[0].CreatedAt = now.Add(-14 * 24 * time.Hour)
	findings[1].CreatedAt = now.Add(-7 * 24 * time.Hour)

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	trends, err := analytics.GetTrends(ctx, missionID, 30*24*time.Hour)
	require.NoError(t, err)

	// Should have at least 2 buckets
	assert.GreaterOrEqual(t, len(trends), 2)
}

func TestGetRiskScore_Empty(t *testing.T) {
	analytics, _, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	score, err := analytics.GetRiskScore(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 0.0, score)
}

func TestGetRiskScore_WithFindings(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with known severities
	// Critical = 4, High = 3, Medium = 2, Low = 1
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityCritical, CategoryJailbreak, StatusOpen, 9.0),        // weight: 4
		createTestFinding(missionID, agent.SeverityHigh, CategoryPromptInjection, StatusOpen, 7.0),      // weight: 3
		createTestFinding(missionID, agent.SeverityMedium, CategoryDataExtraction, StatusOpen, 4.0),     // weight: 2
		createTestFinding(missionID, agent.SeverityLow, CategoryInformationDisclosure, StatusOpen, 1.0), // weight: 1
	}

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	score, err := analytics.GetRiskScore(ctx, missionID)
	require.NoError(t, err)

	// Expected: (4 + 3 + 2 + 1) / 4 = 2.5
	assert.InDelta(t, 2.5, score, 0.01)
}

func TestGetRiskScore_ExcludesResolved(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with some resolved
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityCritical, CategoryJailbreak, StatusOpen, 9.0),       // weight: 4
		createTestFinding(missionID, agent.SeverityHigh, CategoryPromptInjection, StatusResolved, 7.0), // excluded
		createTestFinding(missionID, agent.SeverityMedium, CategoryDataExtraction, StatusOpen, 4.0),    // weight: 2
	}

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	score, err := analytics.GetRiskScore(ctx, missionID)
	require.NoError(t, err)

	// Expected: (4 + 2) / 2 = 3.0 (resolved not counted)
	assert.InDelta(t, 3.0, score, 0.01)
}

func TestGetTopVulnerabilities_Empty(t *testing.T) {
	analytics, _, _ := setupTestAnalytics(t)
	ctx := context.Background()

	patterns, err := analytics.GetTopVulnerabilities(ctx, 10)
	require.NoError(t, err)
	assert.Equal(t, 0, len(patterns))
}

func TestGetTopVulnerabilities_WithFindings(t *testing.T) {
	analytics, store, _ := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with different category/subcategory combinations
	// Note: GetTopVulnerabilities doesn't filter by mission, so we use dummy IDs
	findings := []EnhancedFinding{
		createTestFinding(types.NewID(), agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0),
		createTestFinding(types.NewID(), agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.5),
		createTestFinding(types.NewID(), agent.SeverityMedium, CategoryPromptInjection, StatusOpen, 5.0),
		createTestFinding(types.NewID(), agent.SeverityLow, CategoryDataExtraction, StatusOpen, 2.0),
	}

	// Set subcategories
	findings[0].Subcategory = "dan_bypass"
	findings[1].Subcategory = "dan_bypass"
	findings[2].Subcategory = "indirect_injection"
	findings[3].Subcategory = "pii_extraction"

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	patterns, err := analytics.GetTopVulnerabilities(ctx, 10)
	require.NoError(t, err)

	// Should have patterns sorted by count
	assert.Greater(t, len(patterns), 0)

	// First pattern should be jailbreak/dan_bypass (2 occurrences)
	assert.Equal(t, CategoryJailbreak, patterns[0].Category)
	assert.Equal(t, "dan_bypass", patterns[0].Subcategory)
	assert.Equal(t, 2, patterns[0].Count)
}

func TestGetTopVulnerabilities_Limit(t *testing.T) {
	analytics, store, _ := setupTestAnalytics(t)
	ctx := context.Background()

	// Create many different vulnerability patterns
	categories := []FindingCategory{
		CategoryJailbreak,
		CategoryPromptInjection,
		CategoryDataExtraction,
		CategoryInformationDisclosure,
	}

	for i := 0; i < 20; i++ {
		finding := createTestFinding(
			types.NewID(),
			agent.SeverityMedium,
			categories[i%len(categories)],
			StatusOpen,
			5.0,
		)
		finding.Subcategory = "test_" + string(rune(i))
		err := store.Store(ctx, finding)
		require.NoError(t, err)
	}

	// Request top 5
	patterns, err := analytics.GetTopVulnerabilities(ctx, 5)
	require.NoError(t, err)

	// Should be limited to 5
	assert.LessOrEqual(t, len(patterns), 5)
}

func TestGetTopVulnerabilities_SeverityAveraging(t *testing.T) {
	analytics, store, _ := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with same category but different severities
	findings := []EnhancedFinding{
		createTestFinding(types.NewID(), agent.SeverityCritical, CategoryJailbreak, StatusOpen, 9.0), // weight: 4
		createTestFinding(types.NewID(), agent.SeverityHigh, CategoryJailbreak, StatusOpen, 7.0),     // weight: 3
		createTestFinding(types.NewID(), agent.SeverityMedium, CategoryJailbreak, StatusOpen, 5.0),   // weight: 2
		createTestFinding(types.NewID(), agent.SeverityLow, CategoryJailbreak, StatusOpen, 3.0),      // weight: 1
	}

	// Set all to same subcategory
	for i := range findings {
		findings[i].Subcategory = "same_pattern"
		err := store.Store(ctx, findings[i])
		require.NoError(t, err)
	}

	patterns, err := analytics.GetTopVulnerabilities(ctx, 10)
	require.NoError(t, err)
	require.Len(t, patterns, 1)

	// Average severity should be (4 + 3 + 2 + 1) / 4 = 2.5
	assert.Equal(t, 4, patterns[0].Count)
	assert.InDelta(t, 2.5, patterns[0].AvgSeverity, 0.01)
}

func TestGetTopVulnerabilities_CountOrdering(t *testing.T) {
	analytics, store, _ := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with different counts per pattern
	// Pattern 1: 5 occurrences
	for i := 0; i < 5; i++ {
		f := createTestFinding(types.NewID(), agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0)
		f.Subcategory = "pattern_1"
		require.NoError(t, store.Store(ctx, f))
	}

	// Pattern 2: 3 occurrences
	for i := 0; i < 3; i++ {
		f := createTestFinding(types.NewID(), agent.SeverityMedium, CategoryPromptInjection, StatusOpen, 5.0)
		f.Subcategory = "pattern_2"
		require.NoError(t, store.Store(ctx, f))
	}

	// Pattern 3: 1 occurrence
	f := createTestFinding(types.NewID(), agent.SeverityLow, CategoryDataExtraction, StatusOpen, 2.0)
	f.Subcategory = "pattern_3"
	require.NoError(t, store.Store(ctx, f))

	patterns, err := analytics.GetTopVulnerabilities(ctx, 10)
	require.NoError(t, err)
	require.Len(t, patterns, 3)

	// Should be sorted by count descending
	assert.Equal(t, 5, patterns[0].Count)
	assert.Equal(t, CategoryJailbreak, patterns[0].Category)

	assert.Equal(t, 3, patterns[1].Count)
	assert.Equal(t, CategoryPromptInjection, patterns[1].Category)

	assert.Equal(t, 1, patterns[2].Count)
	assert.Equal(t, CategoryDataExtraction, patterns[2].Category)
}

func TestGetRemediationProgress_Empty(t *testing.T) {
	analytics, _, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	open, resolved, err := analytics.GetRemediationProgress(ctx, missionID)
	require.NoError(t, err)
	assert.Equal(t, 0, open)
	assert.Equal(t, 0, resolved)
}

func TestGetRemediationProgress_WithFindings(t *testing.T) {
	analytics, store, missionID := setupTestAnalytics(t)
	ctx := context.Background()

	// Create findings with different statuses
	findings := []EnhancedFinding{
		createTestFinding(missionID, agent.SeverityHigh, CategoryJailbreak, StatusOpen, 8.0),
		createTestFinding(missionID, agent.SeverityHigh, CategoryPromptInjection, StatusOpen, 7.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryDataExtraction, StatusConfirmed, 5.0),
		createTestFinding(missionID, agent.SeverityMedium, CategoryInformationDisclosure, StatusResolved, 4.0),
		createTestFinding(missionID, agent.SeverityLow, CategoryJailbreak, StatusResolved, 2.0),
		createTestFinding(missionID, agent.SeverityLow, CategoryPromptInjection, StatusFalsePositive, 1.0),
	}

	for _, f := range findings {
		err := store.Store(ctx, f)
		require.NoError(t, err)
	}

	open, resolved, err := analytics.GetRemediationProgress(ctx, missionID)
	require.NoError(t, err)

	// Open = 2 (open) + 1 (confirmed) = 3
	assert.Equal(t, 3, open)
	// Resolved = 2
	assert.Equal(t, 2, resolved)
	// False positive not counted in either
}

func TestGetSeverityWeight(t *testing.T) {
	tests := []struct {
		name     string
		severity agent.FindingSeverity
		expected float64
	}{
		{"Critical", agent.SeverityCritical, 4.0},
		{"High", agent.SeverityHigh, 3.0},
		{"Medium", agent.SeverityMedium, 2.0},
		{"Low", agent.SeverityLow, 1.0},
		{"Info", agent.SeverityInfo, 0.5},
		{"Unknown", "unknown", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			weight := getSeverityWeight(tt.severity)
			assert.Equal(t, tt.expected, weight)
		})
	}
}
