package harness

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ────────────────────────────────────────────────────────────────────────────
// FindingFilter Creation Tests
// ────────────────────────────────────────────────────────────────────────────

func TestNewFindingFilter(t *testing.T) {
	filter := NewFindingFilter()

	assert.NotNil(t, filter)
	assert.Nil(t, filter.Severity)
	assert.Nil(t, filter.MinConfidence)
	assert.Nil(t, filter.MaxConfidence)
	assert.Nil(t, filter.Category)
	assert.Nil(t, filter.TargetID)
	assert.Nil(t, filter.TitleContains)
	assert.Nil(t, filter.DescriptionContains)
	assert.Nil(t, filter.HasCVSS)
	assert.Nil(t, filter.MinCVSS)
	assert.Nil(t, filter.MaxCVSS)
	assert.Nil(t, filter.CWE)
}

func TestFindingFilter_WithSeverity(t *testing.T) {
	filter := NewFindingFilter().WithSeverity(agent.SeverityHigh)

	assert.NotNil(t, filter.Severity)
	assert.Equal(t, agent.SeverityHigh, *filter.Severity)
}

func TestFindingFilter_WithMinConfidence(t *testing.T) {
	filter := NewFindingFilter().WithMinConfidence(0.8)

	assert.NotNil(t, filter.MinConfidence)
	assert.Equal(t, 0.8, *filter.MinConfidence)
}

func TestFindingFilter_WithMaxConfidence(t *testing.T) {
	filter := NewFindingFilter().WithMaxConfidence(0.5)

	assert.NotNil(t, filter.MaxConfidence)
	assert.Equal(t, 0.5, *filter.MaxConfidence)
}

func TestFindingFilter_WithCategory(t *testing.T) {
	filter := NewFindingFilter().WithCategory("injection")

	assert.NotNil(t, filter.Category)
	assert.Equal(t, "injection", *filter.Category)
}

func TestFindingFilter_WithTargetID(t *testing.T) {
	targetID := types.NewID()
	filter := NewFindingFilter().WithTargetID(targetID)

	assert.NotNil(t, filter.TargetID)
	assert.Equal(t, targetID, *filter.TargetID)
}

func TestFindingFilter_WithTitleContains(t *testing.T) {
	filter := NewFindingFilter().WithTitleContains("SQL")

	assert.NotNil(t, filter.TitleContains)
	assert.Equal(t, "SQL", *filter.TitleContains)
}

func TestFindingFilter_WithDescriptionContains(t *testing.T) {
	filter := NewFindingFilter().WithDescriptionContains("vulnerable")

	assert.NotNil(t, filter.DescriptionContains)
	assert.Equal(t, "vulnerable", *filter.DescriptionContains)
}

func TestFindingFilter_WithHasCVSS(t *testing.T) {
	filter := NewFindingFilter().WithHasCVSS(true)

	assert.NotNil(t, filter.HasCVSS)
	assert.True(t, *filter.HasCVSS)
}

func TestFindingFilter_WithMinCVSS(t *testing.T) {
	filter := NewFindingFilter().WithMinCVSS(7.0)

	assert.NotNil(t, filter.MinCVSS)
	assert.Equal(t, 7.0, *filter.MinCVSS)
}

func TestFindingFilter_WithMaxCVSS(t *testing.T) {
	filter := NewFindingFilter().WithMaxCVSS(9.0)

	assert.NotNil(t, filter.MaxCVSS)
	assert.Equal(t, 9.0, *filter.MaxCVSS)
}

func TestFindingFilter_WithCWE(t *testing.T) {
	filter := NewFindingFilter().WithCWE("CWE-89", "CWE-79")

	assert.NotNil(t, filter.CWE)
	assert.Equal(t, []string{"CWE-89", "CWE-79"}, filter.CWE)
}

func TestFindingFilter_Chaining(t *testing.T) {
	filter := NewFindingFilter().
		WithSeverity(agent.SeverityHigh).
		WithMinConfidence(0.8).
		WithCategory("injection").
		WithTitleContains("SQL")

	assert.NotNil(t, filter.Severity)
	assert.Equal(t, agent.SeverityHigh, *filter.Severity)
	assert.NotNil(t, filter.MinConfidence)
	assert.Equal(t, 0.8, *filter.MinConfidence)
	assert.NotNil(t, filter.Category)
	assert.Equal(t, "injection", *filter.Category)
	assert.NotNil(t, filter.TitleContains)
	assert.Equal(t, "SQL", *filter.TitleContains)
}

// ────────────────────────────────────────────────────────────────────────────
// FindingFilter Matches Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFindingFilter_Matches_Severity(t *testing.T) {
	tests := []struct {
		name            string
		filterSeverity  agent.FindingSeverity
		findingSeverity agent.FindingSeverity
		expected        bool
	}{
		{
			name:            "exact match",
			filterSeverity:  agent.SeverityHigh,
			findingSeverity: agent.SeverityHigh,
			expected:        true,
		},
		{
			name:            "no match",
			filterSeverity:  agent.SeverityHigh,
			findingSeverity: agent.SeverityMedium,
			expected:        false,
		},
		{
			name:            "critical matches critical",
			filterSeverity:  agent.SeverityCritical,
			findingSeverity: agent.SeverityCritical,
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter().WithSeverity(tt.filterSeverity)
			finding := agent.NewFinding("Test", "Description", tt.findingSeverity)

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_Confidence(t *testing.T) {
	tests := []struct {
		name              string
		minConfidence     *float64
		maxConfidence     *float64
		findingConfidence float64
		expected          bool
	}{
		{
			name:              "within range",
			minConfidence:     floatPtr(0.5),
			maxConfidence:     floatPtr(0.9),
			findingConfidence: 0.7,
			expected:          true,
		},
		{
			name:              "below min",
			minConfidence:     floatPtr(0.5),
			findingConfidence: 0.3,
			expected:          false,
		},
		{
			name:              "above max",
			maxConfidence:     floatPtr(0.9),
			findingConfidence: 0.95,
			expected:          false,
		},
		{
			name:              "at min boundary",
			minConfidence:     floatPtr(0.5),
			findingConfidence: 0.5,
			expected:          true,
		},
		{
			name:              "at max boundary",
			maxConfidence:     floatPtr(0.9),
			findingConfidence: 0.9,
			expected:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter()
			if tt.minConfidence != nil {
				filter.WithMinConfidence(*tt.minConfidence)
			}
			if tt.maxConfidence != nil {
				filter.WithMaxConfidence(*tt.maxConfidence)
			}

			finding := agent.NewFinding("Test", "Description", agent.SeverityMedium).
				WithConfidence(tt.findingConfidence)

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_Category(t *testing.T) {
	tests := []struct {
		name            string
		filterCategory  string
		findingCategory string
		expected        bool
	}{
		{
			name:            "exact match",
			filterCategory:  "injection",
			findingCategory: "injection",
			expected:        true,
		},
		{
			name:            "substring match",
			filterCategory:  "inject",
			findingCategory: "injection",
			expected:        true,
		},
		{
			name:            "case insensitive match",
			filterCategory:  "INJECTION",
			findingCategory: "injection",
			expected:        true,
		},
		{
			name:            "no match",
			filterCategory:  "xss",
			findingCategory: "injection",
			expected:        false,
		},
		{
			name:            "empty filter matches all",
			filterCategory:  "",
			findingCategory: "injection",
			expected:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter().WithCategory(tt.filterCategory)
			finding := agent.NewFinding("Test", "Description", agent.SeverityMedium).
				WithCategory(tt.findingCategory)

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_TargetID(t *testing.T) {
	targetID1 := types.NewID()
	targetID2 := types.NewID()

	tests := []struct {
		name          string
		filterTarget  types.ID
		findingTarget *types.ID
		expected      bool
	}{
		{
			name:          "exact match",
			filterTarget:  targetID1,
			findingTarget: &targetID1,
			expected:      true,
		},
		{
			name:          "no match",
			filterTarget:  targetID1,
			findingTarget: &targetID2,
			expected:      false,
		},
		{
			name:          "finding has no target",
			filterTarget:  targetID1,
			findingTarget: nil,
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter().WithTargetID(tt.filterTarget)
			finding := agent.NewFinding("Test", "Description", agent.SeverityMedium)
			if tt.findingTarget != nil {
				finding.TargetID = tt.findingTarget
			}

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_TitleContains(t *testing.T) {
	tests := []struct {
		name         string
		filterTitle  string
		findingTitle string
		expected     bool
	}{
		{
			name:         "exact match",
			filterTitle:  "SQL Injection",
			findingTitle: "SQL Injection",
			expected:     true,
		},
		{
			name:         "substring match",
			filterTitle:  "SQL",
			findingTitle: "SQL Injection in login form",
			expected:     true,
		},
		{
			name:         "case insensitive match",
			filterTitle:  "sql",
			findingTitle: "SQL Injection",
			expected:     true,
		},
		{
			name:         "no match",
			filterTitle:  "XSS",
			findingTitle: "SQL Injection",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter().WithTitleContains(tt.filterTitle)
			finding := agent.NewFinding(tt.findingTitle, "Description", agent.SeverityMedium)

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_DescriptionContains(t *testing.T) {
	tests := []struct {
		name               string
		filterDescription  string
		findingDescription string
		expected           bool
	}{
		{
			name:               "exact match",
			filterDescription:  "vulnerable",
			findingDescription: "This endpoint is vulnerable",
			expected:           true,
		},
		{
			name:               "substring match",
			filterDescription:  "vuln",
			findingDescription: "This endpoint is vulnerable",
			expected:           true,
		},
		{
			name:               "case insensitive match",
			filterDescription:  "VULNERABLE",
			findingDescription: "This endpoint is vulnerable",
			expected:           true,
		},
		{
			name:               "no match",
			filterDescription:  "secure",
			findingDescription: "This endpoint is vulnerable",
			expected:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter().WithDescriptionContains(tt.filterDescription)
			finding := agent.NewFinding("Test", tt.findingDescription, agent.SeverityMedium)

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_CVSS(t *testing.T) {
	tests := []struct {
		name        string
		hasCVSS     *bool
		minCVSS     *float64
		maxCVSS     *float64
		findingCVSS *agent.CVSSScore
		expected    bool
	}{
		{
			name:        "has CVSS - match",
			hasCVSS:     boolPtr(true),
			findingCVSS: &agent.CVSSScore{Score: 7.5},
			expected:    true,
		},
		{
			name:        "has CVSS - no match",
			hasCVSS:     boolPtr(true),
			findingCVSS: nil,
			expected:    false,
		},
		{
			name:        "doesn't have CVSS - match",
			hasCVSS:     boolPtr(false),
			findingCVSS: nil,
			expected:    true,
		},
		{
			name:        "doesn't have CVSS - no match",
			hasCVSS:     boolPtr(false),
			findingCVSS: &agent.CVSSScore{Score: 7.5},
			expected:    false,
		},
		{
			name:        "min CVSS - above threshold",
			minCVSS:     floatPtr(7.0),
			findingCVSS: &agent.CVSSScore{Score: 8.0},
			expected:    true,
		},
		{
			name:        "min CVSS - below threshold",
			minCVSS:     floatPtr(7.0),
			findingCVSS: &agent.CVSSScore{Score: 6.0},
			expected:    false,
		},
		{
			name:        "min CVSS - no CVSS score",
			minCVSS:     floatPtr(7.0),
			findingCVSS: nil,
			expected:    false,
		},
		{
			name:        "max CVSS - below threshold",
			maxCVSS:     floatPtr(9.0),
			findingCVSS: &agent.CVSSScore{Score: 8.0},
			expected:    true,
		},
		{
			name:        "max CVSS - above threshold",
			maxCVSS:     floatPtr(9.0),
			findingCVSS: &agent.CVSSScore{Score: 9.5},
			expected:    false,
		},
		{
			name:        "CVSS range - within",
			minCVSS:     floatPtr(7.0),
			maxCVSS:     floatPtr(9.0),
			findingCVSS: &agent.CVSSScore{Score: 8.0},
			expected:    true,
		},
		{
			name:        "CVSS range - outside",
			minCVSS:     floatPtr(7.0),
			maxCVSS:     floatPtr(9.0),
			findingCVSS: &agent.CVSSScore{Score: 6.5},
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter()
			if tt.hasCVSS != nil {
				filter.WithHasCVSS(*tt.hasCVSS)
			}
			if tt.minCVSS != nil {
				filter.WithMinCVSS(*tt.minCVSS)
			}
			if tt.maxCVSS != nil {
				filter.WithMaxCVSS(*tt.maxCVSS)
			}

			finding := agent.NewFinding("Test", "Description", agent.SeverityMedium)
			finding.CVSS = tt.findingCVSS

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_CWE(t *testing.T) {
	tests := []struct {
		name        string
		filterCWEs  []string
		findingCWEs []string
		expected    bool
	}{
		{
			name:        "single CWE match",
			filterCWEs:  []string{"CWE-89"},
			findingCWEs: []string{"CWE-89"},
			expected:    true,
		},
		{
			name:        "multiple CWEs - one matches",
			filterCWEs:  []string{"CWE-89", "CWE-79"},
			findingCWEs: []string{"CWE-89"},
			expected:    true,
		},
		{
			name:        "multiple CWEs - multiple match",
			filterCWEs:  []string{"CWE-89", "CWE-79"},
			findingCWEs: []string{"CWE-89", "CWE-79", "CWE-22"},
			expected:    true,
		},
		{
			name:        "no match",
			filterCWEs:  []string{"CWE-89"},
			findingCWEs: []string{"CWE-79"},
			expected:    false,
		},
		{
			name:        "finding has no CWEs",
			filterCWEs:  []string{"CWE-89"},
			findingCWEs: []string{},
			expected:    false,
		},
		{
			name:        "finding has no CWEs (nil)",
			filterCWEs:  []string{"CWE-89"},
			findingCWEs: nil,
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewFindingFilter().WithCWE(tt.filterCWEs...)
			finding := agent.NewFinding("Test", "Description", agent.SeverityMedium)
			finding.CWE = tt.findingCWEs

			result := filter.Matches(finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindingFilter_Matches_EmptyFilter(t *testing.T) {
	filter := NewFindingFilter()
	finding := agent.NewFinding("Test", "Description", agent.SeverityMedium)

	// Empty filter should match any finding
	result := filter.Matches(finding)
	assert.True(t, result)
}

func TestFindingFilter_Matches_MultipleFilters(t *testing.T) {
	tests := []struct {
		name     string
		filter   *FindingFilter
		finding  agent.Finding
		expected bool
	}{
		{
			name: "all filters match",
			filter: NewFindingFilter().
				WithSeverity(agent.SeverityHigh).
				WithMinConfidence(0.8).
				WithCategory("injection").
				WithTitleContains("SQL"),
			finding: agent.NewFinding("SQL Injection", "Found vulnerability", agent.SeverityHigh).
				WithConfidence(0.9).
				WithCategory("injection"),
			expected: true,
		},
		{
			name: "one filter fails",
			filter: NewFindingFilter().
				WithSeverity(agent.SeverityHigh).
				WithMinConfidence(0.8).
				WithCategory("injection"),
			finding: agent.NewFinding("Test", "Description", agent.SeverityMedium).
				WithConfidence(0.9).
				WithCategory("injection"),
			expected: false,
		},
		{
			name: "complex filter - all match",
			filter: NewFindingFilter().
				WithSeverity(agent.SeverityCritical).
				WithMinConfidence(0.9).
				WithCategory("injection").
				WithTitleContains("SQL").
				WithDescriptionContains("vulnerable").
				WithMinCVSS(9.0).
				WithCWE("CWE-89"),
			finding: func() agent.Finding {
				f := agent.NewFinding("SQL Injection Found", "The endpoint is vulnerable", agent.SeverityCritical).
					WithConfidence(0.95).
					WithCategory("injection").
					WithCWE("CWE-89")
				f.CVSS = &agent.CVSSScore{Score: 9.8}
				return f
			}(),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Matches(tt.finding)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Helper Functions
// ────────────────────────────────────────────────────────────────────────────

func floatPtr(f float64) *float64 {
	return &f
}

func boolPtr(b bool) *bool {
	return &b
}

// ────────────────────────────────────────────────────────────────────────────
// Edge Cases
// ────────────────────────────────────────────────────────────────────────────

func TestFindingFilter_EdgeCases(t *testing.T) {
	t.Run("zero confidence", func(t *testing.T) {
		filter := NewFindingFilter().WithMinConfidence(0.0)
		finding := agent.NewFinding("Test", "Description", agent.SeverityMedium).
			WithConfidence(0.0)

		assert.True(t, filter.Matches(finding))
	})

	t.Run("max confidence 1.0", func(t *testing.T) {
		filter := NewFindingFilter().WithMaxConfidence(1.0)
		finding := agent.NewFinding("Test", "Description", agent.SeverityMedium).
			WithConfidence(1.0)

		assert.True(t, filter.Matches(finding))
	})

	t.Run("empty string title contains", func(t *testing.T) {
		filter := NewFindingFilter().WithTitleContains("")
		finding := agent.NewFinding("Any Title", "Description", agent.SeverityMedium)

		// Empty string is contained in any string
		assert.True(t, filter.Matches(finding))
	})

	t.Run("empty string description contains", func(t *testing.T) {
		filter := NewFindingFilter().WithDescriptionContains("")
		finding := agent.NewFinding("Title", "Any Description", agent.SeverityMedium)

		// Empty string is contained in any string
		assert.True(t, filter.Matches(finding))
	})

	t.Run("empty CWE list", func(t *testing.T) {
		filter := NewFindingFilter().WithCWE()
		finding := agent.NewFinding("Test", "Description", agent.SeverityMedium).
			WithCWE("CWE-89")

		// Empty filter CWE list means don't filter by CWE
		assert.True(t, filter.Matches(finding))
	})
}
