package harness

import (
	"strings"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// FindingFilter provides flexible filtering for agent findings.
// All fields are optional pointers - nil fields are ignored during matching.
// Only non-nil fields are used as filter criteria.
type FindingFilter struct {
	// Severity filters findings by severity level (exact match)
	Severity *agent.FindingSeverity `json:"severity,omitempty"`

	// MinConfidence filters findings with confidence >= this value (0.0 - 1.0)
	MinConfidence *float64 `json:"min_confidence,omitempty"`

	// MaxConfidence filters findings with confidence <= this value (0.0 - 1.0)
	MaxConfidence *float64 `json:"max_confidence,omitempty"`

	// Category filters findings by category (case-insensitive substring match)
	Category *string `json:"category,omitempty"`

	// TargetID filters findings associated with a specific target
	TargetID *types.ID `json:"target_id,omitempty"`

	// TitleContains filters findings whose title contains this substring (case-insensitive)
	TitleContains *string `json:"title_contains,omitempty"`

	// DescriptionContains filters findings whose description contains this substring (case-insensitive)
	DescriptionContains *string `json:"description_contains,omitempty"`

	// HasCVSS filters findings that have (true) or don't have (false) CVSS scores
	HasCVSS *bool `json:"has_cvss,omitempty"`

	// MinCVSS filters findings with CVSS score >= this value
	MinCVSS *float64 `json:"min_cvss,omitempty"`

	// MaxCVSS filters findings with CVSS score <= this value
	MaxCVSS *float64 `json:"max_cvss,omitempty"`

	// CWE filters findings that include any of the specified CWE IDs
	CWE []string `json:"cwe,omitempty"`
}

// Matches checks if a finding satisfies all non-nil filter criteria.
// Returns true if the finding matches all specified filters, false otherwise.
func (f *FindingFilter) Matches(finding agent.Finding) bool {
	// Check severity filter
	if f.Severity != nil && finding.Severity != *f.Severity {
		return false
	}

	// Check minimum confidence filter
	if f.MinConfidence != nil && finding.Confidence < *f.MinConfidence {
		return false
	}

	// Check maximum confidence filter
	if f.MaxConfidence != nil && finding.Confidence > *f.MaxConfidence {
		return false
	}

	// Check category filter (case-insensitive substring match)
	if f.Category != nil {
		categoryLower := strings.ToLower(finding.Category)
		filterLower := strings.ToLower(*f.Category)
		if !strings.Contains(categoryLower, filterLower) {
			return false
		}
	}

	// Check target ID filter
	if f.TargetID != nil {
		if finding.TargetID == nil || *finding.TargetID != *f.TargetID {
			return false
		}
	}

	// Check title contains filter (case-insensitive)
	if f.TitleContains != nil {
		titleLower := strings.ToLower(finding.Title)
		filterLower := strings.ToLower(*f.TitleContains)
		if !strings.Contains(titleLower, filterLower) {
			return false
		}
	}

	// Check description contains filter (case-insensitive)
	if f.DescriptionContains != nil {
		descLower := strings.ToLower(finding.Description)
		filterLower := strings.ToLower(*f.DescriptionContains)
		if !strings.Contains(descLower, filterLower) {
			return false
		}
	}

	// Check CVSS presence filter
	if f.HasCVSS != nil {
		hasCVSS := finding.CVSS != nil
		if hasCVSS != *f.HasCVSS {
			return false
		}
	}

	// Check minimum CVSS filter
	if f.MinCVSS != nil {
		if finding.CVSS == nil || finding.CVSS.Score < *f.MinCVSS {
			return false
		}
	}

	// Check maximum CVSS filter
	if f.MaxCVSS != nil {
		if finding.CVSS == nil || finding.CVSS.Score > *f.MaxCVSS {
			return false
		}
	}

	// Check CWE filter (finding must contain at least one of the specified CWEs)
	if len(f.CWE) > 0 {
		if !hasCWEMatch(finding.CWE, f.CWE) {
			return false
		}
	}

	return true
}

// hasCWEMatch checks if the finding's CWE list contains any of the filter CWE IDs
func hasCWEMatch(findingCWEs, filterCWEs []string) bool {
	if len(findingCWEs) == 0 {
		return false
	}

	for _, filterCWE := range filterCWEs {
		for _, findingCWE := range findingCWEs {
			if findingCWE == filterCWE {
				return true
			}
		}
	}

	return false
}

// NewFindingFilter creates an empty finding filter
func NewFindingFilter() *FindingFilter {
	return &FindingFilter{}
}

// WithSeverity sets the severity filter
func (f *FindingFilter) WithSeverity(severity agent.FindingSeverity) *FindingFilter {
	f.Severity = &severity
	return f
}

// WithMinConfidence sets the minimum confidence filter
func (f *FindingFilter) WithMinConfidence(confidence float64) *FindingFilter {
	f.MinConfidence = &confidence
	return f
}

// WithMaxConfidence sets the maximum confidence filter
func (f *FindingFilter) WithMaxConfidence(confidence float64) *FindingFilter {
	f.MaxConfidence = &confidence
	return f
}

// WithCategory sets the category filter
func (f *FindingFilter) WithCategory(category string) *FindingFilter {
	f.Category = &category
	return f
}

// WithTargetID sets the target ID filter
func (f *FindingFilter) WithTargetID(targetID types.ID) *FindingFilter {
	f.TargetID = &targetID
	return f
}

// WithTitleContains sets the title contains filter
func (f *FindingFilter) WithTitleContains(title string) *FindingFilter {
	f.TitleContains = &title
	return f
}

// WithDescriptionContains sets the description contains filter
func (f *FindingFilter) WithDescriptionContains(description string) *FindingFilter {
	f.DescriptionContains = &description
	return f
}

// WithHasCVSS sets the CVSS presence filter
func (f *FindingFilter) WithHasCVSS(hasCVSS bool) *FindingFilter {
	f.HasCVSS = &hasCVSS
	return f
}

// WithMinCVSS sets the minimum CVSS filter
func (f *FindingFilter) WithMinCVSS(score float64) *FindingFilter {
	f.MinCVSS = &score
	return f
}

// WithMaxCVSS sets the maximum CVSS filter
func (f *FindingFilter) WithMaxCVSS(score float64) *FindingFilter {
	f.MaxCVSS = &score
	return f
}

// WithCWE sets the CWE filter
func (f *FindingFilter) WithCWE(cwe ...string) *FindingFilter {
	f.CWE = cwe
	return f
}
