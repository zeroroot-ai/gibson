package export

import (
	"context"
	"time"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/finding"
)

// Exporter defines the interface for exporting findings in various formats.
// Implementations must be safe for concurrent use from multiple goroutines.
type Exporter interface {
	// Export converts findings to the target format with optional filtering.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - findings: Slice of findings to export
	//   - opts: Export options for filtering and customization
	//
	// Returns:
	//   - []byte: The exported data in the target format
	//   - error: Non-nil if export fails
	Export(ctx context.Context, findings []*finding.EnhancedFinding, opts ExportOptions) ([]byte, error)

	// Format returns the format identifier (e.g., "json", "csv", "sarif")
	Format() string

	// ContentType returns the MIME content type for HTTP responses
	ContentType() string
}

// ExportOptions configures the export operation with filtering and customization.
type ExportOptions struct {
	// IncludeEvidence controls whether evidence is included in the export.
	// Large evidence sets can significantly increase export size.
	IncludeEvidence bool

	// MinSeverity filters findings to only include those at or above this severity.
	// If nil, all severities are included.
	MinSeverity *agent.FindingSeverity

	// DateFrom filters findings created on or after this date.
	// If nil, no lower bound is applied.
	DateFrom *time.Time

	// DateTo filters findings created on or before this date.
	// If nil, no upper bound is applied.
	DateTo *time.Time

	// RedactSensitive removes or masks sensitive information from the export.
	// This should be enabled when exporting for external sharing.
	RedactSensitive bool

	// IncludeResolved controls whether resolved/false positive findings are included.
	// Defaults to false (only active findings).
	IncludeResolved bool

	// Categories filters findings to only include specific categories.
	// If empty, all categories are included.
	Categories []string

	// MinConfidence filters findings to only include those at or above this confidence.
	// Value should be between 0.0 and 1.0. If nil, all confidences are included.
	MinConfidence *float64
}

// DefaultExportOptions returns ExportOptions with sensible defaults
func DefaultExportOptions() ExportOptions {
	return ExportOptions{
		IncludeEvidence: true,
		MinSeverity:     nil,
		DateFrom:        nil,
		DateTo:          nil,
		RedactSensitive: false,
		IncludeResolved: false,
		Categories:      nil,
		MinConfidence:   nil,
	}
}

// ApplyFilters filters findings based on ExportOptions criteria.
// Returns a new slice containing only findings that match all filter conditions.
//
// This function is thread-safe and does not modify the input slice.
func ApplyFilters(findings []*finding.EnhancedFinding, opts ExportOptions) []*finding.EnhancedFinding {
	if len(findings) == 0 {
		return []*finding.EnhancedFinding{}
	}

	result := make([]*finding.EnhancedFinding, 0, len(findings))

	for _, f := range findings {
		// Filter by severity
		if opts.MinSeverity != nil && !meetsMinSeverity(f.Severity, *opts.MinSeverity) {
			continue
		}

		// Filter by date range
		if opts.DateFrom != nil && f.CreatedAt.Before(*opts.DateFrom) {
			continue
		}
		if opts.DateTo != nil && f.CreatedAt.After(*opts.DateTo) {
			continue
		}

		// Filter by resolution status
		if !opts.IncludeResolved {
			if f.Status == finding.StatusResolved || f.Status == finding.StatusFalsePositive {
				continue
			}
		}

		// Filter by categories
		if len(opts.Categories) > 0 && !containsCategory(f.Category, opts.Categories) {
			continue
		}

		// Filter by confidence
		if opts.MinConfidence != nil && f.Confidence < *opts.MinConfidence {
			continue
		}

		// Include this finding
		result = append(result, f)
	}

	return result
}

// meetsMinSeverity checks if the finding severity meets or exceeds the minimum severity
func meetsMinSeverity(findingSeverity, minSeverity agent.FindingSeverity) bool {
	severityOrder := map[agent.FindingSeverity]int{
		agent.SeverityCritical: 4,
		agent.SeverityHigh:     3,
		agent.SeverityMedium:   2,
		agent.SeverityLow:      1,
		agent.SeverityInfo:     0,
	}

	findingLevel, ok1 := severityOrder[findingSeverity]
	minLevel, ok2 := severityOrder[minSeverity]

	// If either severity is unknown, be conservative and include it
	if !ok1 || !ok2 {
		return true
	}

	return findingLevel >= minLevel
}

// containsCategory checks if the finding category matches any of the specified categories
func containsCategory(category string, categories []string) bool {
	for _, c := range categories {
		if category == c {
			return true
		}
	}
	return false
}

// RedactSensitiveData removes or masks sensitive information from findings.
// This modifies the findings in place, so pass a copy if you need to preserve originals.
func RedactSensitiveData(findings []*finding.EnhancedFinding) {
	for _, f := range findings {
		// Redact sensitive metadata fields
		if f.Metadata != nil {
			// Remove common sensitive keys
			sensitiveKeys := []string{
				"password", "secret", "token", "api_key", "apikey",
				"credential", "auth", "authorization", "bearer",
				"session", "cookie", "private_key", "privatekey",
			}

			for _, key := range sensitiveKeys {
				delete(f.Metadata, key)
			}
		}

		// Redact sensitive evidence data
		for i := range f.Evidence {
			if f.Evidence[i].Data != nil {
				for _, key := range []string{
					"password", "secret", "token", "api_key",
					"credential", "auth", "session", "cookie",
				} {
					if _, exists := f.Evidence[i].Data[key]; exists {
						f.Evidence[i].Data[key] = "[REDACTED]"
					}
				}
			}
		}
	}
}
