package export

import (
	"context"
	"encoding/json"

	"github.com/zeroroot-ai/gibson/internal/finding"
)

// JSONExporter exports findings in JSON format.
// Thread-safe for concurrent use.
type JSONExporter struct {
	// Indent controls whether the output is pretty-printed.
	// If true, uses 2-space indentation. If false, compact output.
	Indent bool
}

// NewJSONExporter creates a new JSON exporter
func NewJSONExporter(indent bool) *JSONExporter {
	return &JSONExporter{
		Indent: indent,
	}
}

// Export converts findings to JSON format with optional filtering and redaction.
//
// The output structure is:
//
//	{
//	  "findings": [...],
//	  "metadata": {
//	    "total_count": N,
//	    "exported_count": M,
//	    "filters_applied": {...}
//	  }
//	}
func (e *JSONExporter) Export(ctx context.Context, findings []*finding.EnhancedFinding, opts ExportOptions) ([]byte, error) {
	// Apply filters
	filtered := ApplyFilters(findings, opts)

	// Apply redaction if requested
	if opts.RedactSensitive {
		// Make a copy to avoid modifying original data
		filtered = copyFindings(filtered)
		RedactSensitiveData(filtered)
	}

	// Optionally strip evidence to reduce size
	if !opts.IncludeEvidence {
		filtered = stripEvidence(filtered)
	}

	// Build output structure
	output := struct {
		Findings []*finding.EnhancedFinding `json:"findings"`
		Metadata ExportMetadata             `json:"metadata"`
	}{
		Findings: filtered,
		Metadata: ExportMetadata{
			TotalCount:    len(findings),
			ExportedCount: len(filtered),
			FiltersApplied: FiltersApplied{
				MinSeverity:     opts.MinSeverity,
				DateFrom:        opts.DateFrom,
				DateTo:          opts.DateTo,
				Categories:      opts.Categories,
				IncludeResolved: opts.IncludeResolved,
				IncludeEvidence: opts.IncludeEvidence,
				RedactSensitive: opts.RedactSensitive,
			},
		},
	}

	// Marshal to JSON
	var data []byte
	var err error

	if e.Indent {
		data, err = json.MarshalIndent(output, "", "  ")
	} else {
		data, err = json.Marshal(output)
	}

	return data, err
}

// Format returns "json"
func (e *JSONExporter) Format() string {
	return "json"
}

// ContentType returns "application/json"
func (e *JSONExporter) ContentType() string {
	return "application/json"
}

// ExportMetadata contains metadata about the export operation
type ExportMetadata struct {
	TotalCount     int            `json:"total_count"`
	ExportedCount  int            `json:"exported_count"`
	FiltersApplied FiltersApplied `json:"filters_applied"`
}

// FiltersApplied describes which filters were applied during export
type FiltersApplied struct {
	MinSeverity     interface{} `json:"min_severity,omitempty"`
	DateFrom        interface{} `json:"date_from,omitempty"`
	DateTo          interface{} `json:"date_to,omitempty"`
	Categories      []string    `json:"categories,omitempty"`
	IncludeResolved bool        `json:"include_resolved"`
	IncludeEvidence bool        `json:"include_evidence"`
	RedactSensitive bool        `json:"redact_sensitive"`
}

// copyFindings creates a deep copy of findings to avoid modifying originals
func copyFindings(findings []*finding.EnhancedFinding) []*finding.EnhancedFinding {
	result := make([]*finding.EnhancedFinding, len(findings))
	for i, f := range findings {
		// Create a copy
		copied := *f
		result[i] = &copied
	}
	return result
}

// stripEvidence removes evidence from findings to reduce export size
func stripEvidence(findings []*finding.EnhancedFinding) []*finding.EnhancedFinding {
	result := make([]*finding.EnhancedFinding, len(findings))
	for i, f := range findings {
		copied := *f
		copied.Evidence = nil
		result[i] = &copied
	}
	return result
}

// Ensure JSONExporter implements Exporter interface
var _ Exporter = (*JSONExporter)(nil)
