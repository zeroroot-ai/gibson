package export

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"strings"

	"github.com/zeroroot-ai/gibson/internal/finding"
)

// CSVExporter exports findings in CSV format.
// Thread-safe for concurrent use.
type CSVExporter struct {
	// Columns defines which fields to include in the CSV.
	// If empty, uses default columns.
	Columns []string

	// Delimiter is the field delimiter (default: comma)
	Delimiter rune
}

// Default column names
var DefaultCSVColumns = []string{
	"ID",
	"Title",
	"Severity",
	"Category",
	"Subcategory",
	"Status",
	"RiskScore",
	"Confidence",
	"OccurrenceCount",
	"CreatedAt",
	"MissionID",
	"AgentName",
	"MitreTechniques",
	"CWE",
	"EvidenceCount",
}

// NewCSVExporter creates a new CSV exporter with default columns
func NewCSVExporter() *CSVExporter {
	return &CSVExporter{
		Columns:   DefaultCSVColumns,
		Delimiter: ',',
	}
}

// WithColumns configures custom columns
func (e *CSVExporter) WithColumns(columns ...string) *CSVExporter {
	e.Columns = columns
	return e
}

// WithDelimiter configures a custom delimiter (e.g., tab, semicolon)
func (e *CSVExporter) WithDelimiter(delimiter rune) *CSVExporter {
	e.Delimiter = delimiter
	return e
}

// Export converts findings to CSV format
func (e *CSVExporter) Export(ctx context.Context, findings []*finding.EnhancedFinding, opts ExportOptions) ([]byte, error) {
	// Apply filters
	filtered := ApplyFilters(findings, opts)

	// Create CSV writer
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	writer.Comma = e.Delimiter

	// Write header row
	if err := writer.Write(e.Columns); err != nil {
		return nil, fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data rows
	for _, f := range filtered {
		row := e.buildRow(f, opts)
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	// Flush any buffered data
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return buf.Bytes(), nil
}

// Format returns "csv"
func (e *CSVExporter) Format() string {
	return "csv"
}

// ContentType returns "text/csv"
func (e *CSVExporter) ContentType() string {
	return "text/csv"
}

// buildRow creates a CSV row for a finding based on configured columns
func (e *CSVExporter) buildRow(f *finding.EnhancedFinding, opts ExportOptions) []string {
	row := make([]string, len(e.Columns))

	for i, col := range e.Columns {
		row[i] = e.getFieldValue(f, col, opts)
	}

	return row
}

// getFieldValue extracts a field value from a finding
func (e *CSVExporter) getFieldValue(f *finding.EnhancedFinding, fieldName string, opts ExportOptions) string {
	switch fieldName {
	case "ID":
		return f.ID.String()

	case "Title":
		return escapeCsvField(f.Title)

	case "Description":
		// Truncate long descriptions
		desc := f.Description
		if len(desc) > 200 {
			desc = desc[:200] + "..."
		}
		return escapeCsvField(desc)

	case "Severity":
		return string(f.Severity)

	case "Category":
		return escapeCsvField(f.Category)

	case "Subcategory":
		return escapeCsvField(f.Subcategory)

	case "Status":
		return string(f.Status)

	case "RiskScore":
		return fmt.Sprintf("%.2f", f.RiskScore)

	case "Confidence":
		return fmt.Sprintf("%.2f", f.Confidence)

	case "OccurrenceCount":
		return fmt.Sprintf("%d", f.OccurrenceCount)

	case "CreatedAt":
		return f.CreatedAt.Format("2006-01-02 15:04:05")

	case "UpdatedAt":
		return f.UpdatedAt.Format("2006-01-02 15:04:05")

	case "MissionID":
		return f.MissionID.String()

	case "AgentName":
		return escapeCsvField(f.AgentName)

	case "DelegatedFrom":
		if f.DelegatedFrom != nil {
			return escapeCsvField(*f.DelegatedFrom)
		}
		return ""

	case "TargetID":
		if f.TargetID != nil {
			return f.TargetID.String()
		}
		return ""

	case "MitreTechniques":
		return joinMitreTechniques(f)

	case "CWE":
		return strings.Join(f.CWE, "; ")

	case "EvidenceCount":
		return fmt.Sprintf("%d", len(f.Evidence))

	case "Remediation":
		return escapeCsvField(f.Remediation)

	case "References":
		return strings.Join(f.References, "; ")

	case "CVSS":
		if f.CVSS != nil {
			return fmt.Sprintf("%s (%.1f)", f.CVSS.Vector, f.CVSS.Score)
		}
		return ""

	default:
		return ""
	}
}

// escapeCsvField escapes special characters in CSV fields
func escapeCsvField(s string) string {
	// Remove newlines and carriage returns
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	// Remove multiple spaces
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// joinMitreTechniques combines MITRE ATT&CK and ATLAS techniques into a single field
func joinMitreTechniques(f *finding.EnhancedFinding) string {
	var techniques []string

	// Add ATT&CK techniques
	for _, m := range f.GetMitreAttack() {
		techniques = append(techniques, m.TechniqueID)
	}

	// Add ATLAS techniques
	for _, m := range f.GetMitreAtlas() {
		techniques = append(techniques, m.TechniqueID)
	}

	return strings.Join(techniques, "; ")
}

// Ensure CSVExporter implements Exporter interface
var _ Exporter = (*CSVExporter)(nil)
