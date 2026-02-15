package report

import (
	"fmt"

	"github.com/zero-day-ai/gibson/internal/types"
)

// Error types for report generation

var (
	// ErrReportNotFound is returned when a report cannot be found
	ErrReportNotFound = fmt.Errorf("report not found")

	// ErrMissionNotFound is returned when a mission cannot be found for reporting
	ErrMissionNotFound = fmt.Errorf("mission not found")

	// ErrInvalidReportType is returned when an invalid report type is specified
	ErrInvalidReportType = fmt.Errorf("invalid report type")

	// ErrInvalidReportFormat is returned when an invalid report format is specified
	ErrInvalidReportFormat = fmt.Errorf("invalid report format")

	// ErrTemplateNotFound is returned when a template cannot be found
	ErrTemplateNotFound = fmt.Errorf("template not found")

	// ErrTemplateRenderFailed is returned when template rendering fails
	ErrTemplateRenderFailed = fmt.Errorf("template rendering failed")

	// ErrExportFailed is returned when report export fails
	ErrExportFailed = fmt.Errorf("report export failed")

	// ErrStorageFailed is returned when report storage fails
	ErrStorageFailed = fmt.Errorf("report storage failed")

	// ErrInsufficientData is returned when there is not enough data to generate a report
	ErrInsufficientData = fmt.Errorf("insufficient data for report generation")

	// ErrAggregationFailed is returned when data aggregation fails
	ErrAggregationFailed = fmt.Errorf("data aggregation failed")

	// ErrComplianceMappingFailed is returned when compliance mapping fails
	ErrComplianceMappingFailed = fmt.Errorf("compliance mapping failed")

	// ErrRedactionFailed is returned when sensitive data redaction fails
	ErrRedactionFailed = fmt.Errorf("sensitive data redaction failed")

	// ErrValidationFailed is returned when report data validation fails
	ErrValidationFailed = fmt.Errorf("report validation failed")

	// ErrChromeMissing is returned when Chrome/Chromium is not available for PDF generation
	ErrChromeMissing = fmt.Errorf("Chrome/Chromium not found for PDF generation")

	// ErrTimeoutExceeded is returned when report generation exceeds timeout
	ErrTimeoutExceeded = fmt.Errorf("report generation timeout exceeded")
)

// ReportError represents a report-specific error with context
type ReportError struct {
	Op      string       // Operation that failed (e.g., "aggregate", "render", "export")
	Type    ReportType   // Report type being generated
	Format  ReportFormat // Report format being generated
	Err     error        // Underlying error
	Details string       // Additional error details
}

// Error implements the error interface
func (e *ReportError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("report error [%s] type=%s format=%s: %v (%s)",
			e.Op, e.Type, e.Format, e.Err, e.Details)
	}
	return fmt.Errorf("report error [%s] type=%s format=%s: %w",
		e.Op, e.Type, e.Format, e.Err).Error()
}

// Unwrap returns the underlying error
func (e *ReportError) Unwrap() error {
	return e.Err
}

// NewReportError creates a new ReportError
func NewReportError(op string, reportType ReportType, format ReportFormat, err error) *ReportError {
	return &ReportError{
		Op:     op,
		Type:   reportType,
		Format: format,
		Err:    err,
	}
}

// WithDetails adds additional details to a ReportError
func (e *ReportError) WithDetails(details string) *ReportError {
	e.Details = details
	return e
}

// AggregationError represents an error during data aggregation
type AggregationError struct {
	MissionID types.ID // Mission being aggregated
	Source    string   // Data source that failed (e.g., "findings", "graphrag", "timeline")
	Err       error    // Underlying error
}

// Error implements the error interface
func (e *AggregationError) Error() string {
	return fmt.Sprintf("aggregation error [source=%s mission=%s]: %v",
		e.Source, e.MissionID, e.Err)
}

// Unwrap returns the underlying error
func (e *AggregationError) Unwrap() error {
	return e.Err
}

// NewAggregationError creates a new AggregationError
func NewAggregationError(missionID types.ID, source string, err error) *AggregationError {
	return &AggregationError{
		MissionID: missionID,
		Source:    source,
		Err:       err,
	}
}

// TemplateError represents an error during template processing
type TemplateError struct {
	TemplateName string // Template being processed
	Section      string // Section that failed (if applicable)
	Line         int    // Line number where error occurred (if known)
	Err          error  // Underlying error
}

// Error implements the error interface
func (e *TemplateError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("template error [template=%s section=%s line=%d]: %v",
			e.TemplateName, e.Section, e.Line, e.Err)
	}
	if e.Section != "" {
		return fmt.Sprintf("template error [template=%s section=%s]: %v",
			e.TemplateName, e.Section, e.Err)
	}
	return fmt.Sprintf("template error [template=%s]: %v", e.TemplateName, e.Err)
}

// Unwrap returns the underlying error
func (e *TemplateError) Unwrap() error {
	return e.Err
}

// NewTemplateError creates a new TemplateError
func NewTemplateError(templateName string, err error) *TemplateError {
	return &TemplateError{
		TemplateName: templateName,
		Err:          err,
	}
}

// WithSection adds section context to a TemplateError
func (e *TemplateError) WithSection(section string) *TemplateError {
	e.Section = section
	return e
}

// WithLine adds line number context to a TemplateError
func (e *TemplateError) WithLine(line int) *TemplateError {
	e.Line = line
	return e
}

// ExportError represents an error during format export
type ExportError struct {
	Format ReportFormat // Format being exported to
	Reason string       // Human-readable reason for failure
	Err    error        // Underlying error
}

// Error implements the error interface
func (e *ExportError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("export error [format=%s]: %s: %v", e.Format, e.Reason, e.Err)
	}
	return fmt.Sprintf("export error [format=%s]: %v", e.Format, e.Err)
}

// Unwrap returns the underlying error
func (e *ExportError) Unwrap() error {
	return e.Err
}

// NewExportError creates a new ExportError
func NewExportError(format ReportFormat, err error) *ExportError {
	return &ExportError{
		Format: format,
		Err:    err,
	}
}

// WithReason adds a reason to an ExportError
func (e *ExportError) WithReason(reason string) *ExportError {
	e.Reason = reason
	return e
}

// ValidationError represents a validation error
type ValidationError struct {
	Field  string // Field that failed validation
	Value  any    // Invalid value
	Reason string // Reason for validation failure
}

// Error implements the error interface
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error [field=%s]: %s (value=%v)",
		e.Field, e.Reason, e.Value)
}

// NewValidationError creates a new ValidationError
func NewValidationError(field, reason string, value any) *ValidationError {
	return &ValidationError{
		Field:  field,
		Value:  value,
		Reason: reason,
	}
}

// StorageError represents an error during report storage
type StorageError struct {
	Operation string   // Operation that failed (save, load, delete, etc.)
	ReportID  types.ID // Report ID (if applicable)
	Path      string   // File path (if applicable)
	Err       error    // Underlying error
}

// Error implements the error interface
func (e *StorageError) Error() string {
	if !e.ReportID.IsZero() {
		return fmt.Sprintf("storage error [op=%s report=%s]: %v",
			e.Operation, e.ReportID, e.Err)
	}
	if e.Path != "" {
		return fmt.Sprintf("storage error [op=%s path=%s]: %v",
			e.Operation, e.Path, e.Err)
	}
	return fmt.Sprintf("storage error [op=%s]: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error
func (e *StorageError) Unwrap() error {
	return e.Err
}

// NewStorageError creates a new StorageError
func NewStorageError(operation string, err error) *StorageError {
	return &StorageError{
		Operation: operation,
		Err:       err,
	}
}

// WithReportID adds report ID context to a StorageError
func (e *StorageError) WithReportID(reportID types.ID) *StorageError {
	e.ReportID = reportID
	return e
}

// WithPath adds file path context to a StorageError
func (e *StorageError) WithPath(path string) *StorageError {
	e.Path = path
	return e
}
