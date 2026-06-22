package finding

import (
	"fmt"
)

// FindingErrorCode represents specific error codes for finding operations
type FindingErrorCode string

const (
	ErrorClassificationFailed FindingErrorCode = "classification_failed"
	ErrorLLMTimeout           FindingErrorCode = "llm_timeout"
	ErrorStoreFailed          FindingErrorCode = "store_failed"
	ErrorExportFailed         FindingErrorCode = "export_failed"
	ErrorDuplicateConflict    FindingErrorCode = "duplicate_conflict"
	ErrorMitreNotFound        FindingErrorCode = "mitre_not_found"
	ErrorInvalidFinding       FindingErrorCode = "invalid_finding"
)

// FindingError represents a domain-specific error for finding operations
type FindingError struct {
	Code    FindingErrorCode
	Message string
	Cause   error
}

// Error implements the error interface
func (e *FindingError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error cause
func (e *FindingError) Unwrap() error {
	return e.Cause
}

// Is enables error comparison using errors.Is
func (e *FindingError) Is(target error) bool {
	t, ok := target.(*FindingError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

// NewFindingError creates a new finding error with the given code and message
func NewFindingError(code FindingErrorCode, message string, cause error) *FindingError {
	return &FindingError{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// NewClassificationError creates an error for classification failures
func NewClassificationError(message string, cause error) *FindingError {
	return &FindingError{
		Code:    ErrorClassificationFailed,
		Message: message,
		Cause:   cause,
	}
}

// NewLLMTimeoutError creates an error for LLM timeout
func NewLLMTimeoutError(message string, cause error) *FindingError {
	return &FindingError{
		Code:    ErrorLLMTimeout,
		Message: message,
		Cause:   cause,
	}
}

// NewStoreError creates an error for storage operations
func NewStoreError(message string, cause error) *FindingError {
	return &FindingError{
		Code:    ErrorStoreFailed,
		Message: message,
		Cause:   cause,
	}
}

// NewExportError creates an error for export operations
func NewExportError(message string, cause error) *FindingError {
	return &FindingError{
		Code:    ErrorExportFailed,
		Message: message,
		Cause:   cause,
	}
}

// NewDuplicateError creates an error for duplicate finding conflicts
func NewDuplicateError(message string, cause error) *FindingError {
	return &FindingError{
		Code:    ErrorDuplicateConflict,
		Message: message,
		Cause:   cause,
	}
}

// NewMitreNotFoundError creates an error when a MITRE technique is not found
func NewMitreNotFoundError(techniqueID string) *FindingError {
	return &FindingError{
		Code:    ErrorMitreNotFound,
		Message: fmt.Sprintf("MITRE technique not found: %s", techniqueID),
		Cause:   nil,
	}
}

// NewInvalidFindingError creates an error for invalid finding data
func NewInvalidFindingError(message string, cause error) *FindingError {
	return &FindingError{
		Code:    ErrorInvalidFinding,
		Message: message,
		Cause:   cause,
	}
}

// IsClassificationError checks if the error is a classification error
func IsClassificationError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorClassificationFailed
}

// IsLLMTimeoutError checks if the error is an LLM timeout error
func IsLLMTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorLLMTimeout
}

// IsStoreError checks if the error is a store error
func IsStoreError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorStoreFailed
}

// IsExportError checks if the error is an export error
func IsExportError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorExportFailed
}

// IsDuplicateError checks if the error is a duplicate error
func IsDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorDuplicateConflict
}

// IsMitreNotFoundError checks if the error is a MITRE not found error
func IsMitreNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorMitreNotFound
}

// IsInvalidFindingError checks if the error is an invalid finding error
func IsInvalidFindingError(err error) bool {
	if err == nil {
		return false
	}
	fe, ok := err.(*FindingError)
	return ok && fe.Code == ErrorInvalidFinding
}
