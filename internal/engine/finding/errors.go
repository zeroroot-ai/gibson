// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
