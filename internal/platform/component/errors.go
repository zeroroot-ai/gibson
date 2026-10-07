// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package component

import (
	"errors"
	"fmt"
)

// Sentinel errors for ComponentStore operations.
// These are simple errors that can be checked with errors.Is().
var (

	// ErrComponentNotFound is returned when a component is not found in the store.
	ErrComponentNotFound = errors.New("component not found")
)

// ComponentErrorCode represents specific error codes for component operations.
type ComponentErrorCode string

// Component error codes
const (
	ErrCodeComponentNotFound ComponentErrorCode = "COMPONENT_NOT_FOUND"
	ErrCodeLoadFailed        ComponentErrorCode = "LOAD_FAILED"
	ErrCodeStartFailed       ComponentErrorCode = "START_FAILED"
	ErrCodeExecutionFailed   ComponentErrorCode = "EXECUTION_FAILED"
)

// ComponentError represents a structured error for component operations.
// It includes error code, message, underlying cause, component context, and
// additional context for debugging and error handling.
type ComponentError struct {
	Code      ComponentErrorCode // Error code for programmatic handling
	Message   string             // Human-readable error message
	Cause     error              // Underlying error (if any)
	Component string             // Component name that caused the error
	Context   map[string]any     // Additional context for debugging
}

// Error implements the error interface, returning a formatted error message.
// Format: "[CODE] message" or "[CODE] message: cause" if cause exists.
func (e *ComponentError) Error() string {
	msg := fmt.Sprintf("[%s]", e.Code)

	if e.Component != "" {
		msg += fmt.Sprintf(" component=%s", e.Component)
	}

	msg += fmt.Sprintf(" %s", e.Message)

	if e.Cause != nil {
		msg += fmt.Sprintf(": %v", e.Cause)
	}

	return msg
}

// Unwrap returns the underlying cause error for error unwrapping chains.
// This enables using errors.Is() and errors.As() with wrapped errors.
func (e *ComponentError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error by error code.
// Returns true if target is a ComponentError with the same Code.
func (e *ComponentError) Is(target error) bool {
	var compErr *ComponentError
	if errors.As(target, &compErr) {
		return e.Code == compErr.Code
	}
	return false
}
