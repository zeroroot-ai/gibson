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
	// ErrStoreUnavailable is returned when the component store (etcd) is not available.
	ErrStoreUnavailable = errors.New("component store unavailable")

	// ErrComponentNotFound is returned when a component is not found in the store.
	ErrComponentNotFound = errors.New("component not found")

	// ErrComponentExists is returned when trying to create a component that already exists.
	ErrComponentExists = errors.New("component already exists")

	// ErrTransactionFailed is returned when an etcd transaction fails.
	ErrTransactionFailed = errors.New("transaction failed")
)

// ComponentErrorCode represents specific error codes for component operations.
type ComponentErrorCode string

// Component error codes
const (
	ErrCodeComponentNotFound    ComponentErrorCode = "COMPONENT_NOT_FOUND"
	ErrCodeComponentExists      ComponentErrorCode = "COMPONENT_EXISTS"
	ErrCodeInvalidManifest      ComponentErrorCode = "INVALID_MANIFEST"
	ErrCodeLoadFailed           ComponentErrorCode = "LOAD_FAILED"
	ErrCodeStartFailed          ComponentErrorCode = "START_FAILED"
	ErrCodeStopFailed           ComponentErrorCode = "STOP_FAILED"
	ErrCodeValidationFailed     ComponentErrorCode = "VALIDATION_FAILED"
	ErrCodeConnectionFailed     ComponentErrorCode = "CONNECTION_FAILED"
	ErrCodeExecutionFailed      ComponentErrorCode = "EXECUTION_FAILED"
	ErrCodeInvalidKind          ComponentErrorCode = "INVALID_KIND"
	ErrCodeInvalidSource        ComponentErrorCode = "INVALID_SOURCE"
	ErrCodeInvalidStatus        ComponentErrorCode = "INVALID_STATUS"
	ErrCodeInvalidPath          ComponentErrorCode = "INVALID_PATH"
	ErrCodeInvalidPort          ComponentErrorCode = "INVALID_PORT"
	ErrCodeInvalidVersion       ComponentErrorCode = "INVALID_VERSION"
	ErrCodeDependencyFailed     ComponentErrorCode = "DEPENDENCY_FAILED"
	ErrCodeIncompatibleVersion  ComponentErrorCode = "INCOMPATIBLE_VERSION"
	ErrCodeAlreadyRunning       ComponentErrorCode = "ALREADY_RUNNING"
	ErrCodeNotRunning           ComponentErrorCode = "NOT_RUNNING"
	ErrCodeTimeout              ComponentErrorCode = "TIMEOUT"
	ErrCodePermissionDenied     ComponentErrorCode = "PERMISSION_DENIED"
	ErrCodeUnsupportedOperation ComponentErrorCode = "UNSUPPORTED_OPERATION"
	ErrCodeHealthCheckFailed    ComponentErrorCode = "HEALTH_CHECK_FAILED"
	ErrCodeProtocolDetectFailed ComponentErrorCode = "PROTOCOL_DETECT_FAILED"
	ErrCodeInvalidProtocol      ComponentErrorCode = "INVALID_PROTOCOL"
	ErrCodeLogWriteFailed       ComponentErrorCode = "LOG_WRITE_FAILED"
	ErrCodeLogRotationFailed    ComponentErrorCode = "LOG_ROTATION_FAILED"
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
	Retryable bool               // Whether the operation can be retried
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

// Helper constructors for common error scenarios
