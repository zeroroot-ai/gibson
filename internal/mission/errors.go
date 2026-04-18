package mission

import (
	"errors"
	"fmt"
)

// MissionErrorCode represents specific mission error types.
type MissionErrorCode string

const (
	// ErrMissionNotFound indicates the mission was not found.
	ErrMissionNotFound MissionErrorCode = "mission_not_found"

	// ErrMissionInvalidState indicates an invalid state transition was attempted.
	ErrMissionInvalidState MissionErrorCode = "invalid_state_transition"

	// ErrMissionValidation indicates mission validation failed.
	ErrMissionValidation MissionErrorCode = "validation_failed"

	// ErrMissionTargetNotFound indicates the target was not found.
	ErrMissionTargetNotFound MissionErrorCode = "target_not_found"

	// ErrMissionMissionNotFound indicates the mission was not found.
	ErrMissionMissionNotFound MissionErrorCode = "mission_not_found"

	// ErrMissionMissionFailed indicates mission execution failed.
	ErrMissionMissionFailed MissionErrorCode = "mission_failed"

	// ErrMissionConstraint indicates a constraint was violated.
	ErrMissionConstraint MissionErrorCode = "constraint_violated"

	// ErrMissionApprovalDenied indicates an approval was denied.
	ErrMissionApprovalDenied MissionErrorCode = "approval_denied"

	// ErrMissionTimeout indicates the mission timed out.
	ErrMissionTimeout MissionErrorCode = "mission_timeout"

	// ErrMissionCheckpoint indicates checkpoint save/load failed.
	ErrMissionCheckpoint MissionErrorCode = "checkpoint_error"

	// ErrMissionCancelled indicates the mission was cancelled.
	ErrMissionCancelled MissionErrorCode = "mission_cancelled"

	// ErrMissionInternal indicates an internal mission error.
	ErrMissionInternal MissionErrorCode = "internal_error"
)

// MissionError represents a mission-specific error with code and context.
// It implements the error interface and supports error wrapping with errors.Is/As.
type MissionError struct {
	// Code identifies the specific error type.
	Code MissionErrorCode

	// Message is a human-readable error message.
	Message string

	// Cause is the underlying error that caused this error (optional).
	Cause error

	// Context provides additional contextual information about the error.
	Context map[string]any
}

// Error implements the error interface.
func (e *MissionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap implements the errors.Unwrap interface for error chain traversal.
// This enables errors.Is and errors.As to work with wrapped errors.
func (e *MissionError) Unwrap() error {
	return e.Cause
}

// Is implements the errors.Is interface for error comparison.
// Two MissionErrors are equal if they have the same error code.
func (e *MissionError) Is(target error) bool {
	var missionErr *MissionError
	if errors.As(target, &missionErr) {
		return e.Code == missionErr.Code
	}
	return false
}

// WithContext adds contextual information to the error.
func (e *MissionError) WithContext(key string, value any) *MissionError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// NewMissionError creates a new MissionError with the given code and message.
func NewMissionError(code MissionErrorCode, message string) *MissionError {
	return &MissionError{
		Code:    code,
		Message: message,
		Context: make(map[string]any),
	}
}

// WrapMissionError wraps an existing error with mission error context.
func WrapMissionError(code MissionErrorCode, message string, cause error) *MissionError {
	return &MissionError{
		Code:    code,
		Message: message,
		Cause:   cause,
		Context: make(map[string]any),
	}
}

// Helper functions for common mission errors

// NewNotFoundError creates a mission not found error.
func NewNotFoundError(missionID string) *MissionError {
	return NewMissionError(ErrMissionNotFound, fmt.Sprintf("mission not found: %s", missionID)).
		WithContext("mission_id", missionID)
}

// NewInvalidStateError creates an invalid state transition error.
func NewInvalidStateError(currentState, targetState MissionStatus) *MissionError {
	return NewMissionError(
		ErrMissionInvalidState,
		fmt.Sprintf("invalid state transition from %s to %s", currentState, targetState),
	).WithContext("current_state", currentState).
		WithContext("target_state", targetState)
}

// NewValidationError creates a validation error.
func NewValidationError(message string) *MissionError {
	return NewMissionError(ErrMissionValidation, message)
}

// NewTargetNotFoundError creates a target not found error.
func NewTargetNotFoundError(targetID string) *MissionError {
	return NewMissionError(ErrMissionTargetNotFound, fmt.Sprintf("target not found: %s", targetID)).
		WithContext("target_id", targetID)
}

// NewMissionNotFoundError creates a mission not found error.
func NewMissionNotFoundError(missionDefinitionID string) *MissionError {
	return NewMissionError(ErrMissionMissionNotFound, fmt.Sprintf("mission not found: %s", missionDefinitionID)).
		WithContext("mission_definition_id", missionDefinitionID)
}

// NewMissionFailedError creates a mission execution failed error.
func NewMissionFailedError(missionDefinitionID string, cause error) *MissionError {
	return WrapMissionError(
		ErrMissionMissionFailed,
		fmt.Sprintf("mission execution failed: %s", missionDefinitionID),
		cause,
	).WithContext("mission_definition_id", missionDefinitionID)
}

// NewConstraintViolationError creates a constraint violation error.
func NewConstraintViolationError(violation *ConstraintViolation) *MissionError {
	return NewMissionError(
		ErrMissionConstraint,
		violation.Message,
	).WithContext("constraint", violation.Constraint).
		WithContext("action", violation.Action).
		WithContext("current_value", violation.CurrentValue).
		WithContext("threshold_value", violation.ThresholdValue)
}

// NewApprovalDeniedError creates an approval denied error.
func NewApprovalDeniedError(reason string) *MissionError {
	return NewMissionError(
		ErrMissionApprovalDenied,
		fmt.Sprintf("approval denied: %s", reason),
	).WithContext("reason", reason)
}

// NewTimeoutError creates a mission timeout error.
func NewTimeoutError(maxDuration string) *MissionError {
	return NewMissionError(
		ErrMissionTimeout,
		fmt.Sprintf("mission exceeded maximum duration: %s", maxDuration),
	).WithContext("max_duration", maxDuration)
}

// NewCheckpointError creates a checkpoint error.
func NewCheckpointError(operation string, cause error) *MissionError {
	return WrapMissionError(
		ErrMissionCheckpoint,
		fmt.Sprintf("checkpoint %s failed", operation),
		cause,
	).WithContext("operation", operation)
}

// NewCancelledError creates a mission cancelled error.
func NewCancelledError(reason string) *MissionError {
	return NewMissionError(
		ErrMissionCancelled,
		fmt.Sprintf("mission cancelled: %s", reason),
	).WithContext("reason", reason)
}

// NewInternalError creates an internal mission error.
func NewInternalError(message string, cause error) *MissionError {
	return WrapMissionError(ErrMissionInternal, message, cause)
}

// IsNotFoundError checks if an error is a mission not found error.
func IsNotFoundError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionNotFound
	}
	return false
}

// IsInvalidStateError checks if an error is an invalid state transition error.
func IsInvalidStateError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionInvalidState
	}
	return false
}

// IsValidationError checks if an error is a validation error.
func IsValidationError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionValidation
	}
	return false
}

// IsConstraintViolationError checks if an error is a constraint violation error.
func IsConstraintViolationError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionConstraint
	}
	return false
}

// IsTimeoutError checks if an error is a timeout error.
func IsTimeoutError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionTimeout
	}
	return false
}

// IsCancelledError checks if an error is a cancelled error.
func IsCancelledError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionCancelled
	}
	return false
}
