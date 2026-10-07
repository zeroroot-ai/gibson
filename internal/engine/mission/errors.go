// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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

	// ErrMissionMissionFailed indicates mission execution failed.
	ErrMissionMissionFailed MissionErrorCode = "mission_failed"
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

// IsNotFoundError checks if an error is a mission not found error.
func IsNotFoundError(err error) bool {
	var missionErr *MissionError
	if errors.As(err, &missionErr) {
		return missionErr.Code == ErrMissionNotFound
	}
	return false
}
