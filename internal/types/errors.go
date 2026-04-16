package types

import (
	"errors"
	"fmt"
)

// ErrorCode represents a namespaced error code for Gibson framework errors.
type ErrorCode string

// Configuration error codes
const (
	CONFIG_LOAD_FAILED       ErrorCode = "CONFIG_LOAD_FAILED"
	CONFIG_PARSE_FAILED      ErrorCode = "CONFIG_PARSE_FAILED"
	CONFIG_VALIDATION_FAILED ErrorCode = "CONFIG_VALIDATION_FAILED"
	CONFIG_NOT_FOUND         ErrorCode = "CONFIG_NOT_FOUND"
)

// Database error codes
const (
	DB_OPEN_FAILED      ErrorCode = "DB_OPEN_FAILED"
	DB_MIGRATION_FAILED ErrorCode = "DB_MIGRATION_FAILED"
	DB_QUERY_FAILED     ErrorCode = "DB_QUERY_FAILED"
	DB_CONNECTION_LOST  ErrorCode = "DB_CONNECTION_LOST"
)

// Cryptography error codes
const (
	CRYPTO_ENCRYPT_FAILED        ErrorCode = "CRYPTO_ENCRYPT_FAILED"
	CRYPTO_DECRYPT_FAILED        ErrorCode = "CRYPTO_DECRYPT_FAILED"
	CRYPTO_KEY_GENERATION_FAILED ErrorCode = "CRYPTO_KEY_GENERATION_FAILED"
	CRYPTO_KEY_NOT_FOUND         ErrorCode = "CRYPTO_KEY_NOT_FOUND"
)

// Initialization error codes
const (
	INIT_DIRS_FAILED       ErrorCode = "INIT_DIRS_FAILED"
	INIT_CONFIG_FAILED     ErrorCode = "INIT_CONFIG_FAILED"
	INIT_DB_FAILED         ErrorCode = "INIT_DB_FAILED"
	INIT_VALIDATION_FAILED ErrorCode = "INIT_VALIDATION_FAILED"
)

// Target error codes
const (
	TARGET_NOT_FOUND         ErrorCode = "TARGET_NOT_FOUND"
	TARGET_INVALID           ErrorCode = "TARGET_INVALID"
	TARGET_CONNECTION_FAILED ErrorCode = "TARGET_CONNECTION_FAILED"
)

// Credential error codes
const (
	CREDENTIAL_NOT_FOUND ErrorCode = "CREDENTIAL_NOT_FOUND"
	CREDENTIAL_INVALID   ErrorCode = "CREDENTIAL_INVALID"
	CREDENTIAL_EXPIRED   ErrorCode = "CREDENTIAL_EXPIRED"
)

// Sandbox error codes — sandboxed tool execution path (SandboxedToolExecutor).
const (
	SANDBOX_TOOL_NOT_REGISTERED ErrorCode = "SANDBOX_TOOL_NOT_REGISTERED"
	SANDBOX_LAUNCH_FAILED       ErrorCode = "SANDBOX_LAUNCH_FAILED"
	SANDBOX_WAIT_TIMEOUT        ErrorCode = "SANDBOX_WAIT_TIMEOUT"
	SANDBOX_NON_ZERO_EXIT       ErrorCode = "SANDBOX_NON_ZERO_EXIT"
	SANDBOX_OUTPUT_MALFORMED    ErrorCode = "SANDBOX_OUTPUT_MALFORMED"
	SANDBOX_INPUT_TOO_LARGE     ErrorCode = "SANDBOX_INPUT_TOO_LARGE"
	SANDBOX_STREAM_LOGS_FAILED  ErrorCode = "SANDBOX_STREAM_LOGS_FAILED"
)

// GibsonError represents a structured error with error code, message, and optional cause.
// It supports error wrapping and retryability hints for error handling logic.
type GibsonError struct {
	Code      ErrorCode
	Message   string
	Retryable bool
	Cause     error
}

// Error implements the error interface, returning a formatted error message.
// Format: "[CODE] message" or "[CODE] message: cause" if cause exists.
func (e *GibsonError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error for error unwrapping chains.
// This enables using errors.Is() and errors.As() with wrapped errors.
func (e *GibsonError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error by error code.
// Returns true if target is a GibsonError with the same Code.
func (e *GibsonError) Is(target error) bool {
	var gibsonErr *GibsonError
	if errors.As(target, &gibsonErr) {
		return e.Code == gibsonErr.Code
	}
	return false
}

// NewError creates a new non-retryable GibsonError with the given code and message.
func NewError(code ErrorCode, message string) *GibsonError {
	return &GibsonError{
		Code:      code,
		Message:   message,
		Retryable: false,
		Cause:     nil,
	}
}

// NewRetryableError creates a new retryable GibsonError with the given code and message.
// Use this for transient errors that may succeed on retry (e.g., network timeouts).
func NewRetryableError(code ErrorCode, message string) *GibsonError {
	return &GibsonError{
		Code:      code,
		Message:   message,
		Retryable: true,
		Cause:     nil,
	}
}

// WrapError creates a new non-retryable GibsonError that wraps an existing error.
// The wrapped error is accessible via Unwrap() for error chain inspection.
func WrapError(code ErrorCode, message string, cause error) *GibsonError {
	return &GibsonError{
		Code:      code,
		Message:   message,
		Retryable: false,
		Cause:     cause,
	}
}
