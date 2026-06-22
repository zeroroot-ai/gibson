package authz

import (
	"errors"
	"fmt"
)

// Sentinel errors for the authz package.
//
// Callers distinguish between transport failures (ErrFgaUnavailable, ErrFgaTimeout)
// and logical denials (ErrPermissionDenied) to decide on fail-closed vs fail-open
// behavior when FGA cannot be reached.
var (
	// ErrFgaUnavailable is returned when the FGA service cannot be reached due
	// to a network error, connection refused, or gRPC Unavailable status.
	// Callers should treat this as an infrastructure failure, not a denial.
	ErrFgaUnavailable = errors.New("authz: fga service unavailable")

	// ErrFgaTimeout is returned when a FGA call exceeds the configured timeout_ms.
	// The OTel span records timeout=true. Callers decide whether to retry.
	ErrFgaTimeout = errors.New("authz: fga call timed out")

	// ErrPermissionDenied is returned when FGA explicitly denies the check.
	// This is distinct from ErrFgaUnavailable — the service responded, but the
	// answer was "no".
	ErrPermissionDenied = errors.New("authz: permission denied")

	// ErrInvalidArgument is returned when user, relation, or object is empty.
	// FGA is not consulted; the validation happens in the wrapper before the call.
	ErrInvalidArgument = errors.New("authz: invalid argument")

	// ErrModelNotFound is returned when the specified authorization model ID
	// does not exist in the FGA store.
	ErrModelNotFound = errors.New("authz: authorization model not found")
)

// FgaError wraps a low-level FGA SDK error with additional context.
//
// It preserves the underlying error for unwrapping while providing a
// human-readable message and the specific sentinel error type.
type FgaError struct {
	// Sentinel is the typed sentinel error (ErrFgaUnavailable, etc.)
	Sentinel error

	// Message is the human-readable description of what went wrong.
	Message string

	// Cause is the underlying SDK or network error.
	Cause error
}

// Error implements the error interface.
func (e *FgaError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Sentinel, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Sentinel, e.Message)
}

// Unwrap returns the sentinel error so that errors.Is works for typed checking.
//
// Example: errors.Is(err, authz.ErrFgaUnavailable) returns true when the
// underlying failure is an FGA unavailability error.
func (e *FgaError) Unwrap() error {
	return e.Sentinel
}

// newUnavailableError creates an FgaError wrapping ErrFgaUnavailable.
func newUnavailableError(msg string, cause error) error {
	return &FgaError{
		Sentinel: ErrFgaUnavailable,
		Message:  msg,
		Cause:    cause,
	}
}

// newTimeoutError creates an FgaError wrapping ErrFgaTimeout.
func newTimeoutError(msg string, cause error) error {
	return &FgaError{
		Sentinel: ErrFgaTimeout,
		Message:  msg,
		Cause:    cause,
	}
}

// newInvalidArgumentError creates an FgaError wrapping ErrInvalidArgument.
func newInvalidArgumentError(msg string) error {
	return &FgaError{
		Sentinel: ErrInvalidArgument,
		Message:  msg,
	}
}

// newModelNotFoundError creates an FgaError wrapping ErrModelNotFound.
func newModelNotFoundError(modelID string) error {
	return &FgaError{
		Sentinel: ErrModelNotFound,
		Message:  fmt.Sprintf("model ID %q not found in store", modelID),
	}
}

// IsUnavailable reports whether err is an FGA unavailability error.
func IsUnavailable(err error) bool {
	return errors.Is(err, ErrFgaUnavailable)
}

// IsTimeout reports whether err is an FGA timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrFgaTimeout)
}

// IsInvalidArgument reports whether err is an invalid argument error.
func IsInvalidArgument(err error) bool {
	return errors.Is(err, ErrInvalidArgument)
}

// IsPermissionDenied reports whether err is a permission denied error.
func IsPermissionDenied(err error) bool {
	return errors.Is(err, ErrPermissionDenied)
}

// IsModelNotFound reports whether err is a model not found error.
func IsModelNotFound(err error) bool {
	return errors.Is(err, ErrModelNotFound)
}
