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
	ErrCodeManifestNotFound     ComponentErrorCode = "MANIFEST_NOT_FOUND"
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

// WithContext adds additional context to the error for debugging.
// Returns the error for method chaining.
func (e *ComponentError) WithContext(key string, value any) *ComponentError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// WithComponent adds the component name that caused the error.
// Returns the error for method chaining.
func (e *ComponentError) WithComponent(component string) *ComponentError {
	e.Component = component
	return e
}

// NewComponentError creates a new non-retryable ComponentError with the given code and message.
func NewComponentError(code ComponentErrorCode, message string) *ComponentError {
	return &ComponentError{
		Code:      code,
		Message:   message,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewRetryableComponentError creates a new retryable ComponentError with the given code and message.
// Use this for transient errors that may succeed on retry (e.g., network timeouts, temporary failures).
func NewRetryableComponentError(code ComponentErrorCode, message string) *ComponentError {
	return &ComponentError{
		Code:      code,
		Message:   message,
		Context:   make(map[string]any),
		Retryable: true,
	}
}

// WrapComponentError creates a new ComponentError that wraps an existing error.
// The wrapped error is accessible via Unwrap() for error chain inspection.
func WrapComponentError(code ComponentErrorCode, message string, cause error) *ComponentError {
	return &ComponentError{
		Code:      code,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// Helper constructors for common error scenarios

// NewComponentNotFoundError creates a component not found error.
// This is non-retryable as retrying won't make the component exist.
func NewComponentNotFoundError(name string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeComponentNotFound,
		Message:   fmt.Sprintf("component not found: %s", name),
		Component: name,
		Context: map[string]any{
			"component": name,
		},
		Retryable: false,
	}
}

// NewComponentExistsError creates a component already exists error.
// This is non-retryable as the component already exists.
func NewComponentExistsError(name string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeComponentExists,
		Message:   fmt.Sprintf("component already exists: %s", name),
		Component: name,
		Context: map[string]any{
			"component": name,
		},
		Retryable: false,
	}
}

// NewInvalidManifestError creates an invalid manifest error.
// This is non-retryable as the manifest needs to be fixed.
func NewInvalidManifestError(message string, cause error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeInvalidManifest,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewManifestNotFoundError creates a manifest not found error.
// This is non-retryable as retrying won't make the manifest exist.
func NewManifestNotFoundError(path string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeManifestNotFound,
		Message: fmt.Sprintf("manifest not found at path: %s", path),
		Context: map[string]any{
			"path": path,
		},
		Retryable: false,
	}
}

// NewLoadFailedError creates a component load failure error.
// This may be retryable depending on the cause.
func NewLoadFailedError(component string, cause error, retryable bool) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeLoadFailed,
		Message:   fmt.Sprintf("failed to load component: %s", component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: retryable,
	}
}

// NewStartFailedError creates a component start failure error.
// This may be retryable depending on the cause.
func NewStartFailedError(component string, cause error, retryable bool) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeStartFailed,
		Message:   fmt.Sprintf("failed to start component: %s", component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: retryable,
	}
}

// NewStopFailedError creates a component stop failure error.
// This may be retryable depending on the cause.
func NewStopFailedError(component string, cause error, retryable bool) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeStopFailed,
		Message:   fmt.Sprintf("failed to stop component: %s", component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: retryable,
	}
}

// NewValidationFailedError creates a validation failure error.
// This is non-retryable as the data needs to be fixed.
func NewValidationFailedError(message string, cause error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeValidationFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewConnectionFailedError creates a connection failure error.
// This is typically retryable as network issues may be transient.
func NewConnectionFailedError(component string, cause error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeConnectionFailed,
		Message:   fmt.Sprintf("failed to connect to component: %s", component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: true,
	}
}

// NewExecutionFailedError creates a component execution failure error.
// This may be retryable depending on the cause.
func NewExecutionFailedError(component string, cause error, retryable bool) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeExecutionFailed,
		Message:   fmt.Sprintf("component execution failed: %s", component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: retryable,
	}
}

// NewInvalidKindError creates an invalid component kind error.
// This is non-retryable as the kind needs to be fixed.
func NewInvalidKindError(kind string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidKind,
		Message: "component kind cannot be empty",
		Context: map[string]any{
			"kind": kind,
		},
		Retryable: false,
	}
}

// NewInvalidSourceError creates an invalid component source error.
// This is non-retryable as the source needs to be fixed.
func NewInvalidSourceError(source string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidSource,
		Message: fmt.Sprintf("invalid component source: %s", source),
		Context: map[string]any{
			"source": source,
		},
		Retryable: false,
	}
}

// NewInvalidStatusError creates an invalid component status error.
// This is non-retryable as the status needs to be fixed.
func NewInvalidStatusError(status string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidStatus,
		Message: fmt.Sprintf("invalid component status: %s", status),
		Context: map[string]any{
			"status": status,
		},
		Retryable: false,
	}
}

// NewInvalidPathError creates an invalid path error.
// This is non-retryable as the path needs to be fixed.
func NewInvalidPathError(path string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidPath,
		Message: fmt.Sprintf("invalid component path: %s", path),
		Context: map[string]any{
			"path": path,
		},
		Retryable: false,
	}
}

// NewInvalidPortError creates an invalid port error.
// This is non-retryable as the port needs to be fixed.
func NewInvalidPortError(port int) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidPort,
		Message: fmt.Sprintf("invalid port: %d (must be between 1 and 65535)", port),
		Context: map[string]any{
			"port": port,
		},
		Retryable: false,
	}
}

// NewInvalidVersionError creates an invalid version error.
// This is non-retryable as the version needs to be fixed.
func NewInvalidVersionError(version string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidVersion,
		Message: fmt.Sprintf("invalid version: %s", version),
		Context: map[string]any{
			"version": version,
		},
		Retryable: false,
	}
}

// NewDependencyFailedError creates a dependency failure error.
// This may be retryable depending on the cause.
func NewDependencyFailedError(component string, dependency string, cause error, retryable bool) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeDependencyFailed,
		Message:   fmt.Sprintf("dependency %s failed for component %s", dependency, component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component":  component,
			"dependency": dependency,
		},
		Retryable: retryable,
	}
}

// NewIncompatibleVersionError creates an incompatible version error.
// This is non-retryable as the version needs to be changed.
func NewIncompatibleVersionError(component string, required string, actual string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeIncompatibleVersion,
		Message:   fmt.Sprintf("incompatible version for component %s: required %s, got %s", component, required, actual),
		Component: component,
		Context: map[string]any{
			"component": component,
			"required":  required,
			"actual":    actual,
		},
		Retryable: false,
	}
}

// NewAlreadyRunningError creates an already running error.
// This is non-retryable as the component is already running.
func NewAlreadyRunningError(component string, pid int) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeAlreadyRunning,
		Message:   fmt.Sprintf("component %s is already running (PID: %d)", component, pid),
		Component: component,
		Context: map[string]any{
			"component": component,
			"pid":       pid,
		},
		Retryable: false,
	}
}

// NewNotRunningError creates a not running error.
// This is non-retryable as the component needs to be started first.
func NewNotRunningError(component string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeNotRunning,
		Message:   fmt.Sprintf("component %s is not running", component),
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: false,
	}
}

// NewTimeoutError creates a timeout error.
// This is typically retryable as timeouts may be transient.
func NewTimeoutError(component string, operation string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeTimeout,
		Message:   fmt.Sprintf("timeout during %s for component %s", operation, component),
		Component: component,
		Context: map[string]any{
			"component": component,
			"operation": operation,
		},
		Retryable: true,
	}
}

// NewPermissionDeniedError creates a permission denied error.
// This is non-retryable as permissions need to be fixed.
func NewPermissionDeniedError(component string, operation string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodePermissionDenied,
		Message:   fmt.Sprintf("permission denied for %s on component %s", operation, component),
		Component: component,
		Context: map[string]any{
			"component": component,
			"operation": operation,
		},
		Retryable: false,
	}
}

// NewUnsupportedOperationError creates an unsupported operation error.
// This is non-retryable as the operation is not supported.
func NewUnsupportedOperationError(component string, operation string) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeUnsupportedOperation,
		Message:   fmt.Sprintf("unsupported operation %s for component %s", operation, component),
		Component: component,
		Context: map[string]any{
			"component": component,
			"operation": operation,
		},
		Retryable: false,
	}
}

// NewHealthCheckError creates a health check failure error with protocol context.
// This is typically retryable as health check failures may be transient.
func NewHealthCheckError(component string, protocol string, cause error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeHealthCheckFailed,
		Message:   fmt.Sprintf("%s health check failed for component %s", protocol, component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
			"protocol":  protocol,
		},
		Retryable: true,
	}
}

// NewProtocolDetectError creates a protocol detection failure error.
// This is typically retryable as detection may succeed on retry.
func NewProtocolDetectError(component string, cause error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeProtocolDetectFailed,
		Message:   fmt.Sprintf("failed to detect health check protocol for component %s", component),
		Cause:     cause,
		Component: component,
		Context: map[string]any{
			"component": component,
		},
		Retryable: true,
	}
}

// NewInvalidProtocolError creates an invalid protocol error.
// This is non-retryable as the protocol configuration needs to be fixed.
func NewInvalidProtocolError(protocol string) *ComponentError {
	return &ComponentError{
		Code:    ErrCodeInvalidProtocol,
		Message: fmt.Sprintf("invalid health check protocol: %s (must be 'http', 'grpc', or 'auto')", protocol),
		Context: map[string]any{
			"protocol": protocol,
		},
		Retryable: false,
	}
}

// NewLogWriteError creates an error for failed log write operations.
// This may be retryable depending on the cause (e.g., disk space, permissions).
func NewLogWriteError(componentName string, err error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeLogWriteFailed,
		Message:   fmt.Sprintf("failed to write log for component: %s", componentName),
		Cause:     err,
		Component: componentName,
		Context: map[string]any{
			"component": componentName,
		},
		Retryable: true,
	}
}

// NewLogRotationError creates an error for failed log rotation operations.
// This may be retryable depending on the cause (e.g., disk space, file locks).
func NewLogRotationError(componentName string, err error) *ComponentError {
	return &ComponentError{
		Code:      ErrCodeLogRotationFailed,
		Message:   fmt.Sprintf("failed to rotate log for component: %s", componentName),
		Cause:     err,
		Component: componentName,
		Context: map[string]any{
			"component": componentName,
		},
		Retryable: true,
	}
}
