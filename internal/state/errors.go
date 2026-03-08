package state

import (
	"errors"
	"fmt"
)

var (
	// ErrNotFound indicates that a requested key or document does not exist in Redis.
	// This is returned when a GET operation fails because the key is not present,
	// or when a JSON document path does not exist.
	ErrNotFound = errors.New("key or document not found")

	// ErrModuleNotAvailable indicates that a required Redis module is not loaded.
	// Gibson requires RediSearch and RedisJSON modules for state operations.
	// This error is returned by Health() when module detection fails.
	ErrModuleNotAvailable = errors.New("required Redis module not available")

	// ErrConnectionFailed indicates that the Redis connection could not be established
	// or has been lost. This is returned during client initialization or when
	// operations fail due to network issues.
	ErrConnectionFailed = errors.New("Redis connection failed")

	// ErrAlreadyExists indicates that a resource with a unique identifier already exists.
	// This is returned when attempting to create a resource with a name or key that
	// is already in use, such as credential names or mission names.
	ErrAlreadyExists = errors.New("resource already exists")
)

// IsNotFound checks if an error indicates a not-found condition.
// This helper function unwraps error chains and checks for ErrNotFound
// or redis.Nil errors.
//
// Example:
//
//	val, err := client.Get(ctx, "nonexistent")
//	if state.IsNotFound(err) {
//	    // Handle missing key
//	    return nil
//	}
func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrNotFound)
}

// ModuleError represents an error related to a specific Redis module.
// It provides additional context about which module is missing or misconfigured.
type ModuleError struct {
	// Module is the name of the Redis module (e.g., "search", "ReJSON")
	Module string
	// Err is the underlying error
	Err error
}

// Error implements the error interface.
func (e *ModuleError) Error() string {
	return fmt.Sprintf("module %q: %v", e.Module, e.Err)
}

// Unwrap returns the underlying error for error chain unwrapping.
func (e *ModuleError) Unwrap() error {
	return e.Err
}

// NewModuleError creates a new ModuleError.
func NewModuleError(module string, err error) *ModuleError {
	return &ModuleError{
		Module: module,
		Err:    err,
	}
}

// ConnectionError represents a connection-related error with additional context.
type ConnectionError struct {
	// Operation is the operation that failed (e.g., "dial", "ping", "auth")
	Operation string
	// Addr is the Redis address that failed to connect
	Addr string
	// Err is the underlying error
	Err error
}

// Error implements the error interface.
func (e *ConnectionError) Error() string {
	if e.Addr != "" {
		return fmt.Sprintf("connection failed during %s to %s: %v", e.Operation, e.Addr, e.Err)
	}
	return fmt.Sprintf("connection failed during %s: %v", e.Operation, e.Err)
}

// Unwrap returns the underlying error for error chain unwrapping.
func (e *ConnectionError) Unwrap() error {
	return e.Err
}

// NewConnectionError creates a new ConnectionError.
func NewConnectionError(operation, addr string, err error) *ConnectionError {
	return &ConnectionError{
		Operation: operation,
		Addr:      addr,
		Err:       err,
	}
}
