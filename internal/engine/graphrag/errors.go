package graphrag

import (
	"errors"
	"fmt"
)

// GraphRAGErrorCode represents specific error codes for GraphRAG operations.
type GraphRAGErrorCode string

// GraphRAG error codes
const (
	ErrCodeConnectionFailed     GraphRAGErrorCode = "CONNECTION_FAILED"
	ErrCodeQueryFailed          GraphRAGErrorCode = "QUERY_FAILED"
	ErrCodeNodeNotFound         GraphRAGErrorCode = "NODE_NOT_FOUND"
	ErrCodeRelationshipFailed   GraphRAGErrorCode = "RELATIONSHIP_FAILED"
	ErrCodeEmbeddingFailed      GraphRAGErrorCode = "EMBEDDING_FAILED"
	ErrCodeAuthenticationFailed GraphRAGErrorCode = "AUTHENTICATION_FAILED"
	ErrCodeRateLimited          GraphRAGErrorCode = "RATE_LIMITED"
	ErrCodeProviderUnavailable  GraphRAGErrorCode = "PROVIDER_UNAVAILABLE"
	ErrCodeInvalidQuery         GraphRAGErrorCode = "INVALID_QUERY"
	ErrCodeIndexFailed          GraphRAGErrorCode = "INDEX_FAILED"
	ErrCodeTransactionFailed    GraphRAGErrorCode = "TRANSACTION_FAILED"
	ErrCodeInvalidConfig        GraphRAGErrorCode = "INVALID_CONFIG"
)

// GraphRAGError represents a structured error for GraphRAG operations.
// It includes error code, message, underlying cause, query context, and
// additional context for debugging and error handling.
type GraphRAGError struct {
	Code      GraphRAGErrorCode // Error code for programmatic handling
	Message   string            // Human-readable error message
	Cause     error             // Underlying error (if any)
	Query     string            // Query that caused the error (if applicable)
	Context   map[string]any    // Additional context for debugging
	Retryable bool              // Whether the operation can be retried
}

// Error implements the error interface, returning a formatted error message.
// Format: "[CODE] message" or "[CODE] message: cause" if cause exists.
func (e *GraphRAGError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error for error unwrapping chains.
// This enables using errors.Is() and errors.As() with wrapped errors.
func (e *GraphRAGError) Unwrap() error {
	return e.Cause
}

// Is checks if the target error matches this error by error code.
// Returns true if target is a GraphRAGError with the same Code.
func (e *GraphRAGError) Is(target error) bool {
	var graphErr *GraphRAGError
	if errors.As(target, &graphErr) {
		return e.Code == graphErr.Code
	}
	return false
}

// WithContext adds additional context to the error for debugging.
// Returns the error for method chaining.
func (e *GraphRAGError) WithContext(key string, value any) *GraphRAGError {
	if e.Context == nil {
		e.Context = make(map[string]any)
	}
	e.Context[key] = value
	return e
}

// WithQuery adds the query that caused the error.
// Returns the error for method chaining.
func (e *GraphRAGError) WithQuery(query string) *GraphRAGError {
	e.Query = query
	return e
}

// NewGraphRAGError creates a new non-retryable GraphRAGError with the given code and message.
func NewGraphRAGError(code GraphRAGErrorCode, message string) *GraphRAGError {
	return &GraphRAGError{
		Code:      code,
		Message:   message,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewRetryableGraphRAGError creates a new retryable GraphRAGError with the given code and message.
// Use this for transient errors that may succeed on retry (e.g., network timeouts, rate limits).
func NewRetryableGraphRAGError(code GraphRAGErrorCode, message string) *GraphRAGError {
	return &GraphRAGError{
		Code:      code,
		Message:   message,
		Context:   make(map[string]any),
		Retryable: true,
	}
}

// WrapGraphRAGError creates a new GraphRAGError that wraps an existing error.
// The wrapped error is accessible via Unwrap() for error chain inspection.
func WrapGraphRAGError(code GraphRAGErrorCode, message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      code,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// Helper constructors for common error scenarios

// NewConnectionError creates a connection failure error.
// This is typically retryable as network issues may be transient.
func NewConnectionError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeConnectionFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: true,
	}
}

// NewQueryError creates a query execution error.
// This is typically non-retryable as the query itself may be invalid.
func NewQueryError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeQueryFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewNodeNotFoundError creates a node not found error.
// This is non-retryable as retrying won't make the node exist.
func NewNodeNotFoundError(nodeID string) *GraphRAGError {
	return &GraphRAGError{
		Code:    ErrCodeNodeNotFound,
		Message: fmt.Sprintf("node not found: %s", nodeID),
		Context: map[string]any{
			"node_id": nodeID,
		},
		Retryable: false,
	}
}

// NewRelationshipError creates a relationship operation error.
// This is typically non-retryable as it indicates a structural issue.
func NewRelationshipError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeRelationshipFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewEmbeddingError creates an embedding generation error.
// This may be retryable depending on the cause (e.g., rate limits vs invalid input).
func NewEmbeddingError(message string, cause error, retryable bool) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeEmbeddingFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: retryable,
	}
}

// NewAuthenticationError creates an authentication failure error.
// This is typically non-retryable as credentials need to be fixed.
func NewAuthenticationError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeAuthenticationFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewRateLimitError creates a rate limit error.
// This is retryable with backoff.
func NewRateLimitError(message string) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeRateLimited,
		Message:   message,
		Context:   make(map[string]any),
		Retryable: true,
	}
}

// NewProviderUnavailableError creates a provider unavailable error.
// This is typically retryable as the service may come back online.
func NewProviderUnavailableError(provider string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:    ErrCodeProviderUnavailable,
		Message: fmt.Sprintf("provider %s is unavailable", provider),
		Cause:   cause,
		Context: map[string]any{
			"provider": provider,
		},
		Retryable: true,
	}
}

// NewInvalidQueryError creates an invalid query error.
// This is non-retryable as the query needs to be fixed.
func NewInvalidQueryError(message string) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeInvalidQuery,
		Message:   message,
		Context:   make(map[string]any),
		Retryable: false,
	}
}

// NewTransactionError creates a transaction failure error.
// This is typically retryable as transactions may fail due to conflicts.
func NewTransactionError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeTransactionFailed,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: true,
	}
}

// NewConfigError creates a configuration error.
// This is non-retryable as the configuration needs to be fixed.
func NewConfigError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:      ErrCodeInvalidConfig,
		Message:   message,
		Cause:     cause,
		Context:   make(map[string]any),
		Retryable: false,
	}
}
