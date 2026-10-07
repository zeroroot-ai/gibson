// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package graphrag

import (
	"errors"
	"fmt"
)

// GraphRAGErrorCode represents specific error codes for GraphRAG operations.
type GraphRAGErrorCode string

// GraphRAG error codes
const (
	ErrCodeQueryFailed     GraphRAGErrorCode = "QUERY_FAILED"
	ErrCodeNodeNotFound    GraphRAGErrorCode = "NODE_NOT_FOUND"
	ErrCodeEmbeddingFailed GraphRAGErrorCode = "EMBEDDING_FAILED"
	ErrCodeInvalidQuery    GraphRAGErrorCode = "INVALID_QUERY"
	ErrCodeInvalidConfig   GraphRAGErrorCode = "INVALID_CONFIG"
)

// GraphRAGError represents a structured error for GraphRAG operations.
// It includes error code, message, underlying cause, query context, and
// additional context for debugging and error handling.
type GraphRAGError struct {
	Code    GraphRAGErrorCode // Error code for programmatic handling
	Message string            // Human-readable error message
	Cause   error             // Underlying error (if any)
	Context map[string]any    // Additional context for debugging
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
	return e
}

// Helper constructors for common error scenarios

// NewQueryError creates a query execution error.
// This is typically non-retryable as the query itself may be invalid.
func NewQueryError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:    ErrCodeQueryFailed,
		Message: message,
		Cause:   cause,
		Context: make(map[string]any),
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
	}
}

// NewEmbeddingError creates an embedding generation error.
// This may be retryable depending on the cause (e.g., rate limits vs invalid input).
func NewEmbeddingError(message string, cause error, retryable bool) *GraphRAGError {
	return &GraphRAGError{
		Code:    ErrCodeEmbeddingFailed,
		Message: message,
		Cause:   cause,
		Context: make(map[string]any),
	}
}

// NewInvalidQueryError creates an invalid query error.
// This is non-retryable as the query needs to be fixed.
func NewInvalidQueryError(message string) *GraphRAGError {
	return &GraphRAGError{
		Code:    ErrCodeInvalidQuery,
		Message: message,
		Context: make(map[string]any),
	}
}

// NewConfigError creates a configuration error.
// This is non-retryable as the configuration needs to be fixed.
func NewConfigError(message string, cause error) *GraphRAGError {
	return &GraphRAGError{
		Code:    ErrCodeInvalidConfig,
		Message: message,
		Cause:   cause,
		Context: make(map[string]any),
	}
}
