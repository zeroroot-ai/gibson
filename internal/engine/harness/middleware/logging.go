// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package middleware

// Level defines the verbosity level for logging middleware.
// Higher levels include all information from lower levels.
type Level int

const (
	// LevelQuiet suppresses all logging output.
	// Use when minimal overhead is critical or logging is handled elsewhere.
	LevelQuiet Level = iota

	// LevelNormal logs operation start and completion events only.
	// Includes: operation type, duration, success/failure status.
	// Excludes: request/response details, token counts.
	LevelNormal

	// LevelVerbose adds operational details to normal logging.
	// Includes: everything from Normal plus timing, token usage, result summaries.
	// Excludes: full request/response content.
	LevelVerbose

	// LevelDebug includes full request and response details.
	// Includes: everything from Verbose plus truncated request/response content.
	// Uses redaction for sensitive fields (prompts, API keys).
	LevelDebug
)

// Request types for extracting operation-specific details.
// These would typically be defined in the middleware package or harness package.

// CompletionRequest represents a completion operation request.
type CompletionRequest struct {
}

// TaskInfo holds basic task information for logging.
type TaskInfo struct {
	Name string
}

// Helper functions to extract context values using the context keys from middleware.go
