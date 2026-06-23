package middleware

import (
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
)

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
	Slot     string
	Messages []llm.Message
	Tools    []llm.ToolDef // Only populated for CompleteWithTools
}

// StreamRequest represents a streaming completion request.
type StreamRequest struct {
	Slot     string
	Messages []llm.Message
}

// ToolRequest represents a tool execution request.
type ToolRequest struct {
	Name  string
	Input map[string]any
}

// PluginRequest represents a plugin query request.
type PluginRequest struct {
	Name   string
	Method string
	Params map[string]any
}

// DelegateRequest represents a sub-agent delegation request.
type DelegateRequest struct {
	AgentName string
	Task      TaskInfo // Simplified task info
}

// TaskInfo holds basic task information for logging.
type TaskInfo struct {
	Name string
}

// Helper functions to extract context values using the context keys from middleware.go
