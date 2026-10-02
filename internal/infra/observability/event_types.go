// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

// EventType represents the type of event being logged
type EventType string

// Event type constants for all Gibson operations
const (
	// Mission lifecycle events
	EventTypeMissionStart EventType = "mission_start"

	// Agent lifecycle events

	// Orchestrator decision events

	// LLM interaction events
	EventTypeLLMResponse EventType = "llm_response"

	// Tool execution events

	// Security finding events

	// Memory operation events

	// GraphRAG operation events

	// Error events
)

// LLMRequestEventData captures LLM request metadata (no sensitive content)
type LLMRequestEventData struct {
	Model        string `json:"model"`
	MessageCount int    `json:"message_count"`
}

// LLMResponseEventData captures LLM response metadata and token usage
type LLMResponseEventData struct {
	Model            string `json:"model"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	TotalTokens      int    `json:"total_tokens"`
	LatencyMs        int64  `json:"latency_ms"`
}

// ToolCallEventData captures tool invocation information
type ToolCallEventData struct {
	ToolName string `json:"tool_name"`
	CallID   string `json:"call_id"`
}

// ToolResultEventData captures tool execution results
type ToolResultEventData struct {
	ToolName  string `json:"tool_name"`
	CallID    string `json:"call_id"`
	Success   bool   `json:"success"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// FindingEventData captures security finding information
type FindingEventData struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	TargetAsset string `json:"target_asset"`
}

// MissionEventData captures mission lifecycle information
type MissionEventData struct {
	MissionID   string `json:"mission_id"`
	MissionName string `json:"mission_name"`
	Error       string `json:"error,omitempty"`
}
