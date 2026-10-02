// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package events

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// EventType identifies the category and nature of an event in the Gibson system.
// It consolidates event types from both the daemon EventBus and VerboseEventBus
// into a single unified event taxonomy.
type EventType string

// Mission Lifecycle Events
// These events track the overall mission execution lifecycle.
const (
	EventMissionStarted   EventType = "mission.started"
	EventMissionCompleted EventType = "mission.completed"
)

// String returns the string representation of the event type.
func (t EventType) String() string {
	return string(t)
}

// Event represents a unified observability event in the Gibson system.
// It replaces both the daemon EventBus events and VerboseEventBus events
// with a single event model that includes OpenTelemetry trace correlation.
//
// The Event struct is designed to be JSON-serializable and includes all
// necessary context for distributed tracing, filtering, and analysis.
type Event struct {
	// Type identifies the category and nature of the event
	Type EventType `json:"type"`

	// Timestamp records when the event occurred
	Timestamp time.Time `json:"timestamp"`

	// MissionID associates the event with a mission (empty for system events)
	MissionID types.ID `json:"mission_id,omitempty"`

	// AgentName identifies which agent emitted the event (empty for non-agent events)
	AgentName string `json:"agent_name,omitempty"`

	// TraceID is the OpenTelemetry trace ID for distributed tracing correlation
	TraceID string `json:"trace_id,omitempty"`

	// SpanID is the OpenTelemetry span ID for the specific operation
	SpanID string `json:"span_id,omitempty"`

	// Payload contains event-specific typed data (use type assertion to access)
	Payload any `json:"payload,omitempty"`

	// Attrs contains additional key-value attributes for flexible event metadata
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Filter defines criteria for filtering events in subscriptions.
// All filter fields use AND logic - an event must match all specified criteria.
// Empty fields act as wildcards (match all).
type Filter struct {
	// Types filters by event types (empty = all types)
	Types []EventType `json:"types,omitempty"`

	// MissionID filters by mission (empty = all missions)
	MissionID types.ID `json:"mission_id,omitempty"`

	// AgentName filters by agent (empty = all agents)
	AgentName string `json:"agent_name,omitempty"`
}

// Matches determines if the given event matches this filter's criteria.
// Empty filter fields act as wildcards that match any value.
//
// Returns true if the event matches all non-empty filter criteria.
func (f *Filter) Matches(event Event) bool {
	// Filter by event types (if specified)
	if len(f.Types) > 0 {
		matched := false
		for _, t := range f.Types {
			if event.Type == t {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by mission ID (if specified)
	if f.MissionID != "" && event.MissionID != f.MissionID {
		return false
	}

	// Filter by agent name (if specified)
	if f.AgentName != "" && event.AgentName != f.AgentName {
		return false
	}

	return true
}

// Payload Types
// These structs define the typed payload data for each event type.
// They provide type safety and clear documentation of event data structure.

// MissionStartedPayload contains data for mission.started events.
type MissionStartedPayload struct {
	MissionID   types.ID `json:"mission_id"`
	MissionName string   `json:"mission_name,omitempty"`
	TargetID    types.ID `json:"target_id,omitempty"`
	NodeCount   int      `json:"node_count"`
}

// MissionProgressPayload contains data for mission.progress events.
type MissionProgressPayload struct {
	MissionID      types.ID `json:"mission_id"`
	CompletedNodes int      `json:"completed_nodes"`
	TotalNodes     int      `json:"total_nodes"`
	CurrentNode    string   `json:"current_node,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// MissionCompletedPayload contains data for mission.completed events.
type MissionCompletedPayload struct {
	MissionID     types.ID      `json:"mission_id"`
	Duration      time.Duration `json:"duration"`
	FindingCount  int           `json:"finding_count"`
	NodesExecuted int           `json:"nodes_executed"`
	Success       bool          `json:"success"`
}

// MissionFailedPayload contains data for mission.failed events.
type MissionFailedPayload struct {
	MissionID     types.ID      `json:"mission_id"`
	Error         string        `json:"error"`
	Duration      time.Duration `json:"duration"`
	FindingCount  int           `json:"finding_count"`
	NodesExecuted int           `json:"nodes_executed"`
}

// NodeStartedPayload contains data for node.started events.
type NodeStartedPayload struct {
	MissionID types.ID `json:"mission_id"`
	NodeID    string   `json:"node_id"`
	NodeType  string   `json:"node_type,omitempty"`
	Message   string   `json:"message,omitempty"`
}

// NodeCompletedPayload contains data for node.completed events.
type NodeCompletedPayload struct {
	MissionID types.ID      `json:"mission_id"`
	NodeID    string        `json:"node_id"`
	Duration  time.Duration `json:"duration,omitempty"`
	Message   string        `json:"message,omitempty"`
}

// NodeFailedPayload contains data for node.failed events.
type NodeFailedPayload struct {
	MissionID types.ID      `json:"mission_id"`
	NodeID    string        `json:"node_id"`
	Error     string        `json:"error"`
	Duration  time.Duration `json:"duration,omitempty"`
}

// NodeSkippedPayload contains data for node.skipped events.
type NodeSkippedPayload struct {
	MissionID  types.ID `json:"mission_id"`
	NodeID     string   `json:"node_id"`
	SkipReason string   `json:"skip_reason"`
}

// AgentStartedPayload contains data for agent.started events.
type AgentStartedPayload struct {
	AgentName       string   `json:"agent_name"`
	TaskDescription string   `json:"task_description,omitempty"`
	TargetID        types.ID `json:"target_id,omitempty"`
}

// AgentCompletedPayload contains data for agent.completed events.
type AgentCompletedPayload struct {
	AgentName    string        `json:"agent_name"`
	Duration     time.Duration `json:"duration"`
	FindingCount int           `json:"finding_count"`
	Success      bool          `json:"success"`
}

// AgentFailedPayload contains data for agent.failed events.
type AgentFailedPayload struct {
	AgentName    string        `json:"agent_name"`
	Error        string        `json:"error"`
	Duration     time.Duration `json:"duration"`
	FindingCount int           `json:"finding_count"`
}

// AgentDelegatedPayload contains data for agent.delegated events.
// The trace/span IDs are required for creating DELEGATED_TO relationships
// in the GraphRAG taxonomy between AgentRun nodes.
type AgentDelegatedPayload struct {
	FromAgent       string `json:"from_agent"`
	ToAgent         string `json:"to_agent"`
	TaskDescription string `json:"task_description,omitempty"`
	// Trace context for the delegating agent's run
	FromTraceID string `json:"from_trace_id,omitempty"`
	FromSpanID  string `json:"from_span_id,omitempty"`
	// Trace context for the delegated agent's run
	ToTraceID string `json:"to_trace_id,omitempty"`
	ToSpanID  string `json:"to_span_id,omitempty"`
}

// LLMRequestStartedPayload contains data for llm.request.started events.
type LLMRequestStartedPayload struct {
	Provider      string  `json:"provider"`
	Model         string  `json:"model"`
	SlotName      string  `json:"slot_name"`
	MessageCount  int     `json:"message_count"`
	MaxTokens     int     `json:"max_tokens,omitempty"`
	Temperature   float64 `json:"temperature,omitempty"`
	Stream        bool    `json:"stream"`
	PromptPreview string  `json:"prompt_preview,omitempty"` // Truncated prompt content for debug
	ToolCount     int     `json:"tool_count,omitempty"`     // Number of tools available
}

// LLMRequestCompletedPayload contains data for llm.request.completed events.
type LLMRequestCompletedPayload struct {
	Provider        string        `json:"provider"`
	Model           string        `json:"model"`
	SlotName        string        `json:"slot_name"`
	Duration        time.Duration `json:"duration"`
	InputTokens     int           `json:"input_tokens"`
	OutputTokens    int           `json:"output_tokens"`
	StopReason      string        `json:"stop_reason,omitempty"`
	ResponseLength  int           `json:"response_length"`
	ResponsePreview string        `json:"response_preview,omitempty"` // Truncated response for debug
}

// LLMRequestFailedPayload contains data for llm.request.failed events.
type LLMRequestFailedPayload struct {
	Provider     string        `json:"provider"`
	Model        string        `json:"model"`
	SlotName     string        `json:"slot_name"`
	Error        string        `json:"error"`
	Duration     time.Duration `json:"duration"`
	Retryable    bool          `json:"retryable"`
	ErrorDetails string        `json:"error_details,omitempty"` // Full error details for debug
	RetryAttempt int           `json:"retry_attempt,omitempty"` // Which retry attempt failed
}

// ToolCallStartedPayload contains data for tool.call.started events.
type ToolCallStartedPayload struct {
	ToolName      string         `json:"tool_name"`
	Parameters    map[string]any `json:"parameters,omitempty"`
	ParameterSize int            `json:"parameter_size"`
}

// ToolCallCompletedPayload contains data for tool.call.completed events.
type ToolCallCompletedPayload struct {
	ToolName   string        `json:"tool_name"`
	Duration   time.Duration `json:"duration"`
	ResultSize int           `json:"result_size"`
	Success    bool          `json:"success"`
}

// ToolCallFailedPayload contains data for tool.call.failed events.
type ToolCallFailedPayload struct {
	ToolName string        `json:"tool_name"`
	Error    string        `json:"error"`
	Duration time.Duration `json:"duration"`
}

// ToolProgressPayload contains data for tool.progress events.
type ToolProgressPayload struct {
	ToolName        string `json:"tool_name"`
	CallID          string `json:"call_id"`
	PercentComplete int    `json:"percent_complete"`
	Phase           string `json:"phase"`
	Message         string `json:"message"`
}

// ToolWarningPayload contains data for tool.warning events.
type ToolWarningPayload struct {
	ToolName       string `json:"tool_name"`
	CallID         string `json:"call_id"`
	WarningMessage string `json:"warning_message"`
	WarningContext string `json:"warning_context,omitempty"`
}

// FindingDiscoveredPayload contains data for finding.discovered events.
type FindingDiscoveredPayload struct {
	FindingID   types.ID  `json:"finding_id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category,omitempty"`
	Description string    `json:"description,omitempty"`
	Technique   string    `json:"technique,omitempty"`
	Evidence    string    `json:"evidence,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// FindingSubmittedPayload contains data for agent.finding_submitted events.
type FindingSubmittedPayload struct {
	FindingID    types.ID `json:"finding_id"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	AgentName    string   `json:"agent_name"`
	TechniqueIDs []string `json:"technique_ids,omitempty"`
}
