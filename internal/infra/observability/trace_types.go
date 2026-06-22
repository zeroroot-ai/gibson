package observability

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/engine/graphrag/schema"
)

// MessageLog represents a single message in an LLM conversation for observability.
// This provides structured message data for tracing and debugging.
type MessageLog struct {
	Role       string `json:"role"`                   // Message role (system, user, assistant, tool)
	Content    string `json:"content"`                // Message content
	Name       string `json:"name,omitempty"`         // Optional name (for function/tool messages)
	ToolCallID string `json:"tool_call_id,omitempty"` // Optional tool call ID reference
}

// RequestMetadata captures LLM request configuration for observability.
// This enables full visibility into the parameters used for each LLM call.
type RequestMetadata struct {
	Model       string  `json:"model"`              // LLM model name
	Temperature float64 `json:"temperature"`        // Temperature parameter (0.0-1.0)
	MaxTokens   int     `json:"max_tokens"`         // Maximum tokens to generate
	TopP        float64 `json:"top_p,omitempty"`    // Top-p nucleus sampling parameter
	SlotName    string  `json:"slot_name"`          // LLM slot name used
	Provider    string  `json:"provider,omitempty"` // LLM provider (e.g., "openai", "anthropic")
}

// DecisionLog captures orchestrator decision information for tracing.
type DecisionLog struct {
	Decision      *schema.Decision // The decision node
	Prompt        string           // Full prompt sent to LLM
	Response      string           // Full response from LLM
	Model         string           // LLM model used
	GraphSnapshot string           // Graph state at decision time
	Neo4jNodeID   string           // Neo4j node ID for correlation
	OTELTraceID   string           // OTEL trace ID for correlation with infrastructure traces

	// Messages contains the structured message array sent to the LLM
	// This provides detailed visibility into the conversation structure
	Messages []MessageLog `json:"messages,omitempty"`

	// RequestMeta contains the LLM request configuration parameters
	// This enables full observability of decision-making settings
	RequestMeta *RequestMetadata `json:"request_meta,omitempty"`
}

// AgentExecutionLog captures agent execution information for tracing.
type AgentExecutionLog struct {
	Execution   *schema.AgentExecution // The execution node
	AgentName   string                 // Name of the agent
	Config      map[string]any         // Configuration used
	Neo4jNodeID string                 // Neo4j node ID for correlation
	SpanID      string                 // Parent span ID (set by StartAgentExecution)
	OTELTraceID string                 // OTEL trace ID for correlation with infrastructure traces

	// Statistics accumulated during agent execution
	ToolCallsCount int // Number of tool calls made
	FindingsCount  int // Number of findings submitted
	LLMTimeMs      int // Time spent in LLM calls (milliseconds)
	ToolTimeMs     int // Time spent in tool calls (milliseconds)
	MemoryOpsCount int // Number of memory operations
}

// ToolExecutionLog captures tool execution information for tracing.
type ToolExecutionLog struct {
	Execution   *schema.ToolExecution // The tool execution node
	Neo4jNodeID string                // Neo4j node ID for correlation
	SpanID      string                // Span ID for this tool execution
	OTELTraceID string                // OTEL trace ID for correlation with infrastructure traces
}

// MissionTraceSummary captures final mission statistics for tracing.
// This extends the basic MissionSummary with additional trace-specific fields.
type MissionTraceSummary struct {
	Status          string         // Mission final status
	TotalDecisions  int            // Number of orchestrator decisions
	TotalExecutions int            // Number of agent executions
	TotalTools      int            // Number of tool executions
	TotalTokens     int            // Total LLM tokens used
	TotalCost       float64        // Estimated total cost in USD
	Duration        time.Duration  // Total mission duration
	Outcome         string         // Human-readable outcome summary
	GraphStats      map[string]int // Graph statistics (nodes, relationships, etc.)
}
