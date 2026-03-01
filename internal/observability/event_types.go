package observability

// EventType represents the type of event being logged
type EventType string

// Event type constants for all Gibson operations
const (
	// Mission lifecycle events
	EventTypeMissionStart    EventType = "mission_start"
	EventTypeMissionComplete EventType = "mission_complete"
	EventTypeMissionFailed   EventType = "mission_failed"

	// Agent lifecycle events
	EventTypeAgentStart EventType = "agent_start"
	EventTypeAgentEnd   EventType = "agent_end"
	EventTypeAgentError EventType = "agent_error"

	// Orchestrator decision events
	EventTypeDecision EventType = "decision"

	// LLM interaction events
	EventTypeLLMRequest  EventType = "llm_request"
	EventTypeLLMResponse EventType = "llm_response"

	// Tool execution events
	EventTypeToolCall   EventType = "tool_call"
	EventTypeToolResult EventType = "tool_result"

	// Security finding events
	EventTypeFinding EventType = "finding"

	// Memory operation events
	EventTypeMemoryStore  EventType = "memory_store"
	EventTypeMemoryRecall EventType = "memory_recall"

	// GraphRAG operation events
	EventTypeGraphStore EventType = "graph_store"

	// Error events
	EventTypeError EventType = "error"
)

// DecisionEventData captures orchestrator decision-making information
type DecisionEventData struct {
	Action       string  `json:"action"`
	TargetNodeID string  `json:"target_node_id,omitempty"`
	Confidence   float64 `json:"confidence"`
	Reasoning    string  `json:"reasoning"`
}

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

// AgentStartEventData captures agent initialization information
type AgentStartEventData struct {
	TaskDescription string `json:"task_description"`
}

// AgentEndEventData captures agent completion metrics
type AgentEndEventData struct {
	Success     bool   `json:"success"`
	DurationMs  int64  `json:"duration_ms"`
	ToolCalls   int    `json:"tool_calls"`
	LLMCalls    int    `json:"llm_calls"`
	TotalTokens int    `json:"total_tokens"`
	Error       string `json:"error,omitempty"`
}

// MissionEventData captures mission lifecycle information
type MissionEventData struct {
	MissionID   string `json:"mission_id"`
	MissionName string `json:"mission_name"`
	Error       string `json:"error,omitempty"`
}

// MemoryEventData captures memory operation information
type MemoryEventData struct {
	Operation string `json:"operation"`
	Key       string `json:"key"`
	Success   bool   `json:"success"`
}

// GraphEventData captures GraphRAG operation information
type GraphEventData struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	Operation  string `json:"operation"`
}

// ErrorEventData captures general error information
type ErrorEventData struct {
	Operation string `json:"operation"`
	Error     string `json:"error"`
	Code      string `json:"code,omitempty"`
}
