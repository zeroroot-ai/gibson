package observability

// LLMPromptPayload contains data for LLM_PROMPT events.
type LLMPromptPayload struct {
	Slot             string `json:"slot"`
	Role             string `json:"role"`
	Content          string `json:"content"`
	ContentTruncated bool   `json:"content_truncated"`
	ContentLength    int    `json:"content_length"`
	MessageIndex     int    `json:"message_index"`
	MessageCount     int    `json:"message_count"`
}

// LLMResponsePayload contains data for LLM_RESPONSE events.
type LLMResponsePayload struct {
	Slot             string   `json:"slot"`
	Provider         string   `json:"provider"`
	Model            string   `json:"model"`
	Content          string   `json:"content"`
	ContentTruncated bool     `json:"content_truncated"`
	ContentLength    int      `json:"content_length"`
	InputTokens      int      `json:"input_tokens"`
	OutputTokens     int      `json:"output_tokens"`
	FinishReason     string   `json:"finish_reason"`
	ToolCalls        []string `json:"tool_calls,omitempty"` // Tool names if present
	LatencyMs        int64    `json:"latency_ms"`
}

// ToolCallPayload contains data for TOOL_CALL events.
type ToolCallPayload struct {
	ToolName   string      `json:"tool_name"`
	Parameters interface{} `json:"parameters"`
	Remote     bool        `json:"remote"`
}

// ToolResultPayload contains data for TOOL_RESULT events.
type ToolResultPayload struct {
	ToolName   string      `json:"tool_name"`
	Success    bool        `json:"success"`
	Result     interface{} `json:"result,omitempty"`
	Error      string      `json:"error,omitempty"`
	LatencyMs  int64       `json:"latency_ms"`
	ResultSize int         `json:"result_size"`
}

// FindingPayload contains data for FINDING events.
type FindingPayload struct {
	FindingID  string   `json:"finding_id"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`
	Confidence float64  `json:"confidence"`
	Category   string   `json:"category"`
	CWE        []string `json:"cwe,omitempty"`
	MITRE      []string `json:"mitre,omitempty"`
}

// DecisionPayload contains data for DECISION events.
type DecisionPayload struct {
	Action     string  `json:"action"`
	Target     string  `json:"target,omitempty"`
	Reasoning  string  `json:"reasoning"`
	Confidence float64 `json:"confidence"`
	Iteration  int     `json:"iteration"`
	TokensUsed int     `json:"tokens_used"`
}

// AgentStartPayload contains data for AGENT_START events.
type AgentStartPayload struct {
	TaskDescription string `json:"task_description"`
	TaskID          string `json:"task_id,omitempty"`
}

// AgentEndPayload contains data for AGENT_END events.
type AgentEndPayload struct {
	Status       string `json:"status"` // completed, failed, cancelled
	DurationMs   int64  `json:"duration_ms"`
	FindingCount int    `json:"finding_count"`
	ToolCalls    int    `json:"tool_calls"`
	LLMCalls     int    `json:"llm_calls"`
}

// ErrorPayload contains data for ERROR events.
type ErrorPayload struct {
	Operation string `json:"operation"`
	Error     string `json:"error"`
	ErrorType string `json:"error_type,omitempty"`
}

// MemoryStorePayload contains data for MEMORY_STORE events.
type MemoryStorePayload struct {
	Tier     string `json:"tier"`      // "working", "mission", "longterm"
	Key      string `json:"key"`
	DataSize int    `json:"data_size"`
}

// MemoryRecallPayload contains data for MEMORY_RECALL events.
type MemoryRecallPayload struct {
	Tier  string `json:"tier"`
	Key   string `json:"key"`
	Found bool   `json:"found"`
}

// GraphRAGStorePayload contains data for GRAPHRAG_STORE events.
type GraphRAGStorePayload struct {
	EntityType string `json:"entity_type"` // "Host", "Port", "Service", etc.
	Count      int    `json:"count"`
}

// DelegationPayload contains data for DELEGATION events.
type DelegationPayload struct {
	ParentAgent     string `json:"parent_agent"`
	ChildAgent      string `json:"child_agent"`
	TaskDescription string `json:"task_description"`
}
