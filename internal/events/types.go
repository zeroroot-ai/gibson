package events

import (
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// EventType identifies the category and nature of an event in the Gibson system.
// It consolidates event types from both the daemon EventBus and VerboseEventBus
// into a single unified event taxonomy.
type EventType string

// Mission Lifecycle Events
// These events track the overall mission execution lifecycle.
const (
	EventMissionStarted   EventType = "mission.started"
	EventMissionProgress  EventType = "mission.progress"
	EventMissionNode      EventType = "mission.node"
	EventMissionCompleted EventType = "mission.completed"
	EventMissionFailed    EventType = "mission.failed"
	EventMissionPaused    EventType = "mission.paused"
	EventMissionResumed   EventType = "mission.resumed"
)

// Node Execution Events
// These events track individual workflow node execution within a mission.
const (
	EventNodeStarted   EventType = "node.started"
	EventNodeCompleted EventType = "node.completed"
	EventNodeFailed    EventType = "node.failed"
	EventNodeSkipped   EventType = "node.skipped"
)

// Agent Lifecycle Events
// These events track agent registration, execution, and termination.
const (
	EventAgentRegistered   EventType = "agent.registered"
	EventAgentUnregistered EventType = "agent.unregistered"
	EventAgentStarted      EventType = "agent.started"
	EventAgentCompleted    EventType = "agent.completed"
	EventAgentFailed       EventType = "agent.failed"
	EventAgentDelegated    EventType = "agent.delegated"
	EventAgentCancelled    EventType = "agent.cancelled"
)

// LLM Request Events
// These events track LLM API interactions for both streaming and non-streaming.
const (
	EventLLMRequestStarted   EventType = "llm.request.started"
	EventLLMRequestCompleted EventType = "llm.request.completed"
	EventLLMRequestFailed    EventType = "llm.request.failed"
	EventLLMStreamStarted    EventType = "llm.stream.started"
	EventLLMStreamChunk      EventType = "llm.stream.chunk"
	EventLLMStreamCompleted  EventType = "llm.stream.completed"
)

// Tool Execution Events
// These events track tool calls made by agents during mission execution.
const (
	EventToolCallStarted   EventType = "tool.call.started"
	EventToolCallCompleted EventType = "tool.call.completed"
	EventToolCallFailed    EventType = "tool.call.failed"
	EventToolNotFound      EventType = "tool.not_found"
)

// Tool Progress Events
// These events track tool execution progress, partial results, and warnings.
const (
	EventToolProgress        EventType = "tool.progress"
	EventToolPartialResult   EventType = "tool.partial_result"
	EventToolWarning         EventType = "tool.warning"
	EventToolProgressStalled EventType = "tool.progress_stalled"
)

// Plugin Lifecycle Events
// These events track plugin initialization, health, and shutdown.
const (
	EventPluginInitialized          EventType = "plugin.initialized"
	EventPluginInitializationFailed EventType = "plugin.initialization_failed"
	EventPluginShutdown             EventType = "plugin.shutdown"
	EventPluginHealthChanged        EventType = "plugin.health_changed"
)

// Plugin Query Events
// These events track plugin query execution.
const (
	EventPluginQueryStarted   EventType = "plugin.query.started"
	EventPluginQueryCompleted EventType = "plugin.query.completed"
	EventPluginQueryFailed    EventType = "plugin.query.failed"
)

// Finding Events
// These events track security finding discovery and submission.
const (
	EventFindingDiscovered EventType = "finding.discovered"
	EventFindingSubmitted  EventType = "agent.finding_submitted"
)

// Memory Events
// These events track memory tier operations (working, mission, long-term).
const (
	EventMemoryGet    EventType = "memory.get"
	EventMemorySet    EventType = "memory.set"
	EventMemorySearch EventType = "memory.search"
)

// System Events
// These events track daemon and component lifecycle.
const (
	EventSystemComponentRegistered EventType = "system.component_registered"
	EventSystemComponentHealth     EventType = "system.component_health"
	EventSystemDaemonStarted       EventType = "system.daemon_started"
)

// Attack Events
// These events track attack execution via the attack command.
const (
	EventAttackStarted   EventType = "attack.started"
	EventAttackCompleted EventType = "attack.completed"
	EventAttackFailed    EventType = "attack.failed"
)

// Approval Events
// These events track human approval requests for sensitive operations.
const (
	EventApprovalRequested EventType = "approval.requested"
	EventApprovalGranted   EventType = "approval.granted"
	EventApprovalRejected  EventType = "approval.rejected"
	EventApprovalTimeout   EventType = "approval.timeout"
)

// Abort Events
// These events track mission abort and cleanup operations.
const (
	EventMissionAborted  EventType = "mission.aborted"
	EventCleanupRequired EventType = "mission.cleanup_required"
)

// Escalation Events
// These events track escalations to humans or specialist agents.
const (
	EventEscalationCreated      EventType = "escalation.created"
	EventEscalationAcknowledged EventType = "escalation.acknowledged"
)

// Rollback Events
// These events track checkpoint creation and workflow rollback.
const (
	EventCheckpointCreated EventType = "checkpoint.created"
	EventRollbackStarted   EventType = "rollback.started"
	EventRollbackCompleted EventType = "rollback.completed"
)

// Reflection Events
// These events track self-evaluation LLM calls.
const (
	EventReflectionStarted   EventType = "reflection.started"
	EventReflectionCompleted EventType = "reflection.completed"
)

// Recall Events
// These events track memory query operations.
const (
	EventRecallStarted   EventType = "recall.started"
	EventRecallCompleted EventType = "recall.completed"
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
	MissionID    types.ID `json:"mission_id"`
	WorkflowName string   `json:"workflow_name,omitempty"`
	TargetID     types.ID `json:"target_id,omitempty"`
	NodeCount    int      `json:"node_count"`
}

// MissionProgressPayload contains data for mission.progress events.
type MissionProgressPayload struct {
	MissionID      types.ID `json:"mission_id"`
	CompletedNodes int      `json:"completed_nodes"`
	TotalNodes     int      `json:"total_nodes"`
	CurrentNode    string   `json:"current_node,omitempty"`
	Message        string   `json:"message,omitempty"`
}

// MissionNodePayload contains data for mission.node events.
type MissionNodePayload struct {
	NodeID   string        `json:"node_id"`
	NodeType string        `json:"node_type"`
	Status   string        `json:"status"`
	Duration time.Duration `json:"duration,omitempty"`
	Error    string        `json:"error,omitempty"`
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

// AgentRegisteredPayload contains data for agent.registered events.
type AgentRegisteredPayload struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Message   string `json:"message,omitempty"`
}

// AgentUnregisteredPayload contains data for agent.unregistered events.
type AgentUnregisteredPayload struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Message   string `json:"message,omitempty"`
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

// AgentCancelledPayload contains data for agent.cancelled events.
type AgentCancelledPayload struct {
	AgentName        string        `json:"agent_name"`
	TaskID           string        `json:"task_id,omitempty"`
	CancelReason     string        `json:"cancel_reason"`
	ProgressAtCancel string        `json:"progress_at_cancel,omitempty"`
	Duration         time.Duration `json:"duration"`
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

// LLMStreamStartedPayload contains data for llm.stream.started events.
type LLMStreamStartedPayload struct {
	Provider     string `json:"provider"`
	Model        string `json:"model"`
	SlotName     string `json:"slot_name"`
	MessageCount int    `json:"message_count"`
}

// LLMStreamChunkPayload contains data for llm.stream.chunk events.
type LLMStreamChunkPayload struct {
	Provider      string `json:"provider"`
	ChunkIndex    int    `json:"chunk_index"`
	ContentDelta  string `json:"content_delta"`
	ContentLength int    `json:"content_length"`
}

// LLMStreamCompletedPayload contains data for llm.stream.completed events.
type LLMStreamCompletedPayload struct {
	Provider           string        `json:"provider"`
	Model              string        `json:"model"`
	SlotName           string        `json:"slot_name"`
	Duration           time.Duration `json:"duration"`
	TotalChunks        int           `json:"total_chunks"`
	InputTokens        int           `json:"input_tokens"`
	OutputTokens       int           `json:"output_tokens"`
	FinalContentLength int           `json:"final_content_length"`
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

// ToolNotFoundPayload contains data for tool.not_found events.
type ToolNotFoundPayload struct {
	ToolName    string `json:"tool_name"`
	RequestedBy string `json:"requested_by,omitempty"`
}

// ToolProgressPayload contains data for tool.progress events.
type ToolProgressPayload struct {
	ToolName        string `json:"tool_name"`
	CallID          string `json:"call_id"`
	PercentComplete int    `json:"percent_complete"`
	Phase           string `json:"phase"`
	Message         string `json:"message"`
}

// ToolPartialResultPayload contains data for tool.partial_result events.
type ToolPartialResultPayload struct {
	ToolName      string `json:"tool_name"`
	CallID        string `json:"call_id"`
	PartialOutput string `json:"partial_output"`
	IsIncremental bool   `json:"is_incremental"`
}

// ToolWarningPayload contains data for tool.warning events.
type ToolWarningPayload struct {
	ToolName       string `json:"tool_name"`
	CallID         string `json:"call_id"`
	WarningMessage string `json:"warning_message"`
	WarningContext string `json:"warning_context,omitempty"`
}

// ToolProgressStalledPayload contains data for tool.progress_stalled events.
type ToolProgressStalledPayload struct {
	ToolName            string        `json:"tool_name"`
	CallID              string        `json:"call_id"`
	LastProgressPercent int           `json:"last_progress_percent"`
	StallDuration       time.Duration `json:"stall_duration"`
}

// PluginInitializedPayload contains data for plugin.initialized events.
type PluginInitializedPayload struct {
	PluginName             string        `json:"plugin_name"`
	Version                string        `json:"version"`
	MethodsAvailable       []string      `json:"methods_available"`
	InitializationDuration time.Duration `json:"initialization_duration"`
}

// PluginInitializationFailedPayload contains data for plugin.initialization_failed events.
type PluginInitializationFailedPayload struct {
	PluginName string `json:"plugin_name"`
	Error      string `json:"error"`
	ErrorCode  string `json:"error_code,omitempty"`
}

// PluginShutdownPayload contains data for plugin.shutdown events.
type PluginShutdownPayload struct {
	PluginName     string `json:"plugin_name"`
	ShutdownReason string `json:"shutdown_reason"`
	QueriesServed  int64  `json:"queries_served"`
}

// PluginHealthChangedPayload contains data for plugin.health_changed events.
type PluginHealthChangedPayload struct {
	PluginName     string `json:"plugin_name"`
	PreviousStatus string `json:"previous_status"`
	CurrentStatus  string `json:"current_status"`
	HealthDetails  string `json:"health_details,omitempty"`
}

// PluginQueryStartedPayload contains data for plugin.query.started events.
type PluginQueryStartedPayload struct {
	PluginName     string         `json:"plugin_name"`
	Method         string         `json:"method"`
	Parameters     map[string]any `json:"parameters,omitempty"`
	ParameterCount int            `json:"parameter_count"`
}

// PluginQueryCompletedPayload contains data for plugin.query.completed events.
type PluginQueryCompletedPayload struct {
	PluginName string        `json:"plugin_name"`
	Method     string        `json:"method"`
	Duration   time.Duration `json:"duration"`
	Success    bool          `json:"success"`
}

// PluginQueryFailedPayload contains data for plugin.query.failed events.
type PluginQueryFailedPayload struct {
	PluginName string        `json:"plugin_name"`
	Method     string        `json:"method"`
	Error      string        `json:"error"`
	Duration   time.Duration `json:"duration"`
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

// MemoryGetPayload contains data for memory.get events.
type MemoryGetPayload struct {
	Tier  string `json:"tier"`
	Key   string `json:"key"`
	Found bool   `json:"found"`
}

// MemorySetPayload contains data for memory.set events.
type MemorySetPayload struct {
	Tier      string `json:"tier"`
	Key       string `json:"key"`
	ValueSize int    `json:"value_size"`
}

// MemorySearchPayload contains data for memory.search events.
type MemorySearchPayload struct {
	Tier        string        `json:"tier"`
	Query       string        `json:"query"`
	ResultCount int           `json:"result_count"`
	Duration    time.Duration `json:"duration"`
}

// ComponentRegisteredPayload contains data for system.component_registered events.
type ComponentRegisteredPayload struct {
	ComponentType string   `json:"component_type"`
	ComponentName string   `json:"component_name"`
	Version       string   `json:"version,omitempty"`
	Capabilities  []string `json:"capabilities,omitempty"`
}

// ComponentHealthPayload contains data for system.component_health events.
type ComponentHealthPayload struct {
	ComponentType string        `json:"component_type"`
	ComponentName string        `json:"component_name"`
	Healthy       bool          `json:"healthy"`
	Status        string        `json:"status,omitempty"`
	ResponseTime  time.Duration `json:"response_time,omitempty"`
}

// DaemonStartedPayload contains data for system.daemon_started events.
type DaemonStartedPayload struct {
	Version       string `json:"version"`
	ConfigPath    string `json:"config_path,omitempty"`
	DataDir       string `json:"data_dir,omitempty"`
	ListenAddress string `json:"listen_address,omitempty"`
}

// AttackStartedPayload contains data for attack.started events.
type AttackStartedPayload struct {
	AttackID   types.ID `json:"attack_id"`
	TargetName string   `json:"target_name,omitempty"`
	AgentName  string   `json:"agent_name"`
}

// AttackCompletedPayload contains data for attack.completed events.
type AttackCompletedPayload struct {
	AttackID     types.ID      `json:"attack_id"`
	Duration     time.Duration `json:"duration"`
	FindingCount int           `json:"finding_count"`
	Success      bool          `json:"success"`
}

// AttackFailedPayload contains data for attack.failed events.
type AttackFailedPayload struct {
	AttackID     types.ID      `json:"attack_id"`
	Error        string        `json:"error"`
	Duration     time.Duration `json:"duration"`
	FindingCount int           `json:"finding_count"`
}
