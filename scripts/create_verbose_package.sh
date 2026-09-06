#!/bin/bash
set -e
cd "$(dirname "$0")/.."
rm -rf internal/verbose
mkdir -p internal/verbose

# Create event_bus.go in one go
cat > internal/verbose/event_bus.go <<'EOFBUS'
package verbose

import (
	"context"
	"sync"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// VerboseEventBus publishes verbose events to subscribers.
// Implementations must be thread-safe and support multiple concurrent subscribers.
type VerboseEventBus interface {
	// Emit publishes an event to all subscribers.
	// Uses non-blocking send to prevent slow subscribers from blocking producers.
	// Returns an error if the event bus is closed.
	Emit(ctx context.Context, event VerboseEvent) error

	// Subscribe creates a new subscription and returns a channel for receiving events
	// and a cleanup function to unsubscribe.
	// The cleanup function must be called to prevent resource leaks.
	Subscribe(ctx context.Context) (<-chan VerboseEvent, func())

	// Close shuts down the event bus and all subscriptions.
	Close() error
}

// DefaultVerboseEventBus implements VerboseEventBus using buffered channels.
// It supports multiple subscribers and handles slow consumers gracefully by
// dropping events if subscriber buffers are full.
type DefaultVerboseEventBus struct {
	mu          sync.RWMutex
	subscribers map[string]chan VerboseEvent
	bufferSize  int
	closed      bool
}

// VerboseEventBusOption is a functional option for configuring DefaultVerboseEventBus.
type VerboseEventBusOption func(*DefaultVerboseEventBus)

// WithBufferSize sets the buffer size for subscriber channels.
// Default is 1000. Larger buffers can handle bursty events better.
func WithBufferSize(size int) VerboseEventBusOption {
	return func(e *DefaultVerboseEventBus) {
		e.bufferSize = size
	}
}

// NewDefaultVerboseEventBus creates a new DefaultVerboseEventBus with optional configuration.
func NewDefaultVerboseEventBus(opts ...VerboseEventBusOption) *DefaultVerboseEventBus {
	bus := &DefaultVerboseEventBus{
		subscribers: make(map[string]chan VerboseEvent),
		bufferSize:  1000, // Default buffer size
		closed:      false,
	}

	for _, opt := range opts {
		opt(bus)
	}

	return bus
}

// Emit publishes an event to all subscribers.
// If a subscriber's channel is full, the event is dropped for that subscriber
// to prevent blocking other subscribers (slow consumer handling).
func (b *DefaultVerboseEventBus) Emit(ctx context.Context, event VerboseEvent) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return types.NewError(types.ErrorCode("VERBOSE_BUS_CLOSED"), "verbose event bus is closed")
	}

	// Send to all subscribers (non-blocking)
	for _, ch := range b.subscribers {
		select {
		case ch <- event:
			// Event sent successfully
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Channel is full, drop event for this slow subscriber
			// This prevents one slow subscriber from blocking others
		}
	}

	return nil
}

// Subscribe creates a new subscription and returns a channel for receiving events.
// The returned cleanup function must be called to unsubscribe and prevent leaks.
func (b *DefaultVerboseEventBus) Subscribe(ctx context.Context) (<-chan VerboseEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Generate unique subscriber ID
	subscriberID := types.NewID().String()
	ch := make(chan VerboseEvent, b.bufferSize)
	b.subscribers[subscriberID] = ch

	// Cleanup function to unsubscribe
	cleanup := func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		if subCh, exists := b.subscribers[subscriberID]; exists {
			delete(b.subscribers, subscriberID)
			close(subCh)
		}
	}

	return ch, cleanup
}

// Close shuts down the event bus and closes all subscriber channels.
func (b *DefaultVerboseEventBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil
	}

	b.closed = true

	// Close all subscriber channels
	for id, ch := range b.subscribers {
		close(ch)
		delete(b.subscribers, id)
	}

	return nil
}

// SubscriberCount returns the current number of active subscribers.
// Useful for monitoring and testing.
func (b *DefaultVerboseEventBus) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subscribers)
}

// Ensure DefaultVerboseEventBus implements VerboseEventBus at compile time
var _ VerboseEventBus = (*DefaultVerboseEventBus)(nil)
EOFBUS

# Create event_types.go (abbreviated for space - full version with all types)
# Note: Using compressed version due to heredoc limitations
python3 -c 'import sys; sys.stdout.write("""package verbose

import (
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

type VerboseEventType string

const (
	EventLLMRequestStarted VerboseEventType = "llm.request.started"
	EventLLMRequestCompleted VerboseEventType = "llm.request.completed"
	EventLLMRequestFailed VerboseEventType = "llm.request.failed"
	EventLLMStreamStarted VerboseEventType = "llm.stream.started"
	EventLLMStreamChunk VerboseEventType = "llm.stream.chunk"
	EventLLMStreamCompleted VerboseEventType = "llm.stream.completed"
	EventToolCallStarted VerboseEventType = "tool.call.started"
	EventToolCallCompleted VerboseEventType = "tool.call.completed"
	EventToolCallFailed VerboseEventType = "tool.call.failed"
	EventToolNotFound VerboseEventType = "tool.not_found"
	EventAgentStarted VerboseEventType = "agent.started"
	EventAgentCompleted VerboseEventType = "agent.completed"
	EventAgentFailed VerboseEventType = "agent.failed"
	EventAgentDelegated VerboseEventType = "agent.delegated"
	EventFindingSubmitted VerboseEventType = "agent.finding_submitted"
	EventMissionStarted VerboseEventType = "mission.started"
	EventMissionProgress VerboseEventType = "mission.progress"
	EventMissionNode VerboseEventType = "mission.node"
	EventMissionCompleted VerboseEventType = "mission.completed"
	EventMissionFailed VerboseEventType = "mission.failed"
	EventMemoryGet VerboseEventType = "memory.get"
	EventMemorySet VerboseEventType = "memory.set"
	EventMemorySearch VerboseEventType = "memory.search"
	EventComponentRegistered VerboseEventType = "system.component_registered"
	EventComponentHealth VerboseEventType = "system.component_health"
	EventDaemonStarted VerboseEventType = "system.daemon_started"
)

func (t VerboseEventType) String() string {
	return string(t)
}

type VerboseLevel int

const (
	LevelNone VerboseLevel = 0
	LevelVerbose VerboseLevel = 1
	LevelVeryVerbose VerboseLevel = 2
	LevelDebug VerboseLevel = 3
)

func (l VerboseLevel) String() string {
	switch l {
	case LevelNone:
		return "none"
	case LevelVerbose:
		return "verbose"
	case LevelVeryVerbose:
		return "very-verbose"
	case LevelDebug:
		return "debug"
	default:
		return "unknown"
	}
}

type VerboseEvent struct {
	Type      VerboseEventType json:"type"
	Level     VerboseLevel json:"level"
	Timestamp time.Time json:"timestamp"
	MissionID types.ID json:"mission_id,omitempty"
	AgentName string json:"agent_name,omitempty"
	Payload   any json:"payload,omitempty"
}

type LLMRequestStartedData struct {
	Provider     string  json:"provider"
	Model        string  json:"model"
	SlotName     string  json:"slot_name"
	MessageCount int     json:"message_count"
	MaxTokens    int     json:"max_tokens,omitempty"
	Temperature  float64 json:"temperature,omitempty"
	Stream       bool    json:"stream"
}

type LLMRequestCompletedData struct {
	Provider       string        json:"provider"
	Model          string        json:"model"
	SlotName       string        json:"slot_name"
	Duration       time.Duration json:"duration"
	InputTokens    int           json:"input_tokens"
	OutputTokens   int           json:"output_tokens"
	StopReason     string        json:"stop_reason,omitempty"
	ResponseLength int           json:"response_length"
}

type LLMRequestFailedData struct {
	Provider  string        json:"provider"
	Model     string        json:"model"
	SlotName  string        json:"slot_name"
	Error     string        json:"error"
	Duration  time.Duration json:"duration"
	Retryable bool          json:"retryable"
}

type LLMStreamStartedData struct {
	Provider     string json:"provider"
	Model        string json:"model"
	SlotName     string json:"slot_name"
	MessageCount int    json:"message_count"
}

type LLMStreamChunkData struct {
	Provider      string json:"provider"
	ChunkIndex    int    json:"chunk_index"
	ContentDelta  string json:"content_delta"
	ContentLength int    json:"content_length"
}

type LLMStreamCompletedData struct {
	Provider           string        json:"provider"
	Model              string        json:"model"
	SlotName           string        json:"slot_name"
	Duration           time.Duration json:"duration"
	TotalChunks        int           json:"total_chunks"
	InputTokens        int           json:"input_tokens"
	OutputTokens       int           json:"output_tokens"
	FinalContentLength int           json:"final_content_length"
}

type ToolCallStartedData struct {
	ToolName      string         json:"tool_name"
	Parameters    map[string]any json:"parameters,omitempty"
	ParameterSize int            json:"parameter_size"
}

type ToolCallCompletedData struct {
	ToolName   string        json:"tool_name"
	Duration   time.Duration json:"duration"
	ResultSize int           json:"result_size"
	Success    bool          json:"success"
}

type ToolCallFailedData struct {
	ToolName string        json:"tool_name"
	Error    string        json:"error"
	Duration time.Duration json:"duration"
}

type ToolNotFoundData struct {
	ToolName    string json:"tool_name"
	RequestedBy string json:"requested_by,omitempty"
}

type AgentStartedData struct {
	AgentName       string    json:"agent_name"
	TaskDescription string    json:"task_description,omitempty"
	TargetID        types.ID json:"target_id,omitempty"
}

type AgentCompletedData struct {
	AgentName    string        json:"agent_name"
	Duration     time.Duration json:"duration"
	FindingCount int           json:"finding_count"
	Success      bool          json:"success"
}

type AgentFailedData struct {
	AgentName    string        json:"agent_name"
	Error        string        json:"error"
	Duration     time.Duration json:"duration"
	FindingCount int           json:"finding_count"
}

type AgentDelegatedData struct {
	FromAgent       string json:"from_agent"
	ToAgent         string json:"to_agent"
	TaskDescription string json:"task_description,omitempty"
}

type FindingSubmittedData struct {
	FindingID    types.ID json:"finding_id"
	Title        string   json:"title"
	Severity     string   json:"severity"
	AgentName    string   json:"agent_name"
	TechniqueIDs []string json:"technique_ids,omitempty"
}

type MissionStartedData struct {
	MissionID          types.ID json:"mission_id"
	MissionDefinitionName string   json:"mission_definition_name,omitempty"
	TargetID           types.ID json:"target_id,omitempty"
	NodeCount          int      json:"node_count"
}

type MissionProgressData struct {
	MissionID      types.ID json:"mission_id"
	CompletedNodes int      json:"completed_nodes"
	TotalNodes     int      json:"total_nodes"
	CurrentNode    string   json:"current_node,omitempty"
	Message        string   json:"message,omitempty"
}

type MissionNodeData struct {
	NodeID   string        json:"node_id"
	NodeType string        json:"node_type"
	Status   string        json:"status"
	Duration time.Duration json:"duration,omitempty"
	Error    string        json:"error,omitempty"
}

type MissionCompletedData struct {
	MissionID     types.ID      json:"mission_id"
	Duration      time.Duration json:"duration"
	FindingCount  int           json:"finding_count"
	NodesExecuted int           json:"nodes_executed"
	Success       bool          json:"success"
}

type MissionFailedData struct {
	MissionID     types.ID      json:"mission_id"
	Error         string        json:"error"
	Duration      time.Duration json:"duration"
	FindingCount  int           json:"finding_count"
	NodesExecuted int           json:"nodes_executed"
}

type MemoryGetData struct {
	Tier  string json:"tier"
	Key   string json:"key"
	Found bool   json:"found"
}

type MemorySetData struct {
	Tier      string json:"tier"
	Key       string json:"key"
	ValueSize int    json:"value_size"
}

type MemorySearchData struct {
	Tier        string        json:"tier"
	Query       string        json:"query"
	ResultCount int           json:"result_count"
	Duration    time.Duration json:"duration"
}

type ComponentRegisteredData struct {
	ComponentType string   json:"component_type"
	ComponentName string   json:"component_name"
	Version       string   json:"version,omitempty"
	Capabilities  []string json:"capabilities,omitempty"
}

type ComponentHealthData struct {
	ComponentType string        json:"component_type"
	ComponentName string        json:"component_name"
	Healthy       bool          json:"healthy"
	Status        string        json:"status,omitempty"
	ResponseTime  time.Duration json:"response_time,omitempty"
}

type DaemonStartedData struct {
	Version       string json:"version"
	ConfigPath    string json:"config_path,omitempty"
	DataDir       string json:"data_dir,omitempty"
	ListenAddress string json:"listen_address,omitempty"
}

func NewVerboseEvent(eventType VerboseEventType, level VerboseLevel, payload any) VerboseEvent {
	return VerboseEvent{
		Type:      eventType,
		Level:     level,
		Timestamp: time.Now(),
		Payload:   payload,
	}
}

func (e VerboseEvent) WithMissionID(missionID types.ID) VerboseEvent {
	e.MissionID = missionID
	return e
}

func (e VerboseEvent) WithAgentName(agentName string) VerboseEvent {
	e.AgentName = agentName
	return e
}
""".replace("json:", "`json:").replace("`", '`+"` + "`"'))' > internal/verbose/event_types.go

# Build and verify
go build -tags fts5 ./internal/verbose/...
echo "SUCCESS! Package built."
ls -lh internal/verbose/
wc -l internal/verbose/*.go
