package database

import (
	"context"
	"encoding/json"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
)

// StreamEventType represents the type of stream event
type StreamEventType string

// Stream event type constants
const (
	StreamEventOutput      StreamEventType = "output"
	StreamEventToolCall    StreamEventType = "tool_call"
	StreamEventToolResult  StreamEventType = "tool_result"
	StreamEventFinding     StreamEventType = "finding"
	StreamEventStatus      StreamEventType = "status"
	StreamEventSteeringAck StreamEventType = "steering_ack"
	StreamEventError       StreamEventType = "error"
)

// SteeringType represents the type of steering message
type SteeringType string

// Steering type constants
const (
	SteeringTypeSteer     SteeringType = "steer"
	SteeringTypeInterrupt SteeringType = "interrupt"
	SteeringTypeResume    SteeringType = "resume"
	SteeringTypePause     SteeringType = "pause"
	SteeringTypeSetMode   SteeringType = "set_mode"
)

// CredentialDAO defines the interface for credential data access operations.
// Both SQLite and Redis implementations satisfy this interface.
type CredentialDAO interface {
	// Create inserts a new credential
	Create(ctx context.Context, cred *types.Credential) error

	// Get retrieves a credential by ID
	Get(ctx context.Context, id types.ID) (*types.Credential, error)

	// GetByName retrieves a credential by name
	GetByName(ctx context.Context, name string) (*types.Credential, error)

	// List retrieves credentials with optional filtering
	List(ctx context.Context, filter *types.CredentialFilter) ([]*types.Credential, error)

	// Update updates an existing credential
	Update(ctx context.Context, cred *types.Credential) error

	// Delete deletes a credential by ID
	Delete(ctx context.Context, id types.ID) error

	// DeleteByName deletes a credential by name
	DeleteByName(ctx context.Context, name string) error

	// Exists checks if a credential with the given name exists
	Exists(ctx context.Context, name string) (bool, error)
}

// TargetDAO defines the interface for target data access operations.
type TargetDAO interface {
	// Create inserts a new target
	Create(ctx context.Context, target *types.Target) error

	// Get retrieves a target by ID
	Get(ctx context.Context, id types.ID) (*types.Target, error)

	// GetByName retrieves a target by name
	GetByName(ctx context.Context, name string) (*types.Target, error)

	// List retrieves targets with optional filtering
	List(ctx context.Context, filter *types.TargetFilter) ([]*types.Target, error)

	// Update updates an existing target
	Update(ctx context.Context, target *types.Target) error

	// Delete deletes a target by ID
	Delete(ctx context.Context, id types.ID) error

	// DeleteByName deletes a target by name
	DeleteByName(ctx context.Context, name string) error

	// Exists checks if a target with the given name exists
	Exists(ctx context.Context, name string) (bool, error)
}

// AgentStatus represents the current status of an agent session
type AgentStatus string

const (
	// AgentStatusRunning indicates the agent is currently executing
	AgentStatusRunning AgentStatus = "running"
	// AgentStatusPaused indicates the agent is paused
	AgentStatusPaused AgentStatus = "paused"
	// AgentStatusWaitingInput indicates the agent is waiting for operator input
	AgentStatusWaitingInput AgentStatus = "waiting_for_input"
	// AgentStatusInterrupted indicates the agent has been interrupted
	AgentStatusInterrupted AgentStatus = "interrupted"
	// AgentStatusCompleted indicates the agent has completed successfully
	AgentStatusCompleted AgentStatus = "completed"
	// AgentStatusFailed indicates the agent execution has failed
	AgentStatusFailed AgentStatus = "failed"
)

// AgentMode represents the operational mode of an agent
type AgentMode string

const (
	// AgentModeAutonomous indicates the agent operates autonomously
	AgentModeAutonomous AgentMode = "autonomous"
	// AgentModeInteractive indicates the agent requires operator interaction
	AgentModeInteractive AgentMode = "interactive"
)

// AgentSession represents a persisted agent execution session
type AgentSession struct {
	ID        types.ID    `db:"id" json:"id"`
	MissionID types.ID    `db:"mission_id" json:"mission_id"`
	AgentName string      `db:"agent_name" json:"agent_name"`
	Status    AgentStatus `db:"status" json:"status"`
	Mode      AgentMode   `db:"mode" json:"mode"`
	StartedAt time.Time   `db:"started_at" json:"started_at"`
	EndedAt   *time.Time  `db:"ended_at" json:"ended_at,omitempty"`
	Metadata  []byte      `db:"metadata" json:"metadata"` // JSON bytes
	CreatedAt time.Time   `db:"created_at" json:"created_at"`
	UpdatedAt time.Time   `db:"updated_at" json:"updated_at"`
}

// StreamEvent represents a session stream event
type StreamEvent struct {
	ID        types.ID        `json:"id"`
	SessionID types.ID        `json:"session_id"`
	Sequence  int64           `json:"sequence"`
	EventType StreamEventType `json:"event_type"`
	Content   json.RawMessage `json:"content"`
	Timestamp time.Time       `json:"timestamp"`
	TraceID   string          `json:"trace_id,omitempty"`
	SpanID    string          `json:"span_id,omitempty"`
}

// SteeringMessage represents a steering control message
type SteeringMessage struct {
	ID             types.ID        `json:"id"`
	SessionID      types.ID        `json:"session_id"`
	Sequence       int64           `json:"sequence"`
	OperatorID     string          `json:"operator_id"`
	MessageType    SteeringType    `json:"message_type"`
	Content        json.RawMessage `json:"content"`
	Timestamp      time.Time       `json:"timestamp"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	TraceID        string          `json:"trace_id,omitempty"`
}

// StreamEventFilter provides filtering options for stream event queries
type StreamEventFilter struct {
	EventTypes []StreamEventType // Filter by event types
	FromSeq    int64             // Filter events with sequence >= FromSeq
	ToSeq      int64             // Filter events with sequence <= ToSeq
	FromTime   time.Time         // Filter events with timestamp >= FromTime
	ToTime     time.Time         // Filter events with timestamp <= ToTime
	Limit      int               // Maximum number of events to return
}

// SessionDAO defines the interface for agent session data access
type SessionDAO interface {
	// Session CRUD operations
	CreateSession(ctx context.Context, session *AgentSession) error
	GetSession(ctx context.Context, id types.ID) (*AgentSession, error)
	UpdateSession(ctx context.Context, session *AgentSession) error
	ListSessionsByMission(ctx context.Context, missionID types.ID) ([]AgentSession, error)

	// Stream events
	InsertStreamEvent(ctx context.Context, event *StreamEvent) error
	InsertStreamEventBatch(ctx context.Context, events []StreamEvent) error
	GetStreamEvents(ctx context.Context, sessionID types.ID, filter StreamEventFilter) ([]StreamEvent, error)

	// Steering messages
	InsertSteeringMessage(ctx context.Context, msg *SteeringMessage) error
	AcknowledgeSteeringMessage(ctx context.Context, id types.ID) error
	GetSteeringMessages(ctx context.Context, sessionID types.ID) ([]SteeringMessage, error)
}
