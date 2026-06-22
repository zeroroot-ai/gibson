package mission

import (
	"context"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// MissionEventType identifies the type of mission event.
type MissionEventType string

const (
	// EventMissionStarted indicates a mission has started execution.
	EventMissionStarted MissionEventType = "mission.started"

	// EventMissionPaused indicates a mission has been paused.
	EventMissionPaused MissionEventType = "mission.paused"

	// EventMissionResumed indicates a mission has resumed execution.
	EventMissionResumed MissionEventType = "mission.resumed"

	// EventMissionCompleted indicates a mission has completed successfully.
	EventMissionCompleted MissionEventType = "mission.completed"

	// EventMissionFailed indicates a mission has failed.
	EventMissionFailed MissionEventType = "mission.failed"

	// EventMissionCancelled indicates a mission was cancelled.
	EventMissionCancelled MissionEventType = "mission.cancelled"

	// EventMissionProgress indicates mission progress update.
	EventMissionProgress MissionEventType = "mission.progress"

	// EventMissionFinding indicates a new finding was discovered.
	EventMissionFinding MissionEventType = "mission.finding"

	// EventMissionCheckpoint indicates a checkpoint was created.
	EventMissionCheckpoint MissionEventType = "mission.checkpoint"

	// EventMissionCheckpointSaved indicates a checkpoint was successfully saved.
	EventMissionCheckpointSaved MissionEventType = "mission.checkpoint.saved"

	// EventMissionCheckpointLoadFailed indicates checkpoint loading failed.
	EventMissionCheckpointLoadFailed MissionEventType = "mission.checkpoint.load_failed"

	// EventMissionResumedFromCheckpoint indicates a mission resumed from a checkpoint.
	EventMissionResumedFromCheckpoint MissionEventType = "mission.resumed_from_checkpoint"

	// EventMissionConstraintViolation indicates a constraint was violated.
	EventMissionConstraintViolation MissionEventType = "mission.constraint_violation"
)

// String returns the string representation of the event type.
func (t MissionEventType) String() string {
	return string(t)
}

// MissionEvent represents a mission lifecycle event.
// Events are emitted throughout mission execution to enable real-time monitoring.
type MissionEvent struct {
	// Type identifies the event type.
	Type MissionEventType `json:"type"`

	// MissionID is the unique identifier of the mission.
	MissionID types.ID `json:"mission_id"`

	// Timestamp is when the event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Payload contains type-specific event data.
	Payload any `json:"payload,omitempty"`
}

// ProgressPayload contains progress update information.
type ProgressPayload struct {
	// Progress is the current mission progress.
	Progress *MissionProgress `json:"progress"`

	// Message is an optional progress message.
	Message string `json:"message,omitempty"`
}

// FindingPayload contains finding event information.
type FindingPayload struct {
	// FindingID is the ID of the discovered finding.
	FindingID types.ID `json:"finding_id"`

	// Title is the finding title.
	Title string `json:"title"`

	// Severity is the finding severity.
	Severity string `json:"severity"`

	// AgentName is the name of the agent that discovered the finding.
	AgentName string `json:"agent_name"`
}

// CheckpointPayload contains checkpoint event information.
type CheckpointPayload struct {
	// CheckpointID is a unique identifier for this checkpoint.
	CheckpointID string `json:"checkpoint_id"`

	// CompletedNodes is the number of nodes completed.
	CompletedNodes int `json:"completed_nodes"`

	// TotalNodes is the total number of nodes.
	TotalNodes int `json:"total_nodes"`
}

// CheckpointSavedPayload contains checkpoint saved event information.
type CheckpointSavedPayload struct {
	// MissionID is the mission this checkpoint belongs to.
	MissionID types.ID `json:"mission_id"`

	// CheckpointCreatedAt is when the checkpoint was created.
	CheckpointCreatedAt time.Time `json:"checkpoint_created_at"`

	// CompletedNodes is the number of nodes completed at checkpoint time.
	CompletedNodes int `json:"completed_nodes"`

	// TotalNodes is the total number of nodes in the mission.
	TotalNodes int `json:"total_nodes"`

	// CurrentNodeID is the ID of the node being executed when checkpointed.
	CurrentNodeID string `json:"current_node_id,omitempty"`
}

// CheckpointLoadFailedPayload contains checkpoint load failure information.
type CheckpointLoadFailedPayload struct {
	// MissionID is the mission whose checkpoint failed to load.
	MissionID types.ID `json:"mission_id"`

	// Error is the error message describing why the load failed.
	Error string `json:"error"`

	// WillStartFresh indicates whether the mission will start from the beginning.
	WillStartFresh bool `json:"will_start_fresh"`
}

// ResumedFromCheckpointPayload contains checkpoint resume information.
type ResumedFromCheckpointPayload struct {
	// MissionID is the mission being resumed.
	MissionID types.ID `json:"mission_id"`

	// CheckpointCreatedAt is when the checkpoint was originally created.
	CheckpointCreatedAt time.Time `json:"checkpoint_created_at"`

	// CompletedNodes is the number of nodes that were completed in the checkpoint.
	CompletedNodes int `json:"completed_nodes"`

	// TotalNodes is the total number of nodes in the mission.
	TotalNodes int `json:"total_nodes"`

	// RemainingNodes is the number of nodes left to execute.
	RemainingNodes int `json:"remaining_nodes"`

	// CurrentNodeID is the node that was being executed when checkpointed.
	CurrentNodeID string `json:"current_node_id,omitempty"`
}

// ConstraintViolationPayload contains constraint violation information.
type ConstraintViolationPayload struct {
	// Violation contains the violation details.
	Violation *ConstraintViolation `json:"violation"`

	// WillPause indicates if the mission will be paused.
	WillPause bool `json:"will_pause"`

	// WillFail indicates if the mission will fail.
	WillFail bool `json:"will_fail"`
}

// EventEmitter publishes mission events to subscribers.
// Implementations must be thread-safe and support multiple concurrent subscribers.
type EventEmitter interface {
	// Emit publishes an event to all subscribers.
	// Returns an error if the event cannot be emitted.
	Emit(ctx context.Context, event MissionEvent) error

	// Subscribe creates a new subscription and returns a channel for receiving events
	// and a cleanup function to unsubscribe.
	// The cleanup function must be called to prevent resource leaks.
	Subscribe(ctx context.Context) (<-chan MissionEvent, func())

	// Close shuts down the emitter and all subscriptions.
	Close() error
}

// DefaultEventEmitter implements EventEmitter using buffered channels.
// It supports multiple subscribers and handles slow consumers gracefully.
type DefaultEventEmitter struct {
	mu          sync.RWMutex
	subscribers map[string]chan MissionEvent
	bufferSize  int
	closed      bool
}

// EventEmitterOption is a functional option for configuring DefaultEventEmitter.
type EventEmitterOption func(*DefaultEventEmitter)

// WithBufferSize sets the buffer size for subscriber channels.
// Default is 100. Larger buffers can handle bursty events better.
func WithBufferSize(size int) EventEmitterOption {
	return func(e *DefaultEventEmitter) {
		e.bufferSize = size
	}
}

// NewDefaultEventEmitter creates a new DefaultEventEmitter with optional configuration.
func NewDefaultEventEmitter(opts ...EventEmitterOption) *DefaultEventEmitter {
	emitter := &DefaultEventEmitter{
		subscribers: make(map[string]chan MissionEvent),
		bufferSize:  100, // Default buffer size
		closed:      false,
	}

	for _, opt := range opts {
		opt(emitter)
	}

	return emitter
}

// Emit publishes an event to all subscribers.
// If a subscriber's channel is full, the event is dropped for that subscriber
// to prevent blocking other subscribers (slow consumer handling).
func (e *DefaultEventEmitter) Emit(ctx context.Context, event MissionEvent) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		return NewInternalError("event emitter is closed", nil)
	}

	// Send to all subscribers (non-blocking)
	for _, ch := range e.subscribers {
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
func (e *DefaultEventEmitter) Subscribe(ctx context.Context) (<-chan MissionEvent, func()) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Generate unique subscriber ID
	subscriberID := types.NewID().String()
	ch := make(chan MissionEvent, e.bufferSize)
	e.subscribers[subscriberID] = ch

	// Cleanup function to unsubscribe
	cleanup := func() {
		e.mu.Lock()
		defer e.mu.Unlock()

		if subCh, exists := e.subscribers[subscriberID]; exists {
			delete(e.subscribers, subscriberID)
			close(subCh)
		}
	}

	return ch, cleanup
}

// Close shuts down the emitter and closes all subscriber channels.
func (e *DefaultEventEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return nil
	}

	e.closed = true

	// Close all subscriber channels
	for id, ch := range e.subscribers {
		close(ch)
		delete(e.subscribers, id)
	}

	return nil
}

// SubscriberCount returns the current number of active subscribers.
// Useful for monitoring and testing.
func (e *DefaultEventEmitter) SubscriberCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.subscribers)
}

// NewMissionEvent creates a new mission event with the current timestamp.
func NewMissionEvent(eventType MissionEventType, missionID types.ID, payload any) MissionEvent {
	return MissionEvent{
		Type:      eventType,
		MissionID: missionID,
		Timestamp: time.Now(),
		Payload:   payload,
	}
}

// Helper functions for creating specific event types

// NewStartedEvent creates a mission started event.
func NewStartedEvent(missionID types.ID) MissionEvent {
	return NewMissionEvent(EventMissionStarted, missionID, nil)
}

// NewPausedEvent creates a mission paused event.
func NewPausedEvent(missionID types.ID, reason string) MissionEvent {
	return NewMissionEvent(EventMissionPaused, missionID, map[string]any{
		"reason": reason,
	})
}

// NewResumedEvent creates a mission resumed event.
func NewResumedEvent(missionID types.ID) MissionEvent {
	return NewMissionEvent(EventMissionResumed, missionID, nil)
}

// NewCompletedEvent creates a mission completed event.
func NewCompletedEvent(missionID types.ID, result *MissionResult) MissionEvent {
	return NewMissionEvent(EventMissionCompleted, missionID, result)
}

// NewFailedEvent creates a mission failed event.
func NewFailedEvent(missionID types.ID, err error) MissionEvent {
	return NewMissionEvent(EventMissionFailed, missionID, map[string]any{
		"error": err.Error(),
	})
}

// NewCancelledEvent creates a mission cancelled event.
func NewCancelledEvent(missionID types.ID, reason string) MissionEvent {
	return NewMissionEvent(EventMissionCancelled, missionID, map[string]any{
		"reason": reason,
	})
}

// NewProgressEvent creates a mission progress event.
func NewProgressEvent(missionID types.ID, progress *MissionProgress, message string) MissionEvent {
	return NewMissionEvent(EventMissionProgress, missionID, &ProgressPayload{
		Progress: progress,
		Message:  message,
	})
}

// NewFindingEvent creates a finding discovered event.
func NewFindingEvent(missionID, findingID types.ID, title, severity, agentName string) MissionEvent {
	return NewMissionEvent(EventMissionFinding, missionID, &FindingPayload{
		FindingID: findingID,
		Title:     title,
		Severity:  severity,
		AgentName: agentName,
	})
}

// NewCheckpointEvent creates a checkpoint created event.
func NewCheckpointEvent(missionID types.ID, checkpointID string, completedNodes, totalNodes int) MissionEvent {
	return NewMissionEvent(EventMissionCheckpoint, missionID, &CheckpointPayload{
		CheckpointID:   checkpointID,
		CompletedNodes: completedNodes,
		TotalNodes:     totalNodes,
	})
}

// NewConstraintViolationEvent creates a constraint violation event.
func NewConstraintViolationEvent(missionID types.ID, violation *ConstraintViolation) MissionEvent {
	return NewMissionEvent(EventMissionConstraintViolation, missionID, &ConstraintViolationPayload{
		Violation: violation,
		WillPause: violation.Action == ConstraintActionPause,
		WillFail:  violation.Action == ConstraintActionFail,
	})
}

// Ensure DefaultEventEmitter implements EventEmitter at compile time
var _ EventEmitter = (*DefaultEventEmitter)(nil)
