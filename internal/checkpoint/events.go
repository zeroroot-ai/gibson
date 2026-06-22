package checkpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/zeroroot-ai/gibson/internal/state"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// CheckpointEventEmitter provides event emission and subscription for checkpoint lifecycle events.
// Events are published to Redis Streams for real-time monitoring and audit trails.
//
// Usage:
//
//	emitter := NewRedisEventEmitter(stateClient)
//	defer emitter.Close()
//
//	// Emit checkpoint created event
//	event := NewCheckpointCreatedEvent(missionID, threadID, checkpointID, sizeBytes)
//	if err := emitter.Emit(ctx, event); err != nil {
//	    log.Printf("failed to emit event: %v", err)
//	}
//
//	// Subscribe to events
//	eventCh, err := emitter.Subscribe(ctx, missionID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	for event := range eventCh {
//	    fmt.Printf("Event: %s at %s\n", event.Type, event.Timestamp)
//	}
type CheckpointEventEmitter interface {
	// Emit sends an event to Redis Streams.
	// Events are published to mission-specific streams for efficient filtering.
	Emit(ctx context.Context, event *CheckpointLifecycleEvent) error

	// Subscribe creates a subscription to checkpoint events for a mission.
	// Returns a channel that receives events in real-time.
	// The channel is closed when the context is cancelled or an error occurs.
	Subscribe(ctx context.Context, missionID types.ID) (<-chan *CheckpointLifecycleEvent, error)

	// SubscribeAll subscribes to all checkpoint events across all missions.
	// Useful for admin dashboards and monitoring tools.
	SubscribeAll(ctx context.Context) (<-chan *CheckpointLifecycleEvent, error)

	// Close releases all resources held by the emitter.
	Close() error
}

// CheckpointLifecycleEvent represents a checkpoint lifecycle event in the system.
// Events are immutable once created and provide an audit trail of all
// checkpoint operations.
//
// Note: This is distinct from checkpoint.CheckpointEvent which is used for
// checkpoint creation policy decisions.
type CheckpointLifecycleEvent struct {
	// ID is the unique event ID assigned by Redis (stream entry ID).
	// Format: <millisecondsTime>-<sequenceNumber>
	ID string `json:"id"`

	// Type indicates the kind of checkpoint event.
	Type LifecycleEventType `json:"type"`

	// MissionID identifies which mission this event belongs to.
	MissionID string `json:"mission_id"`

	// ThreadID identifies which thread this event belongs to.
	ThreadID string `json:"thread_id"`

	// CheckpointID is the checkpoint this event relates to (optional for some events).
	CheckpointID string `json:"checkpoint_id,omitempty"`

	// NodeID is the mission node associated with this event (optional).
	NodeID string `json:"node_id,omitempty"`

	// Timestamp is when this event occurred.
	Timestamp time.Time `json:"timestamp"`

	// Data contains event-specific payload data.
	// Structure varies by event type.
	Data map[string]any `json:"data,omitempty"`

	// CorrelationID links related events together for tracing.
	// Can be a request ID, span ID, or custom correlation identifier.
	CorrelationID string `json:"correlation_id,omitempty"`
}

// LifecycleEventType represents the type of checkpoint lifecycle event.
type LifecycleEventType string

const (
	// Checkpoint lifecycle events
	// EventCheckpointCreated is emitted when a new checkpoint is created.
	EventCheckpointCreated LifecycleEventType = "checkpoint.created"

	// EventCheckpointRestored is emitted when a checkpoint is restored.
	EventCheckpointRestored LifecycleEventType = "checkpoint.restored"

	// EventCheckpointDeleted is emitted when a checkpoint is deleted.
	EventCheckpointDeleted LifecycleEventType = "checkpoint.deleted"

	// EventCheckpointFailed is emitted when checkpoint creation or restoration fails.
	EventCheckpointFailed LifecycleEventType = "checkpoint.failed"

	// Thread lifecycle events
	// EventThreadCreated is emitted when a new thread is created.
	EventThreadCreated LifecycleEventType = "thread.created"

	// EventThreadBranched is emitted when a thread is branched from a checkpoint.
	EventThreadBranched LifecycleEventType = "thread.branched"

	// EventThreadCompleted is emitted when a thread completes successfully.
	EventThreadCompleted LifecycleEventType = "thread.completed"

	// EventThreadDeleted is emitted when a thread is deleted.
	EventThreadDeleted LifecycleEventType = "thread.deleted"

	// Replay events
	// EventReplayStarted is emitted when replay begins from a checkpoint.
	EventReplayStarted LifecycleEventType = "replay.started"

	// EventReplayCompleted is emitted when replay completes successfully.
	EventReplayCompleted LifecycleEventType = "replay.completed"
)

// String returns the string representation of LifecycleEventType.
func (t LifecycleEventType) String() string {
	return string(t)
}

// RedisEventEmitter implements CheckpointEventEmitter using Redis Streams.
// Events are stored in mission-specific streams for efficient filtering and subscription.
type RedisEventEmitter struct {
	client    *state.StateClient
	keyPrefix string
}

// NewRedisEventEmitter creates a new Redis-backed checkpoint event emitter.
// The keyPrefix defaults to "gibson:stream:checkpoint" if not specified.
func NewRedisEventEmitter(client *state.StateClient) *RedisEventEmitter {
	return &RedisEventEmitter{
		client:    client,
		keyPrefix: "gibson:stream:checkpoint",
	}
}

// streamKey returns the Redis stream key for a mission's checkpoint events.
// Format: "gibson:stream:checkpoint:{mission_id}"
func (e *RedisEventEmitter) streamKey(missionID string) string {
	return fmt.Sprintf("%s:%s", e.keyPrefix, missionID)
}

// globalStreamKey returns the Redis stream key for all checkpoint events.
// Format: "gibson:stream:checkpoint:all"
func (e *RedisEventEmitter) globalStreamKey() string {
	return fmt.Sprintf("%s:all", e.keyPrefix)
}

// Emit sends a checkpoint event to Redis Streams.
// Events are published to both the mission-specific stream and the global stream.
func (e *RedisEventEmitter) Emit(ctx context.Context, event *CheckpointLifecycleEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	if event.MissionID == "" {
		return fmt.Errorf("event mission_id cannot be empty")
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Convert event to stream entry
	values := event.toStreamEntry()

	// Publish to mission-specific stream
	missionStreamKey := e.streamKey(event.MissionID)
	id, err := e.client.StreamAdd(ctx, missionStreamKey, values)
	if err != nil {
		return fmt.Errorf("failed to emit event to mission stream: %w", err)
	}

	// Set the event ID from Redis
	event.ID = id

	// Publish to global stream for admin monitoring
	globalStreamKey := e.globalStreamKey()
	if _, err := e.client.StreamAdd(ctx, globalStreamKey, values); err != nil {
		// Log but don't fail if global stream publish fails
		// The mission-specific stream is the primary source of truth
	}

	return nil
}

// Subscribe creates a subscription to checkpoint events for a specific mission.
// Returns a channel that receives events in real-time.
func (e *RedisEventEmitter) Subscribe(ctx context.Context, missionID types.ID) (<-chan *CheckpointLifecycleEvent, error) {
	streamKey := e.streamKey(missionID.String())

	// Subscribe to stream starting from new entries
	entryChan, err := e.client.StreamSubscribe(ctx, streamKey, "$")
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to mission stream: %w", err)
	}

	// Create event channel
	eventChan := make(chan *CheckpointLifecycleEvent, 10)

	// Convert stream entries to checkpoint events
	go func() {
		defer close(eventChan)

		for entry := range entryChan {
			event, err := fromStreamEntry(entry.ID, entry.Values)
			if err != nil {
				// Log error but continue processing
				continue
			}

			select {
			case eventChan <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventChan, nil
}

// SubscribeAll subscribes to all checkpoint events across all missions.
// Useful for admin dashboards and monitoring tools.
func (e *RedisEventEmitter) SubscribeAll(ctx context.Context) (<-chan *CheckpointLifecycleEvent, error) {
	streamKey := e.globalStreamKey()

	// Subscribe to global stream starting from new entries
	entryChan, err := e.client.StreamSubscribe(ctx, streamKey, "$")
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe to global stream: %w", err)
	}

	// Create event channel
	eventChan := make(chan *CheckpointLifecycleEvent, 10)

	// Convert stream entries to checkpoint events
	go func() {
		defer close(eventChan)

		for entry := range entryChan {
			event, err := fromStreamEntry(entry.ID, entry.Values)
			if err != nil {
				// Log error but continue processing
				continue
			}

			select {
			case eventChan <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventChan, nil
}

// Close releases all resources held by the emitter.
// Currently a no-op as the state client handles connection lifecycle.
func (e *RedisEventEmitter) Close() error {
	// No resources to clean up - state client is managed externally
	return nil
}

// toStreamEntry converts a CheckpointLifecycleEvent to Redis stream entry values.
func (e *CheckpointLifecycleEvent) toStreamEntry() map[string]interface{} {
	values := map[string]interface{}{
		"type":       string(e.Type),
		"mission_id": e.MissionID,
		"thread_id":  e.ThreadID,
		"timestamp":  e.Timestamp.Format(time.RFC3339Nano),
	}

	// Add optional fields
	if e.CheckpointID != "" {
		values["checkpoint_id"] = e.CheckpointID
	}

	if e.NodeID != "" {
		values["node_id"] = e.NodeID
	}

	if e.CorrelationID != "" {
		values["correlation_id"] = e.CorrelationID
	}

	// Serialize data as JSON if present
	if len(e.Data) > 0 {
		dataJSON, err := json.Marshal(e.Data)
		if err == nil {
			values["data"] = string(dataJSON)
		}
	}

	return values
}

// fromStreamEntry parses a Redis stream entry into a CheckpointLifecycleEvent.
func fromStreamEntry(id string, values map[string]interface{}) (*CheckpointLifecycleEvent, error) {
	// Extract required fields
	eventType, ok := values["type"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid type field")
	}

	missionID, ok := values["mission_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid mission_id field")
	}

	threadID, ok := values["thread_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid thread_id field")
	}

	timestampStr, ok := values["timestamp"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid timestamp field")
	}

	timestamp, err := time.Parse(time.RFC3339Nano, timestampStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}

	// Build event
	event := &CheckpointLifecycleEvent{
		ID:        id,
		Type:      LifecycleEventType(eventType),
		MissionID: missionID,
		ThreadID:  threadID,
		Timestamp: timestamp,
	}

	// Extract optional fields
	if checkpointID, ok := values["checkpoint_id"].(string); ok {
		event.CheckpointID = checkpointID
	}

	if nodeID, ok := values["node_id"].(string); ok {
		event.NodeID = nodeID
	}

	if correlationID, ok := values["correlation_id"].(string); ok {
		event.CorrelationID = correlationID
	}

	// Parse data if present
	if dataStr, ok := values["data"].(string); ok && dataStr != "" {
		var data map[string]any
		if err := json.Unmarshal([]byte(dataStr), &data); err == nil {
			event.Data = data
		}
	}

	return event, nil
}

// Event builder functions

// NewCheckpointCreatedEvent creates an event for checkpoint creation.
func NewCheckpointCreatedEvent(missionID, threadID, checkpointID string, sizeBytes int64) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventCheckpointCreated,
		MissionID:    missionID,
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"size_bytes": sizeBytes,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewCheckpointRestoredEvent creates an event for checkpoint restoration.
func NewCheckpointRestoredEvent(missionID, threadID, checkpointID string, nodesSkipped int) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventCheckpointRestored,
		MissionID:    missionID,
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"nodes_skipped": nodesSkipped,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewCheckpointDeletedEvent creates an event for checkpoint deletion.
func NewCheckpointDeletedEvent(missionID, threadID, checkpointID string, reason string) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventCheckpointDeleted,
		MissionID:    missionID,
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"reason": reason,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewCheckpointFailedEvent creates an event for checkpoint operation failure.
func NewCheckpointFailedEvent(missionID, threadID, checkpointID, operation, errMsg string) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventCheckpointFailed,
		MissionID:    missionID,
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"operation": operation,
			"error":     errMsg,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewThreadCreatedEvent creates an event for thread creation.
func NewThreadCreatedEvent(missionID, threadID string, isPrimary bool) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:      EventThreadCreated,
		MissionID: missionID,
		ThreadID:  threadID,
		Timestamp: time.Now(),
		Data: map[string]any{
			"is_primary": isPrimary,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewThreadBranchedEvent creates an event for thread branching.
func NewThreadBranchedEvent(missionID, parentThreadID, newThreadID, sourceCheckpointID string) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventThreadBranched,
		MissionID:    missionID,
		ThreadID:     newThreadID,
		CheckpointID: sourceCheckpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"parent_thread_id": parentThreadID,
			"new_thread_id":    newThreadID,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewThreadCompletedEvent creates an event for thread completion.
func NewThreadCompletedEvent(missionID, threadID string, result *ThreadResult) *CheckpointLifecycleEvent {
	event := &CheckpointLifecycleEvent{
		Type:          EventThreadCompleted,
		MissionID:     missionID,
		ThreadID:      threadID,
		Timestamp:     time.Now(),
		Data:          make(map[string]any),
		CorrelationID: ulid.Make().String(),
	}

	if result != nil {
		event.Data["status"] = result.Status.String()
		event.Data["findings_count"] = result.FindingsCount
		event.Data["nodes_completed"] = result.NodesCompleted
		event.Data["nodes_failed"] = result.NodesFailed
		event.Data["duration_ms"] = result.Duration.Milliseconds()
		event.Data["tokens_used"] = result.TokensUsed
		event.Data["cost"] = result.Cost
		if result.Score > 0 {
			event.Data["score"] = result.Score
		}
		if result.Error != "" {
			event.Data["error"] = result.Error
		}
	}

	return event
}

// NewThreadDeletedEvent creates an event for thread deletion.
func NewThreadDeletedEvent(missionID, threadID, reason string) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:      EventThreadDeleted,
		MissionID: missionID,
		ThreadID:  threadID,
		Timestamp: time.Now(),
		Data: map[string]any{
			"reason": reason,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewReplayStartedEvent creates an event for replay start.
func NewReplayStartedEvent(missionID, threadID, checkpointID string, targetNodeID string) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventReplayStarted,
		MissionID:    missionID,
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"target_node_id": targetNodeID,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// NewReplayCompletedEvent creates an event for replay completion.
func NewReplayCompletedEvent(missionID, threadID, checkpointID string, nodesReplayed int, durationMs int64) *CheckpointLifecycleEvent {
	return &CheckpointLifecycleEvent{
		Type:         EventReplayCompleted,
		MissionID:    missionID,
		ThreadID:     threadID,
		CheckpointID: checkpointID,
		Timestamp:    time.Now(),
		Data: map[string]any{
			"nodes_replayed": nodesReplayed,
			"duration_ms":    durationMs,
		},
		CorrelationID: ulid.Make().String(),
	}
}

// WithCorrelationID sets the correlation ID for tracing related events.
func (e *CheckpointLifecycleEvent) WithCorrelationID(correlationID string) *CheckpointLifecycleEvent {
	e.CorrelationID = correlationID
	return e
}

// WithData adds additional data to the event.
func (e *CheckpointLifecycleEvent) WithData(key string, value any) *CheckpointLifecycleEvent {
	if e.Data == nil {
		e.Data = make(map[string]any)
	}
	e.Data[key] = value
	return e
}

// Ensure RedisEventEmitter implements CheckpointEventEmitter at compile time.
var _ CheckpointEventEmitter = (*RedisEventEmitter)(nil)
