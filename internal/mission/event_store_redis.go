package mission

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisEventStore implements EventStore using Redis Streams.
// Events are stored in streams keyed by mission ID for efficient querying and real-time subscriptions.
type RedisEventStore struct {
	client *state.StateClient
}

// NewRedisEventStore creates a new Redis-backed event store.
func NewRedisEventStore(client *state.StateClient) *RedisEventStore {
	return &RedisEventStore{
		client: client,
	}
}

// streamKey returns the Redis stream key for a mission's events.
// Format: "gibson:stream:mission:{mission_id}:events"
func (s *RedisEventStore) streamKey(missionID types.ID) string {
	return fmt.Sprintf("gibson:stream:mission:%s:events", missionID.String())
}

// Append persists an event to the Redis Stream.
// This uses XADD with auto-generated ID ("*") for time-ordered events.
func (s *RedisEventStore) Append(ctx context.Context, event *MissionEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Set timestamp if not set
	timestamp := event.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	// Marshal payload to JSON string
	var payloadJSON string
	if event.Payload != nil {
		data, err := json.Marshal(event.Payload)
		if err != nil {
			return fmt.Errorf("failed to marshal event payload: %w", err)
		}
		payloadJSON = string(data)
	}

	// Prepare stream entry values
	values := map[string]any{
		"event_type": string(event.Type),
		"payload":    payloadJSON,
		"created_at": timestamp.Format(time.RFC3339Nano),
	}

	// Add to stream with auto-generated ID
	streamKey := s.streamKey(event.MissionID)
	_, err := s.client.StreamAdd(ctx, streamKey, values)
	if err != nil {
		return fmt.Errorf("failed to add event to stream: %w", err)
	}

	return nil
}

// Query retrieves events matching filter criteria from Redis Streams.
// Results are ordered by stream ID (which is time-ordered) ascending.
func (s *RedisEventStore) Query(ctx context.Context, filter *EventFilter) ([]*MissionEvent, error) {
	if filter == nil {
		filter = NewEventFilter()
	}

	// Set default limit if not specified
	if filter.Limit == 0 {
		filter.Limit = 100
	}

	// Mission ID is required for Redis Streams implementation
	// (each mission has its own stream)
	if filter.MissionID == nil {
		return nil, fmt.Errorf("mission ID is required for Redis event query")
	}

	missionID := *filter.MissionID
	streamKey := s.streamKey(missionID)

	// Determine start and end IDs based on time filters
	start := "-" // Beginning of stream
	end := "+"   // End of stream

	// Note: Redis Streams use entry IDs (timestamp-sequence) for range queries
	// We can't directly convert time.Time to stream IDs, so we'll fetch all
	// and filter in application if time filters are specified
	// For production optimization, consider storing timestamp in ID format

	// Read entries from stream
	entries, err := s.client.StreamRange(ctx, streamKey, start, end, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read from stream: %w", err)
	}

	// Parse entries to events
	events := make([]*MissionEvent, 0, len(entries))
	for _, entry := range entries {
		event, err := s.parseStreamEntry(entry, missionID)
		if err != nil {
			// Log error but continue processing other entries
			continue
		}

		// Apply event type filter
		if len(filter.EventTypes) > 0 {
			matched := false
			for _, eventType := range filter.EventTypes {
				if event.Type == eventType {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Apply time range filters
		if filter.After != nil && event.Timestamp.Before(*filter.After) {
			continue
		}
		if filter.Before != nil && event.Timestamp.After(*filter.Before) {
			continue
		}

		events = append(events, event)
	}

	// Apply offset and limit
	startIdx := filter.Offset
	if startIdx > len(events) {
		startIdx = len(events)
	}

	endIdx := startIdx + filter.Limit
	if endIdx > len(events) {
		endIdx = len(events)
	}

	return events[startIdx:endIdx], nil
}

// Stream returns a channel of events for a mission starting from a timestamp.
// The channel is closed when all events are sent or context is cancelled.
func (s *RedisEventStore) Stream(ctx context.Context, missionID types.ID, fromTimestamp time.Time) (<-chan *MissionEvent, error) {
	streamKey := s.streamKey(missionID)

	// First, get all historical events from the beginning
	// For a proper implementation, we'd need to convert fromTimestamp to a stream ID
	// For now, we'll use "0" to get all events and filter by timestamp
	allEntries, err := s.client.StreamRange(ctx, streamKey, "-", "+", 0)
	if err != nil {
		return nil, fmt.Errorf("failed to read historical events: %w", err)
	}

	// Create buffered channel
	eventCh := make(chan *MissionEvent, 100)

	go func() {
		defer close(eventCh)

		// First, send all historical events that match the timestamp filter
		for _, entry := range allEntries {
			event, err := s.parseStreamEntry(entry, missionID)
			if err != nil {
				continue
			}

			// Filter by timestamp
			if event.Timestamp.Before(fromTimestamp) {
				continue
			}

			select {
			case eventCh <- event:
			case <-ctx.Done():
				return
			}
		}

		// Subscribe to new events using StreamSubscribe
		// Start from "$" to get only new entries added after subscription
		entryChan, err := s.client.StreamSubscribe(ctx, streamKey, "$")
		if err != nil {
			// Can't return error from goroutine, just exit
			return
		}

		// Forward stream entries as mission events
		for entry := range entryChan {
			event, err := s.parseStreamEntry(entry, missionID)
			if err != nil {
				continue
			}

			select {
			case eventCh <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventCh, nil
}

// parseStreamEntry converts a Redis Stream entry to a MissionEvent.
func (s *RedisEventStore) parseStreamEntry(entry state.StreamEntry, missionID types.ID) (*MissionEvent, error) {
	// Extract event_type
	eventTypeVal, ok := entry.Values["event_type"]
	if !ok {
		return nil, fmt.Errorf("missing event_type in stream entry")
	}
	eventTypeStr, ok := eventTypeVal.(string)
	if !ok {
		return nil, fmt.Errorf("event_type is not a string")
	}

	// Extract created_at
	createdAtVal, ok := entry.Values["created_at"]
	if !ok {
		return nil, fmt.Errorf("missing created_at in stream entry")
	}
	createdAtStr, ok := createdAtVal.(string)
	if !ok {
		return nil, fmt.Errorf("created_at is not a string")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	// Extract and parse payload
	var payload interface{}
	if payloadVal, ok := entry.Values["payload"]; ok && payloadVal != nil {
		if payloadStr, ok := payloadVal.(string); ok && payloadStr != "" {
			if err := json.Unmarshal([]byte(payloadStr), &payload); err != nil {
				return nil, fmt.Errorf("failed to unmarshal payload: %w", err)
			}
		}
	}

	return &MissionEvent{
		Type:      MissionEventType(eventTypeStr),
		MissionID: missionID,
		Timestamp: createdAt,
		Payload:   payload,
	}, nil
}

// Trim removes old events from a mission's stream to limit storage.
// This is useful for implementing retention policies.
func (s *RedisEventStore) Trim(ctx context.Context, missionID types.ID, maxLen int64) (int64, error) {
	if maxLen <= 0 {
		return 0, fmt.Errorf("maxLen must be greater than 0")
	}

	streamKey := s.streamKey(missionID)
	opts := &state.StreamTrimOptions{
		MaxLen:      maxLen,
		Approximate: true, // Use approximate trimming for better performance
	}

	removed, err := s.client.StreamTrim(ctx, streamKey, opts)
	if err != nil {
		return 0, fmt.Errorf("failed to trim stream: %w", err)
	}

	return removed, nil
}

// Delete removes all events for a mission by deleting the stream.
// This is called during cascade delete operations.
func (s *RedisEventStore) Delete(ctx context.Context, missionID types.ID) error {
	streamKey := s.streamKey(missionID)

	err := s.client.StreamDel(ctx, streamKey)
	if err != nil {
		return fmt.Errorf("failed to delete stream: %w", err)
	}

	return nil
}

// consumerGroupKey returns the Redis consumer group name for a mission's events.
// Format: "gibson:cg:mission:{mission_id}:events:{group_name}"
func (s *RedisEventStore) consumerGroupKey(missionID types.ID, groupName string) string {
	return fmt.Sprintf("gibson:cg:mission:%s:events:%s", missionID.String(), groupName)
}

// CreateConsumerGroup creates a consumer group for a mission's event stream.
// Consumer groups enable exactly-once message processing with multiple consumers.
//
// The startID parameter specifies where the group should begin reading:
//   - "0" to process all existing messages
//   - "$" to process only new messages
//   - Specific ID to start from that point
//
// This operation is idempotent - if the group already exists, it returns successfully
// without error.
//
// Example:
//
//	err := store.CreateConsumerGroup(ctx, missionID, "event-processors", "0")
//	if err != nil {
//	    log.Fatalf("failed to create consumer group: %v", err)
//	}
func (s *RedisEventStore) CreateConsumerGroup(ctx context.Context, missionID types.ID, groupName, startID string) error {
	if groupName == "" {
		return fmt.Errorf("group name cannot be empty")
	}

	if startID == "" {
		startID = "0"
	}

	streamKey := s.streamKey(missionID)

	// Create the consumer group using the state client
	// The mkStream parameter is true to create the stream if it doesn't exist
	err := s.client.StreamCreateGroup(ctx, streamKey, groupName, startID, true)
	if err != nil {
		return fmt.Errorf("failed to create consumer group %s: %w", groupName, err)
	}

	return nil
}

// SubscribeWithGroup creates a real-time subscription to mission events using a consumer group.
// This enables exactly-once processing where multiple consumers can process events concurrently,
// and each event is delivered to only one consumer.
//
// The consumer group must be created first using CreateConsumerGroup.
//
// Events are automatically acknowledged unless the NoAck option is set in ConsumerGroupOptions.
// For manual acknowledgment, use AckEvent after processing each event.
//
// The returned channel will be closed when:
//   - The context is cancelled
//   - An unrecoverable error occurs
//
// Example:
//
//	// Create consumer group first
//	err := store.CreateConsumerGroup(ctx, missionID, "processors", "$")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Subscribe with consumer group
//	opts := &state.ConsumerGroupOptions{
//	    Group:    "processors",
//	    Consumer: "worker-1",
//	    Count:    10,
//	    Block:    5 * time.Second,
//	    NoAck:    true, // Require explicit ACK
//	}
//
//	eventCh, err := store.SubscribeWithGroup(ctx, missionID, opts)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for event := range eventCh {
//	    // Process event...
//	    if err := processEvent(event); err != nil {
//	        continue // Will be retried via pending messages
//	    }
//	    // Acknowledge successful processing
//	    store.AckEvent(ctx, missionID, opts.Group, event.StreamID)
//	}
func (s *RedisEventStore) SubscribeWithGroup(ctx context.Context, missionID types.ID, opts *state.ConsumerGroupOptions) (<-chan *MissionEventWithID, error) {
	if opts == nil {
		return nil, fmt.Errorf("consumer group options cannot be nil")
	}

	if opts.Group == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	if opts.Consumer == "" {
		return nil, fmt.Errorf("consumer name cannot be empty")
	}

	streamKey := s.streamKey(missionID)
	eventCh := make(chan *MissionEventWithID, 10) // Buffer to prevent blocking

	go func() {
		defer close(eventCh)

		retryDelay := 100 * time.Millisecond
		maxRetryDelay := 5 * time.Second

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Read new events from consumer group
			// Use ">" to read new messages never delivered to any consumer
			entries, err := s.client.StreamReadGroup(ctx, streamKey, ">", opts)
			if err != nil {
				// Check if context was cancelled
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Sleep and retry with exponential backoff
				time.Sleep(retryDelay)
				if retryDelay < maxRetryDelay {
					retryDelay *= 2
				}
				continue
			}

			// Reset retry delay on successful read
			retryDelay = 100 * time.Millisecond

			// Process entries
			if len(entries) == 0 {
				// No new entries, continue blocking read
				continue
			}

			// Send entries to channel
			for _, entry := range entries {
				event, err := s.parseStreamEntry(entry, missionID)
				if err != nil {
					// Log error but continue processing other entries
					continue
				}

				// Create event with stream ID for acknowledgment
				eventWithID := &MissionEventWithID{
					MissionEvent: *event,
					StreamID:     entry.ID,
				}

				select {
				case eventCh <- eventWithID:
					// Event sent successfully
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return eventCh, nil
}

// AckEvent acknowledges that an event has been successfully processed by a consumer group.
// This marks the event as successfully processed and removes it from the pending entries list (PEL).
//
// Acknowledging events is essential for exactly-once processing to work correctly.
// Unacknowledged events can be claimed by other consumers or reprocessed.
//
// Example:
//
//	// After processing an event from SubscribeWithGroup
//	err := store.AckEvent(ctx, missionID, "processors", event.StreamID)
//	if err != nil {
//	    log.Printf("failed to acknowledge event: %v", err)
//	}
func (s *RedisEventStore) AckEvent(ctx context.Context, missionID types.ID, groupName string, streamIDs ...string) error {
	if groupName == "" {
		return fmt.Errorf("group name cannot be empty")
	}

	if len(streamIDs) == 0 {
		return fmt.Errorf("at least one stream ID must be provided")
	}

	streamKey := s.streamKey(missionID)

	err := s.client.StreamAck(ctx, streamKey, groupName, streamIDs...)
	if err != nil {
		return fmt.Errorf("failed to acknowledge events: %w", err)
	}

	return nil
}

// GetPendingEvents retrieves information about pending (unacknowledged) events
// in a consumer group. This is useful for monitoring stuck events and implementing
// dead letter queues.
//
// The count parameter limits the number of results. Use 0 for default (10).
//
// If consumerName is not empty, only pending events for that consumer are returned.
//
// Example:
//
//	// Get all pending events in the group
//	pending, err := store.GetPendingEvents(ctx, missionID, "processors", 100, "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	for _, msg := range pending {
//	    if msg.IdleTime > 5*time.Minute {
//	        log.Printf("Event %s stuck for %v (consumer: %s)",
//	            msg.ID, msg.IdleTime, msg.Consumer)
//	        // Consider claiming or moving to dead letter queue
//	    }
//	}
func (s *RedisEventStore) GetPendingEvents(ctx context.Context, missionID types.ID, groupName string, count int64, consumerName string) ([]state.PendingMessage, error) {
	if groupName == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	if count == 0 {
		count = 10
	}

	streamKey := s.streamKey(missionID)

	pending, err := s.client.StreamPending(ctx, streamKey, groupName, "-", "+", count, consumerName)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending events: %w", err)
	}

	return pending, nil
}

// ClaimStuckEvents transfers ownership of pending events from one consumer to another.
// This is useful for reprocessing stuck events that have been idle for too long.
//
// The minIdleTime parameter specifies the minimum idle time required to claim an event.
// Only events that have been pending for at least this duration can be claimed.
//
// Returns the claimed events with their stream IDs and payloads.
//
// Example:
//
//	// Find stuck events
//	pending, err := store.GetPendingEvents(ctx, missionID, "processors", 100, "")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Claim events idle for more than 5 minutes
//	stuckIDs := []string{}
//	for _, msg := range pending {
//	    if msg.IdleTime > 5*time.Minute {
//	        stuckIDs = append(stuckIDs, msg.ID)
//	    }
//	}
//
//	if len(stuckIDs) > 0 {
//	    events, err := store.ClaimStuckEvents(ctx, missionID, "processors",
//	        "worker-2", 5*time.Minute, stuckIDs...)
//	    if err != nil {
//	        log.Fatal(err)
//	    }
//	    // Process claimed events...
//	}
func (s *RedisEventStore) ClaimStuckEvents(ctx context.Context, missionID types.ID, groupName, consumerName string, minIdleTime time.Duration, streamIDs ...string) ([]*MissionEventWithID, error) {
	if groupName == "" {
		return nil, fmt.Errorf("group name cannot be empty")
	}

	if consumerName == "" {
		return nil, fmt.Errorf("consumer name cannot be empty")
	}

	if len(streamIDs) == 0 {
		return nil, fmt.Errorf("at least one stream ID must be provided")
	}

	streamKey := s.streamKey(missionID)

	entries, err := s.client.StreamClaim(ctx, streamKey, groupName, consumerName, minIdleTime, streamIDs...)
	if err != nil {
		return nil, fmt.Errorf("failed to claim events: %w", err)
	}

	// Parse entries to events
	events := make([]*MissionEventWithID, 0, len(entries))
	for _, entry := range entries {
		event, err := s.parseStreamEntry(entry, missionID)
		if err != nil {
			// Log error but continue processing other entries
			continue
		}

		// Create event with stream ID for acknowledgment
		eventWithID := &MissionEventWithID{
			MissionEvent: *event,
			StreamID:     entry.ID,
		}

		events = append(events, eventWithID)
	}

	return events, nil
}

// MissionEventWithID wraps a MissionEvent with its Redis Stream ID.
// The StreamID is needed for acknowledging events in consumer groups.
type MissionEventWithID struct {
	MissionEvent
	// StreamID is the Redis Stream entry ID (e.g., "1234567890123-0")
	StreamID string
}

// Ensure RedisEventStore implements EventStore at compile time.
var _ EventStore = (*RedisEventStore)(nil)
