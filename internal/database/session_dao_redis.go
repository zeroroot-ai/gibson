package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// RedisSessionDAO provides Redis-based storage for agent sessions, stream events, and steering messages.
// It uses RedisJSON for session documents, Redis Streams for event streams, and Redis Lists for steering queues.
//
// Key naming convention:
//   - Session document: "gibson:session:{id}" (with TTL)
//   - Session stream: "gibson:stream:session:{id}"
//   - Steering messages: "gibson:session:{id}:steering" (list)
//   - Active sessions set: "gibson:session:active"
//
// TTL and cleanup:
//   - Session documents expire after 24 hours by default
//   - TTL is refreshed on activity (GetSession, UpdateSession)
//   - Active sessions are tracked in a Redis Set
//   - Ended sessions are removed from the active set but retain their TTL
type RedisSessionDAO struct {
	client     *state.StateClient
	sessionTTL time.Duration
}

// Compile-time check to ensure RedisSessionDAO implements SessionDAO interface
var _ SessionDAO = (*RedisSessionDAO)(nil)

const (
	// DefaultSessionTTL is the default expiration time for session documents
	DefaultSessionTTL = 24 * time.Hour
)

// sessionDocument represents the JSON structure stored in Redis.
type sessionDocument struct {
	ID        string `json:"id"`
	MissionID string `json:"mission_id"`
	AgentName string `json:"agent_name"`
	Status    string `json:"status"`
	Mode      string `json:"mode"`
	StartedAt int64  `json:"started_at"` // Unix milliseconds
	EndedAt   *int64 `json:"ended_at,omitempty"`
	Metadata  string `json:"metadata,omitempty"` // JSON string
}

// streamEventDocument represents a stream event as it's stored in Redis Streams.
type streamEventDocument struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Sequence  int64  `json:"sequence"`
	EventType string `json:"event_type"`
	Content   string `json:"content"` // JSON string
	Timestamp int64  `json:"timestamp"`
	TraceID   string `json:"trace_id,omitempty"`
	SpanID    string `json:"span_id,omitempty"`
}

// steeringMessageDocument represents a steering message stored in Redis List.
type steeringMessageDocument struct {
	ID             string `json:"id"`
	SessionID      string `json:"session_id"`
	Sequence       int64  `json:"sequence"`
	OperatorID     string `json:"operator_id"`
	MessageType    string `json:"message_type"`
	Content        string `json:"content"` // JSON string
	Timestamp      int64  `json:"timestamp"`
	AcknowledgedAt *int64 `json:"acknowledged_at,omitempty"`
	TraceID        string `json:"trace_id,omitempty"`
}

// NewRedisSessionDAO creates a new Redis-based session DAO with default TTL.
func NewRedisSessionDAO(client *state.StateClient) *RedisSessionDAO {
	return &RedisSessionDAO{
		client:     client,
		sessionTTL: DefaultSessionTTL,
	}
}

// NewRedisSessionDAOWithTTL creates a new Redis-based session DAO with custom TTL.
func NewRedisSessionDAOWithTTL(client *state.StateClient, ttl time.Duration) *RedisSessionDAO {
	return &RedisSessionDAO{
		client:     client,
		sessionTTL: ttl,
	}
}

// sessionKey returns the Redis key for a session document by ID.
func sessionKey(id types.ID) string {
	return fmt.Sprintf("gibson:session:%s", id.String())
}

// sessionStreamKey returns the Redis key for a session's event stream.
func sessionStreamKey(id types.ID) string {
	return fmt.Sprintf("gibson:stream:session:%s", id.String())
}

// sessionSteeringKey returns the Redis key for a session's steering message queue.
func sessionSteeringKey(id types.ID) string {
	return fmt.Sprintf("gibson:session:%s:steering", id.String())
}

// activeSessionsKey returns the Redis key for the active sessions set.
func activeSessionsKey() string {
	return "gibson:session:active"
}

// toSessionDocument converts an AgentSession to a sessionDocument for Redis storage.
func toSessionDocument(session *AgentSession) *sessionDocument {
	doc := &sessionDocument{
		ID:        session.ID.String(),
		MissionID: session.MissionID.String(),
		AgentName: session.AgentName,
		Status:    string(session.Status),
		Mode:      string(session.Mode),
		StartedAt: session.StartedAt.UnixMilli(),
	}

	if session.EndedAt != nil {
		endedAtMs := session.EndedAt.UnixMilli()
		doc.EndedAt = &endedAtMs
	}

	if len(session.Metadata) > 0 {
		doc.Metadata = string(session.Metadata)
	} else {
		doc.Metadata = "{}"
	}

	return doc
}

// fromSessionDocument converts a sessionDocument from Redis to an AgentSession.
func fromSessionDocument(doc *sessionDocument) (*AgentSession, error) {
	id, err := types.ParseID(doc.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session ID: %w", err)
	}

	missionID, err := types.ParseID(doc.MissionID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse mission ID: %w", err)
	}

	session := &AgentSession{
		ID:        id,
		MissionID: missionID,
		AgentName: doc.AgentName,
		Status:    AgentStatus(doc.Status),
		Mode:      AgentMode(doc.Mode),
		StartedAt: time.UnixMilli(doc.StartedAt),
	}

	if doc.EndedAt != nil {
		endedAt := time.UnixMilli(*doc.EndedAt)
		session.EndedAt = &endedAt
	}

	if doc.Metadata != "" && doc.Metadata != "{}" {
		session.Metadata = json.RawMessage(doc.Metadata)
	}

	return session, nil
}

// CreateSession creates a new agent session with TTL and adds it to the active sessions set.
func (dao *RedisSessionDAO) CreateSession(ctx context.Context, session *AgentSession) error {
	if session.ID.IsZero() {
		session.ID = types.NewID()
	}

	if session.StartedAt.IsZero() {
		session.StartedAt = time.Now()
	}

	doc := toSessionDocument(session)
	key := sessionKey(session.ID)

	// Set the JSON document first (cannot be done in pipeline with RedisJSON)
	if err := dao.client.JSONSet(ctx, key, "$", doc); err != nil {
		return fmt.Errorf("failed to create session document: %w", err)
	}

	// Use pipeline for TTL and active set operations
	pipe := dao.client.Client().Pipeline()

	// Set TTL on the session document
	pipe.Expire(ctx, key, dao.sessionTTL)

	// Add to active sessions set
	pipe.SAdd(ctx, activeSessionsKey(), session.ID.String())

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to execute create session pipeline: %w", err)
	}

	return nil
}

// GetSession retrieves an agent session by ID and refreshes its TTL.
func (dao *RedisSessionDAO) GetSession(ctx context.Context, id types.ID) (*AgentSession, error) {
	key := sessionKey(id)

	// JSONPath $ returns an array, so we unmarshal into a slice
	var docs []sessionDocument
	err := dao.client.JSONGet(ctx, key, "$", &docs)
	if err != nil {
		if err == state.ErrNotFound || err == redis.Nil {
			return nil, fmt.Errorf("session not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if len(docs) == 0 {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	doc := docs[0]

	// Refresh TTL on access
	if err := dao.client.Client().Expire(ctx, key, dao.sessionTTL).Err(); err != nil {
		// Log but don't fail on TTL refresh error
		// In production, you might want to log this
	}

	return fromSessionDocument(&doc)
}

// UpdateSession updates an existing session's status, mode, or metadata.
// Uses JSONPath to update specific fields efficiently.
func (dao *RedisSessionDAO) UpdateSession(ctx context.Context, session *AgentSession) error {
	key := sessionKey(session.ID)

	// Check if session exists
	exists, err := dao.client.Client().Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}
	if exists == 0 {
		return fmt.Errorf("session not found: %s", session.ID)
	}

	// Update specific fields using JSONPath (these cannot be pipelined with RedisJSON)
	// Update status
	if err := dao.client.JSONSet(ctx, key, "$.status", string(session.Status)); err != nil {
		return fmt.Errorf("failed to update status: %w", err)
	}

	// Update mode
	if err := dao.client.JSONSet(ctx, key, "$.mode", string(session.Mode)); err != nil {
		return fmt.Errorf("failed to update mode: %w", err)
	}

	// Update ended_at if set
	if session.EndedAt != nil {
		endedAtMs := session.EndedAt.UnixMilli()
		if err := dao.client.JSONSet(ctx, key, "$.ended_at", endedAtMs); err != nil {
			return fmt.Errorf("failed to update ended_at: %w", err)
		}
	}

	// Update metadata if provided
	if len(session.Metadata) > 0 {
		if err := dao.client.JSONSet(ctx, key, "$.metadata", string(session.Metadata)); err != nil {
			return fmt.Errorf("failed to update metadata: %w", err)
		}
	}

	// Use pipeline for TTL refresh and active set operations
	pipe := dao.client.Client().Pipeline()

	// Refresh TTL on update
	pipe.Expire(ctx, key, dao.sessionTTL)

	// Remove from active set if session has ended
	if session.EndedAt != nil {
		pipe.SRem(ctx, activeSessionsKey(), session.ID.String())
	}

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to execute update session pipeline: %w", err)
	}

	return nil
}

// ListSessionsByMission retrieves all active sessions for a given mission.
// This is implemented by scanning the active sessions set and filtering by mission ID.
func (dao *RedisSessionDAO) ListSessionsByMission(ctx context.Context, missionID types.ID) ([]AgentSession, error) {
	// Get all active session IDs
	sessionIDs, err := dao.client.Client().SMembers(ctx, activeSessionsKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get active sessions: %w", err)
	}

	sessions := make([]AgentSession, 0)

	// Fetch each session and filter by mission ID
	for _, sessionIDStr := range sessionIDs {
		sessionID, err := types.ParseID(sessionIDStr)
		if err != nil {
			// Skip invalid IDs
			continue
		}

		session, err := dao.GetSession(ctx, sessionID)
		if err != nil {
			// Skip sessions that no longer exist
			continue
		}

		if session.MissionID == missionID {
			sessions = append(sessions, *session)
		}
	}

	return sessions, nil
}

// InsertStreamEvent inserts a single stream event into the session's event stream.
func (dao *RedisSessionDAO) InsertStreamEvent(ctx context.Context, event *StreamEvent) error {
	return dao.InsertStreamEventBatch(ctx, []StreamEvent{*event})
}

// InsertStreamEventBatch inserts multiple stream events into the session's event stream.
// Uses Redis Stream XADD for efficient append operations.
func (dao *RedisSessionDAO) InsertStreamEventBatch(ctx context.Context, events []StreamEvent) error {
	if len(events) == 0 {
		return nil
	}

	streamKey := sessionStreamKey(events[0].SessionID)

	// Use pipeline for batch insert
	pipe := dao.client.Client().Pipeline()

	for i := range events {
		event := &events[i]

		if event.ID.IsZero() {
			event.ID = types.NewID()
		}

		if event.Timestamp.IsZero() {
			event.Timestamp = time.Now()
		}

		// Convert event to map for Redis Stream
		values := map[string]interface{}{
			"id":         event.ID.String(),
			"session_id": event.SessionID.String(),
			"sequence":   event.Sequence,
			"event_type": string(event.EventType),
			"content":    string(event.Content),
			"timestamp":  event.Timestamp.UnixMilli(),
		}

		if event.TraceID != "" {
			values["trace_id"] = event.TraceID
		}

		if event.SpanID != "" {
			values["span_id"] = event.SpanID
		}

		// Add to stream with auto-generated ID
		pipe.XAdd(ctx, &redis.XAddArgs{
			Stream: streamKey,
			ID:     "*",
			Values: values,
		})
	}

	// Execute pipeline
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to insert stream events: %w", err)
	}

	return nil
}

// GetStreamEvents retrieves stream events for a session with optional filtering.
// Uses Redis Stream XRANGE for efficient range queries.
func (dao *RedisSessionDAO) GetStreamEvents(ctx context.Context, sessionID types.ID, filter StreamEventFilter) ([]StreamEvent, error) {
	streamKey := sessionStreamKey(sessionID)

	// Determine range parameters
	start := "-" // Beginning of stream
	end := "+"   // End of stream

	// Use XRANGE to fetch events
	messages, err := dao.client.Client().XRange(ctx, streamKey, start, end).Result()
	if err != nil {
		if err == redis.Nil {
			return []StreamEvent{}, nil
		}
		return nil, fmt.Errorf("failed to read stream events: %w", err)
	}

	events := make([]StreamEvent, 0, len(messages))

	for _, msg := range messages {
		// Parse the stream entry
		event, err := parseStreamMessage(msg.Values)
		if err != nil {
			// Skip malformed events
			continue
		}

		// Apply filters
		if len(filter.EventTypes) > 0 {
			matchesType := false
			for _, eventType := range filter.EventTypes {
				if event.EventType == eventType {
					matchesType = true
					break
				}
			}
			if !matchesType {
				continue
			}
		}

		if filter.FromSeq > 0 && event.Sequence < filter.FromSeq {
			continue
		}

		if filter.ToSeq > 0 && event.Sequence > filter.ToSeq {
			continue
		}

		if !filter.FromTime.IsZero() && event.Timestamp.Before(filter.FromTime) {
			continue
		}

		if !filter.ToTime.IsZero() && event.Timestamp.After(filter.ToTime) {
			continue
		}

		events = append(events, event)

		// Apply limit
		if filter.Limit > 0 && len(events) >= filter.Limit {
			break
		}
	}

	return events, nil
}

// parseStreamMessage converts a Redis Stream message to a StreamEvent.
func parseStreamMessage(values map[string]interface{}) (StreamEvent, error) {
	var event StreamEvent

	// Parse ID
	if idStr, ok := values["id"].(string); ok {
		id, err := types.ParseID(idStr)
		if err != nil {
			return event, fmt.Errorf("failed to parse event ID: %w", err)
		}
		event.ID = id
	}

	// Parse SessionID
	if sessionIDStr, ok := values["session_id"].(string); ok {
		sessionID, err := types.ParseID(sessionIDStr)
		if err != nil {
			return event, fmt.Errorf("failed to parse session ID: %w", err)
		}
		event.SessionID = sessionID
	}

	// Parse Sequence
	if seqStr, ok := values["sequence"].(string); ok {
		seq, err := strconv.ParseInt(seqStr, 10, 64)
		if err != nil {
			return event, fmt.Errorf("failed to parse sequence: %w", err)
		}
		event.Sequence = seq
	}

	// Parse EventType
	if eventTypeStr, ok := values["event_type"].(string); ok {
		event.EventType = StreamEventType(eventTypeStr)
	}

	// Parse Content
	if contentStr, ok := values["content"].(string); ok {
		event.Content = json.RawMessage(contentStr)
	}

	// Parse Timestamp
	if tsStr, ok := values["timestamp"].(string); ok {
		tsMs, err := strconv.ParseInt(tsStr, 10, 64)
		if err != nil {
			return event, fmt.Errorf("failed to parse timestamp: %w", err)
		}
		event.Timestamp = time.UnixMilli(tsMs)
	}

	// Parse optional fields
	if traceID, ok := values["trace_id"].(string); ok {
		event.TraceID = traceID
	}

	if spanID, ok := values["span_id"].(string); ok {
		event.SpanID = spanID
	}

	return event, nil
}

// InsertSteeringMessage inserts a steering message into the session's steering queue.
// Uses Redis List LPUSH for FIFO queue semantics.
func (dao *RedisSessionDAO) InsertSteeringMessage(ctx context.Context, msg *SteeringMessage) error {
	if msg.ID.IsZero() {
		msg.ID = types.NewID()
	}

	if msg.Timestamp.IsZero() {
		msg.Timestamp = time.Now()
	}

	doc := &steeringMessageDocument{
		ID:          msg.ID.String(),
		SessionID:   msg.SessionID.String(),
		Sequence:    msg.Sequence,
		OperatorID:  msg.OperatorID,
		MessageType: string(msg.MessageType),
		Content:     string(msg.Content),
		Timestamp:   msg.Timestamp.UnixMilli(),
		TraceID:     msg.TraceID,
	}

	if msg.AcknowledgedAt != nil {
		ackAtMs := msg.AcknowledgedAt.UnixMilli()
		doc.AcknowledgedAt = &ackAtMs
	}

	// Serialize to JSON
	data, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to marshal steering message: %w", err)
	}

	steeringKey := sessionSteeringKey(msg.SessionID)

	// RPUSH to append to the end of the list (FIFO order)
	if err := dao.client.Client().RPush(ctx, steeringKey, string(data)).Err(); err != nil {
		return fmt.Errorf("failed to insert steering message: %w", err)
	}

	return nil
}

// AcknowledgeSteeringMessage marks a steering message as acknowledged.
// This updates the message in the list by finding and replacing it.
func (dao *RedisSessionDAO) AcknowledgeSteeringMessage(ctx context.Context, id types.ID) error {
	// First, we need to find which session this message belongs to
	// Since we don't have an index, we'll need to scan active sessions
	// In a production system, you might want to add a reverse index

	// Get all active session IDs
	sessionIDs, err := dao.client.Client().SMembers(ctx, activeSessionsKey()).Result()
	if err != nil {
		return fmt.Errorf("failed to get active sessions: %w", err)
	}

	messageIDStr := id.String()
	found := false

	for _, sessionIDStr := range sessionIDs {
		sessionID, err := types.ParseID(sessionIDStr)
		if err != nil {
			continue
		}

		steeringKey := sessionSteeringKey(sessionID)

		// Get all messages in the list
		messages, err := dao.client.Client().LRange(ctx, steeringKey, 0, -1).Result()
		if err != nil {
			continue
		}

		// Find and update the message
		for idx, msgData := range messages {
			var doc steeringMessageDocument
			if err := json.Unmarshal([]byte(msgData), &doc); err != nil {
				continue
			}

			if doc.ID == messageIDStr && doc.AcknowledgedAt == nil {
				// Update the message
				now := time.Now()
				ackAtMs := now.UnixMilli()
				doc.AcknowledgedAt = &ackAtMs

				// Serialize back
				updatedData, err := json.Marshal(doc)
				if err != nil {
					return fmt.Errorf("failed to marshal updated message: %w", err)
				}

				// Update in Redis using LSET
				if err := dao.client.Client().LSet(ctx, steeringKey, int64(idx), string(updatedData)).Err(); err != nil {
					return fmt.Errorf("failed to update steering message: %w", err)
				}

				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		return fmt.Errorf("steering message not found or already acknowledged: %s", id)
	}

	return nil
}

// GetSteeringMessages retrieves all steering messages for a session in FIFO order.
func (dao *RedisSessionDAO) GetSteeringMessages(ctx context.Context, sessionID types.ID) ([]SteeringMessage, error) {
	steeringKey := sessionSteeringKey(sessionID)

	// Get all messages from the list
	messages, err := dao.client.Client().LRange(ctx, steeringKey, 0, -1).Result()
	if err != nil {
		if err == redis.Nil {
			return []SteeringMessage{}, nil
		}
		return nil, fmt.Errorf("failed to get steering messages: %w", err)
	}

	steeringMessages := make([]SteeringMessage, 0, len(messages))

	for _, msgData := range messages {
		var doc steeringMessageDocument
		if err := json.Unmarshal([]byte(msgData), &doc); err != nil {
			// Skip malformed messages
			continue
		}

		msg, err := fromSteeringDocument(&doc)
		if err != nil {
			// Skip invalid messages
			continue
		}

		steeringMessages = append(steeringMessages, *msg)
	}

	return steeringMessages, nil
}

// fromSteeringDocument converts a steeringMessageDocument to a SteeringMessage.
func fromSteeringDocument(doc *steeringMessageDocument) (*SteeringMessage, error) {
	id, err := types.ParseID(doc.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse message ID: %w", err)
	}

	sessionID, err := types.ParseID(doc.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse session ID: %w", err)
	}

	msg := &SteeringMessage{
		ID:          id,
		SessionID:   sessionID,
		Sequence:    doc.Sequence,
		OperatorID:  doc.OperatorID,
		MessageType: SteeringType(doc.MessageType),
		Content:     json.RawMessage(doc.Content),
		Timestamp:   time.UnixMilli(doc.Timestamp),
		TraceID:     doc.TraceID,
	}

	if doc.AcknowledgedAt != nil {
		ackAt := time.UnixMilli(*doc.AcknowledgedAt)
		msg.AcknowledgedAt = &ackAt
	}

	return msg, nil
}
