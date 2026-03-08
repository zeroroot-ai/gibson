package database

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// setupRedisSessionDAO creates a test Redis client and DAO for testing.
// Skips the test if Redis is not available.
func setupRedisSessionDAO(t *testing.T) (*RedisSessionDAO, context.Context, func()) {
	t.Helper()

	// Use test Redis configuration
	cfg := &state.Config{
		URL:      "redis://localhost:6379",
		Database: 15, // Use test database
	}

	client, err := state.NewStateClient(cfg)
	if err != nil {
		t.Skipf("Redis not available: %v", err)
		return nil, nil, nil
	}

	ctx := context.Background()

	dao := NewRedisSessionDAO(client)

	// Cleanup function
	cleanup := func() {
		// Clean up test data by deleting all session-related keys
		patterns := []string{
			"gibson:session:*",
			"gibson:stream:session:*",
		}

		for _, pattern := range patterns {
			keys, _ := client.Client().Keys(ctx, pattern).Result()
			if len(keys) > 0 {
				client.Client().Del(ctx, keys...)
			}
		}

		client.Close()
	}

	return dao, ctx, cleanup
}

// createTestSession creates a test agent session.
func createTestSession(missionID types.ID, agentName string) *AgentSession {
	session := &AgentSession{
		ID:        types.NewID(),
		MissionID: missionID,
		AgentName: agentName,
		Status:    AgentStatusRunning,
		Mode:      AgentModeAutonomous,
		StartedAt: time.Now(),
		Metadata:  json.RawMessage(`{"version":"1.0","context":"test"}`),
	}

	return session
}

// createTestStreamEvent creates a test stream event.
func createTestStreamEvent(sessionID types.ID, eventType StreamEventType, sequence int64) StreamEvent {
	return StreamEvent{
		ID:        types.NewID(),
		SessionID: sessionID,
		Sequence:  sequence,
		EventType: eventType,
		Content:   json.RawMessage(`{"message":"test event"}`),
		Timestamp: time.Now(),
		TraceID:   "trace-123",
		SpanID:    "span-456",
	}
}

// createTestSteeringMessage creates a test steering message.
func createTestSteeringMessage(sessionID types.ID, msgType SteeringType, sequence int64) *SteeringMessage {
	return &SteeringMessage{
		ID:          types.NewID(),
		SessionID:   sessionID,
		Sequence:    sequence,
		OperatorID:  "operator-1",
		MessageType: msgType,
		Content:     json.RawMessage(`{"instruction":"test steering"}`),
		Timestamp:   time.Now(),
		TraceID:     "trace-789",
	}
}

func TestRedisSessionDAO_CreateSession(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("create_valid_session", func(t *testing.T) {
		missionID := types.NewID()
		session := createTestSession(missionID, "test-agent")

		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Verify session was created
		retrieved, err := dao.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.Equal(t, session.ID, retrieved.ID)
		assert.Equal(t, session.MissionID, retrieved.MissionID)
		assert.Equal(t, session.AgentName, retrieved.AgentName)
		assert.Equal(t, session.Status, retrieved.Status)
		assert.Equal(t, session.Mode, retrieved.Mode)
		assert.WithinDuration(t, session.StartedAt, retrieved.StartedAt, time.Second)
		assert.Nil(t, retrieved.EndedAt)

		// Verify session is in active set
		activeKey := activeSessionsKey()
		isMember, err := dao.client.Client().SIsMember(ctx, activeKey, session.ID.String()).Result()
		require.NoError(t, err)
		assert.True(t, isMember)
	})

	t.Run("create_session_with_auto_id", func(t *testing.T) {
		session := &AgentSession{
			MissionID: types.NewID(),
			AgentName: "auto-id-agent",
			Status:    AgentStatusRunning,
			Mode:      AgentModeInteractive,
		}

		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Verify ID was auto-generated
		assert.False(t, session.ID.IsZero())

		// Verify session can be retrieved
		retrieved, err := dao.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.Equal(t, session.ID, retrieved.ID)
	})

	t.Run("create_session_with_ttl", func(t *testing.T) {
		session := createTestSession(types.NewID(), "ttl-test-agent")

		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Verify TTL was set
		key := sessionKey(session.ID)
		ttl, err := dao.client.Client().TTL(ctx, key).Result()
		require.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0))
		assert.LessOrEqual(t, ttl, DefaultSessionTTL)
	})
}

func TestRedisSessionDAO_GetSession(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_existing_session", func(t *testing.T) {
		session := createTestSession(types.NewID(), "existing-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		retrieved, err := dao.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.Equal(t, session.ID, retrieved.ID)
		assert.Equal(t, session.MissionID, retrieved.MissionID)
		assert.Equal(t, session.AgentName, retrieved.AgentName)
	})

	t.Run("get_nonexistent_session", func(t *testing.T) {
		nonexistentID := types.NewID()
		_, err := dao.GetSession(ctx, nonexistentID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("get_refreshes_ttl", func(t *testing.T) {
		session := createTestSession(types.NewID(), "ttl-refresh-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Wait a bit
		time.Sleep(100 * time.Millisecond)

		// Get session (should refresh TTL)
		_, err = dao.GetSession(ctx, session.ID)
		require.NoError(t, err)

		// Verify TTL is close to the full duration
		key := sessionKey(session.ID)
		ttl, err := dao.client.Client().TTL(ctx, key).Result()
		require.NoError(t, err)
		assert.Greater(t, ttl, DefaultSessionTTL-time.Minute)
	})
}

func TestRedisSessionDAO_UpdateSession(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("update_session_status", func(t *testing.T) {
		session := createTestSession(types.NewID(), "update-status-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Update status
		session.Status = AgentStatusPaused
		err = dao.UpdateSession(ctx, session)
		require.NoError(t, err)

		// Verify update
		retrieved, err := dao.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.Equal(t, AgentStatusPaused, retrieved.Status)
	})

	t.Run("update_session_mode", func(t *testing.T) {
		session := createTestSession(types.NewID(), "update-mode-agent")
		session.Mode = AgentModeAutonomous
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Update mode
		session.Mode = AgentModeInteractive
		err = dao.UpdateSession(ctx, session)
		require.NoError(t, err)

		// Verify update
		retrieved, err := dao.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.Equal(t, AgentModeInteractive, retrieved.Mode)
	})

	t.Run("update_session_end", func(t *testing.T) {
		session := createTestSession(types.NewID(), "end-session-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// End session
		now := time.Now()
		session.EndedAt = &now
		session.Status = AgentStatusCompleted
		err = dao.UpdateSession(ctx, session)
		require.NoError(t, err)

		// Verify update
		retrieved, err := dao.GetSession(ctx, session.ID)
		require.NoError(t, err)
		assert.NotNil(t, retrieved.EndedAt)
		assert.WithinDuration(t, now, *retrieved.EndedAt, time.Second)

		// Verify removed from active set
		activeKey := activeSessionsKey()
		isMember, err := dao.client.Client().SIsMember(ctx, activeKey, session.ID.String()).Result()
		require.NoError(t, err)
		assert.False(t, isMember)
	})

	t.Run("update_nonexistent_session", func(t *testing.T) {
		session := createTestSession(types.NewID(), "nonexistent-agent")
		err := dao.UpdateSession(ctx, session)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisSessionDAO_ListSessionsByMission(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("list_sessions_for_mission", func(t *testing.T) {
		missionID := types.NewID()

		// Create multiple sessions for the mission
		session1 := createTestSession(missionID, "agent-1")
		session2 := createTestSession(missionID, "agent-2")
		session3 := createTestSession(types.NewID(), "agent-3") // Different mission

		err := dao.CreateSession(ctx, session1)
		require.NoError(t, err)
		err = dao.CreateSession(ctx, session2)
		require.NoError(t, err)
		err = dao.CreateSession(ctx, session3)
		require.NoError(t, err)

		// List sessions for the mission
		sessions, err := dao.ListSessionsByMission(ctx, missionID)
		require.NoError(t, err)
		assert.Len(t, sessions, 2)

		// Verify correct sessions returned
		sessionIDs := []types.ID{sessions[0].ID, sessions[1].ID}
		assert.Contains(t, sessionIDs, session1.ID)
		assert.Contains(t, sessionIDs, session2.ID)
	})

	t.Run("list_sessions_empty_mission", func(t *testing.T) {
		missionID := types.NewID()

		sessions, err := dao.ListSessionsByMission(ctx, missionID)
		require.NoError(t, err)
		assert.Empty(t, sessions)
	})
}

func TestRedisSessionDAO_InsertStreamEvent(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("insert_single_event", func(t *testing.T) {
		session := createTestSession(types.NewID(), "stream-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		event := createTestStreamEvent(session.ID, StreamEventOutput, 1)
		err = dao.InsertStreamEvent(ctx, &event)
		require.NoError(t, err)

		// Verify event was inserted
		events, err := dao.GetStreamEvents(ctx, session.ID, StreamEventFilter{})
		require.NoError(t, err)
		assert.Len(t, events, 1)
		assert.Equal(t, event.EventType, events[0].EventType)
		assert.Equal(t, event.Sequence, events[0].Sequence)
	})

	t.Run("insert_event_with_auto_id", func(t *testing.T) {
		session := createTestSession(types.NewID(), "auto-event-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		event := StreamEvent{
			SessionID: session.ID,
			Sequence:  1,
			EventType: StreamEventToolCall,
			Content:   json.RawMessage(`{"tool":"test"}`),
		}

		err = dao.InsertStreamEvent(ctx, &event)
		require.NoError(t, err)

		// Verify ID and timestamp were set
		assert.False(t, event.ID.IsZero())
		assert.False(t, event.Timestamp.IsZero())
	})
}

func TestRedisSessionDAO_InsertStreamEventBatch(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("insert_multiple_events", func(t *testing.T) {
		session := createTestSession(types.NewID(), "batch-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		events := []StreamEvent{
			createTestStreamEvent(session.ID, StreamEventOutput, 1),
			createTestStreamEvent(session.ID, StreamEventToolCall, 2),
			createTestStreamEvent(session.ID, StreamEventToolResult, 3),
			createTestStreamEvent(session.ID, StreamEventStatus, 4),
		}

		err = dao.InsertStreamEventBatch(ctx, events)
		require.NoError(t, err)

		// Verify all events were inserted
		retrieved, err := dao.GetStreamEvents(ctx, session.ID, StreamEventFilter{})
		require.NoError(t, err)
		assert.Len(t, retrieved, 4)
	})

	t.Run("insert_empty_batch", func(t *testing.T) {
		err := dao.InsertStreamEventBatch(ctx, []StreamEvent{})
		require.NoError(t, err)
	})
}

func TestRedisSessionDAO_GetStreamEvents(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_all_events", func(t *testing.T) {
		session := createTestSession(types.NewID(), "get-events-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert multiple events
		events := []StreamEvent{
			createTestStreamEvent(session.ID, StreamEventOutput, 1),
			createTestStreamEvent(session.ID, StreamEventToolCall, 2),
			createTestStreamEvent(session.ID, StreamEventFinding, 3),
		}
		err = dao.InsertStreamEventBatch(ctx, events)
		require.NoError(t, err)

		// Get all events
		retrieved, err := dao.GetStreamEvents(ctx, session.ID, StreamEventFilter{})
		require.NoError(t, err)
		assert.Len(t, retrieved, 3)
	})

	t.Run("filter_by_event_type", func(t *testing.T) {
		session := createTestSession(types.NewID(), "filter-type-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert events of different types
		events := []StreamEvent{
			createTestStreamEvent(session.ID, StreamEventOutput, 1),
			createTestStreamEvent(session.ID, StreamEventToolCall, 2),
			createTestStreamEvent(session.ID, StreamEventOutput, 3),
			createTestStreamEvent(session.ID, StreamEventToolResult, 4),
		}
		err = dao.InsertStreamEventBatch(ctx, events)
		require.NoError(t, err)

		// Filter for StreamEventOutput only
		filter := StreamEventFilter{
			EventTypes: []StreamEventType{StreamEventOutput},
		}
		retrieved, err := dao.GetStreamEvents(ctx, session.ID, filter)
		require.NoError(t, err)
		assert.Len(t, retrieved, 2)
		for _, event := range retrieved {
			assert.Equal(t, StreamEventOutput, event.EventType)
		}
	})

	t.Run("filter_by_sequence_range", func(t *testing.T) {
		session := createTestSession(types.NewID(), "filter-seq-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert events with different sequences
		events := []StreamEvent{
			createTestStreamEvent(session.ID, StreamEventOutput, 1),
			createTestStreamEvent(session.ID, StreamEventOutput, 2),
			createTestStreamEvent(session.ID, StreamEventOutput, 3),
			createTestStreamEvent(session.ID, StreamEventOutput, 4),
			createTestStreamEvent(session.ID, StreamEventOutput, 5),
		}
		err = dao.InsertStreamEventBatch(ctx, events)
		require.NoError(t, err)

		// Filter for sequences 2-4
		filter := StreamEventFilter{
			FromSeq: 2,
			ToSeq:   4,
		}
		retrieved, err := dao.GetStreamEvents(ctx, session.ID, filter)
		require.NoError(t, err)
		assert.Len(t, retrieved, 3)
		for _, event := range retrieved {
			assert.GreaterOrEqual(t, event.Sequence, int64(2))
			assert.LessOrEqual(t, event.Sequence, int64(4))
		}
	})

	t.Run("filter_with_limit", func(t *testing.T) {
		session := createTestSession(types.NewID(), "filter-limit-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert multiple events
		events := make([]StreamEvent, 10)
		for i := 0; i < 10; i++ {
			events[i] = createTestStreamEvent(session.ID, StreamEventOutput, int64(i+1))
		}
		err = dao.InsertStreamEventBatch(ctx, events)
		require.NoError(t, err)

		// Get with limit
		filter := StreamEventFilter{
			Limit: 5,
		}
		retrieved, err := dao.GetStreamEvents(ctx, session.ID, filter)
		require.NoError(t, err)
		assert.Len(t, retrieved, 5)
	})

	t.Run("get_events_nonexistent_session", func(t *testing.T) {
		nonexistentID := types.NewID()
		events, err := dao.GetStreamEvents(ctx, nonexistentID, StreamEventFilter{})
		require.NoError(t, err)
		assert.Empty(t, events)
	})
}

func TestRedisSessionDAO_InsertSteeringMessage(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("insert_steering_message", func(t *testing.T) {
		session := createTestSession(types.NewID(), "steering-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		msg := createTestSteeringMessage(session.ID, SteeringTypeSteer, 1)
		err = dao.InsertSteeringMessage(ctx, msg)
		require.NoError(t, err)

		// Verify message was inserted
		messages, err := dao.GetSteeringMessages(ctx, session.ID)
		require.NoError(t, err)
		assert.Len(t, messages, 1)
		assert.Equal(t, msg.MessageType, messages[0].MessageType)
		assert.Equal(t, msg.OperatorID, messages[0].OperatorID)
	})

	t.Run("insert_message_with_auto_id", func(t *testing.T) {
		session := createTestSession(types.NewID(), "auto-msg-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		msg := &SteeringMessage{
			SessionID:   session.ID,
			Sequence:    1,
			OperatorID:  "op-1",
			MessageType: SteeringTypeInterrupt,
			Content:     json.RawMessage(`{"reason":"test"}`),
		}

		err = dao.InsertSteeringMessage(ctx, msg)
		require.NoError(t, err)

		// Verify ID and timestamp were set
		assert.False(t, msg.ID.IsZero())
		assert.False(t, msg.Timestamp.IsZero())
	})

	t.Run("insert_multiple_messages_fifo", func(t *testing.T) {
		session := createTestSession(types.NewID(), "fifo-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert messages in order
		msg1 := createTestSteeringMessage(session.ID, SteeringTypeSteer, 1)
		msg2 := createTestSteeringMessage(session.ID, SteeringTypeInterrupt, 2)
		msg3 := createTestSteeringMessage(session.ID, SteeringTypeResume, 3)

		err = dao.InsertSteeringMessage(ctx, msg1)
		require.NoError(t, err)
		err = dao.InsertSteeringMessage(ctx, msg2)
		require.NoError(t, err)
		err = dao.InsertSteeringMessage(ctx, msg3)
		require.NoError(t, err)

		// Verify FIFO order
		messages, err := dao.GetSteeringMessages(ctx, session.ID)
		require.NoError(t, err)
		assert.Len(t, messages, 3)
		assert.Equal(t, int64(1), messages[0].Sequence)
		assert.Equal(t, int64(2), messages[1].Sequence)
		assert.Equal(t, int64(3), messages[2].Sequence)
	})
}

func TestRedisSessionDAO_AcknowledgeSteeringMessage(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("acknowledge_message", func(t *testing.T) {
		session := createTestSession(types.NewID(), "ack-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		msg := createTestSteeringMessage(session.ID, SteeringTypeSteer, 1)
		err = dao.InsertSteeringMessage(ctx, msg)
		require.NoError(t, err)

		// Acknowledge the message
		err = dao.AcknowledgeSteeringMessage(ctx, msg.ID)
		require.NoError(t, err)

		// Verify acknowledgment
		messages, err := dao.GetSteeringMessages(ctx, session.ID)
		require.NoError(t, err)
		assert.Len(t, messages, 1)
		assert.NotNil(t, messages[0].AcknowledgedAt)
	})

	t.Run("acknowledge_already_acknowledged", func(t *testing.T) {
		session := createTestSession(types.NewID(), "reack-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		msg := createTestSteeringMessage(session.ID, SteeringTypeSteer, 1)
		err = dao.InsertSteeringMessage(ctx, msg)
		require.NoError(t, err)

		// Acknowledge once
		err = dao.AcknowledgeSteeringMessage(ctx, msg.ID)
		require.NoError(t, err)

		// Try to acknowledge again
		err = dao.AcknowledgeSteeringMessage(ctx, msg.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already acknowledged")
	})

	t.Run("acknowledge_nonexistent_message", func(t *testing.T) {
		nonexistentID := types.NewID()
		err := dao.AcknowledgeSteeringMessage(ctx, nonexistentID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestRedisSessionDAO_GetSteeringMessages(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("get_all_messages", func(t *testing.T) {
		session := createTestSession(types.NewID(), "get-msgs-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert multiple messages
		for i := 1; i <= 3; i++ {
			msg := createTestSteeringMessage(session.ID, SteeringTypeSteer, int64(i))
			err = dao.InsertSteeringMessage(ctx, msg)
			require.NoError(t, err)
		}

		// Get all messages
		messages, err := dao.GetSteeringMessages(ctx, session.ID)
		require.NoError(t, err)
		assert.Len(t, messages, 3)
	})

	t.Run("get_messages_nonexistent_session", func(t *testing.T) {
		nonexistentID := types.NewID()
		messages, err := dao.GetSteeringMessages(ctx, nonexistentID)
		require.NoError(t, err)
		assert.Empty(t, messages)
	})

	t.Run("get_messages_preserves_order", func(t *testing.T) {
		session := createTestSession(types.NewID(), "order-msgs-agent")
		err := dao.CreateSession(ctx, session)
		require.NoError(t, err)

		// Insert messages in specific order
		msg1 := createTestSteeringMessage(session.ID, SteeringTypeSteer, 1)
		msg2 := createTestSteeringMessage(session.ID, SteeringTypeInterrupt, 2)
		msg3 := createTestSteeringMessage(session.ID, SteeringTypeResume, 3)

		err = dao.InsertSteeringMessage(ctx, msg1)
		require.NoError(t, err)
		err = dao.InsertSteeringMessage(ctx, msg2)
		require.NoError(t, err)
		err = dao.InsertSteeringMessage(ctx, msg3)
		require.NoError(t, err)

		// Verify order is preserved
		messages, err := dao.GetSteeringMessages(ctx, session.ID)
		require.NoError(t, err)
		assert.Len(t, messages, 3)
		assert.Equal(t, SteeringTypeSteer, messages[0].MessageType)
		assert.Equal(t, SteeringTypeInterrupt, messages[1].MessageType)
		assert.Equal(t, SteeringTypeResume, messages[2].MessageType)
	})
}

func TestRedisSessionDAO_SessionTTL(t *testing.T) {
	dao, ctx, cleanup := setupRedisSessionDAO(t)
	if dao == nil {
		return
	}
	defer cleanup()

	t.Run("custom_ttl", func(t *testing.T) {
		// Create DAO with custom TTL
		customTTL := 1 * time.Hour
		customDAO := NewRedisSessionDAOWithTTL(dao.client, customTTL)

		session := createTestSession(types.NewID(), "custom-ttl-agent")
		err := customDAO.CreateSession(ctx, session)
		require.NoError(t, err)

		// Verify custom TTL was set
		key := sessionKey(session.ID)
		ttl, err := dao.client.Client().TTL(ctx, key).Result()
		require.NoError(t, err)
		assert.Greater(t, ttl, time.Duration(0))
		assert.LessOrEqual(t, ttl, customTTL)
	})
}

// Benchmark tests
func BenchmarkRedisSessionDAO_CreateSession(b *testing.B) {
	cfg := &state.Config{
		URL:      "redis://localhost:6379",
		Database: 15,
	}

	client, err := state.NewStateClient(cfg)
	if err != nil {
		b.Skipf("Redis not available: %v", err)
		return
	}
	defer client.Close()

	dao := NewRedisSessionDAO(client)
	ctx := context.Background()
	missionID := types.NewID()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		session := createTestSession(missionID, "bench-agent")
		_ = dao.CreateSession(ctx, session)
	}
}

func BenchmarkRedisSessionDAO_InsertStreamEventBatch(b *testing.B) {
	cfg := &state.Config{
		URL:      "redis://localhost:6379",
		Database: 15,
	}

	client, err := state.NewStateClient(cfg)
	if err != nil {
		b.Skipf("Redis not available: %v", err)
		return
	}
	defer client.Close()

	dao := NewRedisSessionDAO(client)
	ctx := context.Background()

	// Create a session
	session := createTestSession(types.NewID(), "bench-stream-agent")
	_ = dao.CreateSession(ctx, session)

	// Prepare batch of events
	events := make([]StreamEvent, 10)
	for i := 0; i < 10; i++ {
		events[i] = createTestStreamEvent(session.ID, StreamEventOutput, int64(i+1))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = dao.InsertStreamEventBatch(ctx, events)
	}
}
