//go:build integration

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/embedded"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestSteeringFlow_EndToEnd tests the complete steering flow from
// agent connection through steering message delivery and persistence.
func TestSteeringFlow_EndToEnd(t *testing.T) {
	// 1. Setup: Create in-memory dependencies
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("integration-test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	// 2. Create and connect a mock agent
	agentName := "integration-test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// 3. Subscribe to events
	eventCh := manager.Subscribe(agentName)
	require.NotNil(t, eventCh, "Subscribe should return event channel")

	// 4. Send output event from agent to verify stream is working
	outputEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Output{
			Output: &agentpb.OutputChunk{
				Content:     "Agent initialization complete",
				IsReasoning: false,
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- outputEvent

	// 5. Verify event received via subscription
	select {
	case event := <-eventCh:
		assert.Equal(t, database.StreamEventOutput, event.EventType)
		assert.Equal(t, sessionID, event.SessionID)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Timeout waiting for output event")
	}

	// 6. Update session mode to interactive
	session, err := dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	session.Mode = database.AgentModeInteractive
	require.NoError(t, dao.UpdateSession(context.Background(), session))

	// 7. Send steering message
	steeringContent := "Please scan port 443 with nmap"
	metadata := map[string]string{
		"priority": "high",
		"source":   "operator-console",
	}
	err = manager.SendSteering(agentName, steeringContent, metadata)
	require.NoError(t, err, "SendSteering should succeed")

	// 8. Verify steering message was persisted to database
	time.Sleep(50 * time.Millisecond) // Allow async persistence
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 1, "Should have one steering message")

	msg := messages[0]
	assert.Equal(t, database.SteeringTypeSteer, msg.MessageType)
	assert.Equal(t, sessionID, msg.SessionID)
	assert.Equal(t, int64(1), msg.Sequence)

	// Verify content
	var content map[string]any
	err = json.Unmarshal(msg.Content, &content)
	require.NoError(t, err)
	assert.Equal(t, steeringContent, content["content"])
	assert.Equal(t, "high", content["priority"])

	// 9. Send interrupt
	err = manager.SendInterrupt(agentName, "user requested stop")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	messages, err = dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 2, "Should have two steering messages")
	assert.Equal(t, database.SteeringTypeInterrupt, messages[1].MessageType)

	// 10. Simulate status change event from agent
	statusEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Status{
			Status: &agentpb.StatusChange{
				Status:  agentpb.AgentStatus_AGENT_STATUS_INTERRUPTED,
				Message: "Interrupted by user",
			},
		},
		Sequence:    2,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- statusEvent

	// Wait for status update to propagate
	time.Sleep(100 * time.Millisecond)

	// Verify session status was updated
	session, err = dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, database.AgentStatusInterrupted, session.Status)

	// 11. Disconnect and verify cleanup
	manager.Unsubscribe(agentName, eventCh)
	closeStreamForTest(stream)
	err = manager.Disconnect(agentName)
	require.NoError(t, err)

	// Verify client was removed
	manager.mu.RLock()
	_, exists := manager.clients[agentName]
	manager.mu.RUnlock()
	assert.False(t, exists, "Client should be removed after disconnect")

	// Verify session ended
	session, err = dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.NotNil(t, session.EndedAt, "Session should have end time")
}

// TestSteeringFlow_Persistence tests that all events and steering messages
// are correctly persisted to the database and can be retrieved.
func TestSteeringFlow_Persistence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("integration-test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "persistence-test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Send multiple types of events from agent
	events := []*agentpb.StreamExecuteResponse{
		{
			Payload: &agentpb.StreamExecuteResponse_Output{
				Output: &agentpb.OutputChunk{
					Content:     "Starting scan",
					IsReasoning: false,
				},
			},
			Sequence:    1,
			TimestampMs: time.Now().UnixMilli(),
		},
		{
			Payload: &agentpb.StreamExecuteResponse_ToolCall{
				ToolCall: &agentpb.ToolCallEvent{
					ToolName:  "nmap",
					InputJson: `{"target": "192.168.1.1", "ports": "80,443"}`,
					CallId:    "call-001",
				},
			},
			Sequence:    2,
			TimestampMs: time.Now().UnixMilli(),
		},
		{
			Payload: &agentpb.StreamExecuteResponse_ToolResult{
				ToolResult: &agentpb.ToolResultEvent{
					CallId:     "call-001",
					OutputJson: `{"open_ports": [80, 443]}`,
					Success:    true,
				},
			},
			Sequence:    3,
			TimestampMs: time.Now().UnixMilli(),
		},
		{
			Payload: &agentpb.StreamExecuteResponse_Finding{
				Finding: &agentpb.FindingEvent{
					FindingJson: `{"severity": "medium", "title": "Open HTTP port"}`,
				},
			},
			Sequence:    4,
			TimestampMs: time.Now().UnixMilli(),
		},
	}

	// Send all events
	for _, event := range events {
		stream.recvCh <- event
	}

	// Wait for events to be processed
	time.Sleep(200 * time.Millisecond)

	// Verify stream events are persisted
	streamEvents, err := dao.GetStreamEvents(context.Background(), sessionID, database.StreamEventFilter{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(streamEvents), 4, "Should have at least 4 stream events")

	// Verify event types
	eventTypes := make(map[database.StreamEventType]int)
	for _, e := range streamEvents {
		eventTypes[e.EventType]++
	}
	assert.Equal(t, 1, eventTypes[database.StreamEventOutput], "Should have 1 output event")
	assert.Equal(t, 1, eventTypes[database.StreamEventToolCall], "Should have 1 tool_call event")
	assert.Equal(t, 1, eventTypes[database.StreamEventToolResult], "Should have 1 tool_result event")
	assert.Equal(t, 1, eventTypes[database.StreamEventFinding], "Should have 1 finding event")

	// Send steering messages
	err = manager.SendSteering(agentName, "Focus on ports 80-443", map[string]string{"scope": "web"})
	require.NoError(t, err)

	err = manager.SetMode(agentName, database.AgentModeAutonomous)
	require.NoError(t, err)

	err = manager.Resume(agentName, "Continue with detailed output")
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Verify steering messages are persisted
	steeringMsgs, err := dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Len(t, steeringMsgs, 3, "Should have 3 steering messages")

	// Verify message types
	msgTypes := make(map[database.SteeringType]int)
	for _, msg := range steeringMsgs {
		msgTypes[msg.MessageType]++
	}
	assert.Equal(t, 1, msgTypes[database.SteeringTypeSteer])
	assert.Equal(t, 1, msgTypes[database.SteeringTypeSetMode])
	assert.Equal(t, 1, msgTypes[database.SteeringTypeResume])

	// Verify sequence numbers are sequential
	for i, msg := range steeringMsgs {
		assert.Equal(t, int64(i+1), msg.Sequence, "Sequence should be sequential")
	}

	// Query back with filters
	filteredEvents, err := dao.GetStreamEvents(context.Background(), sessionID, database.StreamEventFilter{
		EventTypes: []database.StreamEventType{database.StreamEventToolCall, database.StreamEventToolResult},
	})
	require.NoError(t, err)
	assert.Len(t, filteredEvents, 2, "Should have 2 tool-related events")

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// TestSteeringFlow_ModeSwitch tests the mode switching flow and
// verifies that session mode updates are persisted correctly.
func TestSteeringFlow_ModeSwitch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("integration-test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "mode-switch-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Verify initial mode is autonomous (set in setupTestAgent)
	session, err := dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, database.AgentModeAutonomous, session.Mode, "Initial mode should be autonomous")

	// Switch to interactive mode
	err = manager.SetMode(agentName, database.AgentModeInteractive)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Verify session mode was updated
	session, err = dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, database.AgentModeInteractive, session.Mode, "Mode should be interactive")

	// Verify mode change message was persisted
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 1)
	assert.Equal(t, database.SteeringTypeSetMode, messages[0].MessageType)

	// Verify content contains new mode
	var content map[string]any
	err = json.Unmarshal(messages[0].Content, &content)
	require.NoError(t, err)
	assert.Equal(t, "interactive", content["mode"])

	// Switch back to autonomous
	err = manager.SetMode(agentName, database.AgentModeAutonomous)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Verify mode changed back
	session, err = dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, database.AgentModeAutonomous, session.Mode, "Mode should be autonomous")

	// Verify second mode change message
	messages, err = dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 2)
	assert.Equal(t, database.SteeringTypeSetMode, messages[1].MessageType)

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// TestSteeringFlow_MultipleAgents tests steering flow with multiple
// concurrent agents to verify isolation and correct routing.
func TestSteeringFlow_MultipleAgents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("integration-test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	// Setup multiple agents
	agent1Name := "scanner-agent"
	agent2Name := "exploit-agent"
	agent3Name := "report-agent"

	session1ID, stream1 := setupTestAgent(t, manager, dao, agent1Name)
	session2ID, stream2 := setupTestAgent(t, manager, dao, agent2Name)
	session3ID, stream3 := setupTestAgent(t, manager, dao, agent3Name)

	// Subscribe to all agents
	eventCh1 := manager.Subscribe(agent1Name)
	eventCh2 := manager.Subscribe(agent2Name)
	eventCh3 := manager.Subscribe(agent3Name)

	// Send steering to each agent
	err := manager.SendSteering(agent1Name, "Scan network 192.168.1.0/24", nil)
	require.NoError(t, err)

	err = manager.SendSteering(agent2Name, "Test for SQL injection", nil)
	require.NoError(t, err)

	err = manager.SendSteering(agent3Name, "Generate executive summary", nil)
	require.NoError(t, err)

	time.Sleep(150 * time.Millisecond)

	// Verify each agent received only its own steering message
	messages1, err := dao.GetSteeringMessages(context.Background(), session1ID)
	require.NoError(t, err)
	require.Len(t, messages1, 1)
	var content1 map[string]any
	json.Unmarshal(messages1[0].Content, &content1)
	assert.Contains(t, content1["content"], "Scan network")

	messages2, err := dao.GetSteeringMessages(context.Background(), session2ID)
	require.NoError(t, err)
	require.Len(t, messages2, 1)
	var content2 map[string]any
	json.Unmarshal(messages2[0].Content, &content2)
	assert.Contains(t, content2["content"], "SQL injection")

	messages3, err := dao.GetSteeringMessages(context.Background(), session3ID)
	require.NoError(t, err)
	require.Len(t, messages3, 1)
	var content3 map[string]any
	json.Unmarshal(messages3[0].Content, &content3)
	assert.Contains(t, content3["content"], "executive summary")

	// Send output from agent1 and verify only agent1 subscribers receive it
	outputEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Output{
			Output: &agentpb.OutputChunk{
				Content:     "Found 5 hosts",
				IsReasoning: false,
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream1.recvCh <- outputEvent

	// Agent1 subscriber should receive event
	select {
	case event := <-eventCh1:
		assert.Equal(t, database.StreamEventOutput, event.EventType)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Agent1 subscriber did not receive event")
	}

	// Agent2 and Agent3 should not receive agent1's event
	select {
	case <-eventCh2:
		t.Fatal("Agent2 should not receive agent1's event")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event
	}

	select {
	case <-eventCh3:
		t.Fatal("Agent3 should not receive agent1's event")
	case <-time.After(100 * time.Millisecond):
		// Expected - no event
	}

	// Clean up
	manager.Unsubscribe(agent1Name, eventCh1)
	manager.Unsubscribe(agent2Name, eventCh2)
	manager.Unsubscribe(agent3Name, eventCh3)

	closeStreamForTest(stream1)
	closeStreamForTest(stream2)
	closeStreamForTest(stream3)

	_ = manager.DisconnectAll()
}

// TestSteeringFlow_SteeringAcknowledgment tests that steering messages
// can be acknowledged and the acknowledgment is persisted.
func TestSteeringFlow_SteeringAcknowledgment(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("integration-test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "ack-test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Send steering message
	err := manager.SendSteering(agentName, "Perform deep scan", nil)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Get the steering message ID
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 1)
	msgID := messages[0].ID
	assert.Nil(t, messages[0].AcknowledgedAt, "Should not be acknowledged yet")

	// Simulate agent acknowledging the steering message
	ackEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_SteeringAck{
			SteeringAck: &agentpb.SteeringAck{
				MessageId: msgID.String(),
				Response:  "Acknowledged, starting deep scan",
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- ackEvent

	time.Sleep(100 * time.Millisecond)

	// Verify acknowledgment was persisted
	messages, err = dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 1)
	assert.NotNil(t, messages[0].AcknowledgedAt, "Should be acknowledged")

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// TestSteeringFlow_ErrorHandling tests error handling in the steering flow,
// including handling of error events from agents.
func TestSteeringFlow_ErrorHandling(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("integration-test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "error-test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Subscribe to events
	eventCh := manager.Subscribe(agentName)

	// Simulate agent sending an error event
	errorEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Error{
			Error: &agentpb.ErrorEvent{
				Code:    "NETWORK_ERROR",
				Message: "Failed to connect to target",
				Fatal:   false,
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- errorEvent

	// Verify error event is received
	select {
	case event := <-eventCh:
		assert.Equal(t, database.StreamEventError, event.EventType)
		var errorData map[string]any
		err := json.Unmarshal(event.Content, &errorData)
		require.NoError(t, err)
		assert.Equal(t, "NETWORK_ERROR", errorData["code"])
		assert.Equal(t, "Failed to connect to target", errorData["message"])
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Timeout waiting for error event")
	}

	// Verify error event was persisted
	streamEvents, err := dao.GetStreamEvents(context.Background(), sessionID, database.StreamEventFilter{
		EventTypes: []database.StreamEventType{database.StreamEventError},
	})
	require.NoError(t, err)
	assert.Len(t, streamEvents, 1)

	// Simulate fatal error and verify session status
	fatalErrorEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Error{
			Error: &agentpb.ErrorEvent{
				Code:    "FATAL_ERROR",
				Message: "Critical system failure",
				Fatal:   true,
			},
		},
		Sequence:    2,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- fatalErrorEvent

	// Also send status change to failed
	statusEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Status{
			Status: &agentpb.StatusChange{
				Status:  agentpb.AgentStatus_AGENT_STATUS_FAILED,
				Message: "Agent failed due to critical error",
			},
		},
		Sequence:    3,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- statusEvent

	time.Sleep(150 * time.Millisecond)

	// Verify session status updated to failed
	session, err := dao.GetSession(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, database.AgentStatusFailed, session.Status)

	// Clean up
	manager.Unsubscribe(agentName, eventCh)
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// TestSteeringFlow_OTelSpanCreation tests that steering operations
// create proper OpenTelemetry spans with correct attributes.
func TestSteeringFlow_OTelSpanCreation(t *testing.T) {
	// Setup in-memory span exporter for verification
	exporter := &inMemorySpanExporter{spans: make([]spanSnapshot, 0)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a real tracer with in-memory exporter
	tracer := newTestTracerWithExporter(exporter)

	dao := newMockSessionDAO()
	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "otel-test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Test 1: SendSteering creates span with correct attributes
	err := manager.SendSteering(agentName, "Test steering message", map[string]string{"priority": "high"})
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Verify steering span was created
	spans := exporter.getSpans()
	require.GreaterOrEqual(t, len(spans), 1, "Should have at least one span for steering")

	steeringSpan := findSpanByName(spans, "gibson.steering.send")
	require.NotNil(t, steeringSpan, "Should have gibson.steering.send span")

	// Verify span attributes
	assert.Equal(t, "steer", steeringSpan.attributes["steering.type"])
	assert.Equal(t, agentName, steeringSpan.attributes["agent.name"])
	assert.Equal(t, sessionID.String(), steeringSpan.attributes["session.id"])
	assert.NotEmpty(t, steeringSpan.attributes["steering.message.id"])

	// Test 2: SendInterrupt creates span
	exporter.reset()
	err = manager.SendInterrupt(agentName, "test interrupt")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	spans = exporter.getSpans()
	interruptSpan := findSpanByName(spans, "gibson.steering.interrupt")
	require.NotNil(t, interruptSpan, "Should have gibson.steering.interrupt span")
	assert.Equal(t, "interrupt", interruptSpan.attributes["steering.type"])
	assert.Equal(t, agentName, interruptSpan.attributes["agent.name"])

	// Test 3: SetMode creates span
	exporter.reset()
	err = manager.SetMode(agentName, database.AgentModeInteractive)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	spans = exporter.getSpans()
	modeSpan := findSpanByName(spans, "gibson.steering.set_mode")
	require.NotNil(t, modeSpan, "Should have gibson.steering.set_mode span")
	assert.Equal(t, "set_mode", modeSpan.attributes["steering.type"])
	assert.Equal(t, "interactive", modeSpan.attributes["agent.new_mode"])

	// Test 4: Resume creates span
	exporter.reset()
	err = manager.Resume(agentName, "continue with guidance")
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	spans = exporter.getSpans()
	resumeSpan := findSpanByName(spans, "gibson.steering.resume")
	require.NotNil(t, resumeSpan, "Should have gibson.steering.resume span")
	assert.Equal(t, "resume", resumeSpan.attributes["steering.type"])

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// TestSteeringFlow_OTelTraceContext tests that trace context is properly
// propagated and stored in steering messages.
func TestSteeringFlow_OTelTraceContext(t *testing.T) {
	exporter := &inMemorySpanExporter{spans: make([]spanSnapshot, 0)}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracer := newTestTracerWithExporter(exporter)

	dao := newMockSessionDAO()
	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "trace-context-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Send steering message
	err := manager.SendSteering(agentName, "Test message", nil)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)

	// Verify trace ID was stored in steering message
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	require.NoError(t, err)
	require.Len(t, messages, 1)

	msg := messages[0]
	assert.NotEmpty(t, msg.TraceID, "Steering message should have trace ID")

	// Verify trace ID matches the span's trace ID
	spans := exporter.getSpans()
	steeringSpan := findSpanByName(spans, "gibson.steering.send")
	require.NotNil(t, steeringSpan)

	// The trace ID in the message should match the span's trace ID
	assert.Equal(t, steeringSpan.traceID, msg.TraceID, "Trace IDs should match")

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// TestSteeringFlow_DatabaseAndOTelIntegration tests that database persistence
// and OTel span creation work together correctly.
func TestSteeringFlow_DatabaseAndOTelIntegration(t *testing.T) {
	exporter := &inMemorySpanExporter{spans: make([]spanSnapshot, 0)}

	// Use real in-memory SQLite database for this test
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Apply migrations
	migrator := database.NewMigrator(db)
	err := migrator.Migrate(context.Background())
	if err != nil {
		// Skip test if FTS5 or other required features are not available
		t.Skipf("Skipping test: database migrations failed (likely missing FTS5 support): %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracer := newTestTracerWithExporter(exporter)
	dao := database.NewSessionDAO(db)

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "db-otel-integration-agent"

	// Create session
	session := &database.AgentSession{
		ID:        types.NewID(),
		AgentName: agentName,
		Status:    database.AgentStatusRunning,
		Mode:      database.AgentModeAutonomous,
		StartedAt: time.Now(),
		Metadata:  json.RawMessage("{}"),
	}
	require.NoError(t, dao.CreateSession(ctx, session))

	// Create mock client
	stream := newMockStream(ctx)
	clientCtx, clientCancel := context.WithCancel(ctx)
	defer clientCancel()

	client := &StreamClient{
		stream:     stream,
		agentName:  agentName,
		sessionID:  session.ID,
		eventCh:    make(chan *database.StreamEvent, 100),
		steeringCh: make(chan *agentpb.StreamExecuteRequest, 10),
		ctx:        clientCtx,
		cancel:     clientCancel,
		closed:     false,
	}

	client.wg.Add(2)
	go client.sendLoop()
	go client.recvLoop()

	manager.mu.Lock()
	manager.clients[agentName] = client
	manager.mu.Unlock()

	go manager.processEvents(agentName, client)

	// Consume messages from send channel
	go func() {
		for range stream.sendCh {
		}
	}()

	// Send steering message
	err = manager.SendSteering(agentName, "Database integration test", map[string]string{"test": "true"})
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Verify database persistence
	steeringMessages, err := dao.GetSteeringMessages(ctx, session.ID)
	require.NoError(t, err)
	require.Len(t, steeringMessages, 1)

	msg := steeringMessages[0]
	assert.Equal(t, database.SteeringTypeSteer, msg.MessageType)
	assert.NotEmpty(t, msg.TraceID, "Message should have trace ID")

	// Verify OTel span creation
	spans := exporter.getSpans()
	steeringSpan := findSpanByName(spans, "gibson.steering.send")
	require.NotNil(t, steeringSpan, "Should have steering span")

	// Verify span contains session ID for Langfuse grouping
	assert.Equal(t, session.ID.String(), steeringSpan.attributes["session.id"])
	assert.Equal(t, session.ID.String(), steeringSpan.attributes["agent.session.id"])

	// Verify trace correlation
	assert.Equal(t, steeringSpan.traceID, msg.TraceID)

	// Send stream event
	outputEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Output{
			Output: &agentpb.OutputChunk{
				Content:     "Test output",
				IsReasoning: false,
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}
	stream.recvCh <- outputEvent

	time.Sleep(100 * time.Millisecond)

	// Verify stream event persistence
	streamEvents, err := dao.GetStreamEvents(ctx, session.ID, database.StreamEventFilter{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(streamEvents), 1, "Should have at least one stream event")

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

// Helper types and functions for OTel testing

// spanSnapshot captures span data for verification
type spanSnapshot struct {
	name       string
	traceID    string
	spanID     string
	attributes map[string]interface{}
	status     string
}

// inMemorySpanExporter is a simple in-memory span exporter for testing
type inMemorySpanExporter struct {
	mu    sync.RWMutex
	spans []spanSnapshot
}

func (e *inMemorySpanExporter) addSpan(span spanSnapshot) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = append(e.spans, span)
}

func (e *inMemorySpanExporter) getSpans() []spanSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make([]spanSnapshot, len(e.spans))
	copy(result, e.spans)
	return result
}

func (e *inMemorySpanExporter) reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.spans = make([]spanSnapshot, 0)
}

// testTracer wraps a tracer to capture spans in the exporter
type testTracer struct {
	embedded.Tracer
	exporter *inMemorySpanExporter
}

func newTestTracerWithExporter(exporter *inMemorySpanExporter) *testTracer {
	return &testTracer{exporter: exporter}
}

func (t *testTracer) Start(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	// Create a mock span that will be captured
	span := &testSpan{
		name:       spanName,
		traceID:    types.NewID().String(),
		spanID:     types.NewID().String(),
		attributes: make(map[string]interface{}),
		exporter:   t.exporter,
	}

	return ctx, span
}

// testSpan implements trace.Span for testing
type testSpan struct {
	embedded.Span
	name       string
	traceID    string
	spanID     string
	attributes map[string]interface{}
	status     string
	exporter   *inMemorySpanExporter
}

func (s *testSpan) End(options ...trace.SpanEndOption) {
	// Capture the span when it ends
	s.exporter.addSpan(spanSnapshot{
		name:       s.name,
		traceID:    s.traceID,
		spanID:     s.spanID,
		attributes: s.attributes,
		status:     s.status,
	})
}

func (s *testSpan) AddEvent(name string, options ...trace.EventOption) {}

func (s *testSpan) AddLink(link trace.Link) {}

func (s *testSpan) IsRecording() bool { return true }

func (s *testSpan) RecordError(err error, options ...trace.EventOption) {
	s.status = "error"
}

func (s *testSpan) SpanContext() trace.SpanContext {
	// Create a valid span context with proper trace ID format
	// Parse the UUID string to get trace ID bytes
	traceIDStr := s.traceID
	// Remove dashes from UUID and use first 32 hex chars
	traceIDStr = traceIDStr[:8] + traceIDStr[9:13] + traceIDStr[14:18] + traceIDStr[19:23] + traceIDStr[24:]

	var traceIDBytes [16]byte
	var spanIDBytes [8]byte

	// Convert hex string to bytes for trace ID
	for i := 0; i < 16 && i*2 < len(traceIDStr); i++ {
		var b byte
		if i*2+1 < len(traceIDStr) {
			fmt.Sscanf(traceIDStr[i*2:i*2+2], "%02x", &b)
		}
		traceIDBytes[i] = b
	}

	// Use first 8 bytes of span ID
	copy(spanIDBytes[:], s.spanID[:8])

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID(traceIDBytes),
		SpanID:     trace.SpanID(spanIDBytes),
		TraceFlags: trace.FlagsSampled,
	})

	// Store the hex representation for comparison
	s.traceID = sc.TraceID().String()

	return sc
}

func (s *testSpan) SetStatus(code codes.Code, description string) {
	if code == codes.Ok {
		s.status = "ok"
	} else {
		s.status = "error"
	}
}

func (s *testSpan) SetName(name string) {
	s.name = name
}

func (s *testSpan) SetAttributes(kv ...attribute.KeyValue) {
	for _, attr := range kv {
		s.attributes[string(attr.Key)] = attr.Value.AsInterface()
	}
}

func (s *testSpan) TracerProvider() trace.TracerProvider {
	return nil
}

// Helper function to find span by name
func findSpanByName(spans []spanSnapshot, name string) *spanSnapshot {
	for i := range spans {
		if spans[i].name == name {
			return &spans[i]
		}
	}
	return nil
}

// setupTestDB creates a temporary SQLite database for testing
func setupTestDB(t *testing.T) (*database.DB, func()) {
	t.Helper()

	// Create temporary directory
	tmpDir := t.TempDir()
	dbPath := tmpDir + "/test.db"

	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup := func() {
		if err := db.Close(); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}

	return db, cleanup
}
