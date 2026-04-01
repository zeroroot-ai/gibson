package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
	agentpb "github.com/zero-day-ai/sdk/api/gen/gibson/agent/v1"
	"go.opentelemetry.io/otel/trace/noop"
)

// mockSessionDAO provides a thread-safe in-memory implementation of database.SessionDAO for testing
type mockSessionDAO struct {
	mu               sync.RWMutex
	sessions         map[types.ID]*database.AgentSession
	streamEvents     map[types.ID][]database.StreamEvent
	steeringMessages map[types.ID][]database.SteeringMessage
}

func newMockSessionDAO() *mockSessionDAO {
	return &mockSessionDAO{
		sessions:         make(map[types.ID]*database.AgentSession),
		streamEvents:     make(map[types.ID][]database.StreamEvent),
		steeringMessages: make(map[types.ID][]database.SteeringMessage),
	}
}

func (m *mockSessionDAO) CreateSession(ctx context.Context, session *database.AgentSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionDAO) UpdateSession(ctx context.Context, session *database.AgentSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[session.ID] = session
	return nil
}

func (m *mockSessionDAO) GetSession(ctx context.Context, id types.ID) (*database.AgentSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	session, ok := m.sessions[id]
	if !ok {
		return nil, errors.New("session not found")
	}
	// Return copy to avoid data races
	sessionCopy := *session
	return &sessionCopy, nil
}

func (m *mockSessionDAO) ListSessionsByMission(ctx context.Context, missionID types.ID) ([]database.AgentSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var sessions []database.AgentSession
	for _, session := range m.sessions {
		if session.MissionID == missionID {
			sessions = append(sessions, *session)
		}
	}
	return sessions, nil
}

func (m *mockSessionDAO) InsertStreamEvent(ctx context.Context, event *database.StreamEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamEvents[event.SessionID] = append(m.streamEvents[event.SessionID], *event)
	return nil
}

func (m *mockSessionDAO) InsertStreamEventBatch(ctx context.Context, events []database.StreamEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, event := range events {
		m.streamEvents[event.SessionID] = append(m.streamEvents[event.SessionID], event)
	}
	return nil
}

func (m *mockSessionDAO) GetStreamEvents(ctx context.Context, sessionID types.ID, filter database.StreamEventFilter) ([]database.StreamEvent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.streamEvents[sessionID], nil
}

func (m *mockSessionDAO) InsertSteeringMessage(ctx context.Context, msg *database.SteeringMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.steeringMessages[msg.SessionID] = append(m.steeringMessages[msg.SessionID], *msg)
	return nil
}

func (m *mockSessionDAO) AcknowledgeSteeringMessage(ctx context.Context, id types.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Find and update message
	for sessionID, messages := range m.steeringMessages {
		for i, msg := range messages {
			if msg.ID == id {
				now := time.Now()
				m.steeringMessages[sessionID][i].AcknowledgedAt = &now
				return nil
			}
		}
	}
	return errors.New("steering message not found")
}

func (m *mockSessionDAO) GetSteeringMessages(ctx context.Context, sessionID types.ID) ([]database.SteeringMessage, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	messages := m.steeringMessages[sessionID]
	// Return copy to avoid data races
	result := make([]database.SteeringMessage, len(messages))
	copy(result, messages)
	return result, nil
}

// Helper to create a StreamManager with mock dependencies
func createTestStreamManager(t *testing.T) (*StreamManager, *mockSessionDAO, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	dao := newMockSessionDAO()
	tracer := noop.NewTracerProvider().Tracer("test")

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	return manager, dao, cancel
}

// Helper to setup a test agent with mock client
func setupTestAgent(t *testing.T, manager *StreamManager, dao *mockSessionDAO, agentName string) (types.ID, *mockStream) {
	t.Helper()
	ctx := context.Background()

	// Create session
	session := &database.AgentSession{
		ID:        types.NewID(),
		AgentName: agentName,
		Status:    database.AgentStatusRunning,
		Mode:      database.AgentModeAutonomous,
		StartedAt: time.Now(),
		Metadata:  json.RawMessage("{}"),
	}

	if err := dao.CreateSession(ctx, session); err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}

	// Create mock client
	stream := newMockStream(manager.ctx)
	clientCtx, cancel := context.WithCancel(manager.ctx)

	client := &StreamClient{
		stream:     stream,
		agentName:  agentName,
		sessionID:  session.ID,
		eventCh:    make(chan *database.StreamEvent, 100),
		steeringCh: make(chan *agentpb.StreamExecuteRequest, 10),
		ctx:        clientCtx,
		cancel:     cancel,
		closed:     false,
	}

	// Start goroutines
	client.wg.Add(2)
	go client.sendLoop()
	go client.recvLoop()

	// Register client with manager
	manager.mu.Lock()
	manager.clients[agentName] = client
	manager.mu.Unlock()

	// Start event processing
	go manager.processEvents(agentName, client)

	// Consume messages from send channel
	go func() {
		for range stream.sendCh {
		}
	}()

	return session.ID, stream
}

// Helper to close stream properly before disconnect
func closeStreamForTest(stream *mockStream) {
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if !stream.closed {
		close(stream.recvCh)
	}
}

func TestStreamManager_Disconnect(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Verify client exists
	manager.mu.RLock()
	_, exists := manager.clients[agentName]
	manager.mu.RUnlock()

	if !exists {
		t.Fatal("client should exist before disconnect")
	}

	// Close the recv channel to allow recvLoop to exit
	closeStreamForTest(stream)

	// Disconnect
	err := manager.Disconnect(agentName)
	if err != nil {
		t.Fatalf("Disconnect() error = %v", err)
	}

	// Verify client was removed
	manager.mu.RLock()
	_, exists = manager.clients[agentName]
	manager.mu.RUnlock()

	if exists {
		t.Error("client still exists after Disconnect()")
	}

	// Verify session was updated
	session, err := dao.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}

	if session.EndedAt == nil {
		t.Error("session.EndedAt should be set after Disconnect()")
	}

	// Disconnect non-existent agent should fail
	err = manager.Disconnect("non-existent")
	if err == nil {
		t.Error("Disconnect() of non-existent agent should return error")
	}
}

func TestStreamManager_DisconnectAll(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	// Connect multiple agents
	agents := []string{"agent-1", "agent-2", "agent-3"}
	sessionIDs := make([]types.ID, len(agents))
	streams := make([]*mockStream, len(agents))

	for i, agentName := range agents {
		sessionID, stream := setupTestAgent(t, manager, dao, agentName)
		sessionIDs[i] = sessionID
		streams[i] = stream
	}

	// Verify all connected
	manager.mu.RLock()
	clientCount := len(manager.clients)
	manager.mu.RUnlock()

	if clientCount != 3 {
		t.Fatalf("Expected 3 clients, got %d", clientCount)
	}

	// Close all streams before disconnecting
	for _, stream := range streams {
		closeStreamForTest(stream)
	}

	// Disconnect all
	err := manager.DisconnectAll()
	if err != nil {
		t.Fatalf("DisconnectAll() error = %v", err)
	}

	// Verify all clients removed
	manager.mu.RLock()
	clientCount = len(manager.clients)
	manager.mu.RUnlock()

	if clientCount != 0 {
		t.Errorf("Expected 0 clients after DisconnectAll(), got %d", clientCount)
	}

	// Verify all sessions ended
	for i, sessionID := range sessionIDs {
		session, err := dao.GetSession(context.Background(), sessionID)
		if err != nil {
			t.Errorf("GetSession(%s) error = %v", agents[i], err)
			continue
		}

		if session.EndedAt == nil {
			t.Errorf("session %s should have EndedAt set", agents[i])
		}
	}
}

func TestStreamManager_Subscribe(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	_, stream := setupTestAgent(t, manager, dao, agentName)

	// Subscribe to events
	eventCh := manager.Subscribe(agentName)
	if eventCh == nil {
		t.Fatal("Subscribe() returned nil channel")
	}

	// Simulate an event from the agent
	testEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Output{
			Output: &agentpb.OutputChunk{
				Content:     "test output",
				IsReasoning: false,
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}

	stream.recvCh <- testEvent

	// Wait for event to be received
	select {
	case event := <-eventCh:
		if event.EventType != database.StreamEventOutput {
			t.Errorf("Expected StreamEventOutput, got %v", event.EventType)
		}

		var content map[string]any
		if err := json.Unmarshal(event.Content, &content); err != nil {
			t.Fatalf("Failed to unmarshal event content: %v", err)
		}

		if content["content"] != "test output" {
			t.Errorf("content = %v, want 'test output'", content["content"])
		}

	case <-time.After(200 * time.Millisecond):
		t.Fatal("Timeout waiting for event")
	}

	// Clean up
	manager.Unsubscribe(agentName, eventCh)
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_Unsubscribe(t *testing.T) {
	manager, _, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"

	// Subscribe
	eventCh := manager.Subscribe(agentName)

	// Verify subscription exists
	manager.mu.RLock()
	subCount := len(manager.subscribers[agentName])
	manager.mu.RUnlock()

	if subCount != 1 {
		t.Fatalf("Expected 1 subscriber, got %d", subCount)
	}

	// Unsubscribe
	manager.Unsubscribe(agentName, eventCh)

	// Verify subscription removed
	manager.mu.RLock()
	subCount = len(manager.subscribers[agentName])
	manager.mu.RUnlock()

	if subCount != 0 {
		t.Errorf("Expected 0 subscribers after Unsubscribe(), got %d", subCount)
	}

	// Verify channel is closed
	_, ok := <-eventCh
	if ok {
		t.Error("Event channel should be closed after Unsubscribe()")
	}
}

func TestStreamManager_MultipleSubscribers(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	_, stream := setupTestAgent(t, manager, dao, agentName)

	// Create multiple subscribers
	sub1 := manager.Subscribe(agentName)
	sub2 := manager.Subscribe(agentName)
	sub3 := manager.Subscribe(agentName)

	// Simulate an event
	testEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Output{
			Output: &agentpb.OutputChunk{
				Content:     "broadcast test",
				IsReasoning: false,
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}

	stream.recvCh <- testEvent

	// Verify all subscribers receive the event
	subscribers := []<-chan *database.StreamEvent{sub1, sub2, sub3}
	receivedCount := 0

	for _, sub := range subscribers {
		select {
		case event := <-sub:
			if event.EventType != database.StreamEventOutput {
				t.Errorf("Expected StreamEventOutput, got %v", event.EventType)
			}
			receivedCount++
		case <-time.After(200 * time.Millisecond):
			t.Error("Timeout waiting for event")
		}
	}

	if receivedCount != 3 {
		t.Errorf("Expected 3 subscribers to receive event, got %d", receivedCount)
	}

	// Clean up
	manager.Unsubscribe(agentName, sub1)
	manager.Unsubscribe(agentName, sub2)
	manager.Unsubscribe(agentName, sub3)
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_SendSteering(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Update session mode to interactive
	session, _ := dao.GetSession(context.Background(), sessionID)
	session.Mode = database.AgentModeInteractive
	_ = dao.UpdateSession(context.Background(), session)

	// Send steering message
	content := "Please scan port 443"
	metadata := map[string]string{
		"priority": "high",
		"source":   "user",
	}

	err := manager.SendSteering(agentName, content, metadata)
	if err != nil {
		t.Fatalf("SendSteering() error = %v", err)
	}

	// Give message time to be processed
	time.Sleep(10 * time.Millisecond)

	// Verify message was persisted to database
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSteeringMessages() error = %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 steering message, got %d", len(messages))
	}

	msg := messages[0]
	if msg.MessageType != database.SteeringTypeSteer {
		t.Errorf("message type = %v, want %v", msg.MessageType, database.SteeringTypeSteer)
	}

	if msg.Sequence != 1 {
		t.Errorf("sequence = %v, want 1", msg.Sequence)
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_SendInterrupt(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Send interrupt
	reason := "user requested stop"
	err := manager.SendInterrupt(agentName, reason)
	if err != nil {
		t.Fatalf("SendInterrupt() error = %v", err)
	}

	// Give message time to be processed
	time.Sleep(10 * time.Millisecond)

	// Verify message was persisted
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSteeringMessages() error = %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 steering message, got %d", len(messages))
	}

	if messages[0].MessageType != database.SteeringTypeInterrupt {
		t.Errorf("message type = %v, want %v", messages[0].MessageType, database.SteeringTypeInterrupt)
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_SetMode(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Change mode
	newMode := database.AgentModeInteractive
	err := manager.SetMode(agentName, newMode)
	if err != nil {
		t.Fatalf("SetMode() error = %v", err)
	}

	// Give message time to be processed
	time.Sleep(10 * time.Millisecond)

	// Verify session mode was updated
	session, err := dao.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}

	if session.Mode != newMode {
		t.Errorf("session mode = %v, want %v", session.Mode, newMode)
	}

	// Verify message was persisted
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSteeringMessages() error = %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 steering message, got %d", len(messages))
	}

	if messages[0].MessageType != database.SteeringTypeSetMode {
		t.Errorf("message type = %v, want %v", messages[0].MessageType, database.SteeringTypeSetMode)
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_Resume(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Send resume with guidance
	guidance := "Continue with increased verbosity"
	err := manager.Resume(agentName, guidance)
	if err != nil {
		t.Fatalf("Resume() error = %v", err)
	}

	// Give message time to be processed
	time.Sleep(10 * time.Millisecond)

	// Verify message was persisted
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSteeringMessages() error = %v", err)
	}

	if len(messages) != 1 {
		t.Fatalf("Expected 1 steering message, got %d", len(messages))
	}

	if messages[0].MessageType != database.SteeringTypeResume {
		t.Errorf("message type = %v, want %v", messages[0].MessageType, database.SteeringTypeResume)
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_GetSession(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Get session
	session, err := manager.GetSession(agentName)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}

	if session.ID != sessionID {
		t.Errorf("session ID = %v, want %v", session.ID, sessionID)
	}

	if session.AgentName != agentName {
		t.Errorf("agent name = %v, want %v", session.AgentName, agentName)
	}

	// Get session for non-existent agent
	_, err = manager.GetSession("non-existent")
	if err == nil {
		t.Error("GetSession() for non-existent agent should return error")
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_ListActiveSessions(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	// Initially empty
	sessions := manager.ListActiveSessions()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 active sessions, got %d", len(sessions))
	}

	// Connect multiple agents
	agents := []string{"agent-1", "agent-2", "agent-3"}
	streams := make([]*mockStream, len(agents))
	for i, agentName := range agents {
		_, stream := setupTestAgent(t, manager, dao, agentName)
		streams[i] = stream
	}

	// List active sessions
	sessions = manager.ListActiveSessions()
	if len(sessions) != 3 {
		t.Errorf("Expected 3 active sessions, got %d", len(sessions))
	}

	// Verify agent names
	agentNames := make(map[string]bool)
	for _, session := range sessions {
		agentNames[session.AgentName] = true
	}

	for _, expected := range agents {
		if !agentNames[expected] {
			t.Errorf("Expected agent %s in active sessions", expected)
		}
	}

	// Clean up
	for _, stream := range streams {
		closeStreamForTest(stream)
	}
	_ = manager.DisconnectAll()
}

func TestStreamManager_SteeringOperationsOnNonExistentAgent(t *testing.T) {
	manager, _, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "non-existent"

	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "SendSteering",
			fn: func() error {
				return manager.SendSteering(agentName, "test", nil)
			},
		},
		{
			name: "SendInterrupt",
			fn: func() error {
				return manager.SendInterrupt(agentName, "test")
			},
		},
		{
			name: "SetMode",
			fn: func() error {
				return manager.SetMode(agentName, database.AgentModeAutonomous)
			},
		},
		{
			name: "Resume",
			fn: func() error {
				return manager.Resume(agentName, "test")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			if err == nil {
				t.Errorf("%s on non-existent agent should return error", tt.name)
			}

			expectedMsg := "agent non-existent is not connected"
			if err.Error() != expectedMsg {
				t.Errorf("error = %v, want %v", err.Error(), expectedMsg)
			}
		})
	}
}

func TestStreamManager_StatusChangeHandling(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Simulate status change event
	statusEvent := &agentpb.StreamExecuteResponse{
		Payload: &agentpb.StreamExecuteResponse_Status{
			Status: &agentpb.StatusChange{
				Status:  agentpb.AgentStatus_AGENT_STATUS_COMPLETED,
				Message: "Task completed successfully",
			},
		},
		Sequence:    1,
		TimestampMs: time.Now().UnixMilli(),
	}

	stream.recvCh <- statusEvent

	// Wait for event to be processed
	time.Sleep(100 * time.Millisecond)

	// Verify session status was updated
	session, err := dao.GetSession(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSession() error = %v", err)
	}

	if session.Status != database.AgentStatusCompleted {
		t.Errorf("session status = %v, want %v", session.Status, database.AgentStatusCompleted)
	}

	if session.EndedAt == nil {
		t.Error("session EndedAt should be set for completed status")
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_ConcurrentAccess(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	var wg sync.WaitGroup
	numAgents := 10

	// Concurrently connect multiple agents
	for i := 0; i < numAgents; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			agentName := types.NewID().String()
			_, stream := setupTestAgent(t, manager, dao, agentName)

			// Send some steering messages
			_ = manager.SendSteering(agentName, "test", nil)
			_ = manager.SendInterrupt(agentName, "test")

			// Subscribe and unsubscribe
			ch := manager.Subscribe(agentName)
			manager.Unsubscribe(agentName, ch)

			// Close stream and disconnect
			closeStreamForTest(stream)
			_ = manager.Disconnect(agentName)
		}(i)
	}

	wg.Wait()

	// Verify all cleaned up
	manager.mu.RLock()
	clientCount := len(manager.clients)
	subCount := len(manager.subscribers)
	manager.mu.RUnlock()

	if clientCount != 0 {
		t.Errorf("Expected 0 clients after concurrent test, got %d", clientCount)
	}

	if subCount != 0 {
		t.Errorf("Expected 0 subscribers after concurrent test, got %d", subCount)
	}
}

func TestStreamManager_SequenceNumbering(t *testing.T) {
	manager, dao, cancel := createTestStreamManager(t)
	defer cancel()

	agentName := "test-agent"
	sessionID, stream := setupTestAgent(t, manager, dao, agentName)

	// Send multiple steering messages
	_ = manager.SendSteering(agentName, "message 1", nil)
	_ = manager.SendSteering(agentName, "message 2", nil)
	_ = manager.SendInterrupt(agentName, "interrupt")
	_ = manager.Resume(agentName, "resume")

	// Verify sequence numbers are incremental
	messages, err := dao.GetSteeringMessages(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("GetSteeringMessages() error = %v", err)
	}

	if len(messages) != 4 {
		t.Fatalf("Expected 4 messages, got %d", len(messages))
	}

	expectedSequence := int64(1)
	for _, msg := range messages {
		if msg.Sequence != expectedSequence {
			t.Errorf("message sequence = %v, want %v", msg.Sequence, expectedSequence)
		}
		expectedSequence++
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}

func TestStreamManager_TracerIntegration(t *testing.T) {
	// Create a custom tracer provider to verify tracing
	tp := noop.NewTracerProvider()
	tracer := tp.Tracer("test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dao := newMockSessionDAO()

	manager := NewStreamManager(ctx, StreamManagerConfig{
		SessionDAO: dao,
		Tracer:     tracer,
	})

	agentName := "test-agent"
	_, stream := setupTestAgent(t, manager, dao, agentName)

	// Perform steering operations - they should not panic even with noop tracer
	operations := []func() error{
		func() error { return manager.SendSteering(agentName, "test", nil) },
		func() error { return manager.SendInterrupt(agentName, "test") },
		func() error { return manager.SetMode(agentName, database.AgentModeAutonomous) },
		func() error { return manager.Resume(agentName, "test") },
	}

	for _, op := range operations {
		if err := op(); err != nil {
			t.Errorf("Operation failed: %v", err)
		}
	}

	// Clean up
	closeStreamForTest(stream)
	_ = manager.Disconnect(agentName)
}
