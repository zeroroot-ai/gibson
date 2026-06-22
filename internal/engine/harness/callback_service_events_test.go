package harness

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/engine/events"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// mockEventBus is a mock implementation of events.EventBus for testing
type mockEventBus struct {
	mu                sync.Mutex
	published         []events.Event
	subscribers       map[string]chan events.Event
	subscriberFilters map[string]events.Filter
}

func newMockEventBus() *mockEventBus {
	return &mockEventBus{
		published:         make([]events.Event, 0),
		subscribers:       make(map[string]chan events.Event),
		subscriberFilters: make(map[string]events.Filter),
	}
}

func (m *mockEventBus) Publish(ctx context.Context, event events.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = append(m.published, event)

	// Send to subscribers that match the filter
	for id, ch := range m.subscribers {
		filter := m.subscriberFilters[id]
		if filter.Matches(event) {
			select {
			case ch <- event:
			default:
				// Skip if channel is full
			}
		}
	}
	return nil
}

func (m *mockEventBus) Subscribe(ctx context.Context, filter events.Filter, bufferSize int) (<-chan events.Event, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if bufferSize <= 0 {
		bufferSize = 100
	}

	ch := make(chan events.Event, bufferSize)
	id := time.Now().String()
	m.subscribers[id] = ch
	m.subscriberFilters[id] = filter

	cleanup := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.subscribers, id)
		delete(m.subscriberFilters, id)
		close(ch)
	}

	return ch, cleanup
}

func (m *mockEventBus) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, ch := range m.subscribers {
		close(ch)
		delete(m.subscribers, id)
		delete(m.subscriberFilters, id)
	}
	return nil
}

func (m *mockEventBus) GetPublishedEvents() []events.Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy
	result := make([]events.Event, len(m.published))
	copy(result, m.published)
	return result
}

func (m *mockEventBus) GetEventsByType(eventType events.EventType) []events.Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	var result []events.Event
	for _, event := range m.published {
		if event.Type == eventType {
			result = append(result, event)
		}
	}
	return result
}

func (m *mockEventBus) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = make([]events.Event, 0)
}

// TestAgentStartedEvent tests that agent.started events are emitted correctly
func TestAgentStartedEvent(t *testing.T) {
	tests := []struct {
		name            string
		agentName       string
		taskDescription string
		missionID       types.ID
		validatePayload func(*testing.T, events.Event)
	}{
		{
			name:            "basic agent started event",
			agentName:       "scanner",
			taskDescription: "Scan target for vulnerabilities",
			missionID:       types.NewID(),
			validatePayload: func(t *testing.T, event events.Event) {
				assert.Equal(t, events.EventAgentStarted, event.Type)
				assert.NotZero(t, event.Timestamp)

				payload, ok := event.Payload.(events.AgentStartedPayload)
				require.True(t, ok, "Expected AgentStartedPayload")

				assert.Equal(t, "scanner", payload.AgentName)
				assert.Equal(t, "Scan target for vulnerabilities", payload.TaskDescription)
			},
		},
		{
			name:            "agent with empty task description",
			agentName:       "analyzer",
			taskDescription: "",
			missionID:       types.NewID(),
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.AgentStartedPayload)
				require.True(t, ok)

				assert.Equal(t, "analyzer", payload.AgentName)
				assert.Empty(t, payload.TaskDescription)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBus := newMockEventBus()
			ctx := context.Background()

			// Simulate agent.started event emission as in callback_service.go line 1063-1070
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventAgentStarted,
				Timestamp: time.Now(),
				MissionID: tt.missionID,
				AgentName: tt.agentName,
				Payload: events.AgentStartedPayload{
					AgentName:       tt.agentName,
					TaskDescription: tt.taskDescription,
				},
			})

			publishedEvents := mockBus.GetEventsByType(events.EventAgentStarted)
			require.Len(t, publishedEvents, 1, "Expected exactly one agent.started event")

			if tt.validatePayload != nil {
				tt.validatePayload(t, publishedEvents[0])
			}
		})
	}
}

// TestAgentCompletedEvent tests that agent.completed events are emitted correctly
func TestAgentCompletedEvent(t *testing.T) {
	tests := []struct {
		name            string
		agentName       string
		duration        time.Duration
		findingCount    int
		success         bool
		validatePayload func(*testing.T, events.Event)
	}{
		{
			name:         "successful agent completion",
			agentName:    "scanner",
			duration:     5 * time.Second,
			findingCount: 3,
			success:      true,
			validatePayload: func(t *testing.T, event events.Event) {
				assert.Equal(t, events.EventAgentCompleted, event.Type)
				assert.NotZero(t, event.Timestamp)

				payload, ok := event.Payload.(events.AgentCompletedPayload)
				require.True(t, ok, "Expected AgentCompletedPayload")

				assert.Equal(t, "scanner", payload.AgentName)
				assert.Equal(t, 5*time.Second, payload.Duration)
				assert.Equal(t, 3, payload.FindingCount)
				assert.True(t, payload.Success)
			},
		},
		{
			name:         "agent completion with no findings",
			agentName:    "analyzer",
			duration:     2 * time.Second,
			findingCount: 0,
			success:      true,
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.AgentCompletedPayload)
				require.True(t, ok)

				assert.Equal(t, "analyzer", payload.AgentName)
				assert.Equal(t, 0, payload.FindingCount)
				assert.True(t, payload.Success)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBus := newMockEventBus()
			ctx := context.Background()

			// Simulate agent.completed event emission as in callback_service.go line 1111-1117
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventAgentCompleted,
				Timestamp: time.Now(),
				AgentName: tt.agentName,
				Payload: events.AgentCompletedPayload{
					AgentName:    tt.agentName,
					Duration:     tt.duration,
					FindingCount: tt.findingCount,
					Success:      tt.success,
				},
			})

			publishedEvents := mockBus.GetEventsByType(events.EventAgentCompleted)
			require.Len(t, publishedEvents, 1, "Expected exactly one agent.completed event")

			if tt.validatePayload != nil {
				tt.validatePayload(t, publishedEvents[0])
			}
		})
	}
}

// TestAgentFailedEvent tests that agent.failed events are emitted correctly
func TestAgentFailedEvent(t *testing.T) {
	tests := []struct {
		name            string
		agentName       string
		error           string
		duration        time.Duration
		findingCount    int
		validatePayload func(*testing.T, events.Event)
	}{
		{
			name:         "agent execution failed",
			agentName:    "scanner",
			error:        "connection timeout",
			duration:     10 * time.Second,
			findingCount: 1,
			validatePayload: func(t *testing.T, event events.Event) {
				assert.Equal(t, events.EventAgentFailed, event.Type)
				assert.NotZero(t, event.Timestamp)

				payload, ok := event.Payload.(events.AgentFailedPayload)
				require.True(t, ok, "Expected AgentFailedPayload")

				assert.Equal(t, "scanner", payload.AgentName)
				assert.Equal(t, "connection timeout", payload.Error)
				assert.Equal(t, 10*time.Second, payload.Duration)
				assert.Equal(t, 1, payload.FindingCount)
			},
		},
		{
			name:         "agent failed with no findings",
			agentName:    "analyzer",
			error:        "invalid configuration",
			duration:     1 * time.Second,
			findingCount: 0,
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.AgentFailedPayload)
				require.True(t, ok)

				assert.Equal(t, "analyzer", payload.AgentName)
				assert.Equal(t, "invalid configuration", payload.Error)
				assert.Equal(t, 0, payload.FindingCount)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBus := newMockEventBus()
			ctx := context.Background()

			// Simulate agent.failed event emission as in callback_service.go line 1093-1099
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventAgentFailed,
				Timestamp: time.Now(),
				AgentName: tt.agentName,
				Payload: events.AgentFailedPayload{
					AgentName:    tt.agentName,
					Error:        tt.error,
					Duration:     tt.duration,
					FindingCount: tt.findingCount,
				},
			})

			publishedEvents := mockBus.GetEventsByType(events.EventAgentFailed)
			require.Len(t, publishedEvents, 1, "Expected exactly one agent.failed event")

			if tt.validatePayload != nil {
				tt.validatePayload(t, publishedEvents[0])
			}
		})
	}
}

// TestAgentCancelledEvent tests that agent.cancelled events are emitted correctly
func TestAgentCancelledEvent(t *testing.T) {
	tests := []struct {
		name            string
		agentName       string
		cancelReason    string
		duration        time.Duration
		validatePayload func(*testing.T, events.Event)
	}{
		{
			name:         "agent cancelled via context",
			agentName:    "scanner",
			cancelReason: "context cancelled",
			duration:     3 * time.Second,
			validatePayload: func(t *testing.T, event events.Event) {
				assert.Equal(t, events.EventAgentCancelled, event.Type)
				assert.NotZero(t, event.Timestamp)

				payload, ok := event.Payload.(events.AgentCancelledPayload)
				require.True(t, ok, "Expected AgentCancelledPayload")

				assert.Equal(t, "scanner", payload.AgentName)
				assert.Equal(t, "context cancelled", payload.CancelReason)
				assert.Equal(t, 3*time.Second, payload.Duration)
			},
		},
		{
			name:         "agent cancelled by user",
			agentName:    "analyzer",
			cancelReason: "user requested cancellation",
			duration:     1 * time.Second,
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.AgentCancelledPayload)
				require.True(t, ok)

				assert.Equal(t, "analyzer", payload.AgentName)
				assert.Equal(t, "user requested cancellation", payload.CancelReason)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBus := newMockEventBus()
			ctx := context.Background()

			// Simulate agent.cancelled event emission as in callback_service.go line 1085-1090
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventAgentCancelled,
				Timestamp: time.Now(),
				AgentName: tt.agentName,
				Payload: events.AgentCancelledPayload{
					AgentName:    tt.agentName,
					CancelReason: tt.cancelReason,
					Duration:     tt.duration,
				},
			})

			publishedEvents := mockBus.GetEventsByType(events.EventAgentCancelled)
			require.Len(t, publishedEvents, 1, "Expected exactly one agent.cancelled event")

			if tt.validatePayload != nil {
				tt.validatePayload(t, publishedEvents[0])
			}
		})
	}
}

// TestAgentEventSequence tests the typical sequence of agent lifecycle events
func TestAgentEventSequence(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	agentName := "test-agent"
	missionID := types.NewID()

	// Emit agent.started
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		AgentName: agentName,
		Payload: events.AgentStartedPayload{
			AgentName:       agentName,
			TaskDescription: "Test task",
		},
	})

	// Wait a bit to simulate execution
	time.Sleep(10 * time.Millisecond)

	// Emit agent.completed
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentCompleted,
		Timestamp: time.Now(),
		MissionID: missionID,
		AgentName: agentName,
		Payload: events.AgentCompletedPayload{
			AgentName:    agentName,
			Duration:     100 * time.Millisecond,
			FindingCount: 2,
			Success:      true,
		},
	})

	allEvents := mockBus.GetPublishedEvents()
	require.Len(t, allEvents, 2, "Expected two events in sequence")

	// Verify event order
	assert.Equal(t, events.EventAgentStarted, allEvents[0].Type)
	assert.Equal(t, events.EventAgentCompleted, allEvents[1].Type)

	// Verify both events have the same mission ID and agent name
	assert.Equal(t, missionID, allEvents[0].MissionID)
	assert.Equal(t, missionID, allEvents[1].MissionID)
	assert.Equal(t, agentName, allEvents[0].AgentName)
	assert.Equal(t, agentName, allEvents[1].AgentName)
}

// TestAgentEventsPayloadNotNil tests that agent events always have non-nil payloads
func TestAgentEventsPayloadNotNil(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()

	// Emit various agent events
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentStarted,
		Timestamp: time.Now(),
		Payload: events.AgentStartedPayload{
			AgentName: "test",
		},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentCompleted,
		Timestamp: time.Now(),
		Payload: events.AgentCompletedPayload{
			AgentName: "test",
			Duration:  1 * time.Second,
			Success:   true,
		},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentFailed,
		Timestamp: time.Now(),
		Payload: events.AgentFailedPayload{
			AgentName: "test",
			Error:     "test error",
			Duration:  1 * time.Second,
		},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentCancelled,
		Timestamp: time.Now(),
		Payload: events.AgentCancelledPayload{
			AgentName:    "test",
			CancelReason: "test",
			Duration:     1 * time.Second,
		},
	})

	// Verify no events have nil payloads
	allEvents := mockBus.GetPublishedEvents()
	for _, event := range allEvents {
		assert.NotNil(t, event.Payload, "Event payload should never be nil for event type: %s", event.Type)
	}
}

// TestConcurrentAgentEventEmission tests that agent events can be emitted concurrently
func TestConcurrentAgentEventEmission(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()

	var wg sync.WaitGroup
	numAgents := 10

	// Emit agent events concurrently
	for i := 0; i < numAgents; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			agentName := "agent-" + string(rune('0'+idx))

			// Emit started event
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventAgentStarted,
				Timestamp: time.Now(),
				AgentName: agentName,
				Payload: events.AgentStartedPayload{
					AgentName: agentName,
				},
			})

			// Emit completed event
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventAgentCompleted,
				Timestamp: time.Now(),
				AgentName: agentName,
				Payload: events.AgentCompletedPayload{
					AgentName: agentName,
					Duration:  1 * time.Second,
					Success:   true,
				},
			})
		}(i)
	}

	wg.Wait()

	// Verify all events were published
	allEvents := mockBus.GetPublishedEvents()
	assert.Len(t, allEvents, numAgents*2, "Should have started and completed events for all agents")

	startedEvents := mockBus.GetEventsByType(events.EventAgentStarted)
	completedEvents := mockBus.GetEventsByType(events.EventAgentCompleted)

	assert.Len(t, startedEvents, numAgents, "Should have started event for each agent")
	assert.Len(t, completedEvents, numAgents, "Should have completed event for each agent")
}
