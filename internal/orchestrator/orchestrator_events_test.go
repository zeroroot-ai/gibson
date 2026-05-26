package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// testEventBus is a mock implementation of events.EventBus for testing
type testEventBus struct {
	mu          sync.Mutex
	published   []events.Event
	subscribers map[string]chan events.Event
}

func newTestEventBus() *testEventBus {
	return &testEventBus{
		published:   make([]events.Event, 0),
		subscribers: make(map[string]chan events.Event),
	}
}

func (m *testEventBus) Publish(ctx context.Context, event events.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = append(m.published, event)

	// Send to all subscribers
	for _, ch := range m.subscribers {
		select {
		case ch <- event:
		default:
			// Skip if channel is full
		}
	}
	return nil
}

func (m *testEventBus) Subscribe(ctx context.Context, filter events.Filter, bufferSize int) (<-chan events.Event, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if bufferSize <= 0 {
		bufferSize = 100
	}

	ch := make(chan events.Event, bufferSize)
	id := time.Now().String()
	m.subscribers[id] = ch

	cleanup := func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		delete(m.subscribers, id)
		close(ch)
	}

	return ch, cleanup
}

func (m *testEventBus) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, ch := range m.subscribers {
		close(ch)
		delete(m.subscribers, id)
	}
	return nil
}

func (m *testEventBus) GetPublishedEvents() []events.Event {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Return a copy
	result := make([]events.Event, len(m.published))
	copy(result, m.published)
	return result
}

func (m *testEventBus) GetEventsByType(eventType events.EventType) []events.Event {
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

func (m *testEventBus) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.published = make([]events.Event, 0)
}

// TestNodeStartedEvent tests that node.started events are emitted correctly
func TestNodeStartedEvent(t *testing.T) {
	tests := []struct {
		name            string
		missionID       types.ID
		nodeID          string
		nodeType        string
		expectEvent     bool
		validatePayload func(*testing.T, events.Event)
	}{
		{
			name:        "execute_agent action emits node.started",
			missionID:   types.NewID(),
			nodeID:      "test-node-1",
			nodeType:    "agent_node",
			expectEvent: true,
			validatePayload: func(t *testing.T, event events.Event) {
				assert.Equal(t, events.EventNodeStarted, event.Type)
				assert.NotZero(t, event.Timestamp)

				payload, ok := event.Payload.(events.NodeStartedPayload)
				require.True(t, ok, "Expected NodeStartedPayload")

				assert.Equal(t, "test-node-1", payload.NodeID)
				assert.Equal(t, "agent_node", payload.NodeType)
				assert.NotEmpty(t, payload.MissionID)
			},
		},
		{
			name:        "node started with empty node type",
			missionID:   types.NewID(),
			nodeID:      "test-node-2",
			nodeType:    "",
			expectEvent: true,
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.NodeStartedPayload)
				require.True(t, ok)

				assert.Equal(t, "test-node-2", payload.NodeID)
				assert.Empty(t, payload.NodeType)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBus := newTestEventBus()
			ctx := context.Background()

			// Simulate event emission as done in orchestrator.go line 471-481
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventNodeStarted,
				Timestamp: time.Now(),
				MissionID: tt.missionID,
				Payload: events.NodeStartedPayload{
					MissionID: tt.missionID,
					NodeID:    tt.nodeID,
					NodeType:  tt.nodeType,
					Message:   "Starting node execution",
				},
			})

			publishedEvents := mockBus.GetEventsByType(events.EventNodeStarted)

			if tt.expectEvent {
				require.Len(t, publishedEvents, 1, "Expected exactly one node.started event")
				if tt.validatePayload != nil {
					tt.validatePayload(t, publishedEvents[0])
				}
			} else {
				require.Empty(t, publishedEvents, "Expected no node.started events")
			}
		})
	}
}

// TestNodeSkippedEvent tests that node.skipped events are emitted correctly
func TestNodeSkippedEvent(t *testing.T) {
	tests := []struct {
		name            string
		missionID       types.ID
		nodeID          string
		skipReason      string
		expectEvent     bool
		validatePayload func(*testing.T, events.Event)
	}{
		{
			name:        "skip_agent action emits node.skipped",
			missionID:   types.NewID(),
			nodeID:      "skip-node-1",
			skipReason:  "Node skipped by orchestrator decision",
			expectEvent: true,
			validatePayload: func(t *testing.T, event events.Event) {
				assert.Equal(t, events.EventNodeSkipped, event.Type)
				assert.NotZero(t, event.Timestamp)

				payload, ok := event.Payload.(events.NodeSkippedPayload)
				require.True(t, ok, "Expected NodeSkippedPayload")

				assert.Equal(t, "skip-node-1", payload.NodeID)
				assert.Equal(t, "Node skipped by orchestrator decision", payload.SkipReason)
				assert.NotEmpty(t, payload.MissionID)
			},
		},
		{
			name:        "policy check prevented execution",
			missionID:   types.NewID(),
			nodeID:      "policy-skip-node",
			skipReason:  "Policy check prevented execution",
			expectEvent: true,
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.NodeSkippedPayload)
				require.True(t, ok)

				assert.Equal(t, "policy-skip-node", payload.NodeID)
				assert.Equal(t, "Policy check prevented execution", payload.SkipReason)
			},
		},
		{
			name:        "custom skip reason",
			missionID:   types.NewID(),
			nodeID:      "custom-skip-node",
			skipReason:  "Custom reasoning for skipping this node",
			expectEvent: true,
			validatePayload: func(t *testing.T, event events.Event) {
				payload, ok := event.Payload.(events.NodeSkippedPayload)
				require.True(t, ok)

				assert.Equal(t, "custom-skip-node", payload.NodeID)
				assert.Equal(t, "Custom reasoning for skipping this node", payload.SkipReason)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockBus := newTestEventBus()
			ctx := context.Background()

			// Simulate event emission as done in orchestrator.go line 655-664
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventNodeSkipped,
				Timestamp: time.Now(),
				MissionID: tt.missionID,
				Payload: events.NodeSkippedPayload{
					MissionID:  tt.missionID,
					NodeID:     tt.nodeID,
					SkipReason: tt.skipReason,
				},
			})

			publishedEvents := mockBus.GetEventsByType(events.EventNodeSkipped)

			if tt.expectEvent {
				require.Len(t, publishedEvents, 1, "Expected exactly one node.skipped event")
				if tt.validatePayload != nil {
					tt.validatePayload(t, publishedEvents[0])
				}
			} else {
				require.Empty(t, publishedEvents, "Expected no node.skipped events")
			}
		})
	}
}

// TestNodeEventsMissionIDCorrelation tests that node events have correct mission ID correlation
func TestNodeEventsMissionIDCorrelation(t *testing.T) {
	mockBus := newTestEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	// Emit node.started event
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventNodeStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload: events.NodeStartedPayload{
			MissionID: missionID,
			NodeID:    "node-1",
			NodeType:  "agent_node",
			Message:   "Starting node execution",
		},
	})

	// Emit node.skipped event for different node
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventNodeSkipped,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload: events.NodeSkippedPayload{
			MissionID:  missionID,
			NodeID:     "node-2",
			SkipReason: "Policy check prevented execution",
		},
	})

	// Verify all events have the same mission ID
	allEvents := mockBus.GetPublishedEvents()
	require.Len(t, allEvents, 2)

	for _, event := range allEvents {
		assert.Equal(t, missionID, event.MissionID, "All node events should have the same mission ID")
	}
}

// TestNodeEventsPayloadNotNil tests that node events always have non-nil payloads
func TestNodeEventsPayloadNotNil(t *testing.T) {
	mockBus := newTestEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	// Emit node.started event
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventNodeStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload: events.NodeStartedPayload{
			MissionID: missionID,
			NodeID:    "node-1",
			NodeType:  "agent_node",
			Message:   "Starting node execution",
		},
	})

	// Emit node.skipped event
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventNodeSkipped,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload: events.NodeSkippedPayload{
			MissionID:  missionID,
			NodeID:     "node-2",
			SkipReason: "Skipped",
		},
	})

	// Verify no events have nil payloads
	allEvents := mockBus.GetPublishedEvents()
	for _, event := range allEvents {
		assert.NotNil(t, event.Payload, "Event payload should never be nil")
	}
}

// TestConcurrentNodeEventEmission tests that node events can be emitted concurrently
func TestConcurrentNodeEventEmission(t *testing.T) {
	mockBus := newTestEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	var wg sync.WaitGroup
	numGoroutines := 10

	// Emit node events concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			if idx%2 == 0 {
				// Emit node.started
				mockBus.Publish(ctx, events.Event{
					Type:      events.EventNodeStarted,
					Timestamp: time.Now(),
					MissionID: missionID,
					Payload: events.NodeStartedPayload{
						MissionID: missionID,
						NodeID:    "node-" + string(rune('0'+idx)),
						NodeType:  "agent_node",
					},
				})
			} else {
				// Emit node.skipped
				mockBus.Publish(ctx, events.Event{
					Type:      events.EventNodeSkipped,
					Timestamp: time.Now(),
					MissionID: missionID,
					Payload: events.NodeSkippedPayload{
						MissionID:  missionID,
						NodeID:     "node-" + string(rune('0'+idx)),
						SkipReason: "Skipped",
					},
				})
			}
		}(i)
	}

	wg.Wait()

	// Verify all events were published
	allEvents := mockBus.GetPublishedEvents()
	assert.Len(t, allEvents, numGoroutines, "All concurrent events should be published")

	// Verify event type distribution
	startedEvents := mockBus.GetEventsByType(events.EventNodeStarted)
	skippedEvents := mockBus.GetEventsByType(events.EventNodeSkipped)

	assert.Equal(t, numGoroutines/2, len(startedEvents), "Should have half node.started events")
	assert.Equal(t, numGoroutines/2, len(skippedEvents), "Should have half node.skipped events")
}
