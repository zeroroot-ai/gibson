package harness

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

// TestFullEventFlowSequence tests the complete event sequence for a mission
func TestFullEventFlowSequence(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	// Simulate a complete mission event flow
	eventSequence := []events.Event{
		// 1. Mission starts
		{
			Type:      events.EventMissionStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.MissionStartedPayload{
				MissionID:   missionID,
				MissionName: "test-mission",
				NodeCount:   3,
			},
		},
		// 2. First node starts
		{
			Type:      events.EventNodeStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.NodeStartedPayload{
				MissionID: missionID,
				NodeID:    "node-1",
				NodeType:  "agent_node",
			},
		},
		// 3. Agent starts
		{
			Type:      events.EventAgentStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			AgentName: "scanner",
			Payload: events.AgentStartedPayload{
				AgentName:       "scanner",
				TaskDescription: "Scan target",
			},
		},
		// 4. Tool call starts
		{
			Type:      events.EventToolCallStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			AgentName: "scanner",
			Payload: events.ToolCallStartedPayload{
				ToolName:      "nmap",
				ParameterSize: 100,
			},
		},
		// 5. Tool call completes
		{
			Type:      events.EventToolCallCompleted,
			Timestamp: time.Now(),
			MissionID: missionID,
			AgentName: "scanner",
			Payload: events.ToolCallCompletedPayload{
				ToolName:   "nmap",
				Duration:   5 * time.Second,
				ResultSize: 500,
				Success:    true,
			},
		},
		// 6. Agent completes
		{
			Type:      events.EventAgentCompleted,
			Timestamp: time.Now(),
			MissionID: missionID,
			AgentName: "scanner",
			Payload: events.AgentCompletedPayload{
				AgentName:    "scanner",
				Duration:     10 * time.Second,
				FindingCount: 2,
				Success:      true,
			},
		},
		// 7. Node completes
		{
			Type:      events.EventNodeCompleted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.NodeCompletedPayload{
				MissionID: missionID,
				NodeID:    "node-1",
				Duration:  11 * time.Second,
			},
		},
		// 8. Second node is skipped
		{
			Type:      events.EventNodeSkipped,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.NodeSkippedPayload{
				MissionID:  missionID,
				NodeID:     "node-2",
				SkipReason: "Policy prevented execution",
			},
		},
		// 9. Mission completes
		{
			Type:      events.EventMissionCompleted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.MissionCompletedPayload{
				MissionID:     missionID,
				Duration:      15 * time.Second,
				FindingCount:  2,
				NodesExecuted: 1,
				Success:       true,
			},
		},
	}

	// Publish all events in sequence
	for _, event := range eventSequence {
		err := mockBus.Publish(ctx, event)
		require.NoError(t, err)
		time.Sleep(1 * time.Millisecond) // Small delay to ensure ordering
	}

	// Verify event sequence
	publishedEvents := mockBus.GetPublishedEvents()
	require.Len(t, publishedEvents, len(eventSequence), "All events should be published")

	// Verify expected event sequence
	expectedTypes := []events.EventType{
		events.EventMissionStarted,
		events.EventNodeStarted,
		events.EventAgentStarted,
		events.EventToolCallStarted,
		events.EventToolCallCompleted,
		events.EventAgentCompleted,
		events.EventNodeCompleted,
		events.EventNodeSkipped,
		events.EventMissionCompleted,
	}

	for i, expectedType := range expectedTypes {
		assert.Equal(t, expectedType, publishedEvents[i].Type,
			"Event %d should be %s", i, expectedType)
	}

	// Verify all events have the same mission ID
	for i, event := range publishedEvents {
		assert.Equal(t, missionID, event.MissionID,
			"Event %d should have mission ID %s", i, missionID)
	}
}

// TestToolCallCorrelationInEventFlow tests that tool call/result events share callID
func TestToolCallCorrelationInEventFlow(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()
	agentName := "test-agent"

	// Generate a unique call ID (simulating what streaming middleware does)
	callID := "call-" + types.NewID().String()

	// Emit tool.call.started event with callID
	err := mockBus.Publish(ctx, events.Event{
		Type:      events.EventToolCallStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		AgentName: agentName,
		Attrs: map[string]any{
			"call_id": callID,
		},
		Payload: events.ToolCallStartedPayload{
			ToolName: "search",
			Parameters: map[string]any{
				"query": "test",
			},
			ParameterSize: 50,
		},
	})
	require.NoError(t, err)

	// Simulate tool execution
	time.Sleep(10 * time.Millisecond)

	// Emit tool.call.completed event with same callID
	err = mockBus.Publish(ctx, events.Event{
		Type:      events.EventToolCallCompleted,
		Timestamp: time.Now(),
		MissionID: missionID,
		AgentName: agentName,
		Attrs: map[string]any{
			"call_id": callID,
		},
		Payload: events.ToolCallCompletedPayload{
			ToolName:   "search",
			Duration:   10 * time.Millisecond,
			ResultSize: 200,
			Success:    true,
		},
	})
	require.NoError(t, err)

	// Verify both events were published
	publishedEvents := mockBus.GetPublishedEvents()
	require.Len(t, publishedEvents, 2)

	// Verify callID correlation
	startEvent := publishedEvents[0]
	completeEvent := publishedEvents[1]

	assert.Equal(t, events.EventToolCallStarted, startEvent.Type)
	assert.Equal(t, events.EventToolCallCompleted, completeEvent.Type)

	// Extract callID from Attrs
	startCallID, ok := startEvent.Attrs["call_id"].(string)
	require.True(t, ok, "Tool call started event should have call_id in attrs")

	completeCallID, ok := completeEvent.Attrs["call_id"].(string)
	require.True(t, ok, "Tool call completed event should have call_id in attrs")

	// CRITICAL: Verify callID matches
	assert.Equal(t, startCallID, completeCallID,
		"CallID must match between tool.call.started and tool.call.completed")
	assert.Equal(t, callID, startCallID,
		"CallID should match the generated ID")
}

// TestMultipleToolCallsWithCorrelation tests multiple concurrent tool calls with unique callIDs
func TestMultipleToolCallsWithCorrelation(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()
	agentName := "multi-tool-agent"

	numTools := 5
	callIDs := make([]string, numTools)

	var wg sync.WaitGroup

	// Emit tool call pairs concurrently
	for i := 0; i < numTools; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			callID := "call-" + types.NewID().String()
			callIDs[idx] = callID

			// Emit tool.call.started
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventToolCallStarted,
				Timestamp: time.Now(),
				MissionID: missionID,
				AgentName: agentName,
				Attrs: map[string]any{
					"call_id": callID,
				},
				Payload: events.ToolCallStartedPayload{
					ToolName:      "tool-" + string(rune('0'+idx)),
					ParameterSize: 100,
				},
			})

			// Simulate tool execution
			time.Sleep(5 * time.Millisecond)

			// Emit tool.call.completed
			mockBus.Publish(ctx, events.Event{
				Type:      events.EventToolCallCompleted,
				Timestamp: time.Now(),
				MissionID: missionID,
				AgentName: agentName,
				Attrs: map[string]any{
					"call_id": callID,
				},
				Payload: events.ToolCallCompletedPayload{
					ToolName:   "tool-" + string(rune('0'+idx)),
					Duration:   5 * time.Millisecond,
					ResultSize: 200,
					Success:    true,
				},
			})
		}(i)
	}

	wg.Wait()

	// Verify all events were published
	publishedEvents := mockBus.GetPublishedEvents()
	require.Len(t, publishedEvents, numTools*2, "Should have start and complete events for each tool")

	// Group events by callID
	eventsByCallID := make(map[string][]events.Event)
	for _, event := range publishedEvents {
		if callID, ok := event.Attrs["call_id"].(string); ok {
			eventsByCallID[callID] = append(eventsByCallID[callID], event)
		}
	}

	// Verify each callID has exactly 2 events (started and completed)
	assert.Len(t, eventsByCallID, numTools, "Should have unique callIDs for each tool")

	for callID, eventPair := range eventsByCallID {
		require.Len(t, eventPair, 2, "CallID %s should have exactly 2 events", callID)

		// Verify one is started and one is completed
		var hasStarted, hasCompleted bool
		for _, event := range eventPair {
			if event.Type == events.EventToolCallStarted {
				hasStarted = true
			} else if event.Type == events.EventToolCallCompleted {
				hasCompleted = true
			}
		}

		assert.True(t, hasStarted, "CallID %s should have a started event", callID)
		assert.True(t, hasCompleted, "CallID %s should have a completed event", callID)
	}
}

// TestNoNilPayloadsInEventFlow tests that no events have nil payloads
func TestNoNilPayloadsInEventFlow(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	// Emit various event types
	testEvents := []events.Event{
		{
			Type:      events.EventMissionStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.MissionStartedPayload{
				MissionID: missionID,
				NodeCount: 1,
			},
		},
		{
			Type:      events.EventNodeStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.NodeStartedPayload{
				MissionID: missionID,
				NodeID:    "node-1",
			},
		},
		{
			Type:      events.EventNodeSkipped,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.NodeSkippedPayload{
				MissionID:  missionID,
				NodeID:     "node-2",
				SkipReason: "Skipped",
			},
		},
		{
			Type:      events.EventAgentStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.AgentStartedPayload{
				AgentName: "agent",
			},
		},
		{
			Type:      events.EventAgentCompleted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.AgentCompletedPayload{
				AgentName: "agent",
				Duration:  1 * time.Second,
				Success:   true,
			},
		},
		{
			Type:      events.EventAgentFailed,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.AgentFailedPayload{
				AgentName: "agent",
				Error:     "test error",
				Duration:  1 * time.Second,
			},
		},
		{
			Type:      events.EventAgentCancelled,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.AgentCancelledPayload{
				AgentName:    "agent",
				CancelReason: "cancelled",
				Duration:     1 * time.Second,
			},
		},
		{
			Type:      events.EventToolCallStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.ToolCallStartedPayload{
				ToolName:      "tool",
				ParameterSize: 50,
			},
		},
		{
			Type:      events.EventToolCallCompleted,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload: events.ToolCallCompletedPayload{
				ToolName:   "tool",
				Duration:   1 * time.Second,
				ResultSize: 100,
				Success:    true,
			},
		},
	}

	// Publish all events
	for _, event := range testEvents {
		err := mockBus.Publish(ctx, event)
		require.NoError(t, err)
	}

	// Verify no nil payloads
	publishedEvents := mockBus.GetPublishedEvents()
	for i, event := range publishedEvents {
		assert.NotNil(t, event.Payload,
			"Event %d (type=%s) should not have nil payload", i, event.Type)
	}
}

// TestEventTimestampOrdering tests that events maintain timestamp ordering
func TestEventTimestampOrdering(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	// Emit events with deliberate time spacing
	eventTypes := []events.EventType{
		events.EventMissionStarted,
		events.EventNodeStarted,
		events.EventAgentStarted,
		events.EventAgentCompleted,
		events.EventMissionCompleted,
	}

	for _, eventType := range eventTypes {
		mockBus.Publish(ctx, events.Event{
			Type:      eventType,
			Timestamp: time.Now(),
			MissionID: missionID,
			Payload:   map[string]any{}, // Dummy payload
		})
		time.Sleep(2 * time.Millisecond) // Ensure time difference
	}

	// Verify timestamp ordering
	publishedEvents := mockBus.GetPublishedEvents()
	require.Len(t, publishedEvents, len(eventTypes))

	for i := 1; i < len(publishedEvents); i++ {
		prevTimestamp := publishedEvents[i-1].Timestamp
		currTimestamp := publishedEvents[i].Timestamp

		assert.True(t, currTimestamp.After(prevTimestamp) || currTimestamp.Equal(prevTimestamp),
			"Event %d timestamp should be >= previous event timestamp", i)
	}
}

// TestEventFilteringByMissionID tests that events can be filtered by mission ID
func TestEventFilteringByMissionID(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()

	mission1 := types.NewID()
	mission2 := types.NewID()

	// Subscribe to mission1 events only
	eventsChan, cleanup := mockBus.Subscribe(ctx, events.Filter{
		MissionID: mission1,
	}, 10)
	defer cleanup()

	// Publish events for both missions
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: mission1,
		Payload: events.MissionStartedPayload{
			MissionID: mission1,
			NodeCount: 1,
		},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: mission2,
		Payload: events.MissionStartedPayload{
			MissionID: mission2,
			NodeCount: 1,
		},
	})

	// Subscriber should only receive mission1 events
	select {
	case event := <-eventsChan:
		assert.Equal(t, mission1, event.MissionID, "Should receive mission1 event")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for mission1 event")
	}

	// No more events should be received
	select {
	case event := <-eventsChan:
		t.Fatalf("Should not receive mission2 event, got: %+v", event)
	case <-time.After(50 * time.Millisecond):
		// Expected - no mission2 events
	}
}

// TestEventFilteringByAgentName tests that events can be filtered by agent name
func TestEventFilteringByAgentName(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	agent1 := "scanner"
	agent2 := "analyzer"

	// Subscribe to scanner events only
	eventsChan, cleanup := mockBus.Subscribe(ctx, events.Filter{
		AgentName: agent1,
	}, 10)
	defer cleanup()

	// Publish events for both agents
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		AgentName: agent1,
		Payload: events.AgentStartedPayload{
			AgentName: agent1,
		},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		AgentName: agent2,
		Payload: events.AgentStartedPayload{
			AgentName: agent2,
		},
	})

	// Subscriber should only receive scanner events
	select {
	case event := <-eventsChan:
		assert.Equal(t, agent1, event.AgentName, "Should receive scanner event")
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Timeout waiting for scanner event")
	}

	// No more events should be received
	select {
	case event := <-eventsChan:
		t.Fatalf("Should not receive analyzer event, got: %+v", event)
	case <-time.After(50 * time.Millisecond):
		// Expected - no analyzer events
	}
}

// TestEventFilteringByType tests that events can be filtered by event type
func TestEventFilteringByType(t *testing.T) {
	mockBus := newMockEventBus()
	ctx := context.Background()
	missionID := types.NewID()

	// Subscribe to only started events
	eventsChan, cleanup := mockBus.Subscribe(ctx, events.Filter{
		Types: []events.EventType{
			events.EventAgentStarted,
			events.EventNodeStarted,
		},
	}, 10)
	defer cleanup()

	// Publish various events
	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload:   events.AgentStartedPayload{AgentName: "agent"},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventAgentCompleted,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload:   events.AgentCompletedPayload{AgentName: "agent", Duration: 1 * time.Second, Success: true},
	})

	mockBus.Publish(ctx, events.Event{
		Type:      events.EventNodeStarted,
		Timestamp: time.Now(),
		MissionID: missionID,
		Payload:   events.NodeStartedPayload{MissionID: missionID, NodeID: "node-1"},
	})

	// Should receive 2 events (agent.started and node.started)
	receivedCount := 0
	timeout := time.After(200 * time.Millisecond)

eventLoop:
	for {
		select {
		case event := <-eventsChan:
			receivedCount++
			assert.True(t,
				event.Type == events.EventAgentStarted || event.Type == events.EventNodeStarted,
				"Should only receive started events")
		case <-timeout:
			break eventLoop
		}
	}

	assert.Equal(t, 2, receivedCount, "Should receive exactly 2 started events")
}
