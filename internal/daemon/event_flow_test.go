package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// TestEventFlow_MissionStarted verifies that MissionStartedPayload events flow correctly
// from mission orchestrator through EventBusAdapter to gRPC stream.
func TestEventFlow_MissionStarted(t *testing.T) {
	tests := []struct {
		name          string
		payload       events.MissionStartedPayload
		missionID     types.ID
		traceID       string
		spanID        string
		wantEventType string
		wantMissionID string
		wantPayload   map[string]interface{}
		wantTraceID   string
		wantSpanID    string
	}{
		{
			name: "mission started with full payload",
			payload: events.MissionStartedPayload{
				MissionID:   types.ID("mission-123"),
				MissionName: "test-mission",
				TargetID:    types.ID("target-456"),
				NodeCount:   5,
			},
			missionID:     types.ID("mission-123"),
			traceID:       "trace-abc-123",
			spanID:        "span-def-456",
			wantEventType: "mission.started",
			wantMissionID: "mission-123",
			wantPayload: map[string]interface{}{
				"mission_name": "test-mission",
				"target_id":    "target-456",
				"node_count":   5,
			},
			wantTraceID: "trace-abc-123",
			wantSpanID:  "span-def-456",
		},
		{
			name: "mission started with minimal payload",
			payload: events.MissionStartedPayload{
				MissionID: types.ID("mission-min"),
				NodeCount: 1,
			},
			missionID:     types.ID("mission-min"),
			wantEventType: "mission.started",
			wantMissionID: "mission-min",
			wantPayload: map[string]interface{}{
				"mission_name": "",
				"target_id":    "",
				"node_count":   1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create EventBus and adapter
			eventBus := NewEventBus(nil)
			defer eventBus.Close()
			adapter := NewEventBusAdapter(eventBus)

			// Subscribe to events
			eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
			defer cleanup()

			// Create event from mission orchestrator
			event := events.Event{
				Type:      events.EventMissionStarted,
				Timestamp: time.Now(),
				MissionID: tt.missionID,
				TraceID:   tt.traceID,
				SpanID:    tt.spanID,
				Payload:   tt.payload,
			}

			// Publish through adapter (simulating orchestrator)
			err := adapter.Publish(ctx, event)
			require.NoError(t, err)

			// Receive event from EventBus
			select {
			case receivedEvent := <-eventChan:
				// Verify top-level event fields
				assert.Equal(t, tt.wantEventType, receivedEvent.EventType)
				assert.Equal(t, "mission-orchestrator", receivedEvent.Source)
				assert.NotZero(t, receivedEvent.Timestamp)

				// Verify trace context in metadata
				if tt.wantTraceID != "" {
					assert.Equal(t, tt.wantTraceID, receivedEvent.Metadata["trace_id"])
				}
				if tt.wantSpanID != "" {
					assert.Equal(t, tt.wantSpanID, receivedEvent.Metadata["span_id"])
				}

				// Verify MissionEvent is populated (not ToolEvent, LLMEvent, etc.)
				require.NotNil(t, receivedEvent.MissionEvent, "MissionEvent should be populated")
				assert.Nil(t, receivedEvent.ToolEvent, "ToolEvent should be nil")
				assert.Nil(t, receivedEvent.LLMEvent, "LLMEvent should be nil")
				assert.Nil(t, receivedEvent.FindingEvent, "FindingEvent should be nil")

				// Verify MissionEvent fields
				assert.Equal(t, tt.wantEventType, receivedEvent.MissionEvent.EventType)
				assert.Equal(t, tt.wantMissionID, receivedEvent.MissionEvent.MissionID)
				assert.Equal(t, "Mission started", receivedEvent.MissionEvent.Message)

				// Verify payload contents
				assert.Equal(t, tt.wantPayload["mission_name"], receivedEvent.MissionEvent.Payload["mission_name"])
				assert.Equal(t, tt.wantPayload["target_id"], receivedEvent.MissionEvent.Payload["target_id"])
				assert.Equal(t, tt.wantPayload["node_count"], receivedEvent.MissionEvent.Payload["node_count"])

			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for event")
			}
		})
	}
}

// TestEventFlow_ToolCallStarted verifies that ToolCallStartedPayload events flow correctly
// and populate the ToolEvent oneof in the proto Event.
func TestEventFlow_ToolCallStarted(t *testing.T) {
	tests := []struct {
		name             string
		payload          events.ToolCallStartedPayload
		missionID        types.ID
		agentName        string
		traceID          string
		spanID           string
		wantEventType    string
		wantToolName     string
		wantAgentName    string
		wantInputSummary string
		wantMissionID    string
	}{
		{
			name: "tool call with parameters",
			payload: events.ToolCallStartedPayload{
				ToolName: "nmap",
				Parameters: map[string]any{
					"target": "192.168.1.1",
					"ports":  "1-1024",
					"flags":  "-sV",
				},
				ParameterSize: 3,
			},
			missionID:        types.ID("mission-tool-1"),
			agentName:        "recon-agent",
			traceID:          "trace-tool-123",
			spanID:           "span-tool-456",
			wantEventType:    "tool.started",
			wantToolName:     "nmap",
			wantAgentName:    "recon-agent",
			wantInputSummary: "parameters: flags, ports, target",
			wantMissionID:    "mission-tool-1",
		},
		{
			name: "tool call with no parameters",
			payload: events.ToolCallStartedPayload{
				ToolName:      "whoami",
				Parameters:    nil,
				ParameterSize: 0,
			},
			missionID:        types.ID("mission-tool-2"),
			agentName:        "basic-agent",
			wantEventType:    "tool.started",
			wantToolName:     "whoami",
			wantAgentName:    "basic-agent",
			wantInputSummary: "no parameters",
			wantMissionID:    "mission-tool-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create EventBus and adapter
			eventBus := NewEventBus(nil)
			defer eventBus.Close()
			adapter := NewEventBusAdapter(eventBus)

			// Subscribe to events
			eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
			defer cleanup()

			// Create event from mission orchestrator
			event := events.Event{
				Type:      events.EventToolCallStarted,
				Timestamp: time.Now(),
				MissionID: tt.missionID,
				AgentName: tt.agentName,
				TraceID:   tt.traceID,
				SpanID:    tt.spanID,
				Payload:   tt.payload,
			}

			// Publish through adapter
			err := adapter.Publish(ctx, event)
			require.NoError(t, err)

			// Receive event from EventBus
			select {
			case receivedEvent := <-eventChan:
				// Verify ToolEvent is populated (not MissionEvent, LLMEvent, etc.)
				require.NotNil(t, receivedEvent.ToolEvent, "ToolEvent should be populated")
				assert.Nil(t, receivedEvent.MissionEvent, "MissionEvent should be nil")
				assert.Nil(t, receivedEvent.LLMEvent, "LLMEvent should be nil")
				assert.Nil(t, receivedEvent.FindingEvent, "FindingEvent should be nil")

				// Verify ToolEvent fields
				assert.Equal(t, tt.wantEventType, receivedEvent.ToolEvent.EventType)
				assert.Equal(t, tt.wantToolName, receivedEvent.ToolEvent.ToolName)
				assert.Equal(t, tt.wantAgentName, receivedEvent.ToolEvent.AgentName)
				assert.Equal(t, tt.wantMissionID, receivedEvent.ToolEvent.MissionID)
				assert.Contains(t, receivedEvent.ToolEvent.Message, tt.wantToolName)
				assert.Equal(t, tt.wantInputSummary, receivedEvent.ToolEvent.InputSummary)

				// Verify trace context
				if tt.traceID != "" {
					assert.Equal(t, tt.traceID, receivedEvent.Metadata["trace_id"])
				}
				if tt.spanID != "" {
					assert.Equal(t, tt.spanID, receivedEvent.Metadata["span_id"])
				}

			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for event")
			}
		})
	}
}

// TestEventFlow_LLMRequestCompleted verifies that LLMRequestCompletedPayload events
// flow correctly and populate the LLMEvent oneof in the proto Event.
func TestEventFlow_LLMRequestCompleted(t *testing.T) {
	tests := []struct {
		name             string
		payload          events.LLMRequestCompletedPayload
		agentName        string
		traceID          string
		spanID           string
		wantEventType    string
		wantModel        string
		wantSlot         string
		wantPromptTokens int
		wantOutputTokens int
		wantTotalTokens  int
		wantDurationMs   float64
	}{
		{
			name: "successful LLM completion",
			payload: events.LLMRequestCompletedPayload{
				Provider:     "anthropic",
				Model:        "claude-3-opus-20240229",
				SlotName:     "primary",
				Duration:     2500 * time.Millisecond,
				InputTokens:  1000,
				OutputTokens: 500,
				StopReason:   "end_turn",
			},
			agentName:        "analyst-agent",
			traceID:          "trace-llm-123",
			spanID:           "span-llm-456",
			wantEventType:    "llm.request.completed",
			wantModel:        "claude-3-opus-20240229",
			wantSlot:         "primary",
			wantPromptTokens: 1000,
			wantOutputTokens: 500,
			wantTotalTokens:  1500,
			wantDurationMs:   2500, // Duration converted to milliseconds
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create EventBus and adapter
			eventBus := NewEventBus(nil)
			defer eventBus.Close()
			adapter := NewEventBusAdapter(eventBus)

			// Subscribe to events
			eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
			defer cleanup()

			// Create event from mission orchestrator
			event := events.Event{
				Type:      events.EventLLMRequestCompleted,
				Timestamp: time.Now(),
				AgentName: tt.agentName,
				TraceID:   tt.traceID,
				SpanID:    tt.spanID,
				Payload:   tt.payload,
			}

			// Publish through adapter
			err := adapter.Publish(ctx, event)
			require.NoError(t, err)

			// Receive event from EventBus
			select {
			case receivedEvent := <-eventChan:
				// Verify LLMEvent is populated (not MissionEvent, ToolEvent, etc.)
				require.NotNil(t, receivedEvent.LLMEvent, "LLMEvent should be populated")
				assert.Nil(t, receivedEvent.MissionEvent, "MissionEvent should be nil")
				assert.Nil(t, receivedEvent.ToolEvent, "ToolEvent should be nil")
				assert.Nil(t, receivedEvent.FindingEvent, "FindingEvent should be nil")

				// Verify LLMEvent fields
				assert.Equal(t, tt.wantEventType, receivedEvent.LLMEvent.EventType)
				assert.Equal(t, tt.wantModel, receivedEvent.LLMEvent.Model)
				assert.Equal(t, tt.wantSlot, receivedEvent.LLMEvent.Slot)
				assert.Equal(t, tt.agentName, receivedEvent.LLMEvent.AgentName)
				assert.Equal(t, tt.wantPromptTokens, receivedEvent.LLMEvent.PromptTokens)
				assert.Equal(t, tt.wantOutputTokens, receivedEvent.LLMEvent.CompletionTokens)
				assert.Equal(t, tt.wantTotalTokens, receivedEvent.LLMEvent.TotalTokens)
				assert.Equal(t, tt.wantDurationMs, receivedEvent.LLMEvent.Duration)

				// Verify trace context
				if tt.traceID != "" {
					assert.Equal(t, tt.traceID, receivedEvent.Metadata["trace_id"])
				}
				if tt.spanID != "" {
					assert.Equal(t, tt.spanID, receivedEvent.Metadata["span_id"])
				}

			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for event")
			}
		})
	}
}

// TestEventFlow_FindingSubmitted verifies that FindingSubmittedPayload events
// flow correctly and populate the FindingEvent oneof in the proto Event.
func TestEventFlow_FindingSubmitted(t *testing.T) {
	tests := []struct {
		name          string
		payload       events.FindingSubmittedPayload
		missionID     types.ID
		traceID       string
		spanID        string
		wantEventType string
		wantFindingID string
		wantTitle     string
		wantSeverity  string
		wantMissionID string
	}{
		{
			name: "critical finding submitted",
			payload: events.FindingSubmittedPayload{
				FindingID: types.ID("finding-critical-1"),
				Title:     "SQL Injection Vulnerability",
				Severity:  "critical",
				AgentName: "sql-agent",
			},
			missionID:     types.ID("mission-finding-1"),
			traceID:       "trace-finding-123",
			spanID:        "span-finding-456",
			wantEventType: "agent.finding_submitted",
			wantFindingID: "finding-critical-1",
			wantTitle:     "SQL Injection Vulnerability",
			wantSeverity:  "critical",
			wantMissionID: "mission-finding-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Create EventBus and adapter
			eventBus := NewEventBus(nil)
			defer eventBus.Close()
			adapter := NewEventBusAdapter(eventBus)

			// Subscribe to events
			eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
			defer cleanup()

			// Create event from mission orchestrator
			event := events.Event{
				Type:      events.EventFindingSubmitted,
				Timestamp: time.Now(),
				MissionID: tt.missionID,
				TraceID:   tt.traceID,
				SpanID:    tt.spanID,
				Payload:   tt.payload,
			}

			// Publish through adapter
			err := adapter.Publish(ctx, event)
			require.NoError(t, err)

			// Receive event from EventBus
			select {
			case receivedEvent := <-eventChan:
				// Verify FindingEvent is populated (not MissionEvent, ToolEvent, etc.)
				require.NotNil(t, receivedEvent.FindingEvent, "FindingEvent should be populated")
				assert.Nil(t, receivedEvent.MissionEvent, "MissionEvent should be nil")
				assert.Nil(t, receivedEvent.ToolEvent, "ToolEvent should be nil")
				assert.Nil(t, receivedEvent.LLMEvent, "LLMEvent should be nil")

				// Verify FindingEvent fields
				assert.Equal(t, tt.wantEventType, receivedEvent.FindingEvent.EventType)
				assert.Equal(t, tt.wantMissionID, receivedEvent.FindingEvent.MissionID)

				// Verify Finding data
				assert.Equal(t, tt.wantFindingID, receivedEvent.FindingEvent.Finding.ID)
				assert.Equal(t, tt.wantTitle, receivedEvent.FindingEvent.Finding.Title)
				assert.Equal(t, tt.wantSeverity, receivedEvent.FindingEvent.Finding.Severity)

				// Verify trace context
				if tt.traceID != "" {
					assert.Equal(t, tt.traceID, receivedEvent.Metadata["trace_id"])
				}
				if tt.spanID != "" {
					assert.Equal(t, tt.spanID, receivedEvent.Metadata["span_id"])
				}

			case <-time.After(1 * time.Second):
				t.Fatal("timeout waiting for event")
			}
		})
	}
}

// TestEventFlow_MultipleEventTypes verifies that different event types can flow
// through the system simultaneously without interference.
func TestEventFlow_MultipleEventTypes(t *testing.T) {
	ctx := context.Background()

	// Create EventBus and adapter
	eventBus := NewEventBus(nil)
	defer eventBus.Close()
	adapter := NewEventBusAdapter(eventBus)

	// Subscribe to all events
	eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
	defer cleanup()

	missionID := types.ID("mission-multi-1")
	traceID := "trace-multi-123"
	spanID := "span-multi-456"

	// Publish multiple event types
	events := []events.Event{
		{
			Type:      events.EventMissionStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			TraceID:   traceID,
			SpanID:    spanID,
			Payload: events.MissionStartedPayload{
				MissionID: missionID,
				NodeCount: 3,
			},
		},
		{
			Type:      events.EventToolCallStarted,
			Timestamp: time.Now(),
			MissionID: missionID,
			AgentName: "test-agent",
			TraceID:   traceID,
			SpanID:    spanID,
			Payload: events.ToolCallStartedPayload{
				ToolName: "test-tool",
			},
		},
		{
			Type:      events.EventLLMRequestCompleted,
			Timestamp: time.Now(),
			AgentName: "test-agent",
			TraceID:   traceID,
			SpanID:    spanID,
			Payload: events.LLMRequestCompletedPayload{
				Model:        "test-model",
				SlotName:     "primary",
				InputTokens:  100,
				OutputTokens: 50,
			},
		},
		{
			Type:      events.EventFindingSubmitted,
			Timestamp: time.Now(),
			MissionID: missionID,
			TraceID:   traceID,
			SpanID:    spanID,
			Payload: events.FindingSubmittedPayload{
				FindingID: types.ID("finding-1"),
				Title:     "Test Finding",
				Severity:  "low",
			},
		},
	}

	// Publish all events
	for _, event := range events {
		err := adapter.Publish(ctx, event)
		require.NoError(t, err)
	}

	// Collect received events
	receivedEvents := make([]api.EventData, 0, len(events))
	timeout := time.After(2 * time.Second)

	for i := 0; i < len(events); i++ {
		select {
		case event := <-eventChan:
			receivedEvents = append(receivedEvents, event)
		case <-timeout:
			t.Fatalf("timeout waiting for events, received %d of %d", len(receivedEvents), len(events))
		}
	}

	// Verify we received all events
	assert.Len(t, receivedEvents, len(events))

	// Count event types by oneof field
	var missionCount, toolCount, llmCount, findingCount int
	for _, event := range receivedEvents {
		if event.MissionEvent != nil {
			missionCount++
		}
		if event.ToolEvent != nil {
			toolCount++
		}
		if event.LLMEvent != nil {
			llmCount++
		}
		if event.FindingEvent != nil {
			findingCount++
		}
	}

	// Verify correct distribution
	assert.Equal(t, 1, missionCount, "should have 1 MissionEvent")
	assert.Equal(t, 1, toolCount, "should have 1 ToolEvent")
	assert.Equal(t, 1, llmCount, "should have 1 LLMEvent")
	assert.Equal(t, 1, findingCount, "should have 1 FindingEvent")

	// Verify no events have "unknown" type
	for _, event := range receivedEvents {
		assert.NotEqual(t, "unknown", event.EventType, "should not have unknown event type")
	}
}

// TestEventFlow_TraceContextPropagation verifies that trace context (TraceID, SpanID)
// is correctly propagated through the event flow.
func TestEventFlow_TraceContextPropagation(t *testing.T) {
	ctx := context.Background()

	// Create EventBus and adapter
	eventBus := NewEventBus(nil)
	defer eventBus.Close()
	adapter := NewEventBusAdapter(eventBus)

	// Subscribe to events
	eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
	defer cleanup()

	testTraceID := "test-trace-abc-123"
	testSpanID := "test-span-def-456"

	// Create event with trace context
	event := events.Event{
		Type:      events.EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.ID("mission-trace-1"),
		TraceID:   testTraceID,
		SpanID:    testSpanID,
		Payload: events.MissionStartedPayload{
			MissionID: types.ID("mission-trace-1"),
			NodeCount: 1,
		},
	}

	// Publish event
	err := adapter.Publish(ctx, event)
	require.NoError(t, err)

	// Receive and verify trace context
	select {
	case receivedEvent := <-eventChan:
		// Verify trace context is in Metadata
		require.NotNil(t, receivedEvent.Metadata, "Metadata should not be nil")
		assert.Equal(t, testTraceID, receivedEvent.Metadata["trace_id"], "TraceID should match")
		assert.Equal(t, testSpanID, receivedEvent.Metadata["span_id"], "SpanID should match")

	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for event")
	}
}

// TestEventFlow_NoUnknownEvents verifies that all supported event types are
// properly converted and no events fall through to the "unknown" case.
func TestEventFlow_NoUnknownEvents(t *testing.T) {
	ctx := context.Background()

	// Create EventBus and adapter
	eventBus := NewEventBus(nil)
	defer eventBus.Close()
	adapter := NewEventBusAdapter(eventBus)

	// Subscribe to all events
	eventChan, cleanup := eventBus.Subscribe(ctx, nil, "")
	defer cleanup()

	// Test all major event types to ensure none are "unknown"
	testCases := []struct {
		eventType events.EventType
		payload   interface{}
	}{
		{events.EventMissionStarted, events.MissionStartedPayload{MissionID: types.ID("m1"), NodeCount: 1}},
		{events.EventMissionProgress, events.MissionProgressPayload{MissionID: types.ID("m1"), TotalNodes: 1}},
		{events.EventMissionCompleted, events.MissionCompletedPayload{MissionID: types.ID("m1")}},
		{events.EventMissionFailed, events.MissionFailedPayload{MissionID: types.ID("m1"), Error: "test"}},
		{events.EventNodeStarted, events.NodeStartedPayload{MissionID: types.ID("m1"), NodeID: "n1"}},
		{events.EventNodeCompleted, events.NodeCompletedPayload{MissionID: types.ID("m1"), NodeID: "n1"}},
		{events.EventNodeFailed, events.NodeFailedPayload{MissionID: types.ID("m1"), NodeID: "n1", Error: "test"}},
		{events.EventNodeSkipped, events.NodeSkippedPayload{MissionID: types.ID("m1"), NodeID: "n1", SkipReason: "test"}},
		{events.EventAgentStarted, events.AgentStartedPayload{AgentName: "test"}},
		{events.EventAgentCompleted, events.AgentCompletedPayload{AgentName: "test"}},
		{events.EventAgentFailed, events.AgentFailedPayload{AgentName: "test", Error: "test"}},
		{events.EventAgentDelegated, events.AgentDelegatedPayload{FromAgent: "a1", ToAgent: "a2"}},
		{events.EventToolCallStarted, events.ToolCallStartedPayload{ToolName: "test"}},
		{events.EventToolCallCompleted, events.ToolCallCompletedPayload{ToolName: "test"}},
		{events.EventToolCallFailed, events.ToolCallFailedPayload{ToolName: "test", Error: "test"}},
		{events.EventToolProgress, events.ToolProgressPayload{ToolName: "test", CallID: "c1"}},
		{events.EventToolWarning, events.ToolWarningPayload{ToolName: "test", CallID: "c1", WarningMessage: "test"}},
		{events.EventLLMRequestStarted, events.LLMRequestStartedPayload{Model: "test", SlotName: "primary"}},
		{events.EventLLMRequestCompleted, events.LLMRequestCompletedPayload{Model: "test", SlotName: "primary"}},
		{events.EventLLMRequestFailed, events.LLMRequestFailedPayload{Model: "test", SlotName: "primary", Error: "test"}},
		{events.EventFindingDiscovered, events.FindingDiscoveredPayload{FindingID: types.ID("f1"), Title: "test", Severity: "low"}},
		{events.EventFindingSubmitted, events.FindingSubmittedPayload{FindingID: types.ID("f1"), Title: "test", Severity: "low"}},
	}

	// Publish all test events
	for _, tc := range testCases {
		event := events.Event{
			Type:      tc.eventType,
			Timestamp: time.Now(),
			MissionID: types.ID("mission-test"),
			Payload:   tc.payload,
		}

		err := adapter.Publish(ctx, event)
		require.NoError(t, err)
	}

	// Receive and verify all events
	timeout := time.After(5 * time.Second)
	receivedCount := 0

	for receivedCount < len(testCases) {
		select {
		case receivedEvent := <-eventChan:
			// Verify event type is not "unknown"
			assert.NotEqual(t, "unknown", receivedEvent.EventType,
				"Event type should not be 'unknown' for %v", receivedEvent.EventType)

			// Verify at least one oneof field is populated
			hasOneof := receivedEvent.MissionEvent != nil ||
				receivedEvent.ToolEvent != nil ||
				receivedEvent.LLMEvent != nil ||
				receivedEvent.FindingEvent != nil ||
				receivedEvent.AgentEvent != nil

			assert.True(t, hasOneof,
				"Event should have at least one oneof field populated for type: %s", receivedEvent.EventType)

			receivedCount++

		case <-timeout:
			t.Fatalf("timeout waiting for events, received %d of %d", receivedCount, len(testCases))
		}
	}

	assert.Equal(t, len(testCases), receivedCount, "should receive all test events")
}
