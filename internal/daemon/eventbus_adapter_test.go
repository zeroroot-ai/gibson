package daemon

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zeroroot-ai/gibson/internal/daemon/api"
	"github.com/zeroroot-ai/gibson/internal/events"
	"github.com/zeroroot-ai/gibson/internal/types"
)

func TestConvertToAPIEventData(t *testing.T) {
	now := time.Now()
	testMissionID := types.ID("mission-123")
	testAgentName := "test-agent"
	testTraceID := "trace-abc"
	testSpanID := "span-xyz"

	tests := []struct {
		name     string
		event    interface{}
		validate func(t *testing.T, result api.EventData)
	}{
		{
			name: "MissionStartedPayload",
			event: events.Event{
				Type:      events.EventMissionStarted,
				Timestamp: now,
				MissionID: testMissionID,
				TraceID:   testTraceID,
				SpanID:    testSpanID,
				Payload: events.MissionStartedPayload{
					MissionID:   testMissionID,
					MissionName: "test-mission",
					TargetID:    types.ID("target-456"),
					NodeCount:   5,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "mission.started", result.EventType)
				assert.Equal(t, now, result.Timestamp)
				assert.Equal(t, "mission-orchestrator", result.Source)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission.started", result.MissionEvent.EventType)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "Mission started", result.MissionEvent.Message)
				assert.Equal(t, "test-mission", result.MissionEvent.Payload["mission_name"])
				assert.Equal(t, "target-456", result.MissionEvent.Payload["target_id"])
				assert.Equal(t, 5, result.MissionEvent.Payload["node_count"])
				assert.Equal(t, testTraceID, result.Metadata["trace_id"])
				assert.Equal(t, testSpanID, result.Metadata["span_id"])
			},
		},
		{
			name: "MissionProgressPayload",
			event: events.Event{
				Type:      events.EventMissionProgress,
				Timestamp: now,
				MissionID: testMissionID,
				TraceID:   testTraceID,
				SpanID:    testSpanID,
				Payload: events.MissionProgressPayload{
					MissionID:      testMissionID,
					CompletedNodes: 3,
					TotalNodes:     5,
					CurrentNode:    "node-2",
					Message:        "Processing node 2",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "mission.progress", result.EventType)
				assert.Equal(t, now, result.Timestamp)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "node-2", result.MissionEvent.NodeID)
				assert.Equal(t, "Processing node 2", result.MissionEvent.Message)
				assert.Equal(t, 3, result.MissionEvent.Payload["completed_nodes"])
				assert.Equal(t, 5, result.MissionEvent.Payload["total_nodes"])
				assert.Equal(t, "node-2", result.MissionEvent.Payload["current_node"])
			},
		},
		{
			name: "MissionCompletedPayload",
			event: events.Event{
				Type:      events.EventMissionCompleted,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.MissionCompletedPayload{
					MissionID:     testMissionID,
					Duration:      5 * time.Minute,
					FindingCount:  10,
					NodesExecuted: 5,
					Success:       true,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "mission.completed", result.EventType)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "Mission completed", result.MissionEvent.Message)
				assert.Equal(t, float64(300), result.MissionEvent.Payload["duration"]) // 5 minutes in seconds
				assert.Equal(t, 10, result.MissionEvent.Payload["finding_count"])
				assert.Equal(t, 5, result.MissionEvent.Payload["nodes_executed"])
				assert.Equal(t, true, result.MissionEvent.Payload["success"])
			},
		},
		{
			name: "MissionFailedPayload",
			event: events.Event{
				Type:      events.EventMissionFailed,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.MissionFailedPayload{
					MissionID:     testMissionID,
					Error:         "connection timeout",
					Duration:      2 * time.Minute,
					FindingCount:  3,
					NodesExecuted: 2,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "mission.failed", result.EventType)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "connection timeout", result.MissionEvent.Error)
				assert.Equal(t, "Mission failed", result.MissionEvent.Message)
				assert.Equal(t, float64(120), result.MissionEvent.Payload["duration"])
				assert.Equal(t, 3, result.MissionEvent.Payload["finding_count"])
				assert.Equal(t, 2, result.MissionEvent.Payload["nodes_executed"])
			},
		},
		{
			name: "NodeStartedPayload",
			event: events.Event{
				Type:      events.EventNodeStarted,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.NodeStartedPayload{
					MissionID: testMissionID,
					NodeID:    "node-1",
					NodeType:  "agent",
					Message:   "Starting agent node",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "node.started", result.EventType)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "node-1", result.MissionEvent.NodeID)
				assert.Equal(t, "Starting agent node", result.MissionEvent.Message)
				assert.Equal(t, "agent", result.MissionEvent.Payload["node_type"])
			},
		},
		{
			name: "NodeCompletedPayload",
			event: events.Event{
				Type:      events.EventNodeCompleted,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.NodeCompletedPayload{
					MissionID: testMissionID,
					NodeID:    "node-1",
					Duration:  30 * time.Second,
					Message:   "Node completed successfully",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "node.completed", result.EventType)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "node-1", result.MissionEvent.NodeID)
				assert.Equal(t, "Node completed successfully", result.MissionEvent.Message)
				assert.Equal(t, float64(30), result.MissionEvent.Payload["duration"])
			},
		},
		{
			name: "NodeFailedPayload",
			event: events.Event{
				Type:      events.EventNodeFailed,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.NodeFailedPayload{
					MissionID: testMissionID,
					NodeID:    "node-2",
					Error:     "timeout exceeded",
					Duration:  45 * time.Second,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "node.failed", result.EventType)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "node-2", result.MissionEvent.NodeID)
				assert.Equal(t, "timeout exceeded", result.MissionEvent.Error)
				assert.Equal(t, "Node failed", result.MissionEvent.Message)
				assert.Equal(t, float64(45), result.MissionEvent.Payload["duration"])
			},
		},
		{
			name: "NodeSkippedPayload",
			event: events.Event{
				Type:      events.EventNodeSkipped,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.NodeSkippedPayload{
					MissionID:  testMissionID,
					NodeID:     "node-3",
					SkipReason: "condition not met",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "node.skipped", result.EventType)
				assert.NotNil(t, result.MissionEvent)
				assert.Equal(t, "mission-123", result.MissionEvent.MissionID)
				assert.Equal(t, "node-3", result.MissionEvent.NodeID)
				assert.Equal(t, "condition not met", result.MissionEvent.Message)
				assert.Equal(t, "condition not met", result.MissionEvent.Payload["skip_reason"])
			},
		},
		{
			name: "AgentStartedPayload",
			event: events.Event{
				Type:      events.EventAgentStarted,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.AgentStartedPayload{
					AgentName:       testAgentName,
					TaskDescription: "Scan the network",
					TargetID:        types.ID("target-789"),
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "agent.started", result.EventType)
				assert.NotNil(t, result.AgentEvent)
				assert.Equal(t, testAgentName, result.AgentEvent.AgentName)
				assert.Equal(t, "Scan the network", result.AgentEvent.Message)
				assert.Equal(t, "target-789", result.AgentEvent.Metadata["target_id"])
			},
		},
		{
			name: "AgentCompletedPayload",
			event: events.Event{
				Type:      events.EventAgentCompleted,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.AgentCompletedPayload{
					AgentName:    testAgentName,
					Duration:     2 * time.Minute,
					FindingCount: 5,
					Success:      true,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "agent.completed", result.EventType)
				assert.NotNil(t, result.AgentEvent)
				assert.Equal(t, testAgentName, result.AgentEvent.AgentName)
				assert.Equal(t, "Agent completed", result.AgentEvent.Message)
				assert.Equal(t, float64(120), result.AgentEvent.Metadata["duration"])
				assert.Equal(t, 5, result.AgentEvent.Metadata["finding_count"])
				assert.Equal(t, true, result.AgentEvent.Metadata["success"])
			},
		},
		{
			name: "AgentFailedPayload",
			event: events.Event{
				Type:      events.EventAgentFailed,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.AgentFailedPayload{
					AgentName:    testAgentName,
					Error:        "network unreachable",
					Duration:     1 * time.Minute,
					FindingCount: 2,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "agent.failed", result.EventType)
				assert.NotNil(t, result.AgentEvent)
				assert.Equal(t, testAgentName, result.AgentEvent.AgentName)
				assert.Equal(t, "network unreachable", result.AgentEvent.Message)
				assert.Equal(t, float64(60), result.AgentEvent.Metadata["duration"])
				assert.Equal(t, 2, result.AgentEvent.Metadata["finding_count"])
			},
		},
		{
			name: "AgentDelegatedPayload",
			event: events.Event{
				Type:      events.EventAgentDelegated,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.AgentDelegatedPayload{
					FromAgent:       "scanner-agent",
					ToAgent:         "exploit-agent",
					TaskDescription: "Exploit vulnerability",
					FromTraceID:     "trace-123",
					FromSpanID:      "span-456",
					ToTraceID:       "trace-789",
					ToSpanID:        "span-abc",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "agent.delegated", result.EventType)
				assert.NotNil(t, result.AgentEvent)
				assert.Equal(t, "scanner-agent", result.AgentEvent.AgentName)
				assert.Equal(t, "Exploit vulnerability", result.AgentEvent.Message)
				assert.Equal(t, "exploit-agent", result.AgentEvent.Metadata["to_agent"])
				assert.Equal(t, "trace-123", result.AgentEvent.Metadata["from_trace_id"])
				assert.Equal(t, "span-456", result.AgentEvent.Metadata["from_span_id"])
				assert.Equal(t, "trace-789", result.AgentEvent.Metadata["to_trace_id"])
				assert.Equal(t, "span-abc", result.AgentEvent.Metadata["to_span_id"])
			},
		},
		{
			name: "FindingDiscoveredPayload",
			event: events.Event{
				Type:      events.EventFindingDiscovered,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.FindingDiscoveredPayload{
					FindingID:   types.ID("finding-001"),
					Title:       "SQL Injection",
					Severity:    "high",
					Category:    "injection",
					Description: "SQL injection vulnerability found",
					Technique:   "T1190",
					Evidence:    "Error message revealed database schema",
					Timestamp:   now,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "finding.discovered", result.EventType)
				assert.NotNil(t, result.FindingEvent)
				assert.Equal(t, "mission-123", result.FindingEvent.MissionID)
				assert.Equal(t, "finding-001", result.FindingEvent.Finding.ID)
				assert.Equal(t, "SQL Injection", result.FindingEvent.Finding.Title)
				assert.Equal(t, "high", result.FindingEvent.Finding.Severity)
				assert.Equal(t, "injection", result.FindingEvent.Finding.Category)
				assert.Equal(t, "SQL injection vulnerability found", result.FindingEvent.Finding.Description)
				assert.Equal(t, "T1190", result.FindingEvent.Finding.Technique)
				assert.Equal(t, "Error message revealed database schema", result.FindingEvent.Finding.Evidence)
				assert.Equal(t, now, result.FindingEvent.Finding.Timestamp)
			},
		},
		{
			name: "FindingSubmittedPayload",
			event: events.Event{
				Type:      events.EventFindingSubmitted,
				Timestamp: now,
				MissionID: testMissionID,
				Payload: events.FindingSubmittedPayload{
					FindingID: types.ID("finding-002"),
					Title:     "XSS Vulnerability",
					Severity:  "medium",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "agent.finding_submitted", result.EventType)
				assert.NotNil(t, result.FindingEvent)
				assert.Equal(t, "mission-123", result.FindingEvent.MissionID)
				assert.Equal(t, "finding-002", result.FindingEvent.Finding.ID)
				assert.Equal(t, "XSS Vulnerability", result.FindingEvent.Finding.Title)
				assert.Equal(t, "medium", result.FindingEvent.Finding.Severity)
			},
		},
		{
			name: "ToolCallStartedPayload",
			event: events.Event{
				Type:      events.EventToolCallStarted,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.ToolCallStartedPayload{
					ToolName:      "nmap",
					Parameters:    map[string]any{"target": "192.168.1.1", "ports": "1-1000"},
					ParameterSize: 42,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "tool.call.started", result.EventType)
				assert.NotNil(t, result.ToolEvent)
				assert.Equal(t, "tool.started", result.ToolEvent.EventType)
				assert.Equal(t, testAgentName, result.ToolEvent.AgentName)
				assert.Equal(t, "Tool execution started: nmap", result.ToolEvent.Message)
				assert.Equal(t, "nmap", result.ToolEvent.ToolName)
				assert.Equal(t, "mission-123", result.ToolEvent.MissionID)
				assert.Contains(t, result.ToolEvent.InputSummary, "parameters")
			},
		},
		{
			name: "ToolCallCompletedPayload",
			event: events.Event{
				Type:      events.EventToolCallCompleted,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.ToolCallCompletedPayload{
					ToolName:   "nmap",
					Duration:   15 * time.Second,
					ResultSize: 1024,
					Success:    true,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "tool.call.completed", result.EventType)
				assert.NotNil(t, result.ToolEvent)
				assert.Equal(t, "tool.completed", result.ToolEvent.EventType)
				assert.Equal(t, testAgentName, result.ToolEvent.AgentName)
				assert.Equal(t, "Tool execution completed: nmap", result.ToolEvent.Message)
				assert.Equal(t, "nmap", result.ToolEvent.ToolName)
				assert.Equal(t, float64(15), result.ToolEvent.Duration)
				assert.Equal(t, 1024, result.ToolEvent.ResultsCount)
				assert.Contains(t, result.ToolEvent.OutputSummary, "results")
			},
		},
		{
			name: "ToolCallFailedPayload",
			event: events.Event{
				Type:      events.EventToolCallFailed,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.ToolCallFailedPayload{
					ToolName: "nmap",
					Error:    "connection refused",
					Duration: 5 * time.Second,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "tool.call.failed", result.EventType)
				assert.NotNil(t, result.ToolEvent)
				assert.Equal(t, "tool.failed", result.ToolEvent.EventType)
				assert.Equal(t, testAgentName, result.ToolEvent.AgentName)
				assert.Equal(t, "Tool execution failed: nmap - connection refused", result.ToolEvent.Message)
				assert.Equal(t, "nmap", result.ToolEvent.ToolName)
				assert.Equal(t, float64(5), result.ToolEvent.Duration)
				assert.Equal(t, "connection refused", result.ToolEvent.Error)
				assert.NotEmpty(t, result.ToolEvent.ErrorCode)
			},
		},
		{
			name: "LLMRequestStartedPayload",
			event: events.Event{
				Type:      events.EventLLMRequestStarted,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.LLMRequestStartedPayload{
					Provider:     "anthropic",
					Model:        "claude-3-opus-20240229",
					SlotName:     "primary",
					MessageCount: 5,
					Stream:       true,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "llm.request.started", result.EventType)
				assert.NotNil(t, result.LLMEvent)
				assert.Equal(t, "llm.request.started", result.LLMEvent.EventType)
				assert.Equal(t, testAgentName, result.LLMEvent.AgentName)
				assert.Equal(t, "claude-3-opus-20240229", result.LLMEvent.Model)
				assert.Equal(t, "primary", result.LLMEvent.Slot)
				assert.Equal(t, 5, result.LLMEvent.MessageCount)
			},
		},
		{
			name: "LLMRequestCompletedPayload",
			event: events.Event{
				Type:      events.EventLLMRequestCompleted,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.LLMRequestCompletedPayload{
					Provider:        "anthropic",
					Model:           "claude-3-opus-20240229",
					SlotName:        "primary",
					Duration:        2 * time.Second,
					InputTokens:     1000,
					OutputTokens:    500,
					StopReason:      "end_turn",
					ResponseLength:  2048,
					ResponsePreview: "Here is the analysis...",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "llm.request.completed", result.EventType)
				assert.NotNil(t, result.LLMEvent)
				assert.Equal(t, "llm.request.completed", result.LLMEvent.EventType)
				assert.Equal(t, testAgentName, result.LLMEvent.AgentName)
				assert.Equal(t, "claude-3-opus-20240229", result.LLMEvent.Model)
				assert.Equal(t, "primary", result.LLMEvent.Slot)
				assert.Equal(t, float64(2000), result.LLMEvent.Duration) // milliseconds
				assert.Equal(t, 1000, result.LLMEvent.PromptTokens)
				assert.Equal(t, 500, result.LLMEvent.CompletionTokens)
				assert.Equal(t, 1500, result.LLMEvent.TotalTokens)
			},
		},
		{
			name: "LLMRequestFailedPayload",
			event: events.Event{
				Type:      events.EventLLMRequestFailed,
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Payload: events.LLMRequestFailedPayload{
					Provider:     "anthropic",
					Model:        "claude-3-opus-20240229",
					SlotName:     "primary",
					Error:        "rate limit exceeded",
					Duration:     500 * time.Millisecond,
					Retryable:    true,
					RetryAttempt: 2,
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "llm.request.failed", result.EventType)
				assert.NotNil(t, result.LLMEvent)
				assert.Equal(t, "llm.request.failed", result.LLMEvent.EventType)
				assert.Equal(t, testAgentName, result.LLMEvent.AgentName)
				assert.Equal(t, "claude-3-opus-20240229", result.LLMEvent.Model)
				assert.Equal(t, "primary", result.LLMEvent.Slot)
				// Duration is not set for failed LLM events in current implementation
				assert.Equal(t, "rate limit exceeded", result.LLMEvent.Error)
				assert.True(t, result.LLMEvent.WillRetry)
			},
		},
		{
			name: "non-Event type (fallback)",
			event: struct {
				Name  string
				Value int
			}{
				Name:  "test",
				Value: 42,
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "unknown", result.EventType)
				assert.Equal(t, "mission-orchestrator", result.Source)
				assert.NotNil(t, result.Metadata)
				assert.Contains(t, result.Metadata["error"], "failed to type assert")
			},
		},
		{
			name: "unknown payload type",
			event: events.Event{
				Type:      "custom.event",
				Timestamp: now,
				MissionID: testMissionID,
				AgentName: testAgentName,
				Attrs: map[string]any{
					"custom_field": "custom_value",
				},
				Payload: struct {
					CustomData string
				}{
					CustomData: "some data",
				},
			},
			validate: func(t *testing.T, result api.EventData) {
				assert.Equal(t, "custom.event", result.EventType)
				assert.Equal(t, "custom.event", result.Data)
				assert.Equal(t, "mission-123", result.Metadata["mission_id"])
				assert.Equal(t, testAgentName, result.Metadata["agent_name"])
				assert.Equal(t, "custom_value", result.Metadata["custom_field"])
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertToAPIEventData(tt.event)
			tt.validate(t, result)
		})
	}
}

func TestConvertToAPIEventData_EdgeCases(t *testing.T) {
	now := time.Now()

	t.Run("empty trace and span IDs", func(t *testing.T) {
		event := events.Event{
			Type:      events.EventMissionStarted,
			Timestamp: now,
			MissionID: types.ID("mission-123"),
			TraceID:   "", // Empty
			SpanID:    "", // Empty
			Payload: events.MissionStartedPayload{
				MissionID:   types.ID("mission-123"),
				MissionName: "test",
				NodeCount:   1,
			},
		}

		result := convertToAPIEventData(event)

		assert.NotNil(t, result.Metadata)
		assert.NotContains(t, result.Metadata, "trace_id")
		assert.NotContains(t, result.Metadata, "span_id")
	})

	t.Run("event with empty strings in payload", func(t *testing.T) {
		event := events.Event{
			Type:      events.EventMissionStarted,
			Timestamp: now,
			MissionID: types.ID("mission-123"),
			Payload: events.MissionStartedPayload{
				MissionID:   types.ID("mission-123"),
				MissionName: "", // Empty
				TargetID:    types.ID(""),
				NodeCount:   0,
			},
		}

		result := convertToAPIEventData(event)

		assert.Equal(t, "mission.started", result.EventType)
		assert.NotNil(t, result.MissionEvent)
		assert.Equal(t, "", result.MissionEvent.Payload["mission_name"])
		assert.Equal(t, "", result.MissionEvent.Payload["target_id"])
		assert.Equal(t, 0, result.MissionEvent.Payload["node_count"])
	})

	t.Run("zero duration values", func(t *testing.T) {
		event := events.Event{
			Type:      events.EventMissionCompleted,
			Timestamp: now,
			MissionID: types.ID("mission-123"),
			Payload: events.MissionCompletedPayload{
				MissionID:     types.ID("mission-123"),
				Duration:      0, // Zero duration
				FindingCount:  0,
				NodesExecuted: 0,
				Success:       false,
			},
		}

		result := convertToAPIEventData(event)

		assert.Equal(t, "mission.completed", result.EventType)
		assert.NotNil(t, result.MissionEvent)
		assert.Equal(t, float64(0), result.MissionEvent.Payload["duration"])
		assert.Equal(t, 0, result.MissionEvent.Payload["finding_count"])
		assert.Equal(t, false, result.MissionEvent.Payload["success"])
	})

	t.Run("nil payload (should not panic)", func(t *testing.T) {
		event := events.Event{
			Type:      events.EventMissionStarted,
			Timestamp: now,
			MissionID: types.ID("mission-123"),
			Payload:   nil, // nil payload
		}

		result := convertToAPIEventData(event)

		// Should handle gracefully and fall through to default case
		assert.Equal(t, "mission.started", result.EventType)
		assert.Equal(t, "mission.started", result.Data)
	})

	t.Run("event with nil Attrs map", func(t *testing.T) {
		event := events.Event{
			Type:      "custom.event",
			Timestamp: now,
			MissionID: types.ID("mission-123"),
			Attrs:     nil, // nil map
			Payload:   "unknown payload",
		}

		result := convertToAPIEventData(event)

		assert.Equal(t, "custom.event", result.EventType)
		assert.NotNil(t, result.Metadata)
	})
}

func TestConvertToAPIEventData_TimestampConversion(t *testing.T) {
	specificTime := time.Date(2024, 3, 15, 10, 30, 45, 0, time.UTC)

	event := events.Event{
		Type:      events.EventMissionStarted,
		Timestamp: specificTime,
		MissionID: types.ID("mission-123"),
		Payload: events.MissionStartedPayload{
			MissionID: types.ID("mission-123"),
			NodeCount: 1,
		},
	}

	result := convertToAPIEventData(event)

	assert.Equal(t, specificTime, result.Timestamp)
	assert.Equal(t, specificTime, result.MissionEvent.Timestamp)
}

func TestConvertToAPIEventData_TraceContextPreservation(t *testing.T) {
	event := events.Event{
		Type:      events.EventMissionStarted,
		Timestamp: time.Now(),
		MissionID: types.ID("mission-123"),
		TraceID:   "trace-id-with-special-chars-123-abc",
		SpanID:    "span-id-456-def",
		Payload: events.MissionStartedPayload{
			MissionID: types.ID("mission-123"),
			NodeCount: 1,
		},
	}

	result := convertToAPIEventData(event)

	assert.Equal(t, "trace-id-with-special-chars-123-abc", result.Metadata["trace_id"])
	assert.Equal(t, "span-id-456-def", result.Metadata["span_id"])
}
