package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestNewOTelDecisionLogWriterAdapter tests the constructor creates adapter
func TestNewOTelDecisionLogWriterAdapter(t *testing.T) {
	// Create test providers
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	// Create tracer
	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	// Create adapter
	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)

	// Verify success
	require.NoError(t, err)
	assert.NotNil(t, adapter)
	assert.NotNil(t, adapter.tracer)
	assert.NotNil(t, adapter.missionSpan)
	assert.NotNil(t, adapter.agentSpans)
	assert.Equal(t, mission.ID.String(), adapter.missionID)
	assert.Equal(t, mission.Name, adapter.missionName)

	// Clean up
	adapter.Close(context.Background(), nil)
}

// TestNewOTelDecisionLogWriterAdapter_NilTracer tests error handling
func TestNewOTelDecisionLogWriterAdapter_NilTracer(t *testing.T) {
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	// Create adapter with nil tracer
	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), nil, mission)

	// Should return error
	assert.Error(t, err)
	assert.Nil(t, adapter)
}

// TestNewOTelDecisionLogWriterAdapter_NilMission tests error handling
func TestNewOTelDecisionLogWriterAdapter_NilMission(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create adapter with nil mission
	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, nil)

	// Should return error
	assert.Error(t, err)
	assert.Nil(t, adapter)
}

// TestOTelDecisionLogWriterAdapter_LogDecision tests logging decisions correctly
func TestOTelDecisionLogWriterAdapter_LogDecision(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Create decision
	decision := &orchestrator.Decision{
		Reasoning:    "Test reasoning",
		Action:       orchestrator.ActionExecuteAgent,
		TargetNodeID: "node-123",
		Confidence:   0.95,
	}

	// Create think result
	result := &orchestrator.ThinkResult{
		Decision:         decision,
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
		Model:            "gpt-4",
		RawResponse:      "Raw LLM response",
		SystemPrompt:     "System prompt text",
		UserPrompt:       "User prompt text",
		Latency:          1500 * time.Millisecond,
		Messages: []llm.Message{
			{Role: llm.RoleSystem, Content: "System prompt text"},
			{Role: llm.RoleUser, Content: "User prompt text"},
		},
		RequestConfig: orchestrator.RequestConfig{
			Temperature: 0.7,
			MaxTokens:   1000,
			TopP:        0.9,
			SlotName:    "primary",
		},
	}

	// Log decision
	err = adapter.LogDecision(context.Background(), decision, result, 1, mission.ID.String())
	assert.NoError(t, err)

	// Verify mission span statistics
	stats := adapter.missionSpan.GetStatistics()
	assert.Equal(t, 1, stats.TotalDecisions)
	assert.Equal(t, 1, stats.TotalLLMCalls)
	assert.Equal(t, 150, stats.TotalTokens)
}

// TestOTelDecisionLogWriterAdapter_LogDecision_MismatchedMissionID tests validation
func TestOTelDecisionLogWriterAdapter_LogDecision_MismatchedMissionID(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	decision := &orchestrator.Decision{
		Reasoning: "Test reasoning",
		Action:    orchestrator.ActionExecuteAgent,
	}

	result := &orchestrator.ThinkResult{
		Decision: decision,
	}

	// Log with wrong mission ID
	wrongMissionID := types.NewID().String()
	err = adapter.LogDecision(context.Background(), decision, result, 1, wrongMissionID)

	// Should not error (fire-and-forget), but should log warning
	assert.NoError(t, err)

	// Statistics should not be updated
	stats := adapter.missionSpan.GetStatistics()
	assert.Equal(t, 0, stats.TotalDecisions)
}

// TestOTelDecisionLogWriterAdapter_LogAction_ExecuteAgent tests routing agent execution
func TestOTelDecisionLogWriterAdapter_LogAction_ExecuteAgent(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Create agent execution
	execution := &schema.AgentExecution{
		ID:             types.NewID(),
		WorkflowNodeID: "node-123",
		Attempt:        1,
		Status:         schema.ExecutionStatusCompleted,
		StartedAt:      time.Now(),
		Result: map[string]any{
			"tool_calls_count": 3,
			"findings_count":   2,
			"llm_time_ms":      500,
			"tool_time_ms":     1000,
			"memory_ops_count": 5,
		},
	}

	// Create action result
	action := &orchestrator.ActionResult{
		Action:         orchestrator.ActionExecuteAgent,
		AgentExecution: execution,
		NewNode:        nil,
		Error:          nil,
		Metadata: map[string]any{
			"agent_name": "test-agent",
		},
	}

	// Log action
	err = adapter.LogAction(context.Background(), action, 1, mission.ID.String())
	assert.NoError(t, err)

	// Verify agent span was stored
	agentSpan := adapter.GetAgentSpan(execution.ID.String())
	assert.NotNil(t, agentSpan)
	assert.Equal(t, execution.ID, agentSpan.ExecutionID)

	// Verify mission statistics
	stats := adapter.missionSpan.GetStatistics()
	assert.Equal(t, 1, stats.TotalExecutions)
}

// TestOTelDecisionLogWriterAdapter_LogAction_SpawnAgent tests logging spawn actions
func TestOTelDecisionLogWriterAdapter_LogAction_SpawnAgent(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Create new node
	newNode := &schema.WorkflowNode{
		ID:        types.NewID(),
		AgentName: "spawned-agent",
	}

	// Create action result
	action := &orchestrator.ActionResult{
		Action:  orchestrator.ActionSpawnAgent,
		NewNode: newNode,
		Metadata: map[string]any{
			"reason": "spawn for parallel execution",
		},
	}

	// Log action
	err = adapter.LogAction(context.Background(), action, 1, mission.ID.String())
	assert.NoError(t, err)

	// Spawn doesn't create agent spans, but should log successfully
}

// TestOTelDecisionLogWriterAdapter_LogAction_Complete tests handling complete action
func TestOTelDecisionLogWriterAdapter_LogAction_Complete(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Create action result
	action := &orchestrator.ActionResult{
		Action: orchestrator.ActionComplete,
	}

	// Log action
	err = adapter.LogAction(context.Background(), action, 5, mission.ID.String())
	assert.NoError(t, err)

	// Complete action doesn't create spans (logged in Close)
}

// TestOTelDecisionLogWriterAdapter_Close tests finalizing the mission trace
func TestOTelDecisionLogWriterAdapter_Close(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)

	// Add some operations
	adapter.missionSpan.AddDecision()
	adapter.missionSpan.AddExecution()
	adapter.missionSpan.AddToolCall()
	adapter.missionSpan.AddLLMCall(1000, 0.02)

	// Create summary
	summary := &MissionTraceSummary{
		Status:   "completed",
		Outcome:  "Mission completed successfully",
		Duration: 5 * time.Minute,
	}

	// Close adapter
	err = adapter.Close(context.Background(), summary)
	assert.NoError(t, err)

	// Verify spans were created
	spans := spanRecorder.Ended()
	require.GreaterOrEqual(t, len(spans), 1)

	// Find mission span
	var missionSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanMissionExecute {
			missionSpan = span
			break
		}
	}
	require.NotNil(t, missionSpan)

	// Verify attributes
	attrs := missionSpan.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalDecisions])
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalExecutions])
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalToolCalls])
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalLLMCalls])
	assert.Equal(t, int64(1000), attrMap[GibsonMissionTotalTokens])
	assert.Equal(t, "Mission completed successfully", attrMap[GibsonMissionOutcome])
}

// TestOTelDecisionLogWriterAdapter_Close_NilSummary tests default summary creation
func TestOTelDecisionLogWriterAdapter_Close_NilSummary(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)

	// Close with nil summary
	err = adapter.Close(context.Background(), nil)
	assert.NoError(t, err)

	// Should use default summary
}

// TestOTelDecisionLogWriterAdapter_GetAgentSpan tests retrieving stored spans
func TestOTelDecisionLogWriterAdapter_GetAgentSpan(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Create and log agent execution
	executionID := types.NewID()
	execution := &schema.AgentExecution{
		ID:             executionID,
		WorkflowNodeID: "node-123",
		Attempt:        1,
		Status:         schema.ExecutionStatusCompleted,
		StartedAt:      time.Now(),
	}

	action := &orchestrator.ActionResult{
		Action:         orchestrator.ActionExecuteAgent,
		AgentExecution: execution,
		Metadata: map[string]any{
			"agent_name": "test-agent",
		},
	}

	adapter.LogAction(context.Background(), action, 1, mission.ID.String())

	// Retrieve agent span
	agentSpan := adapter.GetAgentSpan(executionID.String())
	assert.NotNil(t, agentSpan)
	assert.Equal(t, executionID, agentSpan.ExecutionID)

	// Try to retrieve non-existent span
	nonExistentSpan := adapter.GetAgentSpan("non-existent-id")
	assert.Nil(t, nonExistentSpan)
}

// TestOTelDecisionLogWriterAdapter_GetMissionContext tests context propagation
func TestOTelDecisionLogWriterAdapter_GetMissionContext(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Get mission context
	ctx := adapter.GetMissionContext()
	assert.NotNil(t, ctx)

	// Context should contain trace information
	// (Actual verification would require extracting span from context)
}

// TestOTelDecisionLogWriterAdapter_TraceID tests trace ID extraction
func TestOTelDecisionLogWriterAdapter_TraceID(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Get trace ID
	traceID := adapter.TraceID()
	assert.NotEmpty(t, traceID)
	assert.Len(t, traceID, 32) // Hex-encoded trace ID is 32 characters
}

// TestOTelDecisionLogWriterAdapter_ThreadSafety tests concurrent access is safe
func TestOTelDecisionLogWriterAdapter_ThreadSafety(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// Run concurrent operations
	var wg sync.WaitGroup
	numGoroutines := 10

	// Concurrent decision logging
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			decision := &orchestrator.Decision{
				Reasoning:  "Test reasoning",
				Action:     orchestrator.ActionExecuteAgent,
				Confidence: 0.95,
			}

			result := &orchestrator.ThinkResult{
				Decision:         decision,
				PromptTokens:     100,
				CompletionTokens: 50,
				TotalTokens:      150,
			}

			adapter.LogDecision(context.Background(), decision, result, iteration, mission.ID.String())
		}(i)
	}

	// Concurrent action logging
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(iteration int) {
			defer wg.Done()

			execution := &schema.AgentExecution{
				ID:             types.NewID(),
				WorkflowNodeID: "node-123",
				Attempt:        1,
				Status:         schema.ExecutionStatusCompleted,
				StartedAt:      time.Now(),
			}

			action := &orchestrator.ActionResult{
				Action:         orchestrator.ActionExecuteAgent,
				AgentExecution: execution,
				Metadata: map[string]any{
					"agent_name": "test-agent",
				},
			}

			adapter.LogAction(context.Background(), action, iteration, mission.ID.String())
		}(i)
	}

	// Concurrent span retrieval
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			adapter.GetAgentSpan("some-id")
		}()
	}

	wg.Wait()

	// Verify no panics and statistics are consistent
	stats := adapter.missionSpan.GetStatistics()
	assert.Equal(t, numGoroutines, stats.TotalDecisions)
	assert.Equal(t, numGoroutines, stats.TotalExecutions)
}

// TestOTelDecisionLogWriterAdapter_NilChecks tests fire-and-forget with nil data
func TestOTelDecisionLogWriterAdapter_NilChecks(t *testing.T) {
	// Setup
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	adapter, err := NewOTelDecisionLogWriterAdapter(context.Background(), tracer, mission)
	require.NoError(t, err)
	defer adapter.Close(context.Background(), nil)

	// All should handle nil gracefully
	assert.NotPanics(t, func() {
		adapter.LogDecision(context.Background(), nil, nil, 1, mission.ID.String())
		adapter.LogAction(context.Background(), nil, 1, mission.ID.String())
	})

	// Statistics should not change
	stats := adapter.missionSpan.GetStatistics()
	assert.Equal(t, 0, stats.TotalDecisions)
	assert.Equal(t, 0, stats.TotalExecutions)
}
