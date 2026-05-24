package observability

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestNewOTelMissionTracer tests the constructor with valid providers
func TestNewOTelMissionTracer(t *testing.T) {
	// Create test providers
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	// Create tracer with default config
	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Verify tracer is initialized
	assert.NotNil(t, tracer)
	assert.NotNil(t, tracer.tracer)
	assert.NotNil(t, tracer.meter)
	assert.NotNil(t, tracer.contentConfig)
	assert.Equal(t, "gibson", tracer.serviceName)
	assert.Equal(t, "", tracer.neo4jBrowserURL)
}

// TestNewOTelMissionTracer_NilProviders tests graceful handling of nil providers
func TestNewOTelMissionTracer_NilProviders(t *testing.T) {
	// Create a custom config
	cfg := DefaultContentLoggingConfig()

	// Create tracer with nil providers - should still create tracer
	// but may have limited functionality
	tracer := NewOTelMissionTracer(nil, nil, &cfg)

	// Tracer should be created (may be a no-op tracer)
	assert.NotNil(t, tracer)
	assert.NotNil(t, tracer.contentConfig)
}

// TestOTelMissionTracer_StartMissionTrace tests creating proper span hierarchy
func TestOTelMissionTracer_StartMissionTrace(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create a test mission
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test mission objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	// Start mission trace
	ctx, missionSpan, err := tracer.StartMissionTrace(context.Background(), mission)

	// Verify success
	require.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.NotNil(t, missionSpan)
	assert.Equal(t, mission.ID, missionSpan.MissionID)
	assert.Equal(t, mission.CreatedAt, missionSpan.StartTime)

	// End the mission span
	missionSpan.End(codes.Ok, "test completed")

	// Verify span was created
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, SpanMissionExecute, spans[0].Name())

	// Verify attributes
	attrs := spans[0].Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, mission.ID.String(), attrMap[GibsonMissionID])
	assert.Equal(t, mission.Name, attrMap[GibsonMissionName])
	assert.Equal(t, mission.Objective, attrMap[GibsonMissionObjective])
	assert.Equal(t, mission.TargetRef, attrMap[GibsonMissionTargetRef])
	assert.Equal(t, mission.Status.String(), attrMap[GibsonMissionStatus])
}

// TestOTelMissionTracer_StartMissionTrace_NilMission tests error handling
func TestOTelMissionTracer_StartMissionTrace_NilMission(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Start with nil mission
	ctx, missionSpan, err := tracer.StartMissionTrace(context.Background(), nil)

	// Should return error
	assert.Error(t, err)
	assert.Nil(t, missionSpan)
	assert.NotNil(t, ctx) // Context should still be returned
}

// TestOTelMissionTracer_LogDecision tests logging a decision with correct attributes
func TestOTelMissionTracer_LogDecision(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission and start trace
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, err := tracer.StartMissionTrace(context.Background(), mission)
	require.NoError(t, err)

	// Create a decision
	decision := schema.NewDecision(mission.ID, 1, schema.DecisionActionExecuteAgent)
	decision.Confidence = 0.95
	decision.Reasoning = "Test reasoning"
	decision.PromptTokens = 100
	decision.CompletionTokens = 50
	decision.WithLatency(1500)
	decision.TargetNodeID = "node-123"

	decisionLog := &DecisionLog{
		Decision:    decision,
		Prompt:      "Test prompt",
		Response:    "Test response",
		Model:       "gpt-4",
		Neo4jNodeID: "neo4j-node-123",
		RequestMeta: &RequestMetadata{
			Provider:    "openai",
			Temperature: 0.7,
			MaxTokens:   1000,
			TopP:        0.9,
		},
	}

	// Log decision
	err = tracer.LogDecision(ctx, missionSpan, decisionLog)
	assert.NoError(t, err)

	// End mission span to flush
	missionSpan.End(codes.Ok, "completed")

	// Verify spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 2) // mission span + decision span

	// Find decision span
	var decisionSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			decisionSpan = span
			break
		}
	}
	require.NotNil(t, decisionSpan)

	// Verify decision attributes
	attrs := decisionSpan.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, "gpt-4", attrMap[GenAIRequestModel])
	assert.Equal(t, "gpt-4", attrMap[GenAIResponseModel])
	assert.Equal(t, "openai", attrMap[GenAISystem])
	assert.Equal(t, int64(100), attrMap[GenAIUsageInputTokens])
	assert.Equal(t, int64(50), attrMap[GenAIUsageOutputTokens])
	assert.Equal(t, 0.7, attrMap[GenAIRequestTemperature])
	assert.Equal(t, int64(1000), attrMap[GenAIRequestMaxTokens])
	assert.Equal(t, 0.9, attrMap[GenAIRequestTopP])
	assert.Equal(t, int64(1), attrMap[GibsonOrchestratorIteration])
	assert.Equal(t, schema.DecisionActionExecuteAgent.String(), attrMap[GibsonOrchestratorAction])
	assert.Equal(t, 0.95, attrMap[GibsonOrchestratorConfidence])
	assert.Equal(t, "Test reasoning", attrMap[GibsonOrchestratorReasoning])
	assert.Equal(t, "node-123", attrMap[GibsonOrchestratorTargetNodeID])

	// Verify mission statistics were updated
	stats := missionSpan.GetStatistics()
	assert.Equal(t, 1, stats.TotalDecisions)
	assert.Equal(t, 1, stats.TotalLLMCalls)
	assert.Equal(t, 150, stats.TotalTokens)
}

// TestOTelMissionTracer_LogAgentExecution tests creating agent spans correctly
func TestOTelMissionTracer_LogAgentExecution(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission and start trace
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, err := tracer.StartMissionTrace(context.Background(), mission)
	require.NoError(t, err)

	// Create agent execution
	execution := &schema.AgentExecution{
		ID:            types.NewID(),
		MissionNodeID: "node-123",
		Attempt:       1,
		Status:        schema.ExecutionStatusCompleted,
		StartedAt:     time.Now(),
	}

	agentLog := &AgentExecutionLog{
		Execution:      execution,
		AgentName:      "test-agent",
		Neo4jNodeID:    "neo4j-node-456",
		ToolCallsCount: 3,
		FindingsCount:  2,
		LLMTimeMs:      500,
		ToolTimeMs:     1000,
		MemoryOpsCount: 5,
	}

	// Log agent execution
	agentCtx, agentSpan, err := tracer.LogAgentExecution(ctx, missionSpan, agentLog)
	assert.NoError(t, err)
	assert.NotNil(t, agentCtx)
	assert.NotNil(t, agentSpan)

	// End spans
	agentSpan.End(codes.Ok, "completed")
	missionSpan.End(codes.Ok, "completed")

	// Verify spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 2) // mission span + agent span

	// Find agent span
	var agentSpanData sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanAgentExecute {
			agentSpanData = span
			break
		}
	}
	require.NotNil(t, agentSpanData)

	// Verify agent attributes
	attrs := agentSpanData.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, "test-agent", attrMap[GibsonAgentName])
	assert.Equal(t, "node-123", attrMap[GibsonAgentMissionNodeID])
	assert.Equal(t, int64(1), attrMap[GibsonAgentAttempt])
	assert.Equal(t, schema.ExecutionStatusCompleted.String(), attrMap[GibsonAgentStatus])
	assert.Equal(t, int64(3), attrMap[GibsonAgentToolCallsCount])
	assert.Equal(t, int64(2), attrMap[GibsonAgentFindingsCount])
	assert.Equal(t, int64(500), attrMap[GibsonAgentLLMTimeMs])
	assert.Equal(t, int64(1000), attrMap[GibsonAgentToolTimeMs])
	assert.Equal(t, int64(5), attrMap[GibsonAgentMemoryOpsCount])

	// Verify mission statistics
	stats := missionSpan.GetStatistics()
	assert.Equal(t, 1, stats.TotalExecutions)
}

// TestOTelMissionTracer_LogToolExecution tests logging tool calls with attributes
func TestOTelMissionTracer_LogToolExecution(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission and agent
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	execution := &schema.AgentExecution{
		ID:            types.NewID(),
		MissionNodeID: "node-123",
		Attempt:       1,
		Status:        schema.ExecutionStatusCompleted,
		StartedAt:     time.Now(),
	}

	agentLog := &AgentExecutionLog{
		Execution: execution,
		AgentName: "test-agent",
	}

	agentCtx, agentSpan, _ := tracer.LogAgentExecution(ctx, missionSpan, agentLog)

	// Create tool execution
	completedAt := time.Now()
	toolExec := &schema.ToolExecution{
		ToolName:    "nmap",
		Status:      schema.ExecutionStatusCompleted,
		StartedAt:   time.Now().Add(-2 * time.Second),
		CompletedAt: &completedAt,
		Error:       "",
	}

	toolLog := &OTelToolExecutionLog{
		Execution:       toolExec,
		Category:        "network",
		Version:         "1.0.0",
		InputString:     "-sV 192.168.1.1",
		OutputString:    "scan results",
		DiscoveryCount:  5,
		OutputSizeBytes: 2048,
		Neo4jNodeID:     "neo4j-tool-789",
	}

	// Log tool execution
	err := tracer.LogToolExecution(agentCtx, agentSpan, toolLog)
	assert.NoError(t, err)

	// End spans
	agentSpan.End(codes.Ok, "completed")
	missionSpan.End(codes.Ok, "completed")

	// Verify spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 3) // mission + agent + tool

	// Find tool span
	var toolSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == "gibson.tool.execute" {
			toolSpan = span
			break
		}
	}
	require.NotNil(t, toolSpan)

	// Verify tool attributes
	attrs := toolSpan.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, "nmap", attrMap[GibsonToolName])
	assert.Equal(t, schema.ExecutionStatusCompleted.String(), attrMap[GibsonToolStatus])
	assert.Equal(t, "network", attrMap[GibsonToolCategory])
	assert.Equal(t, "1.0.0", attrMap[GibsonToolVersion])
	assert.Equal(t, int64(5), attrMap[GibsonToolDiscoveryCount])
	assert.Equal(t, int64(2048), attrMap[GibsonToolOutputSizeBytes])

	// Verify agent statistics
	stats := agentSpan.GetStatistics()
	assert.Equal(t, 1, stats.ToolCalls)
}

// TestOTelMissionTracer_LogFinding tests logging findings with severity/category
func TestOTelMissionTracer_LogFinding(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission and agent
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	execution := &schema.AgentExecution{
		ID:            types.NewID(),
		MissionNodeID: "node-123",
		Attempt:       1,
		Status:        schema.ExecutionStatusCompleted,
		StartedAt:     time.Now(),
	}

	agentLog := &AgentExecutionLog{
		Execution: execution,
		AgentName: "test-agent",
	}

	agentCtx, agentSpan, _ := tracer.LogAgentExecution(ctx, missionSpan, agentLog)

	// Create finding
	targetID := types.NewID()
	finding := &FindingLog{
		ID:          types.NewID(),
		Title:       "SQL Injection",
		Severity:    "high",
		Category:    "injection",
		Confidence:  0.95,
		TargetID:    &targetID,
		CVSSScore:   8.5,
		Neo4jNodeID: "neo4j-finding-999",
	}

	// Log finding
	err := tracer.LogFinding(agentCtx, agentSpan, finding)
	assert.NoError(t, err)

	// End spans
	agentSpan.End(codes.Ok, "completed")
	missionSpan.End(codes.Ok, "completed")

	// Verify spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 3) // mission + agent + finding

	// Find finding span
	var findingSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanFindingSubmit {
			findingSpan = span
			break
		}
	}
	require.NotNil(t, findingSpan)

	// Verify finding attributes
	attrs := findingSpan.Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, finding.ID.String(), attrMap[GibsonFindingID])
	assert.Equal(t, "SQL Injection", attrMap[GibsonFindingTitle])
	assert.Equal(t, "high", attrMap[GibsonFindingSeverity])
	assert.Equal(t, "injection", attrMap[GibsonFindingCategory])
	assert.Equal(t, 0.95, attrMap[GibsonFindingConfidence])
	assert.Equal(t, targetID.String(), attrMap[GibsonFindingTargetID])
	assert.Equal(t, 8.5, attrMap[GibsonFindingCVSSScore])

	// Verify agent statistics
	stats := agentSpan.GetStatistics()
	assert.Equal(t, 1, stats.FindingsCount)
}

// TestOTelMissionTracer_LogMemoryOp tests logging memory operations
func TestOTelMissionTracer_LogMemoryOp(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission and agent
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	execution := &schema.AgentExecution{
		ID:            types.NewID(),
		MissionNodeID: "node-123",
		Attempt:       1,
		Status:        schema.ExecutionStatusCompleted,
		StartedAt:     time.Now(),
	}

	agentLog := &AgentExecutionLog{
		Execution: execution,
		AgentName: "test-agent",
	}

	agentCtx, agentSpan, _ := tracer.LogAgentExecution(ctx, missionSpan, agentLog)

	// Test different memory operations
	tests := []struct {
		name     string
		op       *MemoryOpLog
		spanName string
	}{
		{
			name: "get operation",
			op: &MemoryOpLog{
				Tier:       "short",
				Operation:  "get",
				Key:        "test-key",
				Hit:        true,
				SizeBytes:  1024,
				DurationMs: 5,
			},
			spanName: SpanMemoryGet,
		},
		{
			name: "set operation",
			op: &MemoryOpLog{
				Tier:       "long",
				Operation:  "set",
				Key:        "test-key-2",
				SizeBytes:  2048,
				DurationMs: 10,
			},
			spanName: SpanMemorySet,
		},
		{
			name: "search operation",
			op: &MemoryOpLog{
				Tier:         "vector",
				Operation:    "search",
				Key:          "query",
				ResultsCount: 10,
				DurationMs:   15,
			},
			spanName: SpanMemorySearch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tracer.LogMemoryOp(agentCtx, agentSpan, tt.op)
			assert.NoError(t, err)
		})
	}

	// End spans
	agentSpan.End(codes.Ok, "completed")
	missionSpan.End(codes.Ok, "completed")

	// Verify agent statistics
	stats := agentSpan.GetStatistics()
	assert.Equal(t, 3, stats.MemoryOps)
}

// TestOTelMissionTracer_LogGraphOp tests logging graph operations
func TestOTelMissionTracer_LogGraphOp(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	// Create mission and agent
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	execution := &schema.AgentExecution{
		ID:            types.NewID(),
		MissionNodeID: "node-123",
		Attempt:       1,
		Status:        schema.ExecutionStatusCompleted,
		StartedAt:     time.Now(),
	}

	agentLog := &AgentExecutionLog{
		Execution: execution,
		AgentName: "test-agent",
	}

	agentCtx, agentSpan, _ := tracer.LogAgentExecution(ctx, missionSpan, agentLog)

	// Create graph operation
	graphOp := &GraphOpLog{
		Operation:            "store",
		NodeLabels:           []string{"Host", "Port"},
		NodesCreated:         5,
		RelationshipsCreated: 3,
		QueryType:            "create",
		ResultsCount:         8,
		DurationMs:           50,
	}

	// Log graph operation
	err := tracer.LogGraphOp(agentCtx, agentSpan, graphOp)
	assert.NoError(t, err)

	// End spans
	agentSpan.End(codes.Ok, "completed")
	missionSpan.End(codes.Ok, "completed")

	// Verify mission statistics
	stats := missionSpan.GetStatistics()
	assert.Equal(t, 1, stats.TotalGraphOps)
	assert.Equal(t, 5, stats.GraphNodesCreated)
	assert.Equal(t, 3, stats.GraphRelsCreated)
}

// TestOTelMissionTracer_EndMissionTrace tests ending span with summary stats
func TestOTelMissionTracer_EndMissionTrace(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

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

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	// Add some statistics
	missionSpan.AddDecision()
	missionSpan.AddExecution()
	missionSpan.AddToolCall()
	missionSpan.AddLLMCall(1000, 0.02)
	missionSpan.AddFinding()
	missionSpan.AddMemoryOp()
	missionSpan.AddGraphOp(5, 3)

	// Create summary
	summary := &MissionTraceSummary{
		Status:   "completed",
		Outcome:  "Successfully scanned 10 hosts, found 3 vulnerabilities",
		Duration: 5 * time.Minute,
	}

	// End mission trace
	err := tracer.EndMissionTrace(ctx, missionSpan, summary)
	assert.NoError(t, err)

	// Verify span
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	// Verify attributes include summary
	attrs := spans[0].Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalDecisions])
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalExecutions])
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalToolCalls])
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalLLMCalls])
	assert.Equal(t, int64(1000), attrMap[GibsonMissionTotalTokens])
	assert.InDelta(t, 0.02, attrMap[GibsonMissionTotalCostUSD], 0.001)
	assert.Equal(t, int64(1), attrMap[GibsonMissionTotalFindings])
	assert.Equal(t, int64(1), attrMap["gibson.mission.memory_ops"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.graph_ops"])
	assert.Equal(t, int64(5), attrMap["gibson.mission.graph_nodes_created"])
	assert.Equal(t, int64(3), attrMap["gibson.mission.graph_rels_created"])
	assert.Equal(t, "Successfully scanned 10 hosts, found 3 vulnerabilities", attrMap[GibsonMissionOutcome])

	// Verify status.
	// The OTel SDK only stores Description for codes.Error; for codes.Ok the
	// description is silently discarded (see recordingSpan.SetStatus in the OTel SDK).
	assert.Equal(t, codes.Ok, spans[0].Status().Code)
}

// TestOTelMissionTracer_ContentRedaction verifies redaction patterns work
func TestOTelMissionTracer_ContentRedaction(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	// Create config with content logging enabled
	cfg := DefaultContentLoggingConfig()
	cfg.Enabled = true
	cfg.IncludeToolIO = true

	tracer := NewOTelMissionTracer(tp, mp, &cfg)

	// Create mission
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	// Create decision with sensitive data
	decision := schema.NewDecision(mission.ID, 1, schema.DecisionActionExecuteAgent)
	decision.Confidence = 0.95
	decision.Reasoning = "Test reasoning"
	decision.PromptTokens = 100
	decision.CompletionTokens = 50

	decisionLog := &DecisionLog{
		Decision: decision,
		Prompt:   "User password is secret123 and API key is sk-1234567890",
		Response: "I will use the token abc123def456 to authenticate",
		Model:    "gpt-4",
	}

	// Log decision
	err := tracer.LogDecision(ctx, missionSpan, decisionLog)
	assert.NoError(t, err)

	// End mission
	missionSpan.End(codes.Ok, "completed")

	// Verify spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 2)

	// Find decision span
	var decisionSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			decisionSpan = span
			break
		}
	}
	require.NotNil(t, decisionSpan)

	// Verify events have redacted content
	events := decisionSpan.Events()
	var foundRedaction bool
	for _, event := range events {
		for _, attr := range event.Attributes {
			if attr.Key == "prompt" || attr.Key == "completion" {
				content := attr.Value.AsString()
				// Should NOT contain sensitive data
				assert.NotContains(t, content, "secret123")
				assert.NotContains(t, content, "sk-1234567890")
				assert.NotContains(t, content, "abc123def456")
				foundRedaction = true
			}
		}
	}
	assert.True(t, foundRedaction, "Expected to find redacted content in events")
}

// TestOTelMissionTracer_ContentTruncation verifies truncation works
func TestOTelMissionTracer_ContentTruncation(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	// Create config with content logging enabled and low limits
	cfg := DefaultContentLoggingConfig()
	cfg.Enabled = true
	cfg.MaxPromptLength = 50
	cfg.MaxCompletionLength = 50

	tracer := NewOTelMissionTracer(tp, mp, &cfg)

	// Create mission
	mission := &schema.Mission{
		ID:        types.NewID(),
		Name:      "test-mission",
		Objective: "Test objective",
		TargetRef: "test-target",
		Status:    schema.MissionStatusRunning,
		CreatedAt: time.Now(),
	}

	ctx, missionSpan, _ := tracer.StartMissionTrace(context.Background(), mission)

	// Create decision with long content
	decision := schema.NewDecision(mission.ID, 1, schema.DecisionActionExecuteAgent)
	decision.PromptTokens = 100
	decision.CompletionTokens = 50

	longPrompt := "This is a very long prompt that should be truncated because it exceeds the maximum length configured for content logging in the tracer configuration."
	longResponse := "This is a very long response that should also be truncated because it exceeds the maximum length configured for content logging."

	decisionLog := &DecisionLog{
		Decision: decision,
		Prompt:   longPrompt,
		Response: longResponse,
		Model:    "gpt-4",
	}

	// Log decision
	err := tracer.LogDecision(ctx, missionSpan, decisionLog)
	assert.NoError(t, err)

	// End mission
	missionSpan.End(codes.Ok, "completed")

	// Verify spans
	spans := spanRecorder.Ended()
	require.Len(t, spans, 2)

	// Find decision span
	var decisionSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		if span.Name() == SpanGenAIChat {
			decisionSpan = span
			break
		}
	}
	require.NotNil(t, decisionSpan)

	// Verify events have truncated content.
	// Truncate() keeps maxLen runes and appends "... [truncated]" (15 chars),
	// so the total length is at most MaxPromptLength + 15.
	const truncSuffix = "... [truncated]"
	events := decisionSpan.Events()
	for _, event := range events {
		for _, attr := range event.Attributes {
			if attr.Key == "prompt" || attr.Key == "completion" {
				content := attr.Value.AsString()
				assert.LessOrEqual(t, len(content), cfg.MaxPromptLength+len(truncSuffix))
			}
		}
	}
}

// TestOTelMissionTracer_WithNeo4jBrowserURL tests setting Neo4j browser URL
func TestOTelMissionTracer_WithNeo4jBrowserURL(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	// Create tracer and set Neo4j URL
	tracer := NewOTelMissionTracer(tp, mp, nil).
		WithNeo4jBrowserURL("http://localhost:7474").
		WithServiceName("gibson-test")

	assert.Equal(t, "http://localhost:7474", tracer.neo4jBrowserURL)
	assert.Equal(t, "gibson-test", tracer.serviceName)
}

// TestOTelMissionTracer_NilMissionSpan tests fire-and-forget with nil spans
func TestOTelMissionTracer_NilMissionSpan(t *testing.T) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(spanRecorder),
	)
	defer tp.Shutdown(context.Background())

	reader := metric.NewManualReader()
	mp := metric.NewMeterProvider(metric.WithReader(reader))
	defer mp.Shutdown(context.Background())

	tracer := NewOTelMissionTracer(tp, mp, nil)

	ctx := context.Background()

	// All methods should handle nil gracefully (fire-and-forget)
	assert.NotPanics(t, func() {
		tracer.LogDecision(ctx, nil, &DecisionLog{})
		tracer.LogAgentExecution(ctx, nil, &AgentExecutionLog{})
		tracer.LogToolExecution(ctx, nil, &OTelToolExecutionLog{})
		tracer.LogFinding(ctx, nil, &FindingLog{})
		tracer.LogMemoryOp(ctx, nil, &MemoryOpLog{})
		tracer.LogGraphOp(ctx, nil, &GraphOpLog{})
		tracer.EndMissionTrace(ctx, nil, nil)
	})
}
