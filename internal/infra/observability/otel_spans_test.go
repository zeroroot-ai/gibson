package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// setupTestTracer creates a test tracer with in-memory span recorder
func setupTestTracer() (*trace.TracerProvider, *tracetest.SpanRecorder) {
	spanRecorder := tracetest.NewSpanRecorder()
	tp := trace.NewTracerProvider(
		trace.WithSpanProcessor(spanRecorder),
	)
	otel.SetTracerProvider(tp)
	return tp, spanRecorder
}

func TestMissionSpan_Basic(t *testing.T) {
	tp, spanRecorder := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx := context.Background()

	// Start a mission span
	missionID := types.NewID()
	ctx, span := tracer.Start(ctx, "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: missionID,
		StartTime: time.Now(),
	}

	// Verify basic accessors
	assert.Equal(t, ctx, missionSpan.Context())
	assert.Equal(t, span, missionSpan.Span())
	assert.Equal(t, missionID, missionSpan.MissionID)

	// End the span
	missionSpan.End(codes.Ok, "Mission completed successfully")

	// Verify span was recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "mission-test", spans[0].Name())
	// The OTel SDK only stores Description for codes.Error; for codes.Ok it is
	// silently discarded. Assert only the code.
	assert.Equal(t, codes.Ok, spans[0].Status().Code)
}

func TestMissionSpan_AddDecision(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add decisions
	missionSpan.AddDecision()
	missionSpan.AddDecision()
	missionSpan.AddDecision()

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 3, stats.TotalDecisions)
}

func TestMissionSpan_AddExecution(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add executions
	missionSpan.AddExecution()
	missionSpan.AddExecution()

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 2, stats.TotalExecutions)
}

func TestMissionSpan_AddToolCall(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add tool calls
	missionSpan.AddToolCall()
	missionSpan.AddToolCall()
	missionSpan.AddToolCall()
	missionSpan.AddToolCall()

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 4, stats.TotalToolCalls)
}

func TestMissionSpan_AddLLMCall(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add LLM calls with tokens and costs
	missionSpan.AddLLMCall(1000, 0.02)
	missionSpan.AddLLMCall(1500, 0.03)
	missionSpan.AddLLMCall(2000, 0.04)

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 3, stats.TotalLLMCalls)
	assert.Equal(t, 4500, stats.TotalTokens)
	assert.InDelta(t, 0.09, stats.TotalCostUSD, 0.001)
}

func TestMissionSpan_AddFinding(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add findings
	missionSpan.AddFinding()
	missionSpan.AddFinding()

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 2, stats.TotalFindings)
}

func TestMissionSpan_AddMemoryOp(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add memory operations
	missionSpan.AddMemoryOp()
	missionSpan.AddMemoryOp()
	missionSpan.AddMemoryOp()

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 3, stats.TotalMemoryOps)
}

func TestMissionSpan_AddGraphOp(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Add graph operations
	missionSpan.AddGraphOp(5, 3)
	missionSpan.AddGraphOp(10, 7)

	stats := missionSpan.GetStatistics()
	assert.Equal(t, 2, stats.TotalGraphOps)
	assert.Equal(t, 15, stats.GraphNodesCreated)
	assert.Equal(t, 10, stats.GraphRelsCreated)
}

func TestMissionSpan_GetStatistics(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	startTime := time.Now()
	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: startTime,
	}

	// Add various operations
	missionSpan.AddDecision()
	missionSpan.AddExecution()
	missionSpan.AddToolCall()
	missionSpan.AddLLMCall(1000, 0.02)
	missionSpan.AddFinding()
	missionSpan.AddMemoryOp()
	missionSpan.AddGraphOp(5, 3)

	// Get statistics
	stats := missionSpan.GetStatistics()
	assert.Equal(t, 1, stats.TotalDecisions)
	assert.Equal(t, 1, stats.TotalExecutions)
	assert.Equal(t, 1, stats.TotalToolCalls)
	assert.Equal(t, 1, stats.TotalLLMCalls)
	assert.Equal(t, 1000, stats.TotalTokens)
	assert.InDelta(t, 0.02, stats.TotalCostUSD, 0.001)
	assert.Equal(t, 1, stats.TotalFindings)
	assert.Equal(t, 1, stats.TotalMemoryOps)
	assert.Equal(t, 1, stats.TotalGraphOps)
	assert.Equal(t, 5, stats.GraphNodesCreated)
	assert.Equal(t, 3, stats.GraphRelsCreated)
	assert.Greater(t, stats.Duration, time.Duration(0))
}

func TestMissionSpan_ThreadSafety(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(5)

		go func() {
			defer wg.Done()
			missionSpan.AddDecision()
		}()

		go func() {
			defer wg.Done()
			missionSpan.AddToolCall()
		}()

		go func() {
			defer wg.Done()
			missionSpan.AddLLMCall(100, 0.001)
		}()

		go func() {
			defer wg.Done()
			missionSpan.AddFinding()
		}()

		go func() {
			defer wg.Done()
			missionSpan.AddGraphOp(1, 1)
		}()
	}

	wg.Wait()

	// Verify all operations were counted
	stats := missionSpan.GetStatistics()
	assert.Equal(t, 10, stats.TotalDecisions)
	assert.Equal(t, 10, stats.TotalToolCalls)
	assert.Equal(t, 10, stats.TotalLLMCalls)
	assert.Equal(t, 1000, stats.TotalTokens)
	assert.InDelta(t, 0.01, stats.TotalCostUSD, 0.001)
	assert.Equal(t, 10, stats.TotalFindings)
	assert.Equal(t, 10, stats.TotalGraphOps)
	assert.Equal(t, 10, stats.GraphNodesCreated)
	assert.Equal(t, 10, stats.GraphRelsCreated)
}

func TestAgentSpan_Basic(t *testing.T) {
	tp, spanRecorder := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx := context.Background()

	// Start an agent span
	executionID := types.NewID()
	ctx, span := tracer.Start(ctx, "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: executionID,
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Verify basic accessors
	assert.Equal(t, ctx, agentSpan.Context())
	assert.Equal(t, span, agentSpan.Span())
	assert.Equal(t, executionID, agentSpan.ExecutionID)
	assert.Equal(t, "test-agent", agentSpan.AgentName)

	// End the span
	agentSpan.End(codes.Ok, "Agent execution completed")

	// Verify span was recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)
	assert.Equal(t, "agent-test", spans[0].Name())
	// The OTel SDK only stores Description for codes.Error; for codes.Ok it is
	// silently discarded. Assert only the code.
	assert.Equal(t, codes.Ok, spans[0].Status().Code)
}

func TestAgentSpan_AddToolCall(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Add tool calls
	agentSpan.AddToolCall()
	agentSpan.AddToolCall()

	stats := agentSpan.GetStatistics()
	assert.Equal(t, 2, stats.ToolCalls)
}

func TestAgentSpan_AddLLMCall(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Add LLM calls
	agentSpan.AddLLMCall(500, 0.01)
	agentSpan.AddLLMCall(750, 0.015)

	stats := agentSpan.GetStatistics()
	assert.Equal(t, 2, stats.LLMCalls)
	assert.Equal(t, 1250, stats.TokensUsed)
	assert.InDelta(t, 0.025, stats.CostUSD, 0.001)
}

func TestAgentSpan_AddFinding(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Add findings
	agentSpan.AddFinding()
	agentSpan.AddFinding()
	agentSpan.AddFinding()

	stats := agentSpan.GetStatistics()
	assert.Equal(t, 3, stats.FindingsCount)
}

func TestAgentSpan_AddMemoryOp(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Add memory operations
	agentSpan.AddMemoryOp()

	stats := agentSpan.GetStatistics()
	assert.Equal(t, 1, stats.MemoryOps)
}

func TestAgentSpan_GetStatistics(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	startTime := time.Now()
	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   startTime,
	}

	// Add various operations
	agentSpan.AddToolCall()
	agentSpan.AddLLMCall(500, 0.01)
	agentSpan.AddFinding()
	agentSpan.AddMemoryOp()

	// Get statistics
	stats := agentSpan.GetStatistics()
	assert.Equal(t, 1, stats.ToolCalls)
	assert.Equal(t, 1, stats.LLMCalls)
	assert.Equal(t, 500, stats.TokensUsed)
	assert.InDelta(t, 0.01, stats.CostUSD, 0.001)
	assert.Equal(t, 1, stats.FindingsCount)
	assert.Equal(t, 1, stats.MemoryOps)
	assert.Greater(t, stats.Duration, time.Duration(0))
}

func TestAgentSpan_ThreadSafety(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(4)

		go func() {
			defer wg.Done()
			agentSpan.AddToolCall()
		}()

		go func() {
			defer wg.Done()
			agentSpan.AddLLMCall(100, 0.001)
		}()

		go func() {
			defer wg.Done()
			agentSpan.AddFinding()
		}()

		go func() {
			defer wg.Done()
			agentSpan.AddMemoryOp()
		}()
	}

	wg.Wait()

	// Verify all operations were counted
	stats := agentSpan.GetStatistics()
	assert.Equal(t, 10, stats.ToolCalls)
	assert.Equal(t, 10, stats.LLMCalls)
	assert.Equal(t, 1000, stats.TokensUsed)
	assert.InDelta(t, 0.01, stats.CostUSD, 0.001)
	assert.Equal(t, 10, stats.FindingsCount)
	assert.Equal(t, 10, stats.MemoryOps)
}

func TestAgentSpan_PropagateToParent(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create parent mission span
	missionCtx, missionSpan := tracer.Start(context.Background(), "mission-test")
	missionWrapper := &MissionSpan{
		span:      missionSpan,
		ctx:       missionCtx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Create child agent span with parent reference
	agentCtx, agentSpan := tracer.Start(missionCtx, "agent-test")
	agentWrapper := &AgentSpan{
		span:        agentSpan,
		ctx:         agentCtx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
		parent:      missionWrapper,
	}

	// Add statistics to agent span
	agentWrapper.AddToolCall()
	agentWrapper.AddToolCall()
	agentWrapper.AddLLMCall(500, 0.01)
	agentWrapper.AddLLMCall(750, 0.015)
	agentWrapper.AddFinding()
	agentWrapper.AddMemoryOp()

	// End agent span (should propagate to parent)
	agentWrapper.End(codes.Ok, "Agent execution completed")

	// Verify parent has accumulated the statistics
	missionStats := missionWrapper.GetStatistics()
	assert.Equal(t, 2, missionStats.TotalToolCalls)
	assert.Equal(t, 2, missionStats.TotalLLMCalls)
	assert.Equal(t, 1250, missionStats.TotalTokens)
	assert.InDelta(t, 0.025, missionStats.TotalCostUSD, 0.001)
	assert.Equal(t, 1, missionStats.TotalFindings)
	assert.Equal(t, 1, missionStats.TotalMemoryOps)
}

func TestAgentSpan_PropagateToParentThreadSafe(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create parent mission span
	missionCtx, missionSpan := tracer.Start(context.Background(), "mission-test")
	missionWrapper := &MissionSpan{
		span:      missionSpan,
		ctx:       missionCtx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Create multiple agent spans concurrently
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			agentCtx, agentSpan := tracer.Start(missionCtx, "agent-test")
			agentWrapper := &AgentSpan{
				span:        agentSpan,
				ctx:         agentCtx,
				ExecutionID: types.NewID(),
				AgentName:   "test-agent",
				StartTime:   time.Now(),
				parent:      missionWrapper,
			}

			// Add some statistics
			agentWrapper.AddToolCall()
			agentWrapper.AddLLMCall(100, 0.001)
			agentWrapper.AddFinding()

			// End span to propagate
			agentWrapper.End(codes.Ok, "completed")
		}()
	}

	wg.Wait()

	// Verify parent has accumulated all statistics
	missionStats := missionWrapper.GetStatistics()
	assert.Equal(t, 10, missionStats.TotalToolCalls)
	assert.Equal(t, 10, missionStats.TotalLLMCalls)
	assert.Equal(t, 1000, missionStats.TotalTokens)
	assert.InDelta(t, 0.01, missionStats.TotalCostUSD, 0.001)
	assert.Equal(t, 10, missionStats.TotalFindings)
}

func TestAgentSpan_NilParent(t *testing.T) {
	tp, _ := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")

	// Create agent span without parent
	ctx, span := tracer.Start(context.Background(), "agent-test")
	agentWrapper := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
		parent:      nil, // No parent
	}

	// Add statistics
	agentWrapper.AddToolCall()
	agentWrapper.AddLLMCall(100, 0.001)

	// End span (should not panic with nil parent)
	assert.NotPanics(t, func() {
		agentWrapper.End(codes.Ok, "completed")
	})
}

func TestMissionSpan_End_RecordsAttributes(t *testing.T) {
	tp, spanRecorder := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionID := types.NewID()
	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: missionID,
		StartTime: time.Now(),
	}

	// Add some statistics
	missionSpan.AddDecision()
	missionSpan.AddExecution()
	missionSpan.AddToolCall()
	missionSpan.AddLLMCall(1000, 0.02)
	missionSpan.AddFinding()
	missionSpan.AddMemoryOp()
	missionSpan.AddGraphOp(5, 3)

	// End the span
	missionSpan.End(codes.Ok, "Mission completed")

	// Verify attributes were recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	attrs := spans[0].Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, missionID.String(), attrMap["gibson.mission.id"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.decisions"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.executions"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.tool_calls"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.llm_calls"])
	assert.Equal(t, int64(1000), attrMap["gibson.mission.total_tokens"])
	assert.InDelta(t, 0.02, attrMap["gibson.mission.total_cost_usd"], 0.001)
	assert.Equal(t, int64(1), attrMap["gibson.mission.findings"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.memory_ops"])
	assert.Equal(t, int64(1), attrMap["gibson.mission.graph_ops"])
	assert.Equal(t, int64(5), attrMap["gibson.mission.graph_nodes_created"])
	assert.Equal(t, int64(3), attrMap["gibson.mission.graph_rels_created"])
	assert.NotEmpty(t, attrMap["gibson.mission.duration"])
}

func TestAgentSpan_End_RecordsAttributes(t *testing.T) {
	tp, spanRecorder := setupTestTracer()
	defer tp.Shutdown(context.Background())

	tracer := tp.Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	executionID := types.NewID()
	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: executionID,
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Add some statistics
	agentSpan.AddToolCall()
	agentSpan.AddLLMCall(500, 0.01)
	agentSpan.AddFinding()
	agentSpan.AddMemoryOp()

	// End the span
	agentSpan.End(codes.Ok, "Agent execution completed")

	// Verify attributes were recorded
	spans := spanRecorder.Ended()
	require.Len(t, spans, 1)

	attrs := spans[0].Attributes()
	attrMap := make(map[string]interface{})
	for _, attr := range attrs {
		attrMap[string(attr.Key)] = attr.Value.AsInterface()
	}

	assert.Equal(t, executionID.String(), attrMap["gibson.agent.execution_id"])
	assert.Equal(t, "test-agent", attrMap["gibson.agent.name"])
	assert.Equal(t, int64(1), attrMap["gibson.agent.tool_calls"])
	assert.Equal(t, int64(1), attrMap["gibson.agent.llm_calls"])
	assert.Equal(t, int64(500), attrMap["gibson.agent.tokens_used"])
	assert.InDelta(t, 0.01, attrMap["gibson.agent.cost_usd"], 0.001)
	assert.Equal(t, int64(1), attrMap["gibson.agent.findings"])
	assert.Equal(t, int64(1), attrMap["gibson.agent.memory_ops"])
	assert.NotEmpty(t, attrMap["gibson.agent.duration"])
}
