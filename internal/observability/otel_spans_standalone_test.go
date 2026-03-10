package observability

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestMissionSpan_Standalone tests MissionSpan without external dependencies
func TestMissionSpan_Standalone(t *testing.T) {
	// Use noop tracer to avoid protobuf conflicts
	tracer := noop.NewTracerProvider().Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionID := types.NewID()
	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: missionID,
		StartTime: time.Now(),
	}

	// Test basic accessors
	if missionSpan.Context() != ctx {
		t.Error("Context() returned wrong context")
	}
	if missionSpan.Span() != span {
		t.Error("Span() returned wrong span")
	}

	// Test statistics accumulation
	missionSpan.AddDecision()
	missionSpan.AddDecision()
	missionSpan.AddExecution()
	missionSpan.AddToolCall()
	missionSpan.AddToolCall()
	missionSpan.AddToolCall()
	missionSpan.AddLLMCall(1000, 0.02)
	missionSpan.AddLLMCall(1500, 0.03)
	missionSpan.AddFinding()
	missionSpan.AddMemoryOp()
	missionSpan.AddMemoryOp()
	missionSpan.AddGraphOp(5, 3)
	missionSpan.AddGraphOp(10, 7)

	stats := missionSpan.GetStatistics()
	if stats.TotalDecisions != 2 {
		t.Errorf("Expected 2 decisions, got %d", stats.TotalDecisions)
	}
	if stats.TotalExecutions != 1 {
		t.Errorf("Expected 1 execution, got %d", stats.TotalExecutions)
	}
	if stats.TotalToolCalls != 3 {
		t.Errorf("Expected 3 tool calls, got %d", stats.TotalToolCalls)
	}
	if stats.TotalLLMCalls != 2 {
		t.Errorf("Expected 2 LLM calls, got %d", stats.TotalLLMCalls)
	}
	if stats.TotalTokens != 2500 {
		t.Errorf("Expected 2500 tokens, got %d", stats.TotalTokens)
	}
	if stats.TotalCostUSD < 0.049 || stats.TotalCostUSD > 0.051 {
		t.Errorf("Expected ~0.05 cost, got %f", stats.TotalCostUSD)
	}
	if stats.TotalFindings != 1 {
		t.Errorf("Expected 1 finding, got %d", stats.TotalFindings)
	}
	if stats.TotalMemoryOps != 2 {
		t.Errorf("Expected 2 memory ops, got %d", stats.TotalMemoryOps)
	}
	if stats.TotalGraphOps != 2 {
		t.Errorf("Expected 2 graph ops, got %d", stats.TotalGraphOps)
	}
	if stats.GraphNodesCreated != 15 {
		t.Errorf("Expected 15 nodes created, got %d", stats.GraphNodesCreated)
	}
	if stats.GraphRelsCreated != 10 {
		t.Errorf("Expected 10 rels created, got %d", stats.GraphRelsCreated)
	}
	if stats.Duration <= 0 {
		t.Error("Duration should be greater than 0")
	}

	// Test End
	missionSpan.End(codes.Ok, "Mission completed")
	t.Log("MissionSpan test passed")
}

// TestAgentSpan_Standalone tests AgentSpan without external dependencies
func TestAgentSpan_Standalone(t *testing.T) {
	// Use noop tracer to avoid protobuf conflicts
	tracer := noop.NewTracerProvider().Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	executionID := types.NewID()
	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: executionID,
		AgentName:   "test-agent",
		StartTime:   time.Now(),
	}

	// Test basic accessors
	if agentSpan.Context() != ctx {
		t.Error("Context() returned wrong context")
	}
	if agentSpan.Span() != span {
		t.Error("Span() returned wrong span")
	}

	// Test statistics accumulation
	agentSpan.AddToolCall()
	agentSpan.AddToolCall()
	agentSpan.AddLLMCall(500, 0.01)
	agentSpan.AddLLMCall(750, 0.015)
	agentSpan.AddFinding()
	agentSpan.AddFinding()
	agentSpan.AddMemoryOp()

	stats := agentSpan.GetStatistics()
	if stats.ToolCalls != 2 {
		t.Errorf("Expected 2 tool calls, got %d", stats.ToolCalls)
	}
	if stats.LLMCalls != 2 {
		t.Errorf("Expected 2 LLM calls, got %d", stats.LLMCalls)
	}
	if stats.TokensUsed != 1250 {
		t.Errorf("Expected 1250 tokens, got %d", stats.TokensUsed)
	}
	if stats.CostUSD < 0.024 || stats.CostUSD > 0.026 {
		t.Errorf("Expected ~0.025 cost, got %f", stats.CostUSD)
	}
	if stats.FindingsCount != 2 {
		t.Errorf("Expected 2 findings, got %d", stats.FindingsCount)
	}
	if stats.MemoryOps != 1 {
		t.Errorf("Expected 1 memory op, got %d", stats.MemoryOps)
	}
	if stats.Duration <= 0 {
		t.Error("Duration should be greater than 0")
	}

	// Test End
	agentSpan.End(codes.Ok, "Agent execution completed")
	t.Log("AgentSpan test passed")
}

// TestAgentSpan_PropagationToParent tests statistics propagation
func TestAgentSpan_PropagationToParent(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")

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
	if missionStats.TotalToolCalls != 2 {
		t.Errorf("Expected 2 tool calls in parent, got %d", missionStats.TotalToolCalls)
	}
	if missionStats.TotalLLMCalls != 2 {
		t.Errorf("Expected 2 LLM calls in parent, got %d", missionStats.TotalLLMCalls)
	}
	if missionStats.TotalTokens != 1250 {
		t.Errorf("Expected 1250 tokens in parent, got %d", missionStats.TotalTokens)
	}
	if missionStats.TotalCostUSD < 0.024 || missionStats.TotalCostUSD > 0.026 {
		t.Errorf("Expected ~0.025 cost in parent, got %f", missionStats.TotalCostUSD)
	}
	if missionStats.TotalFindings != 1 {
		t.Errorf("Expected 1 finding in parent, got %d", missionStats.TotalFindings)
	}
	if missionStats.TotalMemoryOps != 1 {
		t.Errorf("Expected 1 memory op in parent, got %d", missionStats.TotalMemoryOps)
	}

	t.Log("Statistics propagation test passed")
}

// TestThreadSafety tests concurrent access to span statistics
func TestThreadSafety(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")
	ctx, span := tracer.Start(context.Background(), "mission-test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Run concurrent operations
	var wg sync.WaitGroup
	iterations := 100

	wg.Add(iterations * 5)
	for i := 0; i < iterations; i++ {
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
			missionSpan.AddLLMCall(10, 0.001)
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

	// Verify all operations were counted correctly
	stats := missionSpan.GetStatistics()
	if stats.TotalDecisions != iterations {
		t.Errorf("Expected %d decisions, got %d", iterations, stats.TotalDecisions)
	}
	if stats.TotalToolCalls != iterations {
		t.Errorf("Expected %d tool calls, got %d", iterations, stats.TotalToolCalls)
	}
	if stats.TotalLLMCalls != iterations {
		t.Errorf("Expected %d LLM calls, got %d", iterations, stats.TotalLLMCalls)
	}
	if stats.TotalTokens != iterations*10 {
		t.Errorf("Expected %d tokens, got %d", iterations*10, stats.TotalTokens)
	}
	if stats.TotalFindings != iterations {
		t.Errorf("Expected %d findings, got %d", iterations, stats.TotalFindings)
	}
	if stats.TotalGraphOps != iterations {
		t.Errorf("Expected %d graph ops, got %d", iterations, stats.TotalGraphOps)
	}

	t.Log("Thread safety test passed")
}

// TestAgentSpan_NilParentStandalone tests that ending an agent span with nil parent doesn't panic
func TestAgentSpan_NilParentStandalone(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")
	ctx, span := tracer.Start(context.Background(), "agent-test")

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test-agent",
		StartTime:   time.Now(),
		parent:      nil, // No parent
	}

	// Add statistics
	agentSpan.AddToolCall()
	agentSpan.AddLLMCall(100, 0.001)

	// End span (should not panic with nil parent)
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("End() panicked with nil parent: %v", r)
		}
	}()

	agentSpan.End(codes.Ok, "completed")
	t.Log("Nil parent test passed")
}

// TestMultipleAgentsPropagation tests multiple agents propagating to same parent
func TestMultipleAgentsPropagation(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")

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
	numAgents := 10

	for i := 0; i < numAgents; i++ {
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

	// Verify parent has accumulated all statistics from all agents
	missionStats := missionWrapper.GetStatistics()
	if missionStats.TotalToolCalls != numAgents {
		t.Errorf("Expected %d tool calls in parent, got %d", numAgents, missionStats.TotalToolCalls)
	}
	if missionStats.TotalLLMCalls != numAgents {
		t.Errorf("Expected %d LLM calls in parent, got %d", numAgents, missionStats.TotalLLMCalls)
	}
	if missionStats.TotalTokens != numAgents*100 {
		t.Errorf("Expected %d tokens in parent, got %d", numAgents*100, missionStats.TotalTokens)
	}
	if missionStats.TotalFindings != numAgents {
		t.Errorf("Expected %d findings in parent, got %d", numAgents, missionStats.TotalFindings)
	}

	t.Log("Multiple agents propagation test passed")
}

// TestSpanInterfaceCompatibility verifies that our wrappers work with trace.Span interface
func TestSpanInterfaceCompatibility(t *testing.T) {
	tracer := noop.NewTracerProvider().Tracer("test")
	ctx, span := tracer.Start(context.Background(), "test")

	missionSpan := &MissionSpan{
		span:      span,
		ctx:       ctx,
		MissionID: types.NewID(),
		StartTime: time.Now(),
	}

	// Verify we can use it as a trace.Span
	var _ trace.Span = missionSpan.Span()

	agentSpan := &AgentSpan{
		span:        span,
		ctx:         ctx,
		ExecutionID: types.NewID(),
		AgentName:   "test",
		StartTime:   time.Now(),
	}

	// Verify we can use it as a trace.Span
	var _ trace.Span = agentSpan.Span()

	t.Log("Span interface compatibility test passed")
}
