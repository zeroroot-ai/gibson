package observability

import (
	"context"
	"sync"
	"time"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// MissionSpan wraps an OpenTelemetry span for mission-level tracing.
// It provides a thread-safe way to track mission-wide statistics and events
// across all agent executions within the mission.
//
// The span automatically aggregates statistics from child AgentSpan instances
// and provides methods for incrementing various counters during mission execution.
//
// All methods are thread-safe and can be called concurrently from multiple goroutines.
type MissionSpan struct {
	span      trace.Span
	ctx       context.Context
	MissionID types.ID
	StartTime time.Time

	// Statistics accumulated during mission execution
	// Protected by mu for thread-safe access
	mu                sync.Mutex
	TotalDecisions    int
	TotalExecutions   int
	TotalToolCalls    int
	TotalLLMCalls     int
	TotalTokens       int
	TotalCostUSD      float64
	TotalFindings     int
	TotalMemoryOps    int
	TotalGraphOps     int
	GraphNodesCreated int
	GraphRelsCreated  int
}

// AgentSpan wraps an OpenTelemetry span for agent-level tracing.
// It provides a thread-safe way to track statistics for a single agent execution
// and automatically propagates these statistics to its parent MissionSpan when ended.
//
// Each AgentSpan represents one agent execution within a mission and maintains
// its own counters for tools, LLM calls, tokens, costs, findings, and memory operations.
//
// All methods are thread-safe and can be called concurrently from multiple goroutines.
type AgentSpan struct {
	span        trace.Span
	ctx         context.Context
	ExecutionID types.ID
	AgentName   string
	StartTime   time.Time
	parent      *MissionSpan // Reference to parent for statistics propagation

	// Statistics for this execution
	// Protected by mu for thread-safe access
	mu            sync.Mutex
	ToolCalls     int
	LLMCalls      int
	TokensUsed    int
	CostUSD       float64
	FindingsCount int
	MemoryOps     int
}

// MissionStatistics provides a snapshot of mission-level statistics.
// This structure is returned by MissionSpan.GetStatistics() and represents
// all accumulated statistics at the time of the call.
type MissionStatistics struct {
	TotalDecisions    int           // Number of orchestrator decisions made
	TotalExecutions   int           // Number of agent executions performed
	TotalToolCalls    int           // Total number of tool invocations across all agents
	TotalLLMCalls     int           // Total number of LLM calls across all agents
	TotalTokens       int           // Total tokens consumed across all LLM calls
	TotalCostUSD      float64       // Total estimated cost in USD
	TotalFindings     int           // Total number of findings submitted
	TotalMemoryOps    int           // Total number of memory read/write operations
	TotalGraphOps     int           // Total number of graph operations
	GraphNodesCreated int           // Total number of graph nodes created
	GraphRelsCreated  int           // Total number of graph relationships created
	Duration          time.Duration // Time elapsed since mission start
}

// AgentStatistics provides a snapshot of agent-level statistics.
// This structure is returned by AgentSpan.GetStatistics() and represents
// all accumulated statistics for a single agent execution.
type AgentStatistics struct {
	ToolCalls     int           // Number of tool invocations during this execution
	LLMCalls      int           // Number of LLM calls during this execution
	TokensUsed    int           // Total tokens consumed during this execution
	CostUSD       float64       // Estimated cost in USD for this execution
	FindingsCount int           // Number of findings submitted during this execution
	MemoryOps     int           // Number of memory operations during this execution
	Duration      time.Duration // Time elapsed since execution start
}

// Context returns the context containing the span for propagation.
// This context should be used for downstream operations to maintain trace continuity.
func (ms *MissionSpan) Context() context.Context {
	return ms.ctx
}

// Span returns the underlying OpenTelemetry span.
// This allows direct access to the span for advanced operations.
func (ms *MissionSpan) Span() trace.Span {
	return ms.span
}

// End finalizes the mission span with the given status and description.
// It records all accumulated statistics as span attributes and ends the underlying span.
//
// Parameters:
//   - status: The final status code (OK, Error, or Unset)
//   - description: A human-readable description of the final status
//
// This method is thread-safe and can be called once per span.
func (ms *MissionSpan) End(status codes.Code, description string) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	// Set span status
	ms.span.SetStatus(status, description)

	// Record all mission statistics as span attributes
	ms.span.SetAttributes(
		attribute.String("gibson.mission.id", ms.MissionID.String()),
		attribute.Int("gibson.mission.decisions", ms.TotalDecisions),
		attribute.Int("gibson.mission.executions", ms.TotalExecutions),
		attribute.Int("gibson.mission.tool_calls", ms.TotalToolCalls),
		attribute.Int("gibson.mission.llm_calls", ms.TotalLLMCalls),
		attribute.Int("gibson.mission.total_tokens", ms.TotalTokens),
		attribute.Float64("gibson.mission.total_cost_usd", ms.TotalCostUSD),
		attribute.Int("gibson.mission.findings", ms.TotalFindings),
		attribute.Int("gibson.mission.memory_ops", ms.TotalMemoryOps),
		attribute.Int("gibson.mission.graph_ops", ms.TotalGraphOps),
		attribute.Int("gibson.mission.graph_nodes_created", ms.GraphNodesCreated),
		attribute.Int("gibson.mission.graph_rels_created", ms.GraphRelsCreated),
		attribute.String("gibson.mission.duration", time.Since(ms.StartTime).String()),
	)

	// End the underlying span
	ms.span.End()
}

// AddDecision increments the decision counter.
// This should be called each time the orchestrator makes a decision.
//
// This method is thread-safe.
func (ms *MissionSpan) AddDecision() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalDecisions++
}

// AddExecution increments the execution counter.
// This should be called each time an agent execution begins.
//
// This method is thread-safe.
func (ms *MissionSpan) AddExecution() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalExecutions++
}

// AddToolCall increments the tool call counter.
// This should be called each time a tool is invoked at the mission level.
//
// This method is thread-safe.
func (ms *MissionSpan) AddToolCall() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalToolCalls++
}

// AddLLMCall records an LLM call with token usage and cost.
// This should be called each time an LLM is invoked at the mission level.
//
// Parameters:
//   - tokens: Number of tokens consumed by the LLM call
//   - cost: Estimated cost in USD for the LLM call
//
// This method is thread-safe.
func (ms *MissionSpan) AddLLMCall(tokens int, cost float64) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalLLMCalls++
	ms.TotalTokens += tokens
	ms.TotalCostUSD += cost
}

// AddFinding increments the finding counter.
// This should be called each time a finding is submitted.
//
// This method is thread-safe.
func (ms *MissionSpan) AddFinding() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalFindings++
}

// AddMemoryOp increments the memory operations counter.
// This should be called each time a memory read or write operation occurs.
//
// This method is thread-safe.
func (ms *MissionSpan) AddMemoryOp() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalMemoryOps++
}

// AddGraphOp records a graph operation with node and relationship counts.
// This should be called each time a graph operation is performed.
//
// Parameters:
//   - nodesCreated: Number of graph nodes created
//   - relsCreated: Number of graph relationships created
//
// This method is thread-safe.
func (ms *MissionSpan) AddGraphOp(nodesCreated, relsCreated int) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.TotalGraphOps++
	ms.GraphNodesCreated += nodesCreated
	ms.GraphRelsCreated += relsCreated
}

// GetStatistics returns a snapshot of current mission statistics.
// The returned statistics are a copy and will not be updated after return.
//
// This method is thread-safe and can be called at any time during mission execution.
func (ms *MissionSpan) GetStatistics() MissionStatistics {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	return MissionStatistics{
		TotalDecisions:    ms.TotalDecisions,
		TotalExecutions:   ms.TotalExecutions,
		TotalToolCalls:    ms.TotalToolCalls,
		TotalLLMCalls:     ms.TotalLLMCalls,
		TotalTokens:       ms.TotalTokens,
		TotalCostUSD:      ms.TotalCostUSD,
		TotalFindings:     ms.TotalFindings,
		TotalMemoryOps:    ms.TotalMemoryOps,
		TotalGraphOps:     ms.TotalGraphOps,
		GraphNodesCreated: ms.GraphNodesCreated,
		GraphRelsCreated:  ms.GraphRelsCreated,
		Duration:          time.Since(ms.StartTime),
	}
}

// Context returns the context containing the span for propagation.
// This context should be used for downstream operations to maintain trace continuity.
func (as *AgentSpan) Context() context.Context {
	return as.ctx
}

// Span returns the underlying OpenTelemetry span.
// This allows direct access to the span for advanced operations.
func (as *AgentSpan) Span() trace.Span {
	return as.span
}

// End finalizes the agent span with the given status and description.
// It records all accumulated statistics as span attributes, propagates the statistics
// to the parent MissionSpan (if present), and ends the underlying span.
//
// Parameters:
//   - status: The final status code (OK, Error, or Unset)
//   - description: A human-readable description of the final status
//
// This method is thread-safe and can be called once per span.
func (as *AgentSpan) End(status codes.Code, description string) {
	as.mu.Lock()
	defer as.mu.Unlock()

	// Set span status
	as.span.SetStatus(status, description)

	// Record all agent statistics as span attributes
	as.span.SetAttributes(
		attribute.String("gibson.agent.execution_id", as.ExecutionID.String()),
		attribute.String("gibson.agent.name", as.AgentName),
		attribute.Int("gibson.agent.tool_calls", as.ToolCalls),
		attribute.Int("gibson.agent.llm_calls", as.LLMCalls),
		attribute.Int("gibson.agent.tokens_used", as.TokensUsed),
		attribute.Float64("gibson.agent.cost_usd", as.CostUSD),
		attribute.Int("gibson.agent.findings", as.FindingsCount),
		attribute.Int("gibson.agent.memory_ops", as.MemoryOps),
		attribute.String("gibson.agent.duration", time.Since(as.StartTime).String()),
	)

	// Propagate statistics to parent mission span if present
	if as.parent != nil {
		as.parent.mu.Lock()
		as.parent.TotalToolCalls += as.ToolCalls
		as.parent.TotalLLMCalls += as.LLMCalls
		as.parent.TotalTokens += as.TokensUsed
		as.parent.TotalCostUSD += as.CostUSD
		as.parent.TotalFindings += as.FindingsCount
		as.parent.TotalMemoryOps += as.MemoryOps
		as.parent.mu.Unlock()
	}

	// End the underlying span
	as.span.End()
}

// AddToolCall increments the tool call counter.
// This should be called each time a tool is invoked during this agent execution.
//
// This method is thread-safe.
func (as *AgentSpan) AddToolCall() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.ToolCalls++
}

// AddLLMCall records an LLM call with token usage and cost.
// This should be called each time an LLM is invoked during this agent execution.
//
// Parameters:
//   - tokens: Number of tokens consumed by the LLM call
//   - cost: Estimated cost in USD for the LLM call
//
// This method is thread-safe.
func (as *AgentSpan) AddLLMCall(tokens int, cost float64) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.LLMCalls++
	as.TokensUsed += tokens
	as.CostUSD += cost
}

// AddFinding increments the finding counter.
// This should be called each time a finding is submitted during this agent execution.
//
// This method is thread-safe.
func (as *AgentSpan) AddFinding() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.FindingsCount++
}

// AddMemoryOp increments the memory operations counter.
// This should be called each time a memory read or write operation occurs
// during this agent execution.
//
// This method is thread-safe.
func (as *AgentSpan) AddMemoryOp() {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.MemoryOps++
}

// GetStatistics returns a snapshot of current agent statistics.
// The returned statistics are a copy and will not be updated after return.
//
// This method is thread-safe and can be called at any time during agent execution.
func (as *AgentSpan) GetStatistics() AgentStatistics {
	as.mu.Lock()
	defer as.mu.Unlock()

	return AgentStatistics{
		ToolCalls:     as.ToolCalls,
		LLMCalls:      as.LLMCalls,
		TokensUsed:    as.TokensUsed,
		CostUSD:       as.CostUSD,
		FindingsCount: as.FindingsCount,
		MemoryOps:     as.MemoryOps,
		Duration:      time.Since(as.StartTime),
	}
}
