package observability

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/orchestrator"
	"github.com/zero-day-ai/gibson/internal/types"
)

// OTelDecisionLogWriterAdapter adapts the orchestrator's DecisionLogWriter interface
// to the OTelMissionTracer implementation. It bridges orchestrator decisions
// and actions to OpenTelemetry traces without creating Langfuse API calls.
//
// Thread Safety: All methods are thread-safe and use fire-and-forget error handling.
// Tracing errors are logged but never propagate to the orchestrator to ensure
// mission execution is never blocked by observability failures.
//
// Usage:
//
//	tracer := NewOTelMissionTracer(tp, mp, contentConfig)
//	adapter, _ := NewOTelDecisionLogWriterAdapter(ctx, tracer, mission)
//	defer adapter.Close(ctx, summary)
//
//	// Pass to orchestrator
//	orch := orchestrator.NewOrchestrator(...,
//		orchestrator.WithDecisionLogWriter(adapter))
type OTelDecisionLogWriterAdapter struct {
	tracer      *OTelMissionTracer
	missionSpan *MissionSpan
	agentSpans  map[string]*AgentSpan // Maps execution ID to AgentSpan
	mu          sync.RWMutex          // Protects agentSpans map
	ctx         context.Context       // Root context for the mission
	missionID   string
	missionName string
}

// NewOTelDecisionLogWriterAdapter creates a new adapter that wraps an OTelMissionTracer.
// It immediately starts a mission trace in OpenTelemetry and returns the adapter
// with the mission span context.
//
// Parameters:
//   - ctx: Context for the trace creation
//   - tracer: The OTelMissionTracer to delegate to (must not be nil)
//   - mission: The mission being traced (must not be nil)
//
// Returns:
//   - *OTelDecisionLogWriterAdapter: The initialized adapter
//   - error: Any error encountered during trace creation
//
// The adapter uses fire-and-forget error handling internally, but returns errors
// during construction so callers can decide whether to proceed without tracing.
func NewOTelDecisionLogWriterAdapter(ctx context.Context, tracer *OTelMissionTracer, mission *schema.Mission) (*OTelDecisionLogWriterAdapter, error) {
	if tracer == nil {
		return nil, fmt.Errorf("tracer cannot be nil")
	}
	if mission == nil {
		return nil, fmt.Errorf("mission cannot be nil")
	}

	// Start the mission trace in OpenTelemetry
	missionCtx, missionSpan, err := tracer.StartMissionTrace(ctx, mission)
	if err != nil {
		return nil, fmt.Errorf("failed to start mission trace: %w", err)
	}

	adapter := &OTelDecisionLogWriterAdapter{
		tracer:      tracer,
		missionSpan: missionSpan,
		agentSpans:  make(map[string]*AgentSpan),
		ctx:         missionCtx,
		missionID:   mission.ID.String(),
		missionName: mission.Name,
	}

	slog.Info("created otel decision log writer adapter",
		"mission_id", mission.ID.String(),
		"trace_id", missionSpan.Span().SpanContext().TraceID().String(),
	)

	return adapter, nil
}

// LogDecision logs an orchestrator decision and its result to OpenTelemetry as a Generation span.
// This method converts orchestrator types to DecisionLog and delegates to OTelMissionTracer.
//
// Parameters:
//   - ctx: Context for the logging operation
//   - decision: The orchestrator decision made
//   - result: The think result containing LLM metadata
//   - iteration: The orchestration iteration number
//   - missionID: The mission ID (used for validation)
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// The method uses fire-and-forget error handling: errors are logged but not propagated
// to ensure orchestration is never blocked by tracing failures.
func (a *OTelDecisionLogWriterAdapter) LogDecision(ctx context.Context, decision *orchestrator.Decision, result *orchestrator.ThinkResult, iteration int, missionID string) error {
	if decision == nil || result == nil {
		slog.Warn("skipping decision log: nil decision or result",
			"mission_id", a.missionID,
			"iteration", iteration,
		)
		return nil
	}

	// Validate mission ID matches
	if missionID != a.missionID {
		slog.Warn("decision log mission ID mismatch",
			"expected", a.missionID,
			"got", missionID,
			"iteration", iteration,
		)
		return nil
	}

	// Convert orchestrator types to schema types for OpenTelemetry
	schemaDecision := a.convertDecision(decision, result, iteration)

	// Build DecisionLog for OTelMissionTracer with full prompt data
	decisionLog := &DecisionLog{
		Decision:      schemaDecision,
		Prompt:        a.buildFullPrompt(result),
		Response:      result.RawResponse,
		Model:         result.Model,
		GraphSnapshot: a.buildGraphSnapshot(decision),
		Neo4jNodeID:   "", // Not stored in Neo4j at this level
		OTELTraceID:   "",
		Messages:      a.convertMessages(result.Messages),
		RequestMeta:   a.buildRequestMetadata(result),
	}

	// Log to OpenTelemetry (fire-and-forget)
	if err := a.tracer.LogDecision(a.ctx, a.missionSpan, decisionLog); err != nil {
		slog.Warn("failed to log decision to opentelemetry",
			"mission_id", a.missionID,
			"iteration", iteration,
			"error", err,
		)
		// Don't return the error - continue execution
	}

	// Increment statistics in mission span
	a.missionSpan.AddDecision()
	a.missionSpan.AddLLMCall(result.TotalTokens, 0.0) // Cost calculation can be added later

	return nil
}

// LogAction logs an action result to OpenTelemetry as agent execution and tool execution spans.
// This method routes to the appropriate span type based on the action.
//
// Parameters:
//   - ctx: Context for the logging operation
//   - action: The action result from the actor
//   - iteration: The orchestration iteration number
//   - missionID: The mission ID (used for validation)
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// The method uses fire-and-forget error handling: errors are logged but not propagated.
func (a *OTelDecisionLogWriterAdapter) LogAction(ctx context.Context, action *orchestrator.ActionResult, iteration int, missionID string) error {
	if action == nil {
		slog.Warn("skipping action log: nil action",
			"mission_id", a.missionID,
			"iteration", iteration,
		)
		return nil
	}

	// Validate mission ID matches
	if missionID != a.missionID {
		slog.Warn("action log mission ID mismatch",
			"expected", a.missionID,
			"got", missionID,
			"iteration", iteration,
		)
		return nil
	}

	// Route based on action type
	switch action.Action {
	case orchestrator.ActionExecuteAgent:
		a.logAgentExecution(ctx, action, iteration)
	case orchestrator.ActionSpawnAgent:
		a.logSpawnAgent(ctx, action, iteration)
	case orchestrator.ActionComplete:
		// Complete is logged in Close()
	default:
		// Other actions (skip, modify, retry) don't create separate spans
		slog.Debug("action logged without span creation",
			"action", action.Action,
			"mission_id", a.missionID,
			"iteration", iteration,
		)
	}

	return nil
}

// logAgentExecution logs an agent execution to OpenTelemetry as a span.
func (a *OTelDecisionLogWriterAdapter) logAgentExecution(ctx context.Context, action *orchestrator.ActionResult, iteration int) {
	if action.AgentExecution == nil {
		return
	}

	exec := action.AgentExecution

	// Extract agent name from metadata
	agentName := "unknown"
	if name, ok := action.Metadata["agent_name"].(string); ok {
		agentName = name
	}

	// Create AgentExecutionLog
	agentLog := &AgentExecutionLog{
		Execution:   exec,
		AgentName:   agentName,
		Config:      make(map[string]any),
		Neo4jNodeID: "",
		OTELTraceID: "",
	}

	// Extract enhanced metadata from execution result (Task 1.4)
	if exec.Result != nil {
		// Tool calls count
		if toolCount, ok := exec.Result["tool_calls_count"].(int); ok {
			agentLog.ToolCallsCount = toolCount
		} else if toolCount, ok := exec.Result["tool_calls_count"].(float64); ok {
			agentLog.ToolCallsCount = int(toolCount)
		}

		// Findings count
		if findingsCount, ok := exec.Result["findings_count"].(int); ok {
			agentLog.FindingsCount = findingsCount
		} else if findingsCount, ok := exec.Result["findings_count"].(float64); ok {
			agentLog.FindingsCount = int(findingsCount)
		}

		// LLM time in milliseconds
		if llmTime, ok := exec.Result["llm_time_ms"].(int); ok {
			agentLog.LLMTimeMs = llmTime
		} else if llmTime, ok := exec.Result["llm_time_ms"].(float64); ok {
			agentLog.LLMTimeMs = int(llmTime)
		}

		// Tool time in milliseconds
		if toolTime, ok := exec.Result["tool_time_ms"].(int); ok {
			agentLog.ToolTimeMs = toolTime
		} else if toolTime, ok := exec.Result["tool_time_ms"].(float64); ok {
			agentLog.ToolTimeMs = int(toolTime)
		}

		// Memory operations count
		if memOps, ok := exec.Result["memory_ops_count"].(int); ok {
			agentLog.MemoryOpsCount = memOps
		} else if memOps, ok := exec.Result["memory_ops_count"].(float64); ok {
			agentLog.MemoryOpsCount = int(memOps)
		}
	}

	// Also try to extract from action metadata as fallback
	if action.Metadata != nil {
		if agentLog.ToolCallsCount == 0 {
			if toolCount, ok := action.Metadata["tool_calls_count"].(int); ok {
				agentLog.ToolCallsCount = toolCount
			} else if toolCount, ok := action.Metadata["tool_calls_count"].(float64); ok {
				agentLog.ToolCallsCount = int(toolCount)
			}
		}
		if agentLog.FindingsCount == 0 {
			if findingsCount, ok := action.Metadata["findings_count"].(int); ok {
				agentLog.FindingsCount = findingsCount
			} else if findingsCount, ok := action.Metadata["findings_count"].(float64); ok {
				agentLog.FindingsCount = int(findingsCount)
			}
		}
	}

	// Log to OpenTelemetry and get AgentSpan (fire-and-forget)
	agentCtx, agentSpan, err := a.tracer.LogAgentExecution(a.ctx, a.missionSpan, agentLog)
	if err != nil {
		slog.Warn("failed to log agent execution to opentelemetry",
			"mission_id", a.missionID,
			"execution_id", exec.ID.String(),
			"error", err,
		)
		return
	}

	// Store agentSpan in map for potential nested operations (tool calls, findings, memory ops)
	if agentSpan != nil {
		a.mu.Lock()
		a.agentSpans[exec.ID.String()] = agentSpan
		a.mu.Unlock()

		slog.Debug("stored agent span",
			"execution_id", exec.ID.String(),
			"agent_name", agentName,
			"span_id", agentSpan.Span().SpanContext().SpanID().String(),
		)
	}

	// Update context for downstream operations
	_ = agentCtx // agentCtx is available for nested operations if needed
}

// logSpawnAgent logs a dynamically spawned agent to OpenTelemetry metadata.
func (a *OTelDecisionLogWriterAdapter) logSpawnAgent(ctx context.Context, action *orchestrator.ActionResult, iteration int) {
	if action.NewNode == nil {
		return
	}

	slog.Debug("spawned agent logged",
		"mission_id", a.missionID,
		"node_id", action.NewNode.ID.String(),
		"agent_name", action.NewNode.AgentName,
		"iteration", iteration,
	)

	// Spawn actions don't create separate OpenTelemetry spans
	// They're captured in decision metadata
}

// Close finalizes the mission trace and sends the summary to OpenTelemetry.
// This method should be called when the mission completes (success or failure).
//
// Parameters:
//   - ctx: Context for the finalization
//   - summary: Optional mission summary with statistics (can be nil)
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// The method uses fire-and-forget error handling: errors are logged but not propagated.
func (a *OTelDecisionLogWriterAdapter) Close(ctx context.Context, summary *MissionTraceSummary) error {
	a.mu.RLock()
	defer a.mu.RUnlock()

	// Get current statistics from mission span
	stats := a.missionSpan.GetStatistics()

	// Build summary if not provided
	if summary == nil {
		summary = a.buildDefaultSummary(stats)
	} else {
		// Merge our statistics with provided summary
		summary.TotalDecisions = stats.TotalDecisions
		summary.TotalExecutions = stats.TotalExecutions
		summary.TotalTools = stats.TotalToolCalls
		if summary.TotalTokens == 0 {
			summary.TotalTokens = stats.TotalTokens
		}
		if summary.Duration == 0 {
			summary.Duration = stats.Duration
		}
	}

	// End the trace (fire-and-forget)
	if err := a.tracer.EndMissionTrace(ctx, a.missionSpan, summary); err != nil {
		slog.Warn("failed to end mission trace in opentelemetry",
			"mission_id", a.missionID,
			"error", err,
		)
	}

	slog.Info("closed otel decision log writer adapter",
		"mission_id", a.missionID,
		"trace_id", a.missionSpan.Span().SpanContext().TraceID().String(),
		"decisions", summary.TotalDecisions,
		"executions", summary.TotalExecutions,
		"duration", summary.Duration,
	)

	return nil
}

// GetAgentSpan returns the AgentSpan for a given execution ID.
// This allows external code to access the agent span for nested operations.
//
// Parameters:
//   - executionID: The agent execution ID
//
// Returns:
//   - *AgentSpan: The agent span, or nil if not found
//
// This method is thread-safe.
func (a *OTelDecisionLogWriterAdapter) GetAgentSpan(executionID string) *AgentSpan {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.agentSpans[executionID]
}

// GetMissionContext returns the context with the mission span for propagation.
// This enables downstream operations to inherit the mission trace context.
//
// Returns:
//   - context.Context: Context containing the mission span
func (a *OTelDecisionLogWriterAdapter) GetMissionContext() context.Context {
	return a.ctx
}

// TraceID returns the OpenTelemetry trace ID for the mission trace.
// This is useful for correlating logs and traces in observability platforms.
//
// Returns:
//   - string: The hex-encoded trace ID (32 characters)
func (a *OTelDecisionLogWriterAdapter) TraceID() string {
	if a.missionSpan == nil {
		return ""
	}
	return a.missionSpan.Span().SpanContext().TraceID().String()
}

// convertDecision converts orchestrator.Decision to schema.Decision.
// This reuses the pattern from DecisionLogWriterAdapter for consistency.
func (a *OTelDecisionLogWriterAdapter) convertDecision(decision *orchestrator.Decision, result *orchestrator.ThinkResult, iteration int) *schema.Decision {
	now := time.Now()

	// Convert orchestrator.DecisionAction to schema.DecisionAction
	schemaAction := schema.DecisionAction(decision.Action.String())

	// Parse missionID from string to types.ID
	missionID := types.ID(a.missionID)

	schemaDecision := schema.NewDecision(
		missionID,
		iteration,
		schemaAction,
	)
	schemaDecision.TargetNodeID = decision.TargetNodeID
	schemaDecision.Reasoning = decision.Reasoning
	schemaDecision.WithConfidence(decision.Confidence)
	schemaDecision.WithTokenUsage(result.PromptTokens, result.CompletionTokens)
	schemaDecision.WithLatency(int(result.Latency.Milliseconds()))
	schemaDecision.Timestamp = now

	// Add modifications if present
	if len(decision.Modifications) > 0 {
		schemaDecision.Modifications = decision.Modifications
	}

	return schemaDecision
}

// buildFullPrompt constructs the complete prompt text from ThinkResult.
// This combines the system prompt and user prompt with clear delimiters for OpenTelemetry display.
func (a *OTelDecisionLogWriterAdapter) buildFullPrompt(result *orchestrator.ThinkResult) string {
	if result == nil {
		return ""
	}

	var sb strings.Builder

	// Add system prompt section
	if result.SystemPrompt != "" {
		sb.WriteString("[SYSTEM]:\n")
		sb.WriteString(result.SystemPrompt)
		sb.WriteString("\n\n---\n\n")
	}

	// Add user prompt section
	if result.UserPrompt != "" {
		sb.WriteString("[USER]:\n")
		sb.WriteString(result.UserPrompt)
	}

	return sb.String()
}

// convertMessages converts orchestrator llm.Message slice to observability MessageLog slice.
// This transforms the message structure for OpenTelemetry ingestion while preserving all fields.
func (a *OTelDecisionLogWriterAdapter) convertMessages(messages []llm.Message) []MessageLog {
	if len(messages) == 0 {
		return nil
	}

	logs := make([]MessageLog, len(messages))
	for i, msg := range messages {
		logs[i] = MessageLog{
			Role:       string(msg.Role),
			Content:    msg.Content,
			Name:       msg.Name,
			ToolCallID: msg.ToolCallID,
		}
	}
	return logs
}

// buildRequestMetadata creates RequestMetadata from ThinkResult.
// This captures the LLM configuration used for the decision.
func (a *OTelDecisionLogWriterAdapter) buildRequestMetadata(result *orchestrator.ThinkResult) *RequestMetadata {
	if result == nil {
		return nil
	}

	return &RequestMetadata{
		Model:       result.Model,
		Temperature: result.RequestConfig.Temperature,
		MaxTokens:   result.RequestConfig.MaxTokens,
		TopP:        result.RequestConfig.TopP,
		SlotName:    result.RequestConfig.SlotName,
		Provider:    "", // Provider info not available in ThinkResult
	}
}

// buildGraphSnapshot creates a snapshot description of the graph state.
func (a *OTelDecisionLogWriterAdapter) buildGraphSnapshot(decision *orchestrator.Decision) string {
	if decision.StopReason != "" {
		return fmt.Sprintf("Mission complete: %s", decision.StopReason)
	}
	if decision.TargetNodeID != "" {
		return fmt.Sprintf("Target node: %s", decision.TargetNodeID)
	}
	return fmt.Sprintf("Action: %s", decision.Action)
}

// buildDefaultSummary creates a default summary from mission statistics.
func (a *OTelDecisionLogWriterAdapter) buildDefaultSummary(stats MissionStatistics) *MissionTraceSummary {
	return &MissionTraceSummary{
		Status:          string(schema.MissionStatusCompleted),
		TotalDecisions:  stats.TotalDecisions,
		TotalExecutions: stats.TotalExecutions,
		TotalTools:      stats.TotalToolCalls,
		TotalTokens:     stats.TotalTokens,
		TotalCost:       stats.TotalCostUSD,
		Duration:        stats.Duration,
		Outcome:         "Mission completed",
		GraphStats:      make(map[string]int),
	}
}

// Ensure OTelDecisionLogWriterAdapter implements orchestrator.DecisionLogWriter
var _ interface {
	LogDecision(ctx context.Context, decision *orchestrator.Decision, result *orchestrator.ThinkResult, iteration int, missionID string) error
	LogAction(ctx context.Context, action *orchestrator.ActionResult, iteration int, missionID string) error
	Close(ctx context.Context, summary *MissionTraceSummary) error
} = (*OTelDecisionLogWriterAdapter)(nil)
