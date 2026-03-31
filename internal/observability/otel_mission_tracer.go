package observability

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/zero-day-ai/gibson/internal/auth"
	"github.com/zero-day-ai/gibson/internal/graphrag/schema"
	"github.com/zero-day-ai/gibson/internal/neo4j"
	"github.com/zero-day-ai/gibson/internal/types"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// OTelMissionTracer provides OpenTelemetry-based tracing for mission execution.
// It creates a hierarchical trace structure aligned with the orchestrator execution model,
// capturing decisions, agent executions, tool calls, findings, memory operations, and graph operations.
//
// The tracer follows a fire-and-forget pattern where tracing errors never block mission execution.
// All public methods are thread-safe and can be called concurrently.
//
// Trace Hierarchy:
//   - Mission Span (gibson.mission.execute)
//     ├── Decision Span (gen_ai.chat) - Orchestrator LLM call
//     │   ├── Event: gen_ai.content.prompt (if content logging enabled)
//     │   └── Event: gen_ai.content.completion (if content logging enabled)
//     ├── Agent Execution Span (gibson.agent.execute)
//     │   ├── Tool Execution Span (gibson.tool.execute)
//     │   │   ├── Event: gibson.tool.input (if content logging + tool I/O enabled)
//     │   │   └── Event: gibson.tool.output (if content logging + tool I/O enabled)
//     │   ├── Finding Span (gibson.finding.submit)
//     │   └── Memory Operation Span (gibson.memory.{get,set,search,delete})
//     └── Graph Operation Span (gibson.graph.store)
type OTelMissionTracer struct {
	tracer          trace.Tracer
	meter           metric.Meter
	contentConfig   *ContentLoggingConfig
	neo4jBrowserURL string
	serviceName     string
}

// NewOTelMissionTracer creates a new OpenTelemetry mission tracer.
//
// The tracer uses the "gibson.mission" instrumentation scope for both traces and metrics,
// enabling correlation between trace and metric data in observability platforms.
//
// Parameters:
//   - tp: TracerProvider for creating trace spans
//   - mp: MeterProvider for recording metrics
//   - cfg: Content logging configuration (optional, uses defaults if nil)
//
// Returns:
//   - *OTelMissionTracer: The initialized tracer ready for use
//
// Example:
//
//	tracer := NewOTelMissionTracer(tp, mp, nil)
//	tracer.WithNeo4jBrowserURL("http://localhost:7474")
func NewOTelMissionTracer(tp trace.TracerProvider, mp metric.MeterProvider, cfg *ContentLoggingConfig) *OTelMissionTracer {
	// Use default content logging config if none provided
	if cfg == nil {
		defaultCfg := DefaultContentLoggingConfig()
		cfg = &defaultCfg
	}

	// Compile redaction patterns for content logging
	if err := cfg.CompilePatterns(); err != nil {
		slog.Error("failed to compile content logging patterns, using defaults",
			"error", err)
		defaultCfg := DefaultContentLoggingConfig()
		if err := defaultCfg.CompilePatterns(); err == nil {
			cfg = &defaultCfg
		}
	}

	return &OTelMissionTracer{
		tracer:          tp.Tracer("gibson.mission"),
		meter:           mp.Meter("gibson.mission"),
		contentConfig:   cfg,
		neo4jBrowserURL: "",
		serviceName:     "gibson",
	}
}

// WithNeo4jBrowserURL sets the Neo4j Browser URL for generating deep links in traces.
// Deep links enable jumping from traces directly to the Neo4j Browser visualization
// of the mission graph state.
//
// This is optional but highly recommended for enhanced observability and debugging.
//
// Parameters:
//   - url: The Neo4j Browser base URL (e.g., "http://localhost:7474")
//
// Returns:
//   - *OTelMissionTracer: The tracer instance for method chaining
//
// Example:
//
//	tracer := NewOTelMissionTracer(tp, mp, nil).
//	    WithNeo4jBrowserURL("http://localhost:7474").
//	    WithServiceName("gibson-prod")
func (t *OTelMissionTracer) WithNeo4jBrowserURL(url string) *OTelMissionTracer {
	t.neo4jBrowserURL = url
	return t
}

// WithServiceName sets the service name for trace attributes.
// This is useful for distinguishing traces from different Gibson deployments
// in a multi-tenant or multi-environment observability setup.
//
// Parameters:
//   - name: The service name to use (default is "gibson")
//
// Returns:
//   - *OTelMissionTracer: The tracer instance for method chaining
func (t *OTelMissionTracer) WithServiceName(name string) *OTelMissionTracer {
	t.serviceName = name
	return t
}

// Note: DecisionLog, AgentExecutionLog, ToolExecutionLog, and MissionTraceSummary
// are defined in langfuse_tracer.go and reused here for consistency.
// These types are shared between Langfuse and OpenTelemetry tracers.

// OTelToolExecutionLog extends ToolExecutionLog with additional fields needed for OpenTelemetry tracing.
// This structure provides more detailed metadata than the base ToolExecutionLog.
type OTelToolExecutionLog struct {
	Execution       *schema.ToolExecution // The tool execution node from the graph
	Category        string                // Tool category (e.g., "network", "discovery")
	Version         string                // Tool version
	InputString     string                // Tool input as string (for logging, may contain sensitive data)
	OutputString    string                // Tool output as string (for logging, may contain sensitive data)
	DiscoveryCount  int                   // Number of discoveries made (e.g., hosts found)
	OutputSizeBytes int                   // Size of tool output in bytes
	Neo4jNodeID     string                // Neo4j node ID for correlation
}

// FindingLog captures security finding information for OpenTelemetry tracing.
// This represents a vulnerability or security issue discovered during mission execution.
type FindingLog struct {
	ID          types.ID  // Unique finding identifier
	Title       string    // Finding title
	Severity    string    // Severity level (critical, high, medium, low, info)
	Category    string    // Finding category (e.g., "authentication", "injection")
	Confidence  float64   // Confidence score (0.0 to 1.0)
	TargetID    *types.ID // Target system identifier
	CVSSScore   float64   // CVSS score if applicable
	Neo4jNodeID string    // Neo4j node ID for correlation
}

// MemoryOpLog captures memory operation information for OpenTelemetry tracing.
// This represents read/write operations to the agent's multi-tier memory system.
type MemoryOpLog struct {
	Tier         string // Memory tier ("short", "long", "vector")
	Operation    string // Operation type ("get", "set", "search", "delete")
	Key          string // Memory key (may be redacted if sensitive)
	Hit          bool   // Whether the operation was a cache hit (for get)
	SizeBytes    int    // Size of data in bytes
	ResultsCount int    // Number of results (for search)
	DurationMs   int64  // Operation duration in milliseconds
}

// GraphOpLog captures graph database operation information for OpenTelemetry tracing.
// This represents operations that store or query data in the Neo4j knowledge graph.
type GraphOpLog struct {
	Operation            string   // Operation type ("store", "query", "update")
	NodeLabels           []string // Node labels involved
	NodesCreated         int      // Number of nodes created
	RelationshipsCreated int      // Number of relationships created
	QueryType            string   // Type of query ("create", "match", "merge")
	ResultsCount         int      // Number of results returned
	DurationMs           int64    // Operation duration in milliseconds
}

// StartMissionTrace creates a root span for mission execution.
// This should be called when a mission begins execution, before any decisions or agent executions.
//
// The returned context contains the mission span and should be passed to all subsequent
// tracing calls. The returned MissionSpan tracks mission-level statistics and must be
// ended with EndMissionTrace when the mission completes.
//
// Parameters:
//   - ctx: Context for trace propagation
//   - mission: The mission being executed
//
// Returns:
//   - context.Context: Context containing the mission span for propagation
//   - *MissionSpan: Mission span handle for tracking statistics
//   - error: Error if span creation fails (should not happen in practice)
//
// Example:
//
//	ctx, missionSpan, err := tracer.StartMissionTrace(ctx, mission)
//	if err != nil {
//	    slog.Error("failed to start mission trace", "error", err)
//	    // Continue without tracing - fire-and-forget pattern
//	}
//	defer tracer.EndMissionTrace(ctx, missionSpan, summary)
func (t *OTelMissionTracer) StartMissionTrace(ctx context.Context, mission *schema.Mission) (context.Context, *MissionSpan, error) {
	if mission == nil {
		err := fmt.Errorf("mission cannot be nil")
		slog.Error("failed to start mission trace", "error", err)
		return ctx, nil, err
	}

	// Create root span for mission execution
	spanCtx, span := t.tracer.Start(ctx, SpanMissionExecute,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(mission.CreatedAt),
	)

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set mission attributes
	span.SetAttributes(
		attribute.String(GibsonMissionID, mission.ID.String()),
		attribute.String(GibsonMissionName, mission.Name),
		attribute.String(GibsonMissionObjective, mission.Objective),
		attribute.String(GibsonMissionTargetRef, mission.TargetRef),
		attribute.String(GibsonMissionStatus, mission.Status.String()),
		attribute.String("tenant_id", tenantID),
	)

	// Create MissionSpan wrapper for statistics tracking
	missionSpan := &MissionSpan{
		span:      span,
		ctx:       spanCtx,
		MissionID: mission.ID,
		StartTime: mission.CreatedAt,
	}

	slog.Debug("started mission trace",
		"mission_id", mission.ID.String(),
		"trace_id", span.SpanContext().TraceID().String(),
	)

	return spanCtx, missionSpan, nil
}

// LogDecision logs an orchestrator decision as a GenAI LLM span.
// Decisions are traced as "gen_ai.chat" spans following OpenTelemetry GenAI semantic conventions.
//
// This method uses a fire-and-forget pattern - errors are logged but never returned.
// Content logging (prompts/completions) is controlled by the ContentLoggingConfig.
//
// Parameters:
//   - ctx: Context containing the mission span
//   - missionSpan: The parent mission span for statistics tracking
//   - log: Decision information including prompt, response, and model details
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	decisionLog := &DecisionLog{
//	    Decision:  decision,
//	    Prompt:    promptText,
//	    Response:  responseText,
//	    Model:     "gpt-4",
//	    Provider:  "openai",
//	}
//	tracer.LogDecision(ctx, missionSpan, decisionLog)
func (t *OTelMissionTracer) LogDecision(ctx context.Context, missionSpan *MissionSpan, log *DecisionLog) error {
	if missionSpan == nil || log == nil || log.Decision == nil {
		slog.Debug("skipping decision log - missing required data")
		return nil
	}

	decision := log.Decision

	// Create child span for LLM call using GenAI conventions
	_, span := t.tracer.Start(ctx, SpanGenAIChat,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(decision.Timestamp),
	)
	defer span.End(trace.WithTimestamp(decision.Timestamp.Add(time.Duration(decision.LatencyMs) * time.Millisecond)))

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set GenAI attributes following OpenTelemetry semantic conventions
	attrs := []attribute.KeyValue{
		attribute.String(GenAIRequestModel, log.Model),
		attribute.String(GenAIResponseModel, log.Model),
		attribute.Int(GenAIUsageInputTokens, decision.PromptTokens),
		attribute.Int(GenAIUsageOutputTokens, decision.CompletionTokens),
		attribute.String("tenant_id", tenantID),
	}

	// Add provider and request parameters from RequestMeta if available
	if log.RequestMeta != nil {
		if log.RequestMeta.Provider != "" {
			attrs = append(attrs, attribute.String(GenAISystem, log.RequestMeta.Provider))
		}
		if log.RequestMeta.Temperature > 0 {
			attrs = append(attrs, attribute.Float64(GenAIRequestTemperature, log.RequestMeta.Temperature))
		}
		if log.RequestMeta.MaxTokens > 0 {
			attrs = append(attrs, attribute.Int(GenAIRequestMaxTokens, log.RequestMeta.MaxTokens))
		}
		if log.RequestMeta.TopP > 0 {
			attrs = append(attrs, attribute.Float64(GenAIRequestTopP, log.RequestMeta.TopP))
		}
	}

	// Set orchestrator-specific attributes
	attrs = append(attrs,
		attribute.Int(GibsonOrchestratorIteration, decision.Iteration),
		attribute.String(GibsonOrchestratorAction, decision.Action.String()),
		attribute.Float64(GibsonOrchestratorConfidence, decision.Confidence),
		attribute.String(GibsonOrchestratorReasoning, decision.Reasoning),
	)

	if decision.TargetNodeID != "" {
		attrs = append(attrs, attribute.String(GibsonOrchestratorTargetNodeID, decision.TargetNodeID))
	}

	if log.Neo4jNodeID != "" {
		attrs = append(attrs, attribute.String("gibson.neo4j_node_id", log.Neo4jNodeID))
	}

	span.SetAttributes(attrs...)

	// Add content logging events if enabled
	if t.contentConfig.Enabled {
		// Log prompt as event
		if log.Prompt != "" {
			prompt := t.contentConfig.Redact(log.Prompt)
			prompt = t.contentConfig.Truncate(prompt, t.contentConfig.MaxPromptLength)
			span.AddEvent(EventGenAIContentPrompt,
				trace.WithAttributes(attribute.String("prompt", prompt)),
			)
		}

		// Log completion as event
		if log.Response != "" {
			response := t.contentConfig.Redact(log.Response)
			response = t.contentConfig.Truncate(response, t.contentConfig.MaxCompletionLength)
			span.AddEvent(EventGenAIContentCompletion,
				trace.WithAttributes(attribute.String("completion", response)),
			)
		}

		// Log graph snapshot if available
		if log.GraphSnapshot != "" {
			snapshot := t.contentConfig.Truncate(log.GraphSnapshot, 5000)
			span.AddEvent("gibson.graph.snapshot",
				trace.WithAttributes(attribute.String("snapshot", snapshot)),
			)
		}
	}

	// Increment mission statistics
	missionSpan.AddDecision()
	missionSpan.AddLLMCall(decision.TotalTokens(), 0.0) // Cost calculation can be added later

	slog.Debug("logged decision",
		"decision_id", decision.ID.String(),
		"iteration", decision.Iteration,
		"action", decision.Action.String(),
	)

	return nil
}

// LogAgentExecution logs the start of an agent execution.
// This creates a child span under the mission span and returns an AgentSpan for
// tracking nested tool calls, findings, and memory operations.
//
// The returned AgentSpan must be ended by calling AgentSpan.End() when the execution completes.
//
// Parameters:
//   - ctx: Context containing the mission span
//   - missionSpan: The parent mission span for statistics tracking
//   - log: Agent execution information
//
// Returns:
//   - context.Context: Context containing the agent span for propagation
//   - *AgentSpan: Agent span handle for tracking nested operations
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	agentLog := &AgentExecutionLog{
//	    Execution: execution,
//	    AgentName: "recon-agent",
//	    Version:   "1.0.0",
//	}
//	ctx, agentSpan, _ := tracer.LogAgentExecution(ctx, missionSpan, agentLog)
//	defer agentSpan.End(codes.Ok, "completed")
func (t *OTelMissionTracer) LogAgentExecution(ctx context.Context, missionSpan *MissionSpan, log *AgentExecutionLog) (context.Context, *AgentSpan, error) {
	if missionSpan == nil || log == nil || log.Execution == nil {
		slog.Debug("skipping agent execution log - missing required data")
		return ctx, nil, nil
	}

	exec := log.Execution

	// Create child span for agent execution
	spanCtx, span := t.tracer.Start(ctx, SpanAgentExecute,
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(exec.StartedAt),
	)

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set agent execution attributes
	attrs := []attribute.KeyValue{
		attribute.String(GibsonAgentName, log.AgentName),
		attribute.String(GibsonAgentWorkflowNodeID, exec.WorkflowNodeID),
		attribute.Int(GibsonAgentAttempt, exec.Attempt),
		attribute.String(GibsonAgentStatus, exec.Status.String()),
		attribute.String("tenant_id", tenantID),
	}

	if log.Neo4jNodeID != "" {
		attrs = append(attrs, attribute.String("gibson.neo4j_node_id", log.Neo4jNodeID))
	}

	// Add enhanced metadata if available
	if log.ToolCallsCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonAgentToolCallsCount, log.ToolCallsCount))
	}
	if log.FindingsCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonAgentFindingsCount, log.FindingsCount))
	}
	if log.LLMTimeMs > 0 {
		attrs = append(attrs, attribute.Int(GibsonAgentLLMTimeMs, log.LLMTimeMs))
	}
	if log.ToolTimeMs > 0 {
		attrs = append(attrs, attribute.Int(GibsonAgentToolTimeMs, log.ToolTimeMs))
	}
	if log.MemoryOpsCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonAgentMemoryOpsCount, log.MemoryOpsCount))
	}

	span.SetAttributes(attrs...)

	// Create AgentSpan wrapper for statistics tracking
	agentSpan := &AgentSpan{
		span:        span,
		ctx:         spanCtx,
		ExecutionID: exec.ID,
		AgentName:   log.AgentName,
		StartTime:   exec.StartedAt,
		parent:      missionSpan,
	}

	// Increment mission statistics
	missionSpan.AddExecution()

	slog.Debug("logged agent execution",
		"execution_id", exec.ID.String(),
		"agent_name", log.AgentName,
		"workflow_node_id", exec.WorkflowNodeID,
	)

	return spanCtx, agentSpan, nil
}

// LogToolExecution logs a tool execution as a child span under an agent execution.
// Tool I/O content logging is controlled by ContentLoggingConfig.IncludeToolIO.
//
// Parameters:
//   - ctx: Context containing the agent span
//   - agentSpan: The parent agent span for statistics tracking
//   - log: Tool execution information including input, output, and timing
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	toolLog := &OTelToolExecutionLog{
//	    Execution:   toolExec,
//	    Category:   "network",
//	    InputString:  "-sV 192.168.1.1",
//	    OutputString: scanResults,
//	}
//	tracer.LogToolExecution(ctx, agentSpan, toolLog)
func (t *OTelMissionTracer) LogToolExecution(ctx context.Context, agentSpan *AgentSpan, log *OTelToolExecutionLog) error {
	if agentSpan == nil || log == nil || log.Execution == nil {
		slog.Debug("skipping tool execution log - missing required data")
		return nil
	}

	exec := log.Execution

	// Calculate duration
	var durationMs int64
	if exec.CompletedAt != nil {
		durationMs = exec.CompletedAt.Sub(exec.StartedAt).Milliseconds()
	}

	// Create child span for tool execution
	_, span := t.tracer.Start(ctx, "gibson.tool.execute",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(exec.StartedAt),
	)

	if exec.CompletedAt != nil {
		defer span.End(trace.WithTimestamp(*exec.CompletedAt))
	} else {
		defer span.End()
	}

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set tool execution attributes
	attrs := []attribute.KeyValue{
		attribute.String(GibsonToolName, exec.ToolName),
		attribute.String(GibsonToolStatus, exec.Status.String()),
		attribute.Int64(GibsonToolDurationMs, durationMs),
		attribute.Int(GibsonToolOutputSizeBytes, log.OutputSizeBytes),
		attribute.String("tenant_id", tenantID),
	}

	if log.Category != "" {
		attrs = append(attrs, attribute.String(GibsonToolCategory, log.Category))
	}

	if log.Version != "" {
		attrs = append(attrs, attribute.String(GibsonToolVersion, log.Version))
	}

	if log.DiscoveryCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonToolDiscoveryCount, log.DiscoveryCount))
	}

	if log.Neo4jNodeID != "" {
		attrs = append(attrs, attribute.String("gibson.neo4j_node_id", log.Neo4jNodeID))
	}

	if exec.Error != "" {
		attrs = append(attrs, attribute.String(GibsonToolError, exec.Error))
		span.SetStatus(codes.Error, exec.Error)
	}

	span.SetAttributes(attrs...)

	// Add content logging events if enabled and tool I/O is included
	if t.contentConfig.Enabled && t.contentConfig.IncludeToolIO {
		// Log tool input as event
		if log.InputString != "" {
			input := t.contentConfig.Redact(log.InputString)
			input = t.contentConfig.Truncate(input, 2000)
			span.AddEvent("gibson.tool.input",
				trace.WithAttributes(attribute.String("input", input)),
			)
		}

		// Log tool output as event
		if log.OutputString != "" {
			output := t.contentConfig.Redact(log.OutputString)
			output = t.contentConfig.Truncate(output, 5000)
			span.AddEvent("gibson.tool.output",
				trace.WithAttributes(attribute.String("output", output)),
			)
		}
	}

	// Increment agent statistics
	agentSpan.AddToolCall()

	slog.Debug("logged tool execution",
		"tool_name", exec.ToolName,
		"status", exec.Status.String(),
		"duration_ms", durationMs,
	)

	return nil
}

// LogFinding logs a security finding as a child span under an agent execution.
// Findings represent vulnerabilities or security issues discovered during the mission.
//
// Parameters:
//   - ctx: Context containing the agent span
//   - agentSpan: The parent agent span for statistics tracking
//   - finding: Finding information including severity, category, and confidence
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	findingLog := &FindingLog{
//	    ID:         types.NewID(),
//	    Title:      "SQL Injection",
//	    Severity:   "high",
//	    Category:   "injection",
//	    Confidence: 0.95,
//	    CVSSScore:  8.5,
//	}
//	tracer.LogFinding(ctx, agentSpan, findingLog)
func (t *OTelMissionTracer) LogFinding(ctx context.Context, agentSpan *AgentSpan, finding *FindingLog) error {
	if agentSpan == nil || finding == nil {
		slog.Debug("skipping finding log - missing required data")
		return nil
	}

	// Create child span for finding submission
	_, span := t.tracer.Start(ctx, SpanFindingSubmit,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set finding attributes
	attrs := []attribute.KeyValue{
		attribute.String(GibsonFindingID, finding.ID.String()),
		attribute.String(GibsonFindingTitle, finding.Title),
		attribute.String(GibsonFindingSeverity, finding.Severity),
		attribute.Float64(GibsonFindingConfidence, finding.Confidence),
		attribute.String("tenant_id", tenantID),
	}

	if finding.Category != "" {
		attrs = append(attrs, attribute.String(GibsonFindingCategory, finding.Category))
	}

	if finding.TargetID != nil {
		attrs = append(attrs, attribute.String(GibsonFindingTargetID, finding.TargetID.String()))
	}

	if finding.CVSSScore > 0 {
		attrs = append(attrs, attribute.Float64(GibsonFindingCVSSScore, finding.CVSSScore))
	}

	if finding.Neo4jNodeID != "" {
		attrs = append(attrs, attribute.String(GibsonFindingNeo4jNodeID, finding.Neo4jNodeID))
	}

	// Add Neo4j browser link if configured
	if t.neo4jBrowserURL != "" && finding.Neo4jNodeID != "" {
		if browserURL, err := neo4j.BrowserURL(t.neo4jBrowserURL, agentSpan.parent.MissionID, neo4j.QueryTypeFull); err == nil {
			attrs = append(attrs, attribute.String("neo4j_browser_url", browserURL))
		}
	}

	span.SetAttributes(attrs...)

	// Increment agent statistics
	agentSpan.AddFinding()

	slog.Debug("logged finding",
		"finding_id", finding.ID.String(),
		"severity", finding.Severity,
		"title", finding.Title,
	)

	return nil
}

// LogMemoryOp logs a memory operation as a child span under an agent execution.
// Memory operations include reads, writes, searches, and deletes across different tiers
// (short-term, long-term, vector).
//
// Parameters:
//   - ctx: Context containing the agent span
//   - agentSpan: The parent agent span for statistics tracking
//   - op: Memory operation information including tier, operation type, and results
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	memoryOp := &MemoryOpLog{
//	    Tier:       "short",
//	    Operation:  "set",
//	    Key:        "last_scan_result",
//	    SizeBytes:  4096,
//	    DurationMs: 15,
//	}
//	tracer.LogMemoryOp(ctx, agentSpan, memoryOp)
func (t *OTelMissionTracer) LogMemoryOp(ctx context.Context, agentSpan *AgentSpan, op *MemoryOpLog) error {
	if agentSpan == nil || op == nil {
		slog.Debug("skipping memory operation log - missing required data")
		return nil
	}

	// Determine span name based on operation
	var spanName string
	switch op.Operation {
	case "get":
		spanName = SpanMemoryGet
	case "set":
		spanName = SpanMemorySet
	case "search":
		spanName = SpanMemorySearch
	case "delete":
		spanName = "gibson.memory.delete"
	default:
		spanName = "gibson.memory.operation"
	}

	// Create child span for memory operation
	_, span := t.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set memory operation attributes
	attrs := []attribute.KeyValue{
		attribute.String(GibsonMemoryTier, op.Tier),
		attribute.String(GibsonMemoryOperation, op.Operation),
		attribute.Int(GibsonMemorySizeBytes, op.SizeBytes),
		attribute.Int64(GibsonMemoryDurationMs, op.DurationMs),
		attribute.String("tenant_id", tenantID),
	}

	if op.Key != "" {
		// Redact sensitive keys
		key := t.contentConfig.Redact(op.Key)
		attrs = append(attrs, attribute.String(GibsonMemoryKey, key))
	}

	if op.Operation == "get" {
		attrs = append(attrs, attribute.Bool(GibsonMemoryHit, op.Hit))
	}

	if op.Operation == "search" && op.ResultsCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonMemorySearchResultsCount, op.ResultsCount))
	}

	span.SetAttributes(attrs...)

	// Increment agent statistics
	agentSpan.AddMemoryOp()

	slog.Debug("logged memory operation",
		"tier", op.Tier,
		"operation", op.Operation,
		"duration_ms", op.DurationMs,
	)

	return nil
}

// LogGraphOp logs a graph database operation.
// Graph operations store or query data in the Neo4j knowledge graph.
//
// This method logs operations at the mission level since graph operations
// affect the overall mission state, not just a single agent execution.
//
// Parameters:
//   - ctx: Context containing the mission or agent span
//   - agentSpan: The current agent span (optional, used for statistics)
//   - op: Graph operation information including nodes, relationships, and timing
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	graphOp := &GraphOpLog{
//	    Operation:            "store",
//	    NodeLabels:           []string{"Host", "Port"},
//	    NodesCreated:         2,
//	    RelationshipsCreated: 1,
//	    DurationMs:           50,
//	}
//	tracer.LogGraphOp(ctx, agentSpan, graphOp)
func (t *OTelMissionTracer) LogGraphOp(ctx context.Context, agentSpan *AgentSpan, op *GraphOpLog) error {
	if op == nil {
		slog.Debug("skipping graph operation log - missing required data")
		return nil
	}

	// Create child span for graph operation
	_, span := t.tracer.Start(ctx, "gibson.graph.store",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	defer span.End()

	// Resolve tenant ID for multi-tenancy attribute.
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Set graph operation attributes
	attrs := []attribute.KeyValue{
		attribute.String(GibsonGraphOperation, op.Operation),
		attribute.Int(GibsonGraphNodesCreated, op.NodesCreated),
		attribute.Int(GibsonGraphRelationshipsCreated, op.RelationshipsCreated),
		attribute.Int64(GibsonGraphDurationMs, op.DurationMs),
		attribute.String("tenant_id", tenantID),
	}

	if len(op.NodeLabels) > 0 {
		attrs = append(attrs, attribute.StringSlice(GibsonGraphNodeLabels, op.NodeLabels))
	}

	if op.QueryType != "" {
		attrs = append(attrs, attribute.String(GibsonGraphQueryType, op.QueryType))
	}

	if op.ResultsCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonGraphResultsCount, op.ResultsCount))
	}

	span.SetAttributes(attrs...)

	// Increment mission-level statistics if agent span is available
	if agentSpan != nil && agentSpan.parent != nil {
		agentSpan.parent.AddGraphOp(op.NodesCreated, op.RelationshipsCreated)
	}

	slog.Debug("logged graph operation",
		"operation", op.Operation,
		"nodes_created", op.NodesCreated,
		"relationships_created", op.RelationshipsCreated,
	)

	return nil
}

// EndMissionTrace finalizes the mission span with summary statistics.
// This should be called when the mission completes or fails.
//
// The method merges statistics from the MissionSpan with any additional summary
// data provided, then sets all final attributes on the span before ending it.
//
// Parameters:
//   - ctx: Context containing the mission span
//   - missionSpan: The mission span to finalize
//   - summary: Additional summary data (optional, can be nil)
//
// Returns:
//   - error: Always returns nil (fire-and-forget pattern)
//
// Example:
//
//	summary := &MissionTraceSummary{
//	    Status:   "completed",
//	    Outcome:  "Successfully scanned 10 hosts, found 3 vulnerabilities",
//	    Duration: time.Since(startTime),
//	}
//	tracer.EndMissionTrace(ctx, missionSpan, summary)
func (t *OTelMissionTracer) EndMissionTrace(ctx context.Context, missionSpan *MissionSpan, summary *MissionTraceSummary) error {
	if missionSpan == nil {
		slog.Debug("skipping mission trace end - missing mission span")
		return nil
	}

	// Get current statistics from mission span
	stats := missionSpan.GetStatistics()

	// Merge with provided summary if available
	var finalStatus string
	var outcome string
	var duration time.Duration

	if summary != nil {
		finalStatus = summary.Status
		outcome = summary.Outcome
		duration = summary.Duration

		// Use summary statistics if they're higher (in case of manual tracking)
		if summary.TotalDecisions > stats.TotalDecisions {
			stats.TotalDecisions = summary.TotalDecisions
		}
		if summary.TotalExecutions > stats.TotalExecutions {
			stats.TotalExecutions = summary.TotalExecutions
		}
		if summary.TotalTools > stats.TotalToolCalls {
			stats.TotalToolCalls = summary.TotalTools
		}
		if summary.TotalTokens > stats.TotalTokens {
			stats.TotalTokens = summary.TotalTokens
		}
		if summary.TotalCost > stats.TotalCostUSD {
			stats.TotalCostUSD = summary.TotalCost
		}
	} else {
		finalStatus = "completed"
		outcome = "Mission completed"
		duration = stats.Duration
	}

	// Set summary attributes using helper function
	summaryAttrs := MissionSummaryAttributes(stats)
	missionSpan.span.SetAttributes(summaryAttrs...)

	// Add outcome and status
	if outcome != "" {
		missionSpan.span.SetAttributes(attribute.String(GibsonMissionOutcome, outcome))
	}

	// Add Neo4j browser link if configured
	if t.neo4jBrowserURL != "" {
		if browserURL, err := neo4j.BrowserURL(t.neo4jBrowserURL, missionSpan.MissionID, neo4j.QueryTypeFull); err == nil {
			missionSpan.span.SetAttributes(attribute.String("neo4j_browser_url", browserURL))
		}
	}

	// Set span status based on mission status
	var spanStatus codes.Code
	var statusDesc string
	switch finalStatus {
	case "completed":
		spanStatus = codes.Ok
		statusDesc = "Mission completed successfully"
	case "failed":
		spanStatus = codes.Error
		statusDesc = "Mission failed"
	default:
		spanStatus = codes.Unset
		statusDesc = finalStatus
	}

	// End the span with appropriate status
	missionSpan.End(spanStatus, statusDesc)

	slog.Debug("ended mission trace",
		"mission_id", missionSpan.MissionID.String(),
		"status", finalStatus,
		"duration", duration,
		"decisions", stats.TotalDecisions,
		"executions", stats.TotalExecutions,
		"tool_calls", stats.TotalToolCalls,
		"findings", stats.TotalFindings,
	)

	return nil
}
