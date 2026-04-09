package observability

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/auth"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Metric attribute key constants for consistent labeling across all metrics.
// These keys are used to add dimensions to metrics for filtering and aggregation.
const (
	// MetricAttrProvider identifies the LLM provider (e.g., "anthropic", "openai", "ollama")
	MetricAttrProvider = "provider"

	// MetricAttrModel identifies the specific model used (e.g., "gpt-4", "claude-3-opus")
	MetricAttrModel = "model"

	// MetricAttrStatus represents the outcome status (e.g., "success", "error", "timeout")
	MetricAttrStatus = "status"

	// MetricAttrTokenType distinguishes between input and output tokens
	MetricAttrTokenType = "token_type"

	// MetricAttrToolName identifies the tool being called
	MetricAttrToolName = "tool_name"

	// MetricAttrSeverity represents finding severity level (e.g., "critical", "high", "medium", "low")
	MetricAttrSeverity = "severity"

	// MetricAttrCategory represents finding category (e.g., "authentication", "injection")
	MetricAttrCategory = "category"

	// MetricAttrAgentName identifies the agent performing an execution
	MetricAttrAgentName = "agent_name"

	// MetricAttrTier identifies the memory tier ("short", "long", "vector")
	MetricAttrTier = "tier"

	// MetricAttrOperation identifies the operation type (e.g., "get", "set", "search", "delete")
	MetricAttrOperation = "operation"

	// MetricAttrAction identifies the orchestrator action taken
	MetricAttrAction = "action"
)

// OTelMetricsRecorder records operational metrics via OpenTelemetry.
// All metrics follow OpenTelemetry naming conventions (dot-separated, lowercase).
//
// The recorder maintains separate instruments for different metric types:
//   - Counters: Monotonically increasing values (requests, tokens, findings)
//   - Histograms: Distribution of values (latencies, durations)
//
// All methods are safe to call with a nil receiver (no-op behavior).
//
// Metric Naming Convention:
// - Namespace: "gibson"
// - Component: specific area (llm, tool, agent, mission, etc.)
// - Metric: what is being measured
// - Unit suffix: explicit unit for clarity (.seconds, .total, etc.)
//
// Example:
//
//	recorder := NewOTelMetricsRecorder(meterProvider)
//	recorder.RecordLLMCompletion(ctx, "anthropic", "claude-3-opus", "success", 100, 200, 1500.0, 0.05)
type OTelMetricsRecorder struct {
	meter metric.Meter

	// Counters track cumulative counts
	llmRequestsTotal     metric.Int64Counter
	llmTokensTotal       metric.Int64Counter
	llmCostTotal         metric.Float64Counter
	toolCallsTotal       metric.Int64Counter
	findingsTotal        metric.Int64Counter
	agentExecutionsTotal metric.Int64Counter
	missionsTotal        metric.Int64Counter
	memoryOpsTotal       metric.Int64Counter
	graphOpsTotal        metric.Int64Counter
	decisionsTotal       metric.Int64Counter
	authzDecisionsTotal  metric.Int64Counter

	// FGA-specific counters (authz-03).
	fgaUnavailableTotal metric.Int64Counter

	// Component authz counters (authz-05).
	componentAuthzTotal        metric.Int64Counter
	componentAuthzFailOpenTotal metric.Int64Counter
	workTTLExpiredTotal        metric.Int64Counter
	classificationsTotal       metric.Int64Counter

	// Histograms track distributions of values
	llmLatencySeconds      metric.Float64Histogram
	toolLatencySeconds     metric.Float64Histogram
	agentDurationSeconds   metric.Float64Histogram
	missionDurationSeconds metric.Float64Histogram
}

// NewOTelMetricsRecorder creates a new OpenTelemetry metrics recorder.
//
// The recorder initializes all metric instruments with appropriate names, descriptions,
// and histogram bucket boundaries. Histogram buckets are carefully chosen to provide
// useful percentile calculations for each metric type.
//
// Parameters:
//   - mp: MeterProvider for creating metric instruments
//
// Returns:
//   - *OTelMetricsRecorder: Initialized recorder ready for use
//   - error: Non-nil if instrument creation fails
//
// Example:
//
//	mp := otel.GetMeterProvider()
//	recorder, err := NewOTelMetricsRecorder(mp)
//	if err != nil {
//	    log.Fatal("failed to create metrics recorder:", err)
//	}
func NewOTelMetricsRecorder(mp metric.MeterProvider) (*OTelMetricsRecorder, error) {
	if mp == nil {
		slog.Warn("nil MeterProvider provided to NewOTelMetricsRecorder, returning no-op recorder")
		return NoopMetricsRecorder(), nil
	}

	meter := mp.Meter("gibson.observability")

	recorder := &OTelMetricsRecorder{
		meter: meter,
	}

	// Create all counter instruments
	var err error

	recorder.llmRequestsTotal, err = meter.Int64Counter(
		"gibson.llm.requests.total",
		metric.WithDescription("Total number of LLM requests"),
	)
	if err != nil {
		return nil, err
	}

	recorder.llmTokensTotal, err = meter.Int64Counter(
		"gibson.llm.tokens.total",
		metric.WithDescription("Total tokens consumed"),
	)
	if err != nil {
		return nil, err
	}

	recorder.llmCostTotal, err = meter.Float64Counter(
		"gibson.llm.cost.total",
		metric.WithDescription("Total estimated cost in USD"),
		metric.WithUnit("USD"),
	)
	if err != nil {
		return nil, err
	}

	recorder.toolCallsTotal, err = meter.Int64Counter(
		"gibson.tool.calls.total",
		metric.WithDescription("Total tool calls"),
	)
	if err != nil {
		return nil, err
	}

	recorder.findingsTotal, err = meter.Int64Counter(
		"gibson.finding.submissions.total",
		metric.WithDescription("Total findings submitted"),
	)
	if err != nil {
		return nil, err
	}

	recorder.agentExecutionsTotal, err = meter.Int64Counter(
		"gibson.agent.executions.total",
		metric.WithDescription("Total agent executions"),
	)
	if err != nil {
		return nil, err
	}

	recorder.missionsTotal, err = meter.Int64Counter(
		"gibson.mission.total",
		metric.WithDescription("Total missions"),
	)
	if err != nil {
		return nil, err
	}

	recorder.memoryOpsTotal, err = meter.Int64Counter(
		"gibson.memory.operations.total",
		metric.WithDescription("Total memory operations"),
	)
	if err != nil {
		return nil, err
	}

	recorder.graphOpsTotal, err = meter.Int64Counter(
		"gibson.graph.operations.total",
		metric.WithDescription("Total graph operations"),
	)
	if err != nil {
		return nil, err
	}

	recorder.decisionsTotal, err = meter.Int64Counter(
		"gibson.orchestrator.decisions.total",
		metric.WithDescription("Total orchestrator decisions"),
	)
	if err != nil {
		return nil, err
	}

	// Authz decisions: counter for every RPC the authz interceptor
	// evaluates, labeled by decision (allow|deny), method, and permission.
	// Added by the declarative-rbac-framework spec (Requirement 9.5).
	recorder.authzDecisionsTotal, err = meter.Int64Counter(
		"gibson.authz.decisions.total",
		metric.WithDescription("Total RPC authorization decisions by decision (allow|deny), method, and permission"),
	)
	if err != nil {
		return nil, err
	}

	// FGA-specific counters (authz-03).
	recorder.fgaUnavailableTotal, err = meter.Int64Counter(
		"gibson.authz.fga_unavailable_total",
		metric.WithDescription("FGA service was unreachable for an authorization check (labeled by method)"),
	)
	if err != nil {
		return nil, err
	}

	// Component authz counters (authz-05).
	// gibson_component_authz_total: every component-level Authorize RPC decision,
	// labeled by action, decision (allow|deny), and tenant_id.
	recorder.componentAuthzTotal, err = meter.Int64Counter(
		"gibson_component_authz_total",
		metric.WithDescription("Total component-level authorization decisions (allow or deny) via the harness callback RPC"),
	)
	if err != nil {
		return nil, err
	}

	// gibson_component_authz_fail_open_total: times the SDK allowed an operation
	// despite the authz service being unreachable (fail-open mode).
	recorder.componentAuthzFailOpenTotal, err = meter.Int64Counter(
		"gibson_component_authz_fail_open_total",
		metric.WithDescription("Total component authz checks allowed due to fail-open policy when the daemon is unreachable"),
	)
	if err != nil {
		return nil, err
	}

	// gibson_work_ttl_expired_total: work items rejected by the SDK serve loop
	// because their AuthzContext TTL had elapsed.
	recorder.workTTLExpiredTotal, err = meter.Int64Counter(
		"gibson_work_ttl_expired_total",
		metric.WithDescription("Total work items rejected by the SDK serve loop due to expired AuthzContext TTL"),
	)
	if err != nil {
		return nil, err
	}

	// Create all histogram instruments with appropriate bucket boundaries
	// LLM latency: 0.1s to 60s (typical range for LLM API calls)
	recorder.llmLatencySeconds, err = meter.Float64Histogram(
		"gibson.llm.latency.seconds",
		metric.WithDescription("LLM request latency distribution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 2, 5, 10, 30, 60),
	)
	if err != nil {
		return nil, err
	}

	// Tool latency: 10ms to 10s (typical range for tool executions)
	recorder.toolLatencySeconds, err = meter.Float64Histogram(
		"gibson.tool.latency.seconds",
		metric.WithDescription("Tool execution latency distribution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(0.01, 0.05, 0.1, 0.5, 1, 5, 10),
	)
	if err != nil {
		return nil, err
	}

	// Agent duration: 1s to 10 minutes (typical range for agent tasks)
	recorder.agentDurationSeconds, err = meter.Float64Histogram(
		"gibson.agent.duration.seconds",
		metric.WithDescription("Agent execution duration distribution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(1, 5, 10, 30, 60, 120, 300, 600),
	)
	if err != nil {
		return nil, err
	}

	// Mission duration: 1 minute to 2 hours (typical range for missions)
	recorder.missionDurationSeconds, err = meter.Float64Histogram(
		"gibson.mission.duration.seconds",
		metric.WithDescription("Mission execution duration distribution"),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(60, 300, 600, 1800, 3600, 7200),
	)
	if err != nil {
		return nil, err
	}

	recorder.classificationsTotal, err = meter.Int64Counter(
		"gibson.finding.classifications",
		metric.WithDescription("Total finding classifications by category and path (heuristic or llm)"),
	)
	if err != nil {
		return nil, err
	}

	slog.Debug("created OTel metrics recorder with all instruments")
	return recorder, nil
}

// NoopMetricsRecorder returns a no-op recorder for use when metrics are disabled.
// All recording methods are safe to call and will return immediately without error.
//
// This is useful for:
//   - Testing without metrics infrastructure
//   - Graceful degradation when MeterProvider is unavailable
//   - Conditional metrics based on configuration
//
// Example:
//
//	var recorder *OTelMetricsRecorder
//	if metricsEnabled {
//	    recorder, _ = NewOTelMetricsRecorder(meterProvider)
//	} else {
//	    recorder = NoopMetricsRecorder()
//	}
func NoopMetricsRecorder() *OTelMetricsRecorder {
	return &OTelMetricsRecorder{}
}

// RecordLLMCompletion records metrics for an LLM completion request.
//
// This method tracks:
//   - Total number of requests (with provider, model, and status labels)
//   - Total tokens consumed (separated by input/output type)
//   - Total cost in USD
//   - Request latency distribution
//
// Parameters:
//   - ctx: Context for trace correlation (unused but kept for consistency)
//   - provider: LLM provider name (e.g., "anthropic", "openai", "ollama")
//   - model: Model identifier (e.g., "claude-3-opus-20240229", "gpt-4")
//   - status: Request outcome (e.g., "success", "error", "timeout")
//   - inputTokens: Number of tokens in the prompt
//   - outputTokens: Number of tokens in the completion
//   - latencyMs: Request latency in milliseconds (converted to seconds for histogram)
//   - cost: Estimated cost in USD
//
// Example:
//
//	recorder.RecordLLMCompletion(ctx, "anthropic", "claude-3-opus", "success", 100, 200, 1500.0, 0.05)
func (r *OTelMetricsRecorder) RecordLLMCompletion(ctx context.Context, provider, model, status string, inputTokens, outputTokens int, latencyMs float64, cost float64) {
	if r == nil || r.llmRequestsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Record request count with labels
	r.llmRequestsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrProvider, provider),
			attribute.String(MetricAttrModel, model),
			attribute.String(MetricAttrStatus, status),
			attribute.String("tenant_id", tenantID),
		),
	)

	// Record input tokens
	if inputTokens > 0 {
		r.llmTokensTotal.Add(ctx, int64(inputTokens),
			metric.WithAttributes(
				attribute.String(MetricAttrProvider, provider),
				attribute.String(MetricAttrModel, model),
				attribute.String(MetricAttrTokenType, "input"),
				attribute.String("tenant_id", tenantID),
			),
		)
	}

	// Record output tokens
	if outputTokens > 0 {
		r.llmTokensTotal.Add(ctx, int64(outputTokens),
			metric.WithAttributes(
				attribute.String(MetricAttrProvider, provider),
				attribute.String(MetricAttrModel, model),
				attribute.String(MetricAttrTokenType, "output"),
				attribute.String("tenant_id", tenantID),
			),
		)
	}

	// Record cost
	if cost > 0 {
		r.llmCostTotal.Add(ctx, cost,
			metric.WithAttributes(
				attribute.String(MetricAttrProvider, provider),
				attribute.String(MetricAttrModel, model),
				attribute.String("tenant_id", tenantID),
			),
		)
	}

	// Record latency (convert milliseconds to seconds)
	if latencyMs > 0 {
		r.llmLatencySeconds.Record(ctx, latencyMs/1000.0,
			metric.WithAttributes(
				attribute.String(MetricAttrProvider, provider),
				attribute.String(MetricAttrModel, model),
				attribute.String("tenant_id", tenantID),
			),
		)
	}
}

// RecordToolCall records metrics for a tool execution.
//
// This method tracks:
//   - Total number of tool calls (with tool name and status labels)
//   - Tool execution latency distribution
//
// Parameters:
//   - ctx: Context for trace correlation
//   - toolName: Name of the tool being executed (e.g., "nmap", "nuclei")
//   - status: Execution outcome (e.g., "success", "error", "timeout")
//   - latencyMs: Execution duration in milliseconds (converted to seconds for histogram)
//
// Example:
//
//	recorder.RecordToolCall(ctx, "nmap", "success", 2500.0)
func (r *OTelMetricsRecorder) RecordToolCall(ctx context.Context, toolName, status string, latencyMs float64) {
	if r == nil || r.toolCallsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Record tool call count
	r.toolCallsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrToolName, toolName),
			attribute.String(MetricAttrStatus, status),
			attribute.String("tenant_id", tenantID),
		),
	)

	// Record latency (convert milliseconds to seconds)
	if latencyMs > 0 {
		r.toolLatencySeconds.Record(ctx, latencyMs/1000.0,
			metric.WithAttributes(
				attribute.String(MetricAttrToolName, toolName),
				attribute.String("tenant_id", tenantID),
			),
		)
	}
}

// RecordFinding records metrics for a security finding submission.
//
// This method tracks:
//   - Total number of findings (with severity and category labels)
//
// Parameters:
//   - ctx: Context for trace correlation
//   - severity: Finding severity level (e.g., "critical", "high", "medium", "low", "info")
//   - category: Finding category (e.g., "authentication", "injection", "misconfiguration")
//
// Example:
//
//	recorder.RecordFinding(ctx, "high", "sql_injection")
func (r *OTelMetricsRecorder) RecordFinding(ctx context.Context, severity, category string) {
	if r == nil || r.findingsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	r.findingsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrSeverity, severity),
			attribute.String(MetricAttrCategory, category),
			attribute.String("tenant_id", tenantID),
		),
	)
}

// RecordAgentExecution records metrics for an agent execution.
//
// This method tracks:
//   - Total number of agent executions (with agent name and status labels)
//   - Agent execution duration distribution
//
// Parameters:
//   - ctx: Context for trace correlation
//   - agentName: Name of the agent (e.g., "recon-agent", "exploit-agent")
//   - status: Execution outcome (e.g., "completed", "failed", "timeout")
//   - durationMs: Execution duration in milliseconds (converted to seconds for histogram)
//
// Example:
//
//	recorder.RecordAgentExecution(ctx, "recon-agent", "completed", 45000.0)
func (r *OTelMetricsRecorder) RecordAgentExecution(ctx context.Context, agentName, status string, durationMs float64) {
	if r == nil || r.agentExecutionsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Record execution count
	r.agentExecutionsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrAgentName, agentName),
			attribute.String(MetricAttrStatus, status),
			attribute.String("tenant_id", tenantID),
		),
	)

	// Record duration (convert milliseconds to seconds)
	if durationMs > 0 {
		r.agentDurationSeconds.Record(ctx, durationMs/1000.0,
			metric.WithAttributes(
				attribute.String(MetricAttrAgentName, agentName),
				attribute.String("tenant_id", tenantID),
			),
		)
	}
}

// RecordMission records metrics for a mission completion.
//
// This method tracks:
//   - Total number of missions (with status label)
//   - Mission execution duration distribution
//
// Parameters:
//   - ctx: Context for trace correlation
//   - status: Mission outcome (e.g., "completed", "failed", "cancelled")
//   - durationMs: Mission duration in milliseconds (converted to seconds for histogram)
//
// Example:
//
//	recorder.RecordMission(ctx, "completed", 300000.0)
func (r *OTelMetricsRecorder) RecordMission(ctx context.Context, status string, durationMs float64) {
	if r == nil || r.missionsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	// Record mission count
	r.missionsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrStatus, status),
			attribute.String("tenant_id", tenantID),
		),
	)

	// Record duration (convert milliseconds to seconds)
	if durationMs > 0 {
		r.missionDurationSeconds.Record(ctx, durationMs/1000.0,
			metric.WithAttributes(
				attribute.String(MetricAttrStatus, status),
				attribute.String("tenant_id", tenantID),
			),
		)
	}
}

// RecordMemoryOp records metrics for a memory operation.
//
// This method tracks:
//   - Total number of memory operations (with tier and operation type labels)
//
// Parameters:
//   - ctx: Context for trace correlation
//   - tier: Memory tier ("short", "long", "vector")
//   - operation: Operation type ("get", "set", "search", "delete")
//
// Example:
//
//	recorder.RecordMemoryOp(ctx, "short", "set")
//	recorder.RecordMemoryOp(ctx, "vector", "search")
func (r *OTelMetricsRecorder) RecordMemoryOp(ctx context.Context, tier, operation string) {
	if r == nil || r.memoryOpsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	r.memoryOpsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrTier, tier),
			attribute.String(MetricAttrOperation, operation),
			attribute.String("tenant_id", tenantID),
		),
	)
}

// RecordGraphOp records metrics for a graph database operation.
//
// This method tracks:
//   - Total number of graph operations (with operation type label)
//
// Parameters:
//   - ctx: Context for trace correlation
//   - operation: Operation type ("store", "query", "update", "delete")
//
// Example:
//
//	recorder.RecordGraphOp(ctx, "store")
//	recorder.RecordGraphOp(ctx, "query")
func (r *OTelMetricsRecorder) RecordGraphOp(ctx context.Context, operation string) {
	if r == nil || r.graphOpsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	r.graphOpsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrOperation, operation),
			attribute.String("tenant_id", tenantID),
		),
	)
}

// RecordDecision records metrics for an orchestrator decision.
//
// This method tracks:
//   - Total number of orchestrator decisions (with action label)
//
// Parameters:
//   - ctx: Context for trace correlation
//   - action: Action taken by the orchestrator (e.g., "execute_agent", "complete", "delegate")
//
// Example:
//
//	recorder.RecordDecision(ctx, "execute_agent")
//	recorder.RecordDecision(ctx, "complete")
func (r *OTelMetricsRecorder) RecordDecision(ctx context.Context, action string) {
	if r == nil || r.decisionsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	r.decisionsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrAction, action),
			attribute.String("tenant_id", tenantID),
		),
	)
}

// RecordAuthzDecision records metrics for a single RPC authorization decision.
//
// Called from the RPC authz interceptor (internal/auth/rpc_authz_interceptor.go)
// after every Enforce call. Labeled by decision, method, and permission so
// operators can drill into "which roles are failing to call which RPCs for
// which permissions" without grepping logs.
//
// Added by the declarative-rbac-framework spec (Requirement 9.5).
//
// Parameters:
//   - ctx: gRPC request context (provides tenant_id label)
//   - decision: "allow" or "deny"
//   - method: fully-qualified gRPC method path
//   - permission: the permission name evaluated (e.g. "tenants:provision"), or
//     "rpc_not_in_schema" for default-deny on unmapped methods, or empty for
//     RPCs with no required permissions
//
// Example:
//
//	recorder.RecordAuthzDecision(ctx, "allow", "/gibson.daemon.admin.v1.DaemonAdminService/ProvisionTenant", "tenants:provision")
//	recorder.RecordAuthzDecision(ctx, "deny", "/gibson.daemon.admin.v1.DaemonAdminService/ListTenants", "tenants:list-all")
func (r *OTelMetricsRecorder) RecordAuthzDecision(ctx context.Context, decision, method, permission string) {
	if r == nil || r.authzDecisionsTotal == nil {
		return
	}

	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}

	attrs := []attribute.KeyValue{
		attribute.String("decision", decision),
		attribute.String("method", method),
		attribute.String("tenant_id", tenantID),
	}
	if permission != "" {
		attrs = append(attrs, attribute.String("permission", permission))
	}

	r.authzDecisionsTotal.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// RecordFgaUnavailable increments the FGA-unavailable counter.
// Called when the FGA service cannot be reached for an authorization check.
//
// Parameters:
//   - ctx: gRPC request context
//   - method: fully-qualified gRPC method path
func (r *OTelMetricsRecorder) RecordFgaUnavailable(ctx context.Context, method string) {
	if r == nil || r.fgaUnavailableTotal == nil {
		return
	}
	r.fgaUnavailableTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("method", method),
	))
}

// ============================================================================
// Component authz metrics (authz-05)
// ============================================================================

// RecordComponentAuthz increments the component-level authz decision counter.
//
// Called from the daemon's HarnessCallbackService.Authorize handler after each
// FGA decision. Labeled by action, decision, and tenant_id so operators can
// alert on unexpected denial rates or monitor per-tenant authz patterns.
//
// Parameters:
//   - ctx: request context providing tenant_id label
//   - action: the action string (e.g., "execute", "read", "write")
//   - decision: "allow" or "deny"
//
// Example:
//
//	recorder.RecordComponentAuthz(ctx, "execute", "allow")
//	recorder.RecordComponentAuthz(ctx, "write", "deny")
func (r *OTelMetricsRecorder) RecordComponentAuthz(ctx context.Context, action, decision string) {
	if r == nil || r.componentAuthzTotal == nil {
		return
	}
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}
	r.componentAuthzTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("decision", decision),
		attribute.String("tenant_id", tenantID),
	))
}

// RecordComponentAuthzFailOpen increments the fail-open counter for component authz.
//
// Called by the SDK serve loop (or proxy) when the daemon's Authorize RPC is
// unreachable AND the component is configured with fail-open mode. This counter
// helps operators detect when fail-open is hiding real authz service outages.
//
// Parameters:
//   - ctx: request context providing tenant_id label
//   - action: the action that was allowed without a real authz check (e.g., "execute")
//
// Example:
//
//	recorder.RecordComponentAuthzFailOpen(ctx, "execute")
func (r *OTelMetricsRecorder) RecordComponentAuthzFailOpen(ctx context.Context, action string) {
	if r == nil || r.componentAuthzFailOpenTotal == nil {
		return
	}
	tenantID := auth.TenantFromContext(ctx)
	if tenantID == "" {
		tenantID = "default"
	}
	r.componentAuthzFailOpenTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("tenant_id", tenantID),
	))
}

// RecordWorkTTLExpired increments the work-item TTL-expired counter.
//
// Called by the SDK serve loop when a work item's AuthzContext TTL has elapsed.
// This indicates that work was queued but not consumed before its signing
// context expired — typically a sign of slow consumers or misconfigured TTLs.
//
// Parameters:
//   - ctx: request context
//   - component: component name (e.g., "tool:nmap", "plugin:gitlab")
//
// Example:
//
//	recorder.RecordWorkTTLExpired(ctx, "tool:nmap")
func (r *OTelMetricsRecorder) RecordWorkTTLExpired(ctx context.Context, component string) {
	if r == nil || r.workTTLExpiredTotal == nil {
		return
	}
	r.workTTLExpiredTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("component", component),
	))
}

// RecordClassification records a single finding classification event.
// The category is the finding category (e.g. "injection", "authentication").
// The path is either "heuristic" or "llm" indicating which classifier produced
// the result. This satisfies Requirement 3.1 of the prod-placeholder-cleanup spec.
func (r *OTelMetricsRecorder) RecordClassification(ctx context.Context, category, path string) {
	if r == nil || r.classificationsTotal == nil {
		return
	}
	r.classificationsTotal.Add(ctx, 1,
		metric.WithAttributes(
			attribute.String(MetricAttrCategory, category),
			attribute.String("classification_path", path),
		),
	)
}
