package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/graphrag/schema"
	"github.com/zeroroot-ai/gibson/internal/observability"
	"github.com/zeroroot-ai/gibson/internal/orchestrator"
)

// CreateOTelDecisionLogWriter creates an OpenTelemetry decision log writer for a mission.
// This method bridges the orchestrator's DecisionLogWriter interface to the OTel observability
// stack, enabling distributed tracing of mission execution with GenAI semantic conventions.
//
// The adapter provides mission-level tracing with hierarchical spans:
//   - Mission Span (root): Captures overall mission execution
//   - Decision Spans: Each orchestrator decision (LLM call)
//   - Agent Execution Spans: Agent invocations and actions
//   - Tool Call Spans: Tool executions with input/output
//   - Finding Spans: Security finding submissions
//   - Memory Operation Spans: Memory store operations
//
// Thread Safety: The returned adapter is thread-safe and safe for concurrent use
// by the orchestrator during mission execution.
//
// Fire-and-Forget Pattern: All tracing operations use fire-and-forget error handling.
// Tracing failures are logged but never block mission execution. This is CRITICAL
// for production reliability - observability must never prevent agent operations.
//
// Graceful Degradation:
//   - If OTel is disabled: Returns (nil, nil) - orchestrator continues without tracing
//   - If OTel init fails: Returns (nil, error) - caller should log warning and continue
//   - If adapter creation fails: Returns (nil, error) - caller should log warning and continue
//
// The orchestrator should always check for nil and proceed without tracing if the
// adapter is unavailable.
//
// Parameters:
//   - ctx: Context for the adapter creation (includes trace context if available)
//   - mission: The mission being traced (must not be nil)
//
// Returns:
//   - orchestrator.DecisionLogWriter: The OTel adapter for logging decisions, or nil if OTel is disabled
//   - error: Non-nil if adapter creation fails (caller should log warning and continue)
//
// Example:
//
//	writer, err := d.CreateOTelDecisionLogWriter(ctx, mission)
//	if err != nil {
//	    d.logger.Warn(ctx, "failed to create otel decision log writer, continuing without tracing",
//	        "error", err)
//	    writer = nil  // Explicitly set to nil for orchestrator
//	}
//	orch := orchestrator.NewOrchestrator(...,
//	    orchestrator.WithDecisionLogWriter(writer))  // May be nil - orchestrator handles this
func (d *daemonImpl) CreateOTelDecisionLogWriter(ctx context.Context, mission *schema.Mission) (orchestrator.DecisionLogWriter, error) {
	// Validate mission parameter
	if mission == nil {
		return nil, fmt.Errorf("mission cannot be nil")
	}

	// Check if OTel stack is available
	// Return nil writer if OTel is disabled - this is the normal case
	if d.infrastructure == nil || d.infrastructure.otelStack == nil {
		d.logger.Debug(ctx, "otel observability not available, decision logging will use fallback",
			"mission_id", mission.ID.String())
		return nil, nil
	}

	d.logger.Info(ctx, "creating otel decision log writer for mission",
		"mission_id", mission.ID.String(),
		"mission_name", mission.Name)

	// Create the OTel decision log writer adapter
	// This starts a mission trace in OpenTelemetry and returns an adapter
	// that implements orchestrator.DecisionLogWriter
	adapter, err := observability.NewOTelDecisionLogWriterAdapter(ctx, d.infrastructure.otelStack.MissionTracer, mission)
	if err != nil {
		return nil, fmt.Errorf("failed to create otel decision log writer adapter: %w", err)
	}

	d.logger.Info(ctx, "otel decision log writer created successfully",
		"mission_id", mission.ID.String(),
		"trace_id", adapter.TraceID())

	return adapter, nil
}

// GetOTelMissionTracer returns the OTelMissionTracer if OTel observability is enabled.
// This is useful for components that need direct access to the mission tracer
// for custom span creation or metrics recording.
//
// Returns:
//   - *observability.OTelMissionTracer: The mission tracer, or nil if OTel is disabled
//
// Example:
//
//	tracer := d.GetOTelMissionTracer()
//	if tracer != nil {
//	    // Record custom metrics or create spans
//	    tracer.RecordAgentExecution(ctx, span, log)
//	}
func (d *daemonImpl) GetOTelMissionTracer() *observability.OTelMissionTracer {
	if d.infrastructure == nil || d.infrastructure.otelStack == nil {
		return nil
	}
	return d.infrastructure.otelStack.MissionTracer
}

// GetOTelMetricsRecorder returns the OTelMetricsRecorder if OTel observability is enabled.
// This is useful for components that need to record custom metrics beyond what
// the mission tracer provides.
//
// Returns:
//   - *observability.OTelMetricsRecorder: The metrics recorder, or nil if OTel is disabled
//
// Example:
//
//	recorder := d.GetOTelMetricsRecorder()
//	if recorder != nil {
//	    recorder.RecordLLMCompletion(ctx, provider, model, status, inputTokens, outputTokens, latency, cost)
//	}
func (d *daemonImpl) GetOTelMetricsRecorder() *observability.OTelMetricsRecorder {
	if d.infrastructure == nil || d.infrastructure.otelStack == nil {
		return nil
	}
	return d.infrastructure.otelStack.MetricsRecorder
}

// GetOTelContentLoggingConfig returns the content logging configuration for OTel tracing.
// This is useful for middleware and other components that need to know whether
// to capture and redact sensitive content (prompts, completions, tool I/O).
//
// Returns:
//   - *observability.ContentLoggingConfig: The content logging config, or nil if OTel is disabled
//
// Example:
//
//	cfg := d.GetOTelContentLoggingConfig()
//	if cfg != nil && cfg.Enabled {
//	    // Redact and truncate content before logging
//	    safeContent := cfg.Redact(cfg.Truncate(rawContent, cfg.MaxPromptLength))
//	}
func (d *daemonImpl) GetOTelContentLoggingConfig() *observability.ContentLoggingConfig {
	if d.infrastructure == nil || d.infrastructure.otelStack == nil {
		return nil
	}
	return d.infrastructure.otelStack.ContentConfig
}

// shutdownOTelObservability gracefully shuts down the OTel observability stack.
// This method is called during daemon shutdown to flush any buffered spans and metrics.
// It should be called with a context that has a reasonable timeout (5-10 seconds).
//
// The method logs warnings for shutdown failures but does not propagate errors,
// following the daemon shutdown pattern where observability cleanup errors
// should not prevent the daemon from shutting down.
//
// Parameters:
//   - ctx: Context with timeout for shutdown (recommended: 5-10s)
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
//	defer cancel()
//	d.shutdownOTelObservability(ctx)
func (d *daemonImpl) shutdownOTelObservability(ctx context.Context) {
	if d.infrastructure == nil || d.infrastructure.otelStack == nil {
		d.logger.Debug(ctx, "no otel stack to shutdown")
		return
	}

	d.logger.Info(ctx, "shutting down opentelemetry observability stack")

	if err := d.infrastructure.otelStack.Close(ctx); err != nil {
		d.logger.Warn(ctx, "failed to shutdown otel observability stack",
			"error", err)
		// Don't propagate error - continue shutdown
	} else {
		d.logger.Info(ctx, "opentelemetry observability stack shutdown complete")
	}
}
