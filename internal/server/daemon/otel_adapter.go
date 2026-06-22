package daemon

import (
	"context"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

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
