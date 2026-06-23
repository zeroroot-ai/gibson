package daemon

import (
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

