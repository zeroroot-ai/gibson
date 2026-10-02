// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// GetOTelMetricsRecorder returns the OTelMetricsRecorder if OTel observability is enabled.
// This is useful for components that need to record custom metrics.
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
