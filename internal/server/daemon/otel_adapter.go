// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// GetOTelMetricsRecorder returns the OTelMetricsRecorder when OTel
// observability is on in the config, else nil. OTel is a config choice, not a
// required dependency, so nil is a valid answer and the caller checks it.
//
// Example usage:
//
//	if recorder := d.GetOTelMetricsRecorder(); recorder != nil {
//	    recorder.RecordLLMCompletion(ctx, provider, model, status, inputTokens, outputTokens, latency, cost)
//	}
func (d *daemonImpl) GetOTelMetricsRecorder() *observability.OTelMetricsRecorder {
	if d.infrastructure != nil && d.infrastructure.otelStack != nil {
		return d.infrastructure.otelStack.MetricsRecorder
	}
	return nil
}
