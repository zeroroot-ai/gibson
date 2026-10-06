// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"testing"

	"github.com/zeroroot-ai/gibson/internal/infra/observability"
)

// The recorder exists only when OTel is on in the config.
func TestGetOTelMetricsRecorder(t *testing.T) {
	rec := &observability.OTelMetricsRecorder{}
	on := &daemonImpl{infrastructure: &Infrastructure{otelStack: &observability.OTelObservabilityStack{MetricsRecorder: rec}}}
	if got := on.GetOTelMetricsRecorder(); got != rec {
		t.Fatalf("OTel on: recorder = %p, want %p", got, rec)
	}
	for name, d := range map[string]*daemonImpl{
		"no infrastructure": {},
		"OTel off":          {infrastructure: &Infrastructure{}},
	} {
		if got := d.GetOTelMetricsRecorder(); got != nil {
			t.Errorf("%s: recorder = %p, want nil", name, got)
		}
	}
}
