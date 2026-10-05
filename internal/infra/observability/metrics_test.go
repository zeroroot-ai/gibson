// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMetricNameConstants tests that metric name constants are properly defined.
func TestMetricNameConstants(t *testing.T) {
	// Verify all metric constants are non-empty and follow naming convention
	metrics := map[string]string{
		"LLM Completions":    MetricLLMCompletions,
		"LLM Input Tokens":   MetricLLMTokensInput,
		"LLM Output Tokens":  MetricLLMTokensOutput,
		"LLM Latency":        MetricLLMLatency,
		"LLM Cost":           MetricLLMCost,
		"Tool Calls":         MetricToolCalls,
		"Tool Duration":      MetricToolDuration,
		"Findings Submitted": MetricFindingsSubmitted,
		"Agent Delegations":  MetricAgentDelegations,
	}

	for name, constant := range metrics {
		t.Run(name, func(t *testing.T) {
			assert.NotEmpty(t, constant, "metric constant should not be empty")
			assert.Contains(t, constant, "gibson.", "metric should have gibson. prefix")
		})
	}
}
