// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

// Metric name constants for Gibson framework observability.
// These constants provide a centralized definition of all metric names
// to ensure consistency across the codebase and prevent typos.
const (
	// LLM completion metrics
	MetricLLMCompletions  = "gibson.llm.completions"
	MetricLLMTokensInput  = "gibson.llm.tokens.input"
	MetricLLMTokensOutput = "gibson.llm.tokens.output"
	MetricLLMLatency      = "gibson.llm.latency"
	MetricLLMCost         = "gibson.llm.cost"

	// Tool execution metrics
	MetricToolCalls    = "gibson.tool.calls"
	MetricToolDuration = "gibson.tool.duration"

	// Finding submission metrics
	MetricFindingsSubmitted = "gibson.findings.submitted"

	// Agent delegation metrics
	MetricAgentDelegations = "gibson.agent.delegations"

	// Mission metrics
	MetricMissionStatus     = "gibson.mission.status"
	MetricMissionDuration   = "gibson.mission.duration"
	MetricMissionNodes      = "gibson.mission.nodes"
	MetricMissionsActive    = "gibson.missions.active"
	MetricMissionsTotal     = "gibson.missions.total"
	MetricMissionIterations = "gibson.mission.iterations"
)
