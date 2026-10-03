// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package observability

import (
	"go.opentelemetry.io/otel/attribute"
)

// Gibson-specific attribute keys for observability
const (
	// Agent-specific attributes
	// GibsonAgentName is the name of the Gibson agent
	GibsonAgentName = "gibson.agent.name"

	// GibsonAgentVersion is the version of the agent
	GibsonAgentVersion = "gibson.agent.version"

	// GibsonAgentMissionNodeID is the mission node ID for agent execution
	GibsonAgentMissionNodeID = "gibson.agent.mission_node_id"

	// GibsonAgentAttempt is the attempt number for agent execution
	GibsonAgentAttempt = "gibson.agent.attempt"

	// GibsonAgentStatus is the execution status of the agent
	GibsonAgentStatus = "gibson.agent.status"

	// GibsonAgentDurationMs is the execution duration in milliseconds
	GibsonAgentDurationMs = "gibson.agent.duration_ms"

	// GibsonAgentError is the error message if agent execution failed
	GibsonAgentError = "gibson.agent.error"

	// GibsonAgentToolCallsCount is the number of tool calls made by the agent
	GibsonAgentToolCallsCount = "gibson.agent.tool_calls_count"

	// GibsonAgentFindingsCount is the number of findings submitted by the agent
	GibsonAgentFindingsCount = "gibson.agent.findings_count"

	// GibsonAgentLLMTimeMs is the time spent in LLM operations in milliseconds
	GibsonAgentLLMTimeMs = "gibson.agent.llm_time_ms"

	// GibsonAgentToolTimeMs is the time spent in tool operations in milliseconds
	GibsonAgentToolTimeMs = "gibson.agent.tool_time_ms"

	// GibsonAgentMemoryOpsCount is the number of memory operations performed
	GibsonAgentMemoryOpsCount = "gibson.agent.memory_ops_count"

	// Mission-specific attributes
	// GibsonMissionID is the unique identifier for the mission
	GibsonMissionID = "gibson.mission.id"

	// GibsonMissionName is the name of the mission
	GibsonMissionName = "gibson.mission.name"

	// GibsonMissionTotalDecisions is the total number of orchestrator decisions
	GibsonMissionTotalDecisions = "gibson.mission.total_decisions"

	// GibsonMissionTotalExecutions is the total number of agent executions
	GibsonMissionTotalExecutions = "gibson.mission.total_executions"

	// GibsonMissionTotalToolCalls is the total number of tool calls
	GibsonMissionTotalToolCalls = "gibson.mission.total_tool_calls"

	// GibsonMissionTotalLLMCalls is the total number of LLM calls
	GibsonMissionTotalLLMCalls = "gibson.mission.total_llm_calls"

	// GibsonMissionTotalTokens is the total number of tokens consumed
	GibsonMissionTotalTokens = "gibson.mission.total_tokens"

	// GibsonMissionTotalCostUSD is the total cost in USD
	GibsonMissionTotalCostUSD = "gibson.mission.total_cost_usd"

	// GibsonMissionTotalFindings is the total number of findings
	GibsonMissionTotalFindings = "gibson.mission.total_findings"

	// GibsonMissionDurationMs is the mission duration in milliseconds
	GibsonMissionDurationMs = "gibson.mission.duration_ms"

	// GibsonMissionOutcome is the final outcome of the mission
	GibsonMissionOutcome = "gibson.mission.outcome"

	// GibsonMissionObjective is the mission objective description
	GibsonMissionObjective = "gibson.mission.objective"

	// GibsonMissionTargetRef is the reference to the target being assessed
	GibsonMissionTargetRef = "gibson.mission.target_ref"

	// GibsonMissionStatus is the current status of the mission
	GibsonMissionStatus = "gibson.mission.status"

	// Orchestrator-specific attributes
	// GibsonOrchestratorIteration is the orchestrator iteration number
	GibsonOrchestratorIteration = "gibson.orchestrator.iteration"

	// GibsonOrchestratorAction is the action taken by the orchestrator
	GibsonOrchestratorAction = "gibson.orchestrator.action"

	// GibsonOrchestratorConfidence is the confidence level of the decision
	GibsonOrchestratorConfidence = "gibson.orchestrator.confidence"

	// GibsonOrchestratorTargetNodeID is the target node ID for execution
	GibsonOrchestratorTargetNodeID = "gibson.orchestrator.target_node_id"

	// GibsonOrchestratorGraphContextSize is the size of the graph context
	GibsonOrchestratorGraphContextSize = "gibson.orchestrator.graph_context_size"

	// GibsonOrchestratorReasoning is the reasoning behind the decision
	GibsonOrchestratorReasoning = "gibson.orchestrator.reasoning"

	// GibsonTurnNumber is the turn number in the agent's execution
	GibsonTurnNumber = "gibson.turn.number"

	// Tool-specific attributes
	// GibsonToolName is the name of the tool being used
	GibsonToolName = "gibson.tool.name"

	// GibsonToolCategory is the category of the tool
	GibsonToolCategory = "gibson.tool.category"

	// GibsonToolVersion is the version of the tool
	GibsonToolVersion = "gibson.tool.version"

	// GibsonToolDiscoveryCount is the number of discoveries made by the tool
	GibsonToolDiscoveryCount = "gibson.tool.discovery_count"

	// GibsonToolOutputSizeBytes is the output size in bytes
	GibsonToolOutputSizeBytes = "gibson.tool.output_size_bytes"

	// GibsonToolInputSizeBytes is the input size in bytes
	GibsonToolInputSizeBytes = "gibson.tool.input_size_bytes"

	// GibsonToolDurationMs is the tool execution duration in milliseconds
	GibsonToolDurationMs = "gibson.tool.duration_ms"

	// GibsonToolStatus is the execution status of the tool
	GibsonToolStatus = "gibson.tool.status"

	// GibsonToolError is the error message if tool execution failed
	GibsonToolError = "gibson.tool.error"

	// Plugin-specific attributes
	// GibsonPluginName is the name of the plugin being called
	GibsonPluginName = "gibson.plugin.name"

	// GibsonPluginMethod is the method being called on the plugin
	GibsonPluginMethod = "gibson.plugin.method"

	// Delegation-specific attributes
	// GibsonDelegationTarget is the target agent for delegation
	GibsonDelegationTarget = "gibson.delegation.target_agent"

	// GibsonDelegationTaskID is the task ID for delegation
	GibsonDelegationTaskID = "gibson.delegation.task_id"

	// Finding-specific attributes
	// GibsonFindingID is the unique identifier for a finding
	GibsonFindingID = "gibson.finding.id"

	// GibsonFindingSeverity is the severity level of a finding
	GibsonFindingSeverity = "gibson.finding.severity"

	// GibsonFindingCategory is the category of the finding
	GibsonFindingCategory = "gibson.finding.category"

	// GibsonFindingTitle is the title of the finding
	GibsonFindingTitle = "gibson.finding.title"

	// GibsonFindingConfidence is the confidence score of the finding
	GibsonFindingConfidence = "gibson.finding.confidence"

	// GibsonFindingTargetID is the target ID associated with the finding
	GibsonFindingTargetID = "gibson.finding.target_id"

	// GibsonFindingCVSSScore is the CVSS score of the finding
	GibsonFindingCVSSScore = "gibson.finding.cvss_score"

	// GibsonFindingNeo4jNodeID is the Neo4j node ID for the finding
	GibsonFindingNeo4jNodeID = "gibson.finding.neo4j_node_id"

	// Memory-specific attributes
	// GibsonMemoryTier is the memory tier (e.g., short-term, long-term)
	GibsonMemoryTier = "gibson.memory.tier"

	// GibsonMemoryKey is the memory key being accessed
	GibsonMemoryKey = "gibson.memory.key"

	// GibsonMemoryOperation is the operation being performed (read, write, search)
	GibsonMemoryOperation = "gibson.memory.operation"

	// GibsonMemoryHit indicates whether the memory operation was a hit
	GibsonMemoryHit = "gibson.memory.hit"

	// GibsonMemorySizeBytes is the size of the memory data in bytes
	GibsonMemorySizeBytes = "gibson.memory.size_bytes"

	// GibsonMemorySearchResultsCount is the number of search results returned
	GibsonMemorySearchResultsCount = "gibson.memory.search_results_count"

	// GibsonMemoryDurationMs is the memory operation duration in milliseconds
	GibsonMemoryDurationMs = "gibson.memory.duration_ms"

	// Graph-specific attributes
	// GibsonGraphOperation is the graph operation being performed
	GibsonGraphOperation = "gibson.graph.operation"

	// GibsonGraphNodesCreated is the number of nodes created
	GibsonGraphNodesCreated = "gibson.graph.nodes_created"

	// GibsonGraphRelationshipsCreated is the number of relationships created
	GibsonGraphRelationshipsCreated = "gibson.graph.relationships_created"

	// GibsonGraphNodeLabels is the labels of nodes involved in the operation
	GibsonGraphNodeLabels = "gibson.graph.node_labels"

	// GibsonGraphQueryType is the type of query being executed
	GibsonGraphQueryType = "gibson.graph.query_type"

	// GibsonGraphResultsCount is the number of results returned
	GibsonGraphResultsCount = "gibson.graph.results_count"

	// GibsonGraphDurationMs is the graph operation duration in milliseconds
	GibsonGraphDurationMs = "gibson.graph.duration_ms"

	// LLM-specific attributes
	// GibsonLLMCost is the cost of LLM operations in USD
	GibsonLLMCost = "gibson.llm.cost"
)

// Gibson span name constants for various operations
const (
	// SpanMissionExecute represents a mission execution operation
	SpanMissionExecute = "gibson.mission.execute"

	// SpanAgentDelegate represents an agent delegation operation
	SpanAgentDelegate = "gibson.agent.delegate"

	// SpanAgentExecute represents an agent execution operation
	SpanAgentExecute = "gibson.agent.execute"

	// SpanFindingSubmit represents a finding submission operation
	SpanFindingSubmit = "gibson.finding.submit"

	// SpanPluginQuery represents a plugin query operation
	SpanPluginQuery = "gibson.plugin.query"

	// SpanMemoryGet represents a memory retrieval operation
	SpanMemoryGet = "gibson.memory.get"

	// SpanMemorySet represents a memory storage operation
	SpanMemorySet = "gibson.memory.set"

	// SpanMemorySearch represents a memory search operation
	SpanMemorySearch = "gibson.memory.search"
)

// AttributeSet is a builder for creating attribute sets.
type AttributeSet struct {
	attrs []attribute.KeyValue
}
