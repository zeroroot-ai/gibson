package observability

import (
	"fmt"
	"net/url"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/types"
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

// MissionAttributes creates OpenTelemetry attributes from a MissionContext.
func MissionAttributes(mission harness.MissionContext) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonMissionID, mission.ID.String()),
		attribute.String(GibsonMissionName, mission.Name),
	}

	if mission.CurrentAgent != "" {
		attrs = append(attrs, attribute.String(GibsonAgentName, mission.CurrentAgent))
	}

	if mission.Phase != "" {
		attrs = append(attrs, attribute.String("gibson.mission.phase", mission.Phase))
	}

	return attrs
}

// AgentAttributes creates OpenTelemetry attributes for an agent operation.
// It accepts the agent name and optional version.
func AgentAttributes(name string, version string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonAgentName, name),
	}

	if version != "" {
		attrs = append(attrs, attribute.String(GibsonAgentVersion, version))
	}

	return attrs
}

// FindingAttributes creates OpenTelemetry attributes from a Finding.
func FindingAttributes(finding agent.Finding) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonFindingID, finding.ID.String()),
		attribute.String(GibsonFindingSeverity, string(finding.Severity)),
	}

	if finding.Category != "" {
		attrs = append(attrs, attribute.String(GibsonFindingCategory, finding.Category))
	}

	if finding.TargetID != nil {
		attrs = append(attrs, attribute.String("gibson.finding.target_id", finding.TargetID.String()))
	}

	// Add confidence score
	attrs = append(attrs, attribute.Float64("gibson.finding.confidence", finding.Confidence))

	return attrs
}

// ToolAttributes creates OpenTelemetry attributes for a tool operation.
func ToolAttributes(toolName string) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(GibsonToolName, toolName),
	}
}

// PluginAttributes creates OpenTelemetry attributes for a plugin operation.
func PluginAttributes(pluginName, method string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonPluginName, pluginName),
	}

	if method != "" {
		attrs = append(attrs, attribute.String(GibsonPluginMethod, method))
	}

	return attrs
}

// DelegationAttributes creates OpenTelemetry attributes for an agent delegation.
func DelegationAttributes(targetAgent string, taskID types.ID) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String(GibsonDelegationTarget, targetAgent),
		attribute.String(GibsonDelegationTaskID, taskID.String()),
	}
}

// TurnAttributes creates OpenTelemetry attributes for an agent turn.
func TurnAttributes(turnNumber int) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int(GibsonTurnNumber, turnNumber),
	}
}

// CostAttributes creates OpenTelemetry attributes for LLM cost tracking.
func CostAttributes(cost float64) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Float64(GibsonLLMCost, cost),
	}
}

// TaskAttributes creates OpenTelemetry attributes for a task operation.
func TaskAttributes(task agent.Task) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("gibson.task.id", task.ID.String()),
		attribute.String("gibson.task.name", task.Name),
		attribute.Int("gibson.task.priority", task.Priority),
	}

	if task.MissionID != nil {
		attrs = append(attrs, attribute.String(GibsonMissionID, task.MissionID.String()))
	}

	if task.ParentTaskID != nil {
		attrs = append(attrs, attribute.String("gibson.task.parent_id", task.ParentTaskID.String()))
	}

	if task.TargetID != nil {
		attrs = append(attrs, attribute.String("gibson.task.target_id", task.TargetID.String()))
	}

	if len(task.Tags) > 0 {
		attrs = append(attrs, attribute.StringSlice("gibson.task.tags", task.Tags))
	}

	return attrs
}

// MetricsAttributes creates OpenTelemetry attributes from task metrics.
func MetricsAttributes(metrics agent.TaskMetrics) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Int("gibson.metrics.llm_calls", metrics.LLMCalls),
		attribute.Int("gibson.metrics.tool_calls", metrics.ToolCalls),
		attribute.Int("gibson.metrics.plugin_calls", metrics.PluginCalls),
		attribute.Int("gibson.metrics.tokens_used", metrics.TokensUsed),
		attribute.Float64(GibsonLLMCost, metrics.Cost),
		attribute.Int("gibson.metrics.findings_count", metrics.FindingsCount),
		attribute.Int("gibson.metrics.errors", metrics.Errors),
		attribute.Int("gibson.metrics.retries", metrics.Retries),
		attribute.Int("gibson.metrics.sub_tasks", metrics.SubTasks),
	}

	if metrics.Duration > 0 {
		attrs = append(attrs, attribute.String("gibson.metrics.duration", metrics.Duration.String()))
	}

	return attrs
}

// ErrorAttributes creates OpenTelemetry attributes for error tracking.
func ErrorAttributes(err error, code string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Bool("error", true),
		attribute.String("error.message", err.Error()),
	}

	if code != "" {
		attrs = append(attrs, attribute.String("error.code", code))
	}

	return attrs
}

// TargetAttributes creates OpenTelemetry attributes from TargetInfo.
func TargetAttributes(target harness.TargetInfo) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String("gibson.target.id", target.ID.String()),
		attribute.String("gibson.target.name", target.Name),
		attribute.String("gibson.target.type", target.Type),
	}

	if target.Provider != "" {
		attrs = append(attrs, attribute.String("gibson.target.provider", target.Provider))
	}

	if target.URL != "" {
		// Sanitize URL to avoid logging credentials
		attrs = append(attrs, attribute.String("gibson.target.url", sanitizeURL(target.URL)))
	}

	return attrs
}

// sanitizeURL removes credentials from URLs for safe logging.
func sanitizeURL(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		// If URL can't be parsed, return redacted version
		return "[redacted-url]"
	}
	// Redact any credentials in the URL
	if parsed.User != nil {
		parsed.User = url.User("[redacted]")
	}
	return parsed.String()
}

// OrchestratorAttributes creates OpenTelemetry attributes for an orchestrator decision.
// It captures the iteration number, action taken, confidence level, and target node ID.
func OrchestratorAttributes(iteration int, action string, confidence float64, targetNodeID string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.Int(GibsonOrchestratorIteration, iteration),
		attribute.String(GibsonOrchestratorAction, action),
		attribute.Float64(GibsonOrchestratorConfidence, confidence),
	}

	if targetNodeID != "" {
		attrs = append(attrs, attribute.String(GibsonOrchestratorTargetNodeID, targetNodeID))
	}

	return attrs
}

// MissionSummaryAttributes creates OpenTelemetry attributes from mission statistics.
// It captures all mission-level metrics including decisions, executions, tool calls,
// LLM usage, costs, findings, and duration.
func MissionSummaryAttributes(stats MissionStatistics) []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.Int(GibsonMissionTotalDecisions, stats.TotalDecisions),
		attribute.Int(GibsonMissionTotalExecutions, stats.TotalExecutions),
		attribute.Int(GibsonMissionTotalToolCalls, stats.TotalToolCalls),
		attribute.Int(GibsonMissionTotalLLMCalls, stats.TotalLLMCalls),
		attribute.Int(GibsonMissionTotalTokens, stats.TotalTokens),
		attribute.Float64(GibsonMissionTotalCostUSD, stats.TotalCostUSD),
		attribute.Int(GibsonMissionTotalFindings, stats.TotalFindings),
		attribute.Int64(GibsonMissionDurationMs, stats.Duration.Milliseconds()),
	}
}

// ToolExecutionAttributes creates OpenTelemetry attributes for a tool execution.
// It captures the tool name, category, status, duration, and output size.
func ToolExecutionAttributes(name, category, status string, durationMs int64, outputSize int) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonToolName, name),
		attribute.String(GibsonToolStatus, status),
		attribute.Int64(GibsonToolDurationMs, durationMs),
		attribute.Int(GibsonToolOutputSizeBytes, outputSize),
	}

	if category != "" {
		attrs = append(attrs, attribute.String(GibsonToolCategory, category))
	}

	return attrs
}

// MemoryOpAttributes creates OpenTelemetry attributes for a memory operation.
// It captures the memory tier, operation type, key, hit status, size, and result count.
func MemoryOpAttributes(tier, operation, key string, hit bool, sizeBytes int, resultCount int) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonMemoryTier, tier),
		attribute.String(GibsonMemoryOperation, operation),
		attribute.Bool(GibsonMemoryHit, hit),
		attribute.Int(GibsonMemorySizeBytes, sizeBytes),
	}

	if key != "" {
		attrs = append(attrs, attribute.String(GibsonMemoryKey, key))
	}

	if resultCount > 0 {
		attrs = append(attrs, attribute.Int(GibsonMemorySearchResultsCount, resultCount))
	}

	return attrs
}

// GraphOpAttributes creates OpenTelemetry attributes for a graph operation.
// It captures the operation type, nodes and relationships created, and node labels.
func GraphOpAttributes(operation string, nodesCreated, relsCreated int, nodeLabels []string) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonGraphOperation, operation),
		attribute.Int(GibsonGraphNodesCreated, nodesCreated),
		attribute.Int(GibsonGraphRelationshipsCreated, relsCreated),
	}

	if len(nodeLabels) > 0 {
		attrs = append(attrs, attribute.StringSlice(GibsonGraphNodeLabels, nodeLabels))
	}

	return attrs
}

// AgentExecutionAttributes creates OpenTelemetry attributes for an agent execution.
// It captures the agent name, mission node ID, status, attempt number, and duration.
func AgentExecutionAttributes(name, missionNodeID, status string, attempt int, durationMs int64) []attribute.KeyValue {
	attrs := []attribute.KeyValue{
		attribute.String(GibsonAgentName, name),
		attribute.String(GibsonAgentStatus, status),
		attribute.Int(GibsonAgentAttempt, attempt),
		attribute.Int64(GibsonAgentDurationMs, durationMs),
	}

	if missionNodeID != "" {
		attrs = append(attrs, attribute.String(GibsonAgentMissionNodeID, missionNodeID))
	}

	return attrs
}

// CombineAttributes merges multiple attribute slices into one.
func CombineAttributes(attrSets ...[]attribute.KeyValue) []attribute.KeyValue {
	var totalLen int
	for _, attrs := range attrSets {
		totalLen += len(attrs)
	}

	combined := make([]attribute.KeyValue, 0, totalLen)
	for _, attrs := range attrSets {
		combined = append(combined, attrs...)
	}

	return combined
}

// AttributeSet is a builder for creating attribute sets.
type AttributeSet struct {
	attrs []attribute.KeyValue
}

// NewAttributeSet creates a new attribute set builder.
func NewAttributeSet() *AttributeSet {
	return &AttributeSet{
		attrs: make([]attribute.KeyValue, 0, 10),
	}
}

// Add adds attributes to the set.
func (a *AttributeSet) Add(attrs ...attribute.KeyValue) *AttributeSet {
	a.attrs = append(a.attrs, attrs...)
	return a
}

// AddString adds a string attribute.
func (a *AttributeSet) AddString(key, value string) *AttributeSet {
	if value != "" {
		a.attrs = append(a.attrs, attribute.String(key, value))
	}
	return a
}

// AddInt adds an int attribute.
func (a *AttributeSet) AddInt(key string, value int) *AttributeSet {
	a.attrs = append(a.attrs, attribute.Int(key, value))
	return a
}

// AddFloat64 adds a float64 attribute.
func (a *AttributeSet) AddFloat64(key string, value float64) *AttributeSet {
	a.attrs = append(a.attrs, attribute.Float64(key, value))
	return a
}

// AddBool adds a bool attribute.
func (a *AttributeSet) AddBool(key string, value bool) *AttributeSet {
	a.attrs = append(a.attrs, attribute.Bool(key, value))
	return a
}

// AddID adds a types.ID attribute.
func (a *AttributeSet) AddID(key string, id types.ID) *AttributeSet {
	a.attrs = append(a.attrs, attribute.String(key, id.String()))
	return a
}

// Build returns the final attribute slice.
func (a *AttributeSet) Build() []attribute.KeyValue {
	return a.attrs
}

// String returns a string representation of the attribute set.
func (a *AttributeSet) String() string {
	return fmt.Sprintf("AttributeSet{len=%d}", len(a.attrs))
}
