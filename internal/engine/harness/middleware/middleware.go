package middleware

import (
	"context"
	"time"
)

// Middleware intercepts harness operations for cross-cutting concerns like
// tracing, logging, event emission, and planning context management.
// Middleware wraps an Operation and returns a new Operation, allowing
// composition of multiple middleware through chaining.
type Middleware func(Operation) Operation

// Operation represents a harness method invocation.
// It takes a context and request payload, returning a response and error.
// Operations are the target of middleware interception.
type Operation func(ctx context.Context, req any) (any, error)

// Chain composes multiple middleware functions into a single middleware.
// Middleware are applied in the order provided, with the first middleware
// being the outermost wrapper (executed first on the way in, last on the way out).
//
// Example:
//
//	middleware := Chain(
//	    TracingMiddleware(tracer),
//	    LoggingMiddleware(logger),
//	    EventMiddleware(bus),
//	)
func Chain(middlewares ...Middleware) Middleware {
	return func(next Operation) Operation {
		// Apply middleware in reverse order so the first middleware
		// in the list becomes the outermost wrapper
		for i := len(middlewares) - 1; i >= 0; i-- {
			next = middlewares[i](next)
		}
		return next
	}
}

// OperationType identifies which harness method is being invoked.
// This allows middleware to behave differently based on the operation type.
type OperationType string

const (
	// LLM Operations
	OpComplete          OperationType = "complete"
	OpCompleteWithTools OperationType = "complete_with_tools"
	OpStream            OperationType = "stream"

	// Component Operations
	OpCallToolProto   OperationType = "call_tool_proto"
	OpQueryPlugin     OperationType = "query_plugin"
	OpDelegateToAgent OperationType = "delegate_to_agent"

	// List Operations
	OpListTools   OperationType = "list_tools"
	OpListPlugins OperationType = "list_plugins"
	OpListAgents  OperationType = "list_agents"

	// Finding Operations
	OpSubmitFinding OperationType = "submit_finding"
	OpGetFindings   OperationType = "get_findings"

	// Memory Operations
	OpMemoryGet    OperationType = "memory_get"
	OpMemorySet    OperationType = "memory_set"
	OpMemoryDelete OperationType = "memory_delete"
	OpMemoryList   OperationType = "memory_list"
	OpMemorySearch OperationType = "memory_search"

	// GraphRAG Query Operations
	OpGraphRAGQuery           OperationType = "graphrag_query"
	OpGraphRAGSimilarAttacks  OperationType = "graphrag_similar_attacks"
	OpGraphRAGSimilarFindings OperationType = "graphrag_similar_findings"
	OpGraphRAGAttackChains    OperationType = "graphrag_attack_chains"
	OpGraphRAGRelatedFindings OperationType = "graphrag_related_findings"
	OpGraphRAGQueryScoped     OperationType = "graphrag_query_scoped"

	// GraphRAG Storage Operations
	OpGraphRAGStoreNode  OperationType = "graphrag_store_node"
	OpGraphRAGCreateRel  OperationType = "graphrag_create_rel"
	OpGraphRAGStoreBatch OperationType = "graphrag_store_batch"
	OpGraphRAGTraverse   OperationType = "graphrag_traverse"
	OpGraphRAGHealth     OperationType = "graphrag_health"

	// Planning Operations
	OpPlanContext     OperationType = "plan_context"
	OpReportStepHints OperationType = "report_step_hints"

	// Mission Context Operations
	OpMissionContext          OperationType = "mission_context"
	OpMissionExecutionContext OperationType = "mission_execution_context"
	OpMissionRunHistory       OperationType = "mission_run_history"
	OpPreviousRunFindings     OperationType = "previous_run_findings"
	OpAllRunFindings          OperationType = "all_run_findings"

	// Streaming Operations
	OpEmitOutput     OperationType = "emit_output"
	OpEmitToolCall   OperationType = "emit_tool_call"
	OpEmitToolResult OperationType = "emit_tool_result"
	OpEmitFinding    OperationType = "emit_finding"
	OpEmitStatus     OperationType = "emit_status"
	OpEmitError      OperationType = "emit_error"
)

// Context keys for middleware communication
type ctxKey string

const (
	// CtxOperationType stores the OperationType being executed
	CtxOperationType ctxKey = "op_type"

	// CtxStartTime stores the operation start time for duration calculation
	CtxStartTime ctxKey = "start_time"

	// CtxMissionID stores the current mission identifier
	CtxMissionID ctxKey = "mission_id"

	// CtxAgentName stores the current agent name
	CtxAgentName ctxKey = "agent_name"

	// CtxTraceID stores the OpenTelemetry trace ID
	CtxTraceID ctxKey = "trace_id"

	// CtxSpanID stores the OpenTelemetry span ID
	CtxSpanID ctxKey = "span_id"

	// CtxSlotName stores the LLM slot name for LLM operations
	CtxSlotName ctxKey = "slot_name"

	// CtxProvider stores the LLM provider name for LLM operations
	CtxProvider ctxKey = "provider"

	// CtxToolName stores the tool name for tool operations
	CtxToolName ctxKey = "tool_name"

	// CtxPluginName stores the plugin name for plugin operations
	CtxPluginName ctxKey = "plugin_name"

	// CtxPluginMethod stores the plugin method name for plugin operations
	CtxPluginMethod ctxKey = "plugin_method"

	// CtxAgentTargetName stores the target agent name for delegation operations
	CtxAgentTargetName ctxKey = "agent_target_name"

	// CtxMessages stores the LLM messages for LLM operations
	CtxMessages ctxKey = "messages"
)

// WithOperationType returns a new context with the operation type set.
func WithOperationType(ctx context.Context, op OperationType) context.Context {
	return context.WithValue(ctx, CtxOperationType, op)
}

// GetOperationType retrieves the operation type from the context.
// Returns empty string if not set.
func GetOperationType(ctx context.Context) OperationType {
	if op, ok := ctx.Value(CtxOperationType).(OperationType); ok {
		return op
	}
	return ""
}

// WithMissionContext returns a new context with mission ID and agent name set.
func WithMissionContext(ctx context.Context, missionID, agentName string) context.Context {
	ctx = context.WithValue(ctx, CtxMissionID, missionID)
	ctx = context.WithValue(ctx, CtxAgentName, agentName)
	return ctx
}

// GetMissionContext retrieves mission ID and agent name from the context.
// Returns empty strings if not set.
func GetMissionContext(ctx context.Context) (missionID, agentName string) {
	if id, ok := ctx.Value(CtxMissionID).(string); ok {
		missionID = id
	}
	if name, ok := ctx.Value(CtxAgentName).(string); ok {
		agentName = name
	}
	return missionID, agentName
}

// WithTraceContext returns a new context with trace ID and span ID set.
func WithTraceContext(ctx context.Context, traceID, spanID string) context.Context {
	ctx = context.WithValue(ctx, CtxTraceID, traceID)
	ctx = context.WithValue(ctx, CtxSpanID, spanID)
	return ctx
}

// GetTraceContext retrieves trace ID and span ID from the context.
// Returns empty strings if not set.
func GetTraceContext(ctx context.Context) (traceID, spanID string) {
	if id, ok := ctx.Value(CtxTraceID).(string); ok {
		traceID = id
	}
	if span, ok := ctx.Value(CtxSpanID).(string); ok {
		spanID = span
	}
	return traceID, spanID
}

// WithStartTime returns a new context with the start time set.
func WithStartTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, CtxStartTime, t)
}

// GetStartTime retrieves the start time from the context.
// Returns zero time if not set.
func GetStartTime(ctx context.Context) time.Time {
	if t, ok := ctx.Value(CtxStartTime).(time.Time); ok {
		return t
	}
	return time.Time{}
}

// Request and response wrapper types for type-safe operation payloads.

// ChatRequest wraps the parameters for LLM chat operations.
type ChatRequest struct {
	Slot     string
	Messages any // []llm.Message
	Options  any // []CompletionOption
	Tools    any // []llm.ToolDef - for CompleteWithTools
}

// ChatResponse wraps the response from LLM chat operations.
type ChatResponse struct {
	Response any // *llm.CompletionResponse or <-chan llm.StreamChunk
	Error    error
}

// AgentRequest wraps the parameters for agent delegation operations.
type AgentRequest struct {
	Name string
	Task any // agent.Task
}

// AgentResponse wraps the response from agent delegation operations.
type AgentResponse struct {
	Result any // agent.Result
	Error  error
}

// FindingRequest wraps the parameters for finding operations.
type FindingRequest struct {
	Finding any // agent.Finding or FindingFilter
}

// FindingResponse wraps the response from finding operations.
type FindingResponse struct {
	Findings any // []agent.Finding
	Error    error
}

// MemoryRequest wraps the parameters for memory operations.
type MemoryRequest struct {
	Key   string
	Value any
	Query string
	Limit int
}

// MemoryResponse wraps the response from memory operations.
type MemoryResponse struct {
	Value  any
	Values []any
	Error  error
}

// GraphRAGRequest wraps the parameters for GraphRAG operations.
type GraphRAGRequest struct {
	Query       any // graphrag.Query
	Content     string
	FindingID   string
	TechniqueID string
	TopK        int
	MaxDepth    int
	Scope       any // graphrag.MissionScope
}

// GraphRAGResponse wraps the response from GraphRAG operations.
type GraphRAGResponse struct {
	Results any      // Type varies by operation
	NodeID  string   // For store operations
	NodeIDs []string // For batch operations
	Error   error
}

// StreamingRequest wraps the parameters for streaming operations.
type StreamingRequest struct {
	Content     string
	IsReasoning bool
	ToolName    string
	Input       map[string]any
	Output      map[string]any
	CallID      string
	Finding     any // *finding.Finding
	Status      string
	Message     string
	Error       error
	Context     string
}

// StreamingResponse wraps the response from streaming operations.
type StreamingResponse struct {
	Error error
}

// GetSlotName retrieves the LLM slot name from the context.
// Returns empty string if not set.
func GetSlotName(ctx context.Context) string {
	if slot, ok := ctx.Value(CtxSlotName).(string); ok {
		return slot
	}
	return ""
}

// WithSlotName returns a new context with the LLM slot name set.
func WithSlotName(ctx context.Context, slot string) context.Context {
	return context.WithValue(ctx, CtxSlotName, slot)
}

// GetProvider retrieves the LLM provider name from the context.
// Returns empty string if not set.
func GetProvider(ctx context.Context) string {
	if provider, ok := ctx.Value(CtxProvider).(string); ok {
		return provider
	}
	return ""
}

// WithProvider returns a new context with the LLM provider name set.
func WithProvider(ctx context.Context, provider string) context.Context {
	return context.WithValue(ctx, CtxProvider, provider)
}

// GetToolName retrieves the tool name from the context.
// Returns empty string if not set.
func GetToolName(ctx context.Context) string {
	if name, ok := ctx.Value(CtxToolName).(string); ok {
		return name
	}
	return ""
}

// WithToolName returns a new context with the tool name set.
func WithToolName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, CtxToolName, name)
}

// GetPluginInfo retrieves plugin name and method from the context.
// Returns empty strings if not set.
func GetPluginInfo(ctx context.Context) (name, method string) {
	if n, ok := ctx.Value(CtxPluginName).(string); ok {
		name = n
	}
	if m, ok := ctx.Value(CtxPluginMethod).(string); ok {
		method = m
	}
	return name, method
}

// WithPluginInfo returns a new context with plugin name and method set.
func WithPluginInfo(ctx context.Context, name, method string) context.Context {
	ctx = context.WithValue(ctx, CtxPluginName, name)
	ctx = context.WithValue(ctx, CtxPluginMethod, method)
	return ctx
}

// GetAgentTargetName retrieves the target agent name from the context.
// Returns empty string if not set.
func GetAgentTargetName(ctx context.Context) string {
	if name, ok := ctx.Value(CtxAgentTargetName).(string); ok {
		return name
	}
	return ""
}

// WithAgentTargetName returns a new context with the target agent name set.
func WithAgentTargetName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, CtxAgentTargetName, name)
}

// GetMessages retrieves the LLM messages from the context.
// Returns nil if not set.
func GetMessages(ctx context.Context) []Message {
	if msgs, ok := ctx.Value(CtxMessages).([]Message); ok {
		return msgs
	}
	return nil
}

// WithMessages returns a new context with the LLM messages set.
func WithMessages(ctx context.Context, msgs []Message) context.Context {
	return context.WithValue(ctx, CtxMessages, msgs)
}

// Message is a simplified message type for context storage.
// This avoids importing llm package in middleware to prevent cycles.
type Message struct {
	Role    string
	Content string
}

// CompletionResult holds the essential response data for LLM completions.
// This allows the middleware to capture response attributes without
// depending on specific types that may be serialized during transport.
type CompletionResult struct {
	ID            string
	Model         string
	Content       string
	FinishReason  string
	InputTokens   int
	OutputTokens  int
	ToolCallCount int
	ToolCallNames []string
}

// CtxCompletionResult is the context key for the completion result
const CtxCompletionResult ctxKey = "completion_result"

// WithCompletionResult returns a new context with the completion result set.
func WithCompletionResult(ctx context.Context, result *CompletionResult) context.Context {
	return context.WithValue(ctx, CtxCompletionResult, result)
}

// GetCompletionResult retrieves the completion result from the context.
// Returns nil if not set.
func GetCompletionResult(ctx context.Context) *CompletionResult {
	if result, ok := ctx.Value(CtxCompletionResult).(*CompletionResult); ok {
		return result
	}
	return nil
}
