package harness

import (
	"context"
	"log/slog"

	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
	sdkagent "github.com/zero-day-ai/sdk/agent"
	"github.com/zero-day-ai/sdk/codegen/workspace"
	sdktypes "github.com/zero-day-ai/sdk/types"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
)

// EventLogger provides structured event logging with trace correlation.
// This interface allows the harness to emit typed events without creating
// a circular dependency on the observability package.
//
// The interface matches the subset of observability.Logger methods needed
// for event emission in the harness.
type EventLogger interface {
	// Event logs a structured event with type and data.
	// Events are logged at Info level and include event_type and event_data fields.
	Event(ctx context.Context, eventType string, msg string, data any)
}

// Event type constants for harness operations
// These match the constants in observability.EventType
const (
	EventLLMRequest  = "llm_request"
	EventLLMResponse = "llm_response"
	EventToolCall    = "tool_call"
	EventToolResult  = "tool_result"
	EventFinding     = "finding"
)

// LLMRequestEventData captures LLM request metadata (no sensitive content)
type LLMRequestEventData struct {
	Model        string `json:"model"`
	MessageCount int    `json:"message_count"`
	Slot         string `json:"slot"`
}

// LLMResponseEventData captures LLM response metadata and token usage
type LLMResponseEventData struct {
	Model            string `json:"model"`
	PromptTokens     int    `json:"prompt_tokens"`
	CompletionTokens int    `json:"completion_tokens"`
	TotalTokens      int    `json:"total_tokens"`
	Slot             string `json:"slot"`
}

// ToolCallEventData captures tool invocation information
type ToolCallEventData struct {
	ToolName string `json:"tool_name"`
}

// ToolResultEventData captures tool execution results
type ToolResultEventData struct {
	ToolName string `json:"tool_name"`
	Success  bool   `json:"success"`
	Error    string `json:"error,omitempty"`
}

// FindingEventData captures security finding information
type FindingEventData struct {
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Confidence  string `json:"confidence"`
	TargetAsset string `json:"target_asset,omitempty"`
}

// StructuredCompletionResult contains the result of a structured completion
// along with token usage information for observability and cost tracking.
type StructuredCompletionResult struct {
	// Result is the parsed structured output (pointer to the schema type)
	Result any

	// Model is the name of the model that was used
	Model string

	// RawJSON is the raw JSON response from the LLM
	RawJSON string

	// PromptTokens is the number of tokens in the prompt
	PromptTokens int

	// CompletionTokens is the number of tokens in the completion
	CompletionTokens int

	// TotalTokens is the total token usage (prompt + completion)
	TotalTokens int
}

// AgentHarness is the primary interface provided to agents during execution.
// It orchestrates access to all framework capabilities including LLM operations,
// tool execution, plugin queries, sub-agent delegation, finding management,
// memory storage, and observability primitives.
//
// The harness abstracts infrastructure complexity, allowing agents to focus on
// implementing their core logic while the framework handles:
//   - LLM provider management and slot-based model selection
//   - Tool registration, validation, and execution
//   - Plugin lifecycle and communication
//   - Sub-agent discovery and delegation
//   - Finding storage and querying
//   - Memory tier coordination (working, mission, long-term)
//   - Distributed tracing and structured logging
//   - Metrics collection and token usage tracking
//
// All methods are safe for concurrent use. The harness ensures thread-safety
// for shared resources and coordinates access across multiple agents.
//
// Example usage:
//
//	func (a *MyAgent) Execute(ctx context.Context, task agent.Task, harness harness.AgentHarness) (agent.Result, error) {
//	    // Use the harness to perform LLM completion
//	    resp, err := harness.Complete(ctx, "primary", messages)
//
//	    // Submit a security finding
//	    finding := agent.NewFinding("XSS Vulnerability", "Found in login form", agent.SeverityHigh)
//	    harness.SubmitFinding(ctx, finding)
//
//	    // Store data in working memory
//	    harness.Memory().Working().Set(ctx, "scan_results", scanData)
//
//	    return result, nil
//	}
type AgentHarness interface {
	// ────────────────────────────────────────────────────────────────────────────
	// LLM Access
	// ────────────────────────────────────────────────────────────────────────────

	// Complete performs a synchronous LLM completion using the specified slot.
	// The slot determines which provider and model to use based on configuration.
	//
	// Parameters:
	//   - ctx: Context for cancellation, timeout, and distributed tracing
	//   - slot: Name of the LLM slot (e.g., "primary", "reasoning", "fast")
	//   - messages: Conversation history with system, user, and assistant messages
	//   - opts: Optional configuration (temperature, max tokens, etc.)
	//
	// Returns:
	//   - *llm.CompletionResponse: The LLM's response with generated message and token usage
	//   - error: Non-nil if completion fails (invalid slot, API error, budget exceeded)
	//
	// The harness automatically:
	//   - Validates messages before sending to the provider
	//   - Tracks token usage and enforces budget limits
	//   - Records metrics (latency, token count, cost)
	//   - Creates distributed trace spans
	//   - Handles provider-specific error translation
	//
	// Example:
	//   messages := []llm.Message{
	//       llm.NewSystemMessage("You are a security analyst"),
	//       llm.NewUserMessage("Analyze this code for vulnerabilities"),
	//   }
	//   resp, err := harness.Complete(ctx, "primary", messages, WithTemperature(0.2))
	Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error)

	// CompleteWithTools performs a completion with tool-calling capabilities.
	// The LLM can request tool executions by returning tool calls in the response.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - slot: Name of the LLM slot to use
	//   - messages: Conversation history
	//   - tools: Available tools the LLM can choose to call
	//   - opts: Optional configuration
	//
	// Returns:
	//   - *llm.CompletionResponse: Response that may contain tool calls or final text
	//   - error: Non-nil if completion fails
	//
	// The agent is responsible for:
	//   1. Checking response.Message.ToolCalls to see if the LLM requested tool execution
	//   2. Executing the requested tools using CallToolProto()
	//   3. Appending tool results to messages and calling Complete() again
	//
	// Example:
	//   resp, err := harness.CompleteWithTools(ctx, "primary", messages, tools)
	//   for _, toolCall := range resp.Message.ToolCalls {
	//       req := &toolpb.Request{} // Populate from toolCall
	//       resp := &toolpb.Response{}
	//       harness.CallToolProto(ctx, toolCall.Name, req, resp)
	//       messages = append(messages, llm.NewToolResultMessage(toolCall.ID, resp))
	//   }
	CompleteWithTools(ctx context.Context, slot string, messages []llm.Message, tools []llm.ToolDef, opts ...CompletionOption) (*llm.CompletionResponse, error)

	// Stream performs a streaming LLM completion, returning chunks as they arrive.
	// This enables real-time processing and display of LLM output.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - slot: Name of the LLM slot to use
	//   - messages: Conversation history
	//   - opts: Optional configuration
	//
	// Returns:
	//   - <-chan llm.StreamChunk: Read-only channel of response chunks
	//   - error: Non-nil if stream setup fails (does not include streaming errors)
	//
	// The returned channel:
	//   - Sends incremental chunks (StreamChunk) as the LLM generates output
	//   - Sends a chunk with FinishReason when generation completes
	//   - Sends a chunk with Error field set if streaming fails
	//   - Is closed when the stream ends (success or failure)
	//
	// The caller must consume the channel until it closes. Context cancellation
	// will close the channel and stop streaming.
	//
	// Example:
	//   chunks, err := harness.Stream(ctx, "primary", messages)
	//   for chunk := range chunks {
	//       if chunk.Error != nil {
	//           return chunk.Error
	//       }
	//       fmt.Print(chunk.Delta.Content)
	//   }
	Stream(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (<-chan llm.StreamChunk, error)

	// CompleteStructuredAny performs a completion with provider-native structured output.
	// The response is guaranteed to match the provided schema using provider-specific
	// mechanisms (tool_use for Anthropic, response_format for OpenAI).
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - slot: Name of the LLM slot to use
	//   - messages: Conversation history (should be natural language, no JSON instructions)
	//   - schemaType: An instance of the struct type to populate (e.g., MyStruct{})
	//   - opts: Optional configuration
	//
	// Returns:
	//   - any: A pointer to the populated struct instance (e.g., *MyStruct)
	//   - error: Non-nil if completion fails or response doesn't match schema
	//
	// The prompt should be natural language - the harness handles schema enforcement.
	// For Anthropic: uses tool_use pattern with forced tool choice
	// For OpenAI: uses response_format with json_schema
	//
	// Example:
	//   type Analysis struct {
	//       RiskLevel   string   `json:"risk_level"`
	//       Findings    []string `json:"findings"`
	//   }
	//   result, err := harness.CompleteStructuredAny(ctx, "primary", messages, Analysis{})
	//   analysis := result.(*Analysis)
	CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error)

	// CompleteStructuredAnyWithUsage performs structured output completion and returns
	// token usage information along with the result. This is useful for cost tracking
	// and observability in orchestration systems.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - slot: Name of the LLM slot to use
	//   - messages: Conversation history
	//   - schemaType: An instance of the struct type to populate
	//   - opts: Optional configuration
	//
	// Returns:
	//   - *StructuredCompletionResult: Contains the parsed result, model, and token usage
	//   - error: Non-nil if completion fails or response doesn't match schema
	CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error)

	// ────────────────────────────────────────────────────────────────────────────
	// Tool Execution
	// ────────────────────────────────────────────────────────────────────────────

	// CallToolProto executes a registered tool by name using Protocol Buffer messages.
	// This is the canonical method for tool execution in Gibson. Tools are typically
	// called in response to LLM tool requests, but agents can also call tools directly.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - name: Name of the tool to execute (must be registered)
	//   - request: Tool input as a proto message (validated against tool's proto schema)
	//   - response: Proto message to populate with tool output
	//
	// Returns:
	//   - error: Non-nil if tool not found, validation fails, or execution fails
	//
	// The harness:
	//   - Validates request against the tool's proto schema
	//   - Executes the tool with proper context propagation
	//   - Records execution metrics (duration, success/failure)
	//   - Creates distributed trace spans
	//   - Handles timeouts and cancellation
	//   - Populates the response proto message with tool output
	//
	// Example:
	//   req := &portscannerpb.ScanRequest{Target: "192.168.1.1", Ports: "1-1024"}
	//   resp := &portscannerpb.ScanResponse{}
	//   err := harness.CallToolProto(ctx, "nmap_scan", req, resp)
	CallToolProto(ctx context.Context, name string, request, response proto.Message) error

	// CallToolProtoStream invokes a tool by name with streaming event callbacks.
	// This is the streaming counterpart to CallToolProto. The tool reports
	// progress, partial results, and warnings to the callback as it executes;
	// the final output proto is populated on success and is also delivered to
	// the callback as a partial just before this method returns.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - name: Name of the tool to execute (must be registered)
	//   - request: Tool input as a proto message (validated against tool's proto schema)
	//   - response: Proto message to populate with tool output (final state)
	//   - callback: Streaming callback receiving Progress / Partial / Warning / Error events
	//
	// Returns:
	//   - error: Non-nil if tool not found, validation fails, or execution fails fatally
	//
	// Spec: headline-feature-completion R1.
	CallToolProtoStream(ctx context.Context, name string, request, response proto.Message, callback sdkagent.ToolStreamCallback) error

	// ListTools returns descriptors for all registered tools.
	// This enables dynamic tool discovery and capability introspection.
	//
	// Returns:
	//   - []ToolDescriptor: Metadata for each available tool (name, description, schema)
	//
	// Use this to:
	//   - Build tool lists for LLM tool-calling
	//   - Discover available capabilities
	//   - Filter tools by tags or capabilities
	//
	// Example:
	//   tools := harness.ListTools()
	//   for _, t := range tools {
	//       if t.HasTag("network") {
	//           fmt.Printf("Network tool: %s - %s\n", t.Name, t.Description)
	//       }
	//   }
	ListTools() []ToolDescriptor

	// GetToolDescriptor returns the descriptor for a specific tool by name.
	// This enables retrieval of tool metadata including output schema with taxonomy mappings.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - name: Name of the tool to retrieve
	//
	// Returns:
	//   - *ToolDescriptor: Metadata for the tool (name, description, schema with taxonomy)
	//   - error: Non-nil if tool is not found
	//
	// The output schema's Taxonomy field contains mappings for entity extraction.
	GetToolDescriptor(ctx context.Context, name string) (*ToolDescriptor, error)

	// GetToolCapabilities retrieves runtime capabilities for a registered tool.
	// This method queries the tool to understand what operations it can perform
	// based on the execution environment (e.g., root access, raw socket capability).
	//
	// Capabilities include:
	//   - HasRoot: Tool is running with root privileges
	//   - HasSudo: Passwordless sudo access is available
	//   - CanRawSocket: Ability to create raw network sockets
	//   - Features: Tool-specific feature availability flags
	//   - BlockedArgs: Command-line arguments that cannot be used
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - toolName: Name of the tool to query (must be registered)
	//
	// Returns:
	//   - *sdktypes.Capabilities: The tool's runtime capabilities
	//   - error: Non-nil if tool not found or capabilities unavailable
	//
	// Example:
	//   caps, err := harness.GetToolCapabilities(ctx, "nmap")
	//   if err != nil {
	//       return err
	//   }
	//   if caps.CanRawSocket {
	//       // Use stealth scan (-sS)
	//   } else {
	//       // Fall back to connect scan (-sT)
	//   }
	GetToolCapabilities(ctx context.Context, toolName string) (*sdktypes.Capabilities, error)

	// GetAllToolCapabilities returns capabilities for all registered tools.
	// This enables agents to understand tool privilege requirements and limitations.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//
	// Returns:
	//   - map[string]*sdktypes.Capabilities: Map of tool names to their capabilities
	//   - error: Non-nil if retrieval fails
	//
	// Tools that don't implement CapabilityProvider are excluded from the result.
	// The returned map can be stored in working memory for agent access.
	//
	// Example:
	//   caps, err := harness.GetAllToolCapabilities(ctx)
	//   if err == nil {
	//       harness.Memory().Working().Set(ctx, "tool_capabilities", caps)
	//   }
	GetAllToolCapabilities(ctx context.Context) (map[string]*sdktypes.Capabilities, error)

	// ────────────────────────────────────────────────────────────────────────────
	// Plugin Access
	// ────────────────────────────────────────────────────────────────────────────

	// QueryPlugin calls a method on a registered plugin with the given parameters.
	// Plugins provide extended functionality beyond tools, often with stateful
	// or complex interactions.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - name: Name of the plugin (must be registered and initialized)
	//   - method: Name of the method to call on the plugin
	//   - params: Method parameters as a map (plugin-specific format)
	//
	// Returns:
	//   - any: Method return value (type depends on plugin method)
	//   - error: Non-nil if plugin not found, method doesn't exist, or execution fails
	//
	// The harness:
	//   - Ensures the plugin is initialized before calling methods
	//   - Validates method existence and parameters
	//   - Records metrics for plugin operations
	//   - Creates distributed trace spans
	//   - Handles plugin lifecycle (initialization, health checks)
	//
	// Example:
	//   params := map[string]any{"query": "SELECT * FROM findings WHERE severity='critical'"}
	//   result, err := harness.QueryPlugin(ctx, "database", "query", params)
	QueryPlugin(ctx context.Context, name string, method string, params map[string]any) (any, error)

	// ListPlugins returns descriptors for all registered plugins.
	// This enables dynamic plugin discovery and capability introspection.
	//
	// Returns:
	//   - []PluginDescriptor: Metadata for each available plugin (name, version, methods, status)
	//
	// Example:
	//   plugins := harness.ListPlugins()
	//   for _, p := range plugins {
	//       fmt.Printf("Plugin: %s v%s (%d methods)\n", p.Name, p.Version, len(p.Methods))
	//   }
	ListPlugins() []PluginDescriptor

	// ────────────────────────────────────────────────────────────────────────────
	// Sub-Agent Delegation
	// ────────────────────────────────────────────────────────────────────────────

	// DelegateToAgent delegates a task to another registered agent for execution.
	// This enables hierarchical agent missions and specialization.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing (inherited by sub-agent)
	//   - name: Name of the agent to delegate to (must be registered)
	//   - task: The task to execute (contains input, constraints, etc.)
	//
	// Returns:
	//   - agent.Result: The sub-agent's execution result (output, findings, metrics)
	//   - error: Non-nil if agent not found or delegation fails
	//
	// The harness:
	//   - Validates the target agent exists and is available
	//   - Propagates context (mission ID, tracing, logging) to the sub-agent
	//   - Provides the sub-agent with its own harness instance
	//   - Aggregates metrics and findings from the sub-agent
	//   - Handles sub-agent failures and timeouts
	//
	// The sub-agent receives:
	//   - The same mission context
	//   - Access to the same memory store (mission and long-term memory)
	//   - Its own working memory instance (isolated from parent)
	//   - Its own token usage tracking (aggregated to mission level)
	//
	// Example:
	//   task := agent.NewTask("subdomain_enum", "Enumerate subdomains for target", input)
	//   result, err := harness.DelegateToAgent(ctx, "recon_agent", task)
	//   parentResult.Findings = append(parentResult.Findings, result.Findings...)
	DelegateToAgent(ctx context.Context, name string, task agent.Task) (agent.Result, error)

	// ListAgents returns descriptors for all registered agents.
	// This enables dynamic agent discovery and delegation planning.
	//
	// Returns:
	//   - []AgentDescriptor: Metadata for each available agent (name, capabilities, slots)
	//
	// Example:
	//   agents := harness.ListAgents()
	//   for _, a := range agents {
	//       if a.HasCapability("network_scanning") {
	//           result, _ := harness.DelegateToAgent(ctx, a.Name, scanTask)
	//       }
	//   }
	ListAgents() []AgentDescriptor

	// ────────────────────────────────────────────────────────────────────────────
	// Findings Management
	// ────────────────────────────────────────────────────────────────────────────

	// SubmitFinding stores a security finding for the current mission.
	// Findings are indexed by mission ID and available for querying and reporting.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - finding: The security finding to store (must have valid severity, confidence, etc.)
	//
	// Returns:
	//   - error: Non-nil if storage fails
	//
	// The harness:
	//   - Associates the finding with the current mission ID
	//   - Validates finding fields (severity, confidence range)
	//   - Records metrics (findings by severity, category, etc.)
	//   - Emits events for finding submission (for real-time monitoring)
	//
	// Example:
	//   finding := agent.NewFinding("SQL Injection", "Parameter 'id' is vulnerable", agent.SeverityHigh).
	//       WithConfidence(0.95).
	//       WithCategory("injection").
	//       WithCWE("CWE-89")
	//   err := harness.SubmitFinding(ctx, finding)
	SubmitFinding(ctx context.Context, finding agent.Finding) error

	// GetFindings retrieves findings for the current mission, optionally filtered.
	// This enables agents to query previous findings and avoid duplicate work.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - filter: Filter criteria (severity, confidence, category, etc.)
	//
	// Returns:
	//   - []agent.Finding: Findings matching the filter (empty if none match)
	//   - error: Non-nil if retrieval fails
	//
	// Example:
	//   // Get all critical findings
	//   filter := NewFindingFilter().WithSeverity(agent.SeverityCritical)
	//   findings, err := harness.GetFindings(ctx, *filter)
	GetFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error)

	// ────────────────────────────────────────────────────────────────────────────
	// Memory Access
	// ────────────────────────────────────────────────────────────────────────────

	// Memory provides access to the unified memory store with three tiers:
	//   - Working: Ephemeral key-value storage scoped to agent execution
	//   - Mission: Persistent storage scoped to the current mission
	//   - LongTerm: Semantic search over historical data across all missions
	//
	// Returns:
	//   - memory.MemoryStore: Interface for accessing all memory tiers
	//
	// Working memory:
	//   - Isolated per agent execution (not shared with sub-agents)
	//   - Cleared when agent completes
	//   - Fast in-memory operations
	//
	// Mission memory:
	//   - Shared across all agents in a mission
	//   - Persisted for mission duration
	//   - Enables inter-agent communication
	//
	// Long-term memory:
	//   - Vector embeddings for semantic search
	//   - Persisted across missions
	//   - Enables learning from historical executions
	//
	// Example:
	//   // Store in working memory
	//   harness.Memory().Working().Set(ctx, "scan_results", data)
	//
	//   // Query mission memory
	//   targets, _ := harness.Memory().Mission().Get(ctx, "discovered_targets")
	//
	//   // Search long-term memory
	//   similar, _ := harness.Memory().LongTerm().Search(ctx, "SQL injection findings", 10)
	Memory() memory.MemoryStore

	// ────────────────────────────────────────────────────────────────────────────
	// Context Access
	// ────────────────────────────────────────────────────────────────────────────

	// MissionID returns the mission ID for the current execution context.
	//
	// Returns:
	//   - types.ID: The unique identifier for the current mission
	//
	// Example:
	//   missionID := harness.MissionID()
	//   logger.Info("Executing mission", "mission_id", missionID)
	MissionID() types.ID

	// Mission returns the current mission context.
	// This provides mission-level metadata, phase information, and constraints.
	//
	// Returns:
	//   - MissionContext: Current mission metadata
	//
	// Example:
	//   mission := harness.Mission()
	//   logger.Info("Executing mission", "name", mission.Name, "phase", mission.Phase)
	Mission() MissionContext

	// Workspace returns the primary workspace for single-repository
	// missions. Returns nil if no workspaces are configured for this
	// mission.
	//
	// Spec: callback-harness-workspace-rpcs (lifts the method onto the
	// AgentHarness interface so the callback service handlers can
	// route to it through any middleware wrapper).
	Workspace() workspace.Workspace

	// Workspaces returns all workspaces keyed by repository name.
	// Returns an empty map if no workspaces are configured.
	Workspaces() map[string]workspace.Workspace

	// MissionExecutionContext returns comprehensive mission execution information.
	// This includes run history, resume status, and memory continuity indicators
	// to help agents make informed decisions based on mission history.
	//
	// Returns:
	//   - MissionExecutionContextSDK: Enhanced mission context with run history
	//
	// Example:
	//   execCtx := harness.MissionExecutionContext()
	//   if execCtx.IsResumed {
	//       logger.Info("Resuming mission", "run_number", execCtx.RunNumber)
	//   }
	//   if execCtx.MemoryContinuity == "new_run_with_history" {
	//       // Query previous run findings for context
	//   }
	MissionExecutionContext() MissionExecutionContextSDK

	// GetMissionRunHistory returns all runs for the current mission name.
	// Results are ordered by run number descending (most recent first).
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//
	// Returns:
	//   - []MissionRunSummarySDK: Summary of all runs for this mission
	//   - error: Non-nil if retrieval fails
	//
	// Example:
	//   runs, err := harness.GetMissionRunHistory(ctx)
	//   for _, run := range runs {
	//       logger.Info("Previous run", "number", run.RunNumber, "status", run.Status, "findings", run.FindingsCount)
	//   }
	GetMissionRunHistory(ctx context.Context) ([]MissionRunSummarySDK, error)

	// GetPreviousRunFindings retrieves findings from the previous mission run.
	// This enables agents to understand what was discovered in prior attempts.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - filter: Filter criteria for findings (severity, category, etc.)
	//
	// Returns:
	//   - []agent.Finding: Findings from the previous run matching the filter
	//   - error: Non-nil if retrieval fails
	//
	// Example:
	//   // Get all critical findings from previous run
	//   filter := NewFindingFilter().WithSeverity(agent.SeverityCritical)
	//   prevFindings, err := harness.GetPreviousRunFindings(ctx, *filter)
	GetPreviousRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error)

	// GetAllRunFindings retrieves findings from all runs of this mission.
	// This provides complete historical context across all mission executions.
	//
	// Parameters:
	//   - ctx: Context for cancellation and tracing
	//   - filter: Filter criteria for findings (severity, category, etc.)
	//
	// Returns:
	//   - []agent.Finding: Findings from all runs matching the filter
	//   - error: Non-nil if retrieval fails
	//
	// Example:
	//   // Get all findings across all runs
	//   filter := NewFindingFilter()
	//   allFindings, err := harness.GetAllRunFindings(ctx, *filter)
	GetAllRunFindings(ctx context.Context, filter FindingFilter) ([]agent.Finding, error)

	// Target returns information about the current target.
	// This provides target URL, authentication, and provider-specific metadata.
	//
	// Returns:
	//   - TargetInfo: Current target metadata
	//
	// Example:
	//   target := harness.Target()
	//   req, _ := http.NewRequest("GET", target.URL, nil)
	//   for k, v := range target.Headers {
	//       req.Header.Set(k, v)
	//   }
	Target() TargetInfo

	// ────────────────────────────────────────────────────────────────────────────
	// Observability
	// ────────────────────────────────────────────────────────────────────────────

	// ────────────────────────────────────────────────────────────────────────────
	// Checkpoint Access
	// ────────────────────────────────────────────────────────────────────────────

	// Checkpoint provides access to the checkpointing system for state management.
	// This enables agents to interact with checkpoints for history tracking and
	// cross-run continuity.
	//
	// Returns:
	//   - CheckpointAccess: Interface for checkpoint operations
	//
	// If checkpointing is not enabled for the mission, all checkpoint methods
	// will return ErrCheckpointingDisabled.
	//
	// Use this to:
	//   - Access current checkpoint state
	//   - Create explicit checkpoints at important milestones
	//   - Review checkpoint history
	//   - Access state from previous runs
	//
	// Example:
	//   // Get current checkpoint
	//   cp, err := harness.Checkpoint().GetCurrentCheckpoint()
	//   if err != nil && err != ErrCheckpointingDisabled {
	//       return err
	//   }
	//
	//   // Create labeled checkpoint
	//   cp, err := harness.Checkpoint().CreateCheckpoint("pre_exploit")
	//
	//   // Compare with previous run
	//   prevCP, err := harness.Checkpoint().GetPreviousRunCheckpoint(1)
	//   if err == nil {
	//       // Compare findings, strategies, etc.
	//   }
	Checkpoint() CheckpointAccess

	// ────────────────────────────────────────────────────────────────────────────
	// Observability
	// ────────────────────────────────────────────────────────────────────────────

	// Tracer returns the OpenTelemetry tracer for distributed tracing.
	// Use this to create custom spans for agent-specific operations.
	//
	// Returns:
	//   - trace.Tracer: OpenTelemetry tracer instance
	//
	// The harness automatically creates spans for:
	//   - LLM completions
	//   - Tool executions
	//   - Plugin queries
	//   - Sub-agent delegations
	//
	// Create custom spans for agent-specific logic:
	//
	// Example:
	//   ctx, span := harness.Tracer().Start(ctx, "analyze_response")
	//   defer span.End()
	//   // ... analysis logic ...
	Tracer() trace.Tracer

	// Logger returns the structured logger for this agent execution.
	// The logger is pre-configured with mission and agent context.
	//
	// Returns:
	//   - *slog.Logger: Structured logger instance
	//
	// The logger automatically includes:
	//   - Mission ID
	//   - Agent name
	//   - Task ID
	//   - Trace ID (for correlation with traces)
	//
	// Example:
	//   harness.Logger().Info("Starting reconnaissance",
	//       "target", target.URL,
	//       "method", "subdomain_enumeration")
	Logger() *slog.Logger

	// Metrics returns the metrics recorder for operational metrics.
	// Use this to record custom metrics for agent-specific operations.
	//
	// Returns:
	//   - MetricsRecorder: Interface for recording counters, gauges, and histograms
	//
	// The harness automatically records metrics for:
	//   - LLM completions (latency, token count, cost)
	//   - Tool executions (count, duration, success/failure)
	//   - Plugin queries (count, duration)
	//   - Findings submitted (count by severity)
	//
	// Example:
	//   harness.Metrics().RecordCounter("custom.vulnerabilities.found", 1, map[string]string{
	//       "type": "xss",
	//       "severity": "high",
	//   })
	Metrics() MetricsRecorder

	// TokenUsage returns the token usage tracker for the current execution.
	// This provides access to token consumption and cost data at multiple scopes.
	//
	// Returns:
	//   - *llm.TokenTracker: Token usage tracker with hierarchical tracking
	//
	// The tracker maintains usage at three levels:
	//   - Slot level: Usage per LLM slot (e.g., "primary", "reasoning")
	//   - Agent level: Aggregate usage for this agent
	//   - Mission level: Aggregate usage for the entire mission
	//
	// Use this to:
	//   - Check remaining budget before expensive operations
	//   - Query costs for reporting
	//   - Make cost-aware decisions (e.g., use cheaper models when low on budget)
	//
	// Example:
	//   tracker := harness.TokenUsage()
	//   scope := llm.UsageScope{MissionID: mission.ID, AgentName: "recon"}
	//   cost, _ := tracker.GetCost(scope)
	//   if cost > 0.50 {
	//       // Use cheaper model or reduce max tokens
	//   }
	TokenUsage() *llm.TokenTracker
}
