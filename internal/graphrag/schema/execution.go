// Package schema provides strongly-typed schema definitions for GraphRAG execution tracking.
// These types represent nodes that track orchestrator execution state, decisions, and tool invocations.
package schema

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/types"
)

// ExecutionStatus represents the status of an agent or tool execution.
type ExecutionStatus string

const (
	// ExecutionStatusRunning indicates execution is in progress
	ExecutionStatusRunning ExecutionStatus = "running"
	// ExecutionStatusCompleted indicates execution finished successfully
	ExecutionStatusCompleted ExecutionStatus = "completed"
	// ExecutionStatusFailed indicates execution failed with an error
	ExecutionStatusFailed ExecutionStatus = "failed"
)

// String returns the string representation of ExecutionStatus.
func (s ExecutionStatus) String() string {
	return string(s)
}

// Validate checks if the ExecutionStatus is valid.
func (s ExecutionStatus) Validate() error {
	switch s {
	case ExecutionStatusRunning, ExecutionStatusCompleted, ExecutionStatusFailed:
		return nil
	default:
		return fmt.Errorf("invalid execution status: %s", s)
	}
}

// Node label constants for execution tracking
const (
	// NodeLabelAgentExecution represents an agent execution node
	NodeLabelAgentExecution = "AgentExecution"
	// NodeLabelDecision represents an orchestrator decision node
	NodeLabelDecision = "Decision"
	// NodeLabelToolExecution represents a tool execution node
	NodeLabelToolExecution = "ToolExecution"
)

// DecisionAction represents the action type chosen by the orchestrator
type DecisionAction string

const (
	// DecisionActionExecuteAgent indicates the orchestrator decided to execute an agent
	DecisionActionExecuteAgent DecisionAction = "execute_agent"
	// DecisionActionSkipAgent indicates the orchestrator decided to skip an agent
	DecisionActionSkipAgent DecisionAction = "skip_agent"
	// DecisionActionModifyParams indicates the orchestrator modified agent parameters
	DecisionActionModifyParams DecisionAction = "modify_params"
	// DecisionActionComplete indicates the orchestrator completed the mission
	DecisionActionComplete DecisionAction = "complete"
	// DecisionActionSpawnAgent indicates the orchestrator spawned a new dynamic agent
	DecisionActionSpawnAgent DecisionAction = "spawn_agent"
)

// String returns the string representation of DecisionAction.
func (a DecisionAction) String() string {
	return string(a)
}

// AgentExecution represents an agent execution node in the graph.
// It tracks the lifecycle of a single agent execution including configuration,
// status, timing, and results.
type AgentExecution struct {
	// ID is the unique identifier for this execution
	ID types.ID `json:"id"`

	// MissionNodeID is the ID of the mission node being executed
	MissionNodeID string `json:"mission_node_id"`

	// MissionID is the ID of the parent mission
	MissionID types.ID `json:"mission_id"`

	// Status indicates the current execution status
	Status ExecutionStatus `json:"status"`

	// StartedAt is when the execution started
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the execution finished (nil if still running)
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Attempt tracks retry attempts (starts at 1)
	Attempt int `json:"attempt"`

	// ConfigUsed stores the actual configuration used (may be modified by orchestrator)
	ConfigUsed map[string]any `json:"config_used,omitempty"`

	// Result stores the agent execution result
	Result map[string]any `json:"result,omitempty"`

	// Error stores the error message if execution failed
	Error string `json:"error,omitempty"`

	// ErrorClass categorizes the error by its nature (infrastructure/semantic/transient/permanent)
	ErrorClass string `json:"error_class,omitempty"`

	// ErrorCode is the standard error code (e.g., BINARY_NOT_FOUND, TIMEOUT)
	ErrorCode string `json:"error_code,omitempty"`

	// RecoveryHints stores recovery suggestions as JSON-compatible structures
	RecoveryHints []map[string]any `json:"recovery_hints,omitempty"`

	// LangfuseSpanID correlates this execution to Langfuse observability
	LangfuseSpanID string `json:"langfuse_span_id,omitempty"`

	// CreatedAt is the timestamp when this node was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this node was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// NewAgentExecution creates a new AgentExecution with the given parameters.
// The status is set to running, attempt is set to 1, and timestamps are initialized.
func NewAgentExecution(missionNodeID string, missionID types.ID) *AgentExecution {
	now := time.Now()
	return &AgentExecution{
		ID:            types.NewID(),
		MissionNodeID: missionNodeID,
		MissionID:     missionID,
		Status:        ExecutionStatusRunning,
		StartedAt:     now,
		Attempt:       1,
		ConfigUsed:    make(map[string]any),
		Result:        make(map[string]any),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// WithID sets the execution ID.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithID(id types.ID) *AgentExecution {
	ae.ID = id
	ae.UpdatedAt = time.Now()
	return ae
}

// WithStatus updates the execution status.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithStatus(status ExecutionStatus) *AgentExecution {
	ae.Status = status
	ae.UpdatedAt = time.Now()
	return ae
}

// WithConfig sets the configuration used for this execution.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithConfig(config map[string]any) *AgentExecution {
	ae.ConfigUsed = config
	ae.UpdatedAt = time.Now()
	return ae
}

// WithResult sets the execution result.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithResult(result map[string]any) *AgentExecution {
	ae.Result = result
	ae.UpdatedAt = time.Now()
	return ae
}

// WithError sets the error message.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithError(err string) *AgentExecution {
	ae.Error = err
	ae.UpdatedAt = time.Now()
	return ae
}

// WithLangfuseSpanID sets the Langfuse span ID for observability correlation.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithLangfuseSpanID(spanID string) *AgentExecution {
	ae.LangfuseSpanID = spanID
	ae.UpdatedAt = time.Now()
	return ae
}

// WithAttempt sets the retry attempt number.
// Returns the execution for method chaining.
func (ae *AgentExecution) WithAttempt(attempt int) *AgentExecution {
	ae.Attempt = attempt
	ae.UpdatedAt = time.Now()
	return ae
}

// MarkCompleted marks the execution as completed and sets the completion timestamp.
// Returns the execution for method chaining.
func (ae *AgentExecution) MarkCompleted() *AgentExecution {
	now := time.Now()
	ae.Status = ExecutionStatusCompleted
	ae.CompletedAt = &now
	ae.UpdatedAt = now
	return ae
}

// MarkFailed marks the execution as failed with the given error message.
// Returns the execution for method chaining.
func (ae *AgentExecution) MarkFailed(err string) *AgentExecution {
	now := time.Now()
	ae.Status = ExecutionStatusFailed
	ae.Error = err
	ae.CompletedAt = &now
	ae.UpdatedAt = now
	return ae
}

// MarkFailedWithDetails marks the execution as failed with structured error details.
// This method stores error classification, error code, and recovery hints for semantic error recovery.
// The hints parameter should be []RecoveryHint from the toolerr package, which will be converted
// to JSON-compatible map[string]any structures for storage.
// Returns the execution for method chaining.
func (ae *AgentExecution) MarkFailedWithDetails(err string, errorClass string, errorCode string, hints any) *AgentExecution {
	now := time.Now()
	ae.Status = ExecutionStatusFailed
	ae.Error = err
	ae.ErrorClass = errorClass
	ae.ErrorCode = errorCode

	// Convert hints to []map[string]any for JSON compatibility
	// The hints parameter is expected to be []RecoveryHint from toolerr package
	if hints != nil {
		// Use JSON marshaling/unmarshaling to convert any struct type to map[string]any
		// This works because RecoveryHint has proper json tags
		hintsJSON, err := json.Marshal(hints)
		if err == nil {
			var hintsMap []map[string]any
			if err := json.Unmarshal(hintsJSON, &hintsMap); err == nil {
				ae.RecoveryHints = hintsMap
			}
		}
		// If conversion fails, RecoveryHints remains nil (graceful degradation)
	}

	ae.CompletedAt = &now
	ae.UpdatedAt = now
	return ae
}

// Validate checks that all required fields are set correctly.
func (ae *AgentExecution) Validate() error {
	if err := ae.ID.Validate(); err != nil {
		return fmt.Errorf("invalid agent execution ID: %w", err)
	}
	if ae.MissionNodeID == "" {
		return fmt.Errorf("mission_node_id is required")
	}
	if err := ae.MissionID.Validate(); err != nil {
		return fmt.Errorf("invalid mission_id: %w", err)
	}
	if err := ae.Status.Validate(); err != nil {
		return err
	}
	if ae.Attempt < 1 {
		return fmt.Errorf("attempt must be >= 1, got %d", ae.Attempt)
	}
	if ae.StartedAt.IsZero() {
		return fmt.Errorf("started_at is required")
	}
	return nil
}

// Duration returns the execution duration.
// Returns 0 if the execution hasn't completed yet.
func (ae *AgentExecution) Duration() time.Duration {
	if ae.CompletedAt == nil {
		return 0
	}
	return ae.CompletedAt.Sub(ae.StartedAt)
}

// IsComplete returns true if the execution has completed (successfully or failed).
func (ae *AgentExecution) IsComplete() bool {
	return ae.Status == ExecutionStatusCompleted || ae.Status == ExecutionStatusFailed
}

// Decision represents an orchestrator decision node in the graph.
// It captures the reasoning, action, and context for each orchestrator decision point.
type Decision struct {
	// ID is the unique identifier for this decision
	ID types.ID `json:"id"`

	// MissionID is the ID of the parent mission
	MissionID types.ID `json:"mission_id"`

	// Iteration is the orchestrator iteration number
	Iteration int `json:"iteration"`

	// Timestamp is when the decision was made
	Timestamp time.Time `json:"timestamp"`

	// Action is the decision action taken
	Action DecisionAction `json:"action"`

	// TargetNodeID is the mission node affected by this decision
	TargetNodeID string `json:"target_node_id,omitempty"`

	// Reasoning contains the chain-of-thought explanation
	Reasoning string `json:"reasoning"`

	// Confidence is the decision confidence score (0.0 to 1.0)
	Confidence float64 `json:"confidence"`

	// Modifications stores any parameter modifications made
	Modifications map[string]any `json:"modifications,omitempty"`

	// GraphStateSummary captures the graph state at decision time
	GraphStateSummary string `json:"graph_state_summary,omitempty"`

	// PromptTokens is the number of tokens in the prompt
	PromptTokens int `json:"prompt_tokens,omitempty"`

	// CompletionTokens is the number of tokens in the completion
	CompletionTokens int `json:"completion_tokens,omitempty"`

	// LatencyMs is the LLM call latency in milliseconds
	LatencyMs int `json:"latency_ms,omitempty"`

	// Model is the LLM model used for this decision
	Model string `json:"model,omitempty"`

	// LangfuseSpanID correlates this decision to Langfuse observability
	LangfuseSpanID string `json:"langfuse_span_id,omitempty"`

	// CreatedAt is the timestamp when this node was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this node was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// NewDecision creates a new Decision with the given parameters.
// Timestamps are initialized to the current time.
func NewDecision(missionID types.ID, iteration int, action DecisionAction) *Decision {
	now := time.Now()
	return &Decision{
		ID:            types.NewID(),
		MissionID:     missionID,
		Iteration:     iteration,
		Timestamp:     now,
		Action:        action,
		Confidence:    1.0,
		Modifications: make(map[string]any),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

// WithID sets the decision ID.
// Returns the decision for method chaining.
func (d *Decision) WithID(id types.ID) *Decision {
	d.ID = id
	d.UpdatedAt = time.Now()
	return d
}

// WithTargetNode sets the target mission node ID.
// Returns the decision for method chaining.
func (d *Decision) WithTargetNode(nodeID string) *Decision {
	d.TargetNodeID = nodeID
	d.UpdatedAt = time.Now()
	return d
}

// WithReasoning sets the chain-of-thought reasoning.
// Returns the decision for method chaining.
func (d *Decision) WithReasoning(reasoning string) *Decision {
	d.Reasoning = reasoning
	d.UpdatedAt = time.Now()
	return d
}

// WithConfidence sets the decision confidence score.
// Returns the decision for method chaining.
func (d *Decision) WithConfidence(confidence float64) *Decision {
	d.Confidence = confidence
	d.UpdatedAt = time.Now()
	return d
}

// WithModifications sets the parameter modifications.
// Returns the decision for method chaining.
func (d *Decision) WithModifications(mods map[string]any) *Decision {
	d.Modifications = mods
	d.UpdatedAt = time.Now()
	return d
}

// WithGraphStateSummary sets the graph state summary.
// Returns the decision for method chaining.
func (d *Decision) WithGraphStateSummary(summary string) *Decision {
	d.GraphStateSummary = summary
	d.UpdatedAt = time.Now()
	return d
}

// WithTokenUsage sets the LLM token usage metrics.
// Returns the decision for method chaining.
func (d *Decision) WithTokenUsage(promptTokens, completionTokens int) *Decision {
	d.PromptTokens = promptTokens
	d.CompletionTokens = completionTokens
	d.UpdatedAt = time.Now()
	return d
}

// WithLatency sets the LLM call latency in milliseconds.
// Returns the decision for method chaining.
func (d *Decision) WithLatency(latencyMs int) *Decision {
	d.LatencyMs = latencyMs
	d.UpdatedAt = time.Now()
	return d
}

// WithLangfuseSpanID sets the Langfuse span ID for observability correlation.
// Returns the decision for method chaining.
func (d *Decision) WithLangfuseSpanID(spanID string) *Decision {
	d.LangfuseSpanID = spanID
	d.UpdatedAt = time.Now()
	return d
}

// Validate checks that all required fields are set correctly.
func (d *Decision) Validate() error {
	if err := d.ID.Validate(); err != nil {
		return fmt.Errorf("invalid decision ID: %w", err)
	}
	if err := d.MissionID.Validate(); err != nil {
		return fmt.Errorf("invalid mission_id: %w", err)
	}
	if d.Iteration < 0 {
		return fmt.Errorf("iteration must be >= 0, got %d", d.Iteration)
	}
	if d.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	if d.Action == "" {
		return fmt.Errorf("action is required")
	}
	if d.Confidence < 0.0 || d.Confidence > 1.0 {
		return fmt.Errorf("confidence must be between 0.0 and 1.0, got %f", d.Confidence)
	}
	return nil
}

// TotalTokens returns the sum of prompt and completion tokens.
func (d *Decision) TotalTokens() int {
	return d.PromptTokens + d.CompletionTokens
}

// ToolExecution represents a tool execution node in the graph.
// It tracks individual tool invocations within an agent execution.
type ToolExecution struct {
	// ID is the unique identifier for this tool execution
	ID types.ID `json:"id"`

	// AgentExecutionID is the ID of the parent agent execution
	AgentExecutionID types.ID `json:"agent_execution_id"`

	// ToolName is the name of the tool that was executed
	ToolName string `json:"tool_name"`

	// Input stores the tool input parameters
	Input map[string]any `json:"input,omitempty"`

	// Output stores the tool output/result
	Output map[string]any `json:"output,omitempty"`

	// StartedAt is when the tool execution started
	StartedAt time.Time `json:"started_at"`

	// CompletedAt is when the tool execution finished (nil if still running)
	CompletedAt *time.Time `json:"completed_at,omitempty"`

	// Status indicates the current execution status
	Status ExecutionStatus `json:"status"`

	// Error stores the error message if execution failed
	Error string `json:"error,omitempty"`

	// LangfuseSpanID correlates this execution to Langfuse observability
	LangfuseSpanID string `json:"langfuse_span_id,omitempty"`

	// CreatedAt is the timestamp when this node was created
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is the timestamp when this node was last updated
	UpdatedAt time.Time `json:"updated_at"`
}

// NewToolExecution creates a new ToolExecution with the given parameters.
// The status is set to running and timestamps are initialized.
func NewToolExecution(agentExecutionID types.ID, toolName string) *ToolExecution {
	now := time.Now()
	return &ToolExecution{
		ID:               types.NewID(),
		AgentExecutionID: agentExecutionID,
		ToolName:         toolName,
		Status:           ExecutionStatusRunning,
		StartedAt:        now,
		Input:            make(map[string]any),
		Output:           make(map[string]any),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// WithID sets the tool execution ID.
// Returns the execution for method chaining.
func (te *ToolExecution) WithID(id types.ID) *ToolExecution {
	te.ID = id
	te.UpdatedAt = time.Now()
	return te
}

// WithInput sets the tool input parameters.
// Returns the execution for method chaining.
func (te *ToolExecution) WithInput(input map[string]any) *ToolExecution {
	te.Input = input
	te.UpdatedAt = time.Now()
	return te
}

// WithOutput sets the tool output/result.
// Returns the execution for method chaining.
func (te *ToolExecution) WithOutput(output map[string]any) *ToolExecution {
	te.Output = output
	te.UpdatedAt = time.Now()
	return te
}

// WithStatus updates the execution status.
// Returns the execution for method chaining.
func (te *ToolExecution) WithStatus(status ExecutionStatus) *ToolExecution {
	te.Status = status
	te.UpdatedAt = time.Now()
	return te
}

// WithError sets the error message.
// Returns the execution for method chaining.
func (te *ToolExecution) WithError(err string) *ToolExecution {
	te.Error = err
	te.UpdatedAt = time.Now()
	return te
}

// WithLangfuseSpanID sets the Langfuse span ID for observability correlation.
// Returns the execution for method chaining.
func (te *ToolExecution) WithLangfuseSpanID(spanID string) *ToolExecution {
	te.LangfuseSpanID = spanID
	te.UpdatedAt = time.Now()
	return te
}

// MarkCompleted marks the execution as completed and sets the completion timestamp.
// Returns the execution for method chaining.
func (te *ToolExecution) MarkCompleted() *ToolExecution {
	now := time.Now()
	te.Status = ExecutionStatusCompleted
	te.CompletedAt = &now
	te.UpdatedAt = now
	return te
}

// MarkFailed marks the execution as failed with the given error message.
// Returns the execution for method chaining.
func (te *ToolExecution) MarkFailed(err string) *ToolExecution {
	now := time.Now()
	te.Status = ExecutionStatusFailed
	te.Error = err
	te.CompletedAt = &now
	te.UpdatedAt = now
	return te
}

// Validate checks that all required fields are set correctly.
func (te *ToolExecution) Validate() error {
	if err := te.ID.Validate(); err != nil {
		return fmt.Errorf("invalid tool execution ID: %w", err)
	}
	if err := te.AgentExecutionID.Validate(); err != nil {
		return fmt.Errorf("invalid agent_execution_id: %w", err)
	}
	if te.ToolName == "" {
		return fmt.Errorf("tool_name is required")
	}
	if err := te.Status.Validate(); err != nil {
		return err
	}
	if te.StartedAt.IsZero() {
		return fmt.Errorf("started_at is required")
	}
	return nil
}

// Duration returns the execution duration.
// Returns 0 if the execution hasn't completed yet.
func (te *ToolExecution) Duration() time.Duration {
	if te.CompletedAt == nil {
		return 0
	}
	return te.CompletedAt.Sub(te.StartedAt)
}

// IsComplete returns true if the execution has completed (successfully or failed).
func (te *ToolExecution) IsComplete() bool {
	return te.Status == ExecutionStatusCompleted || te.Status == ExecutionStatusFailed
}
