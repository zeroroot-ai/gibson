package plan

import (
	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// ExecutionStep represents a single step in an execution plan.
// Steps can be of different types (tool, plugin, agent, condition, parallel)
// and can have dependencies on other steps.
type ExecutionStep struct {
	ID          types.ID `json:"id"`
	Sequence    int      `json:"sequence"`
	Type        StepType `json:"type"`
	Name        string   `json:"name"`
	Description string   `json:"description"`

	// Tool step fields
	ToolName  string         `json:"tool_name,omitempty"`
	ToolInput map[string]any `json:"tool_input,omitempty"`

	// Plugin step fields
	PluginName   string         `json:"plugin_name,omitempty"`
	PluginMethod string         `json:"plugin_method,omitempty"`
	PluginParams map[string]any `json:"plugin_params,omitempty"`

	// Agent step fields
	AgentName string      `json:"agent_name,omitempty"`
	AgentTask *agent.Task `json:"agent_task,omitempty"`

	// Condition step fields
	Condition *StepCondition `json:"condition,omitempty"`

	// Parallel step fields
	ParallelSteps []ExecutionStep `json:"parallel_steps,omitempty"`

	// Risk assessment
	RiskLevel        RiskLevel `json:"risk_level"`
	RequiresApproval bool      `json:"requires_approval"`
	RiskRationale    string    `json:"risk_rationale,omitempty"`

	// Execution state
	Status StepStatus  `json:"status"`
	Result *StepResult `json:"result,omitempty"`

	// Dependencies and metadata
	DependsOn []types.ID     `json:"depends_on,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// StepType represents the type of execution step
type StepType string

const (
	StepTypeTool      StepType = "tool"
	StepTypePlugin    StepType = "plugin"
	StepTypeAgent     StepType = "agent"
	StepTypeCondition StepType = "condition"
	StepTypeParallel  StepType = "parallel"
)

// StepStatus represents the current status of a step
type StepStatus string

const (
	StepStatusPending   StepStatus = "pending"
	StepStatusApproved  StepStatus = "approved"
	StepStatusRunning   StepStatus = "running"
	StepStatusCompleted StepStatus = "completed"
	StepStatusFailed    StepStatus = "failed"
	StepStatusSkipped   StepStatus = "skipped"
)

// IsTerminal returns true if the step status is a terminal state
// (completed, failed, or skipped).
func (s StepStatus) IsTerminal() bool {
	return s == StepStatusCompleted || s == StepStatusFailed || s == StepStatusSkipped
}

// RiskLevel represents the risk level of a step
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// IsHighRisk returns true if the risk level is high or critical
func (r RiskLevel) IsHighRisk() bool {
	return r == RiskLevelHigh || r == RiskLevelCritical
}

// StepCondition represents a conditional branching in the execution plan.
// It allows for dynamic execution paths based on runtime evaluation.
type StepCondition struct {
	Expression string     `json:"expression"`
	TrueSteps  []types.ID `json:"true_steps,omitempty"`
	FalseSteps []types.ID `json:"false_steps,omitempty"`
}
