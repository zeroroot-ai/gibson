package plan

import (
	"context"
	"errors"

	"github.com/zeroroot-ai/gibson/internal/agent"
	"github.com/zeroroot-ai/gibson/internal/harness"
)

// PlanGenerator defines the interface for generating execution plans from high-level tasks.
// Implementations should analyze the task, available resources (tools, plugins, agents),
// and constraints to produce an optimized execution plan.
type PlanGenerator interface {
	// Generate creates an execution plan based on the provided input and harness.
	// The harness provides access to agent capabilities for plan generation.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - input: Input parameters including task, available resources, and constraints
	//   - harness: Agent harness providing access to AI capabilities for plan generation
	//
	// Returns:
	//   - *ExecutionPlan: The generated execution plan with steps and resource allocations
	//   - error: Any error encountered during plan generation
	Generate(ctx context.Context, input GenerateInput, harness harness.AgentHarness) (*ExecutionPlan, error)
}

// GenerateInput encapsulates all the information needed to generate an execution plan.
// It includes the task to be performed, available resources that can be used,
// and any constraints that must be respected during planning.
type GenerateInput struct {
	// Task is the high-level task that needs to be executed.
	// This describes what needs to be accomplished.
	Task agent.Task `json:"task"`

	// AvailableTools lists all tools that can be used in the execution plan.
	// The planner should select appropriate tools based on task requirements.
	AvailableTools []harness.ToolDescriptor `json:"available_tools"`

	// AvailablePlugins lists all plugins that can be leveraged in the plan.
	// Plugins provide extended capabilities beyond basic tools.
	AvailablePlugins []harness.PluginDescriptor `json:"available_plugins"`

	// AvailableAgents lists all agents that can be delegated to.
	// The planner can decompose tasks and assign subtasks to specialized agents.
	AvailableAgents []harness.AgentDescriptor `json:"available_agents"`

	// Constraints are optional restrictions that the plan must satisfy.
	// Examples: resource limits, timeout requirements, security policies.
	Constraints []string `json:"constraints,omitempty"`
}

// Validate checks that the GenerateInput contains all required fields and is well-formed.
//
// Returns:
//   - error: ErrInvalidInput if validation fails, nil otherwise
func (g *GenerateInput) Validate() error {
	if g.Task.Name == "" {
		return errors.New("task name cannot be empty")
	}
	return nil
}
