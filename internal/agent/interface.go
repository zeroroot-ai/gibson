package agent

import (
	"context"

	"github.com/zero-day-ai/gibson/internal/types"
)

// AgentHarness is imported from harness package - it's the canonical interface
// through which agents interact with the Gibson platform during execution.
// See internal/harness/harness.go for the full interface definition.
type AgentHarness interface {
	// QueryPlugin queries a plugin for data or executes a plugin method
	QueryPlugin(ctx context.Context, plugin, method string, params map[string]any) (any, error)

	// DelegateToAgent delegates a task to another agent
	DelegateToAgent(ctx context.Context, agentName string, task Task) (Result, error)

	// Log writes a structured log message
	Log(level, message string, fields map[string]any)
}

// Agent represents an autonomous, LLM-powered component that can execute
// security testing tasks. Agents are the primary execution units in Gibson,
// combining LLM reasoning with structured execution.
type Agent interface {
	// Name returns the unique identifier for this agent
	Name() string

	// Version returns the semantic version of this agent
	Version() string

	// Description returns a human-readable description of the agent's purpose
	Description() string

	// Capabilities returns a list of capabilities this agent provides
	Capabilities() []string

	// TargetTypes returns the types of targets this agent can operate against
	TargetTypes() []types.TargetType

	// TechniqueTypes returns the types of techniques this agent can execute
	TechniqueTypes() []types.TechniqueType

	// LLMSlots returns the LLM slot definitions this agent requires
	LLMSlots() []SlotDefinition

	// Execute runs the agent against a task using the provided harness
	Execute(ctx context.Context, task Task, harness AgentHarness) (Result, error)

	// Initialize prepares the agent for execution with the given configuration
	Initialize(ctx context.Context, cfg AgentConfig) error

	// Shutdown cleanly terminates the agent and releases resources
	Shutdown(ctx context.Context) error

	// Health returns the current health status of the agent
	Health(ctx context.Context) types.HealthStatus
}
