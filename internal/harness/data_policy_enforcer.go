package harness

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/contextkeys"
	"github.com/zero-day-ai/sdk/graphrag"
)

// DataPolicyEnforcer applies data policy constraints to GraphRAG queries.
// It enforces the input_scope policy by filtering queries based on mission context,
// ensuring agents only see data allowed by their configured policy.
//
// The enforcer operates transparently - agents call QueryNodes() with a simple query,
// and the harness automatically applies scope filters based on the mission's data_policy.
type DataPolicyEnforcer interface {
	// ApplyInputScope modifies the query to filter by the agent's input_scope policy.
	// Returns error if:
	//   - Agent explicitly set mission_id or mission_run_id filters (cannot override policy)
	//   - Policy cannot be retrieved
	//   - Context is missing required values (mission_id or mission_run_id)
	ApplyInputScope(ctx context.Context, query *graphrag.Query) error
}

// dataPolicyEnforcer implements DataPolicyEnforcer using a PolicySource to retrieve
// the current agent's data policy configuration.
type dataPolicyEnforcer struct {
	policySource PolicySource
}

// PolicySource provides access to mission data policies.
// This interface is typically implemented by the MissionConfig or orchestrator
// components that parse and manage mission YAML.
//
// NOTE: This mirrors orchestrator.PolicySource but returns DataPolicyConfig
// instead of orchestrator.DataPolicy to avoid circular dependencies.
// Implementers should convert orchestrator.DataPolicy to DataPolicyConfig.
type PolicySource interface {
	// GetDataPolicy returns the data policy for the specified agent.
	// Returns nil policy if no policy is configured (uses defaults).
	// Returns error only on system failures (not for missing policies).
	GetDataPolicy(agentName string) (*DataPolicyConfig, error)
}

// DataPolicyConfig is a simplified data policy DTO used by the enforcer.
// This avoids circular dependencies with the orchestrator package.
// The mission.DataPolicy should be converted to this type when passed to the enforcer.
type DataPolicyConfig struct {
	// OutputScope controls where stored data is visible.
	// Values: "mission_run", "mission", "global"
	OutputScope string

	// InputScope controls what data this agent can query.
	// Values: "mission_run", "mission", "global"
	InputScope string

	// Reuse controls when to skip agent execution if data exists.
	// Values: "skip", "always", "never"
	Reuse string
}

// Scope constants for policy enforcement
const (
	ScopeMissionRun = "mission_run"
	ScopeMission    = "mission"
	ScopeGlobal     = "global"
)

// NewDataPolicyEnforcer creates a new DataPolicyEnforcer with the given policy source.
func NewDataPolicyEnforcer(source PolicySource) DataPolicyEnforcer {
	return &dataPolicyEnforcer{
		policySource: source,
	}
}

// ApplyInputScope enforces the agent's input_scope policy by adding filters to the query.
//
// Behavior by input_scope value:
//   - "mission_run": Filter to mission_run_id = current run ID (most restrictive)
//   - "mission": Filter to mission_id = current mission ID (all runs of this mission)
//   - "global": No filter (see all data across all missions)
//
// Error cases:
//   - Query already has MissionID or MissionRunID set (agent cannot override policy)
//   - Policy source fails to retrieve policy
//   - Context is missing required mission_id or mission_run_id
func (e *dataPolicyEnforcer) ApplyInputScope(ctx context.Context, query *graphrag.Query) error {
	// Detect if agent is trying to override scope by setting mission filters explicitly
	if query.MissionID != "" {
		return fmt.Errorf("cannot set MissionID on query: input_scope is enforced by data policy")
	}
	if query.MissionRunID != "" {
		return fmt.Errorf("cannot set MissionRunID on query: input_scope is enforced by data policy")
	}

	// Get agent name from context to look up policy
	// NOTE: This assumes the agent name is available in context - will be added in Task 3.3
	// For now, we'll need to pass it through somehow. The orchestrator will handle this.
	agentName := agentNameFromContext(ctx)
	if agentName == "" {
		// If no agent name in context, we can't look up policy - skip enforcement
		// This allows for queries outside of agent execution (e.g., from CLI tools)
		return nil
	}

	// Retrieve the data policy for this agent
	policy, err := e.policySource.GetDataPolicy(agentName)
	if err != nil {
		return fmt.Errorf("failed to retrieve data policy: %w", err)
	}

	// If no policy is configured, use defaults
	if policy == nil {
		policy = &DataPolicyConfig{
			OutputScope: ScopeMission,
			InputScope:  ScopeMission,
			Reuse:       "never",
		}
	}

	// Apply input_scope filter based on policy
	switch policy.InputScope {
	case ScopeMissionRun:
		// Most restrictive: filter to current mission run only
		missionRunID := MissionRunIDFromContext(ctx)
		if missionRunID == "" {
			return fmt.Errorf("input_scope=mission_run requires mission_run_id in context")
		}
		query.MissionRunID = missionRunID

	case ScopeMission:
		// Filter to all runs of the current mission
		missionID := missionIDFromContext(ctx)
		if missionID == "" {
			return fmt.Errorf("input_scope=mission requires mission_id in context")
		}
		query.MissionID = missionID

	case ScopeGlobal:
		// No filter - agent can see everything across all missions
		// This is intentionally left empty - no filters added

	default:
		// Unknown scope value - treat as error to fail fast on misconfiguration
		return fmt.Errorf("invalid input_scope value %q: must be mission_run, mission, or global", policy.InputScope)
	}

	return nil
}

// agentNameFromContext retrieves the agent name from context.
// Returns empty string if not set.
func agentNameFromContext(ctx context.Context) string {
	if v := ctx.Value(contextkeys.AgentName); v != nil {
		if name, ok := v.(string); ok {
			return name
		}
	}
	return ""
}

// missionIDFromContext retrieves the mission ID from context.
// This is different from MissionContext.ID which is a types.ID - this is the raw string.
// Returns empty string if not set.
func missionIDFromContext(ctx context.Context) string {
	if v := ctx.Value(contextkeys.MissionID); v != nil {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}
