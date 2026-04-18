package orchestrator

import (
	"context"
	"log/slog"
)

// PolicyChecker determines whether an agent should execute based on data reuse policies.
// It checks for existing data in the graph and applies the configured reuse strategy.
type PolicyChecker interface {
	// ShouldExecute returns true if the agent should run, false if it should be skipped.
	// The reason string explains why the agent was skipped (empty if should execute).
	ShouldExecute(ctx context.Context, agentName string) (bool, string)
}

// PolicySource provides access to data policies defined in mission YAML.
// This interface is typically implemented by the mission configuration parser.
type PolicySource interface {
	// GetDataPolicy retrieves the data policy for a specific agent in the mission.
	// Returns nil if no policy is defined (defaults will be applied).
	GetDataPolicy(agentName string) (*DataPolicy, error)
}

// NodeStore provides access to the graph database for querying existing data.
// This interface abstracts the GraphRAG storage layer for policy checking.
type NodeStore interface {
	// CountByAgentInScope counts nodes stored by an agent within a specific scope.
	// The scope determines the filtering (mission_run, mission, or global).
	// Returns the count of nodes matching the agent_name property.
	CountByAgentInScope(ctx context.Context, agentName, scope string) (int, error)
}

// policyChecker implements PolicyChecker for reuse policy enforcement.
type policyChecker struct {
	policySource PolicySource
	graphStore   NodeStore
	logger       *slog.Logger
}

// NewPolicyChecker creates a new PolicyChecker with the given policy source and graph store.
func NewPolicyChecker(source PolicySource, store NodeStore, logger *slog.Logger) PolicyChecker {
	if logger == nil {
		logger = slog.Default()
	}
	return &policyChecker{
		policySource: source,
		graphStore:   store,
		logger:       logger,
	}
}

// ShouldExecute determines if an agent should execute based on its reuse policy.
//
// Reuse Policy Logic:
// - "never": Always returns true (always execute)
// - "always": Always returns false (never execute, reuse existing data)
// - "skip": Queries the graph for existing data:
//   - If data exists from this agent in the input_scope: returns false (skip execution)
//   - If no data exists: returns true (execute normally)
//
// The reason string is non-empty only when returning false (skip execution).
func (pc *policyChecker) ShouldExecute(ctx context.Context, agentName string) (bool, string) {
	// Retrieve the data policy for this agent from the mission configuration
	policy, err := pc.policySource.GetDataPolicy(agentName)
	if err != nil {
		// If policy retrieval fails, log warning and default to executing
		pc.logger.Warn("Failed to retrieve data policy, defaulting to execute",
			"agent", agentName,
			"error", err)
		return true, ""
	}

	// Apply defaults if no policy was defined
	if policy == nil {
		policy = &DataPolicy{}
	}
	policy.SetDefaults()

	// Apply reuse policy logic
	switch policy.Reuse {
	case ReuseNever:
		// Always execute, regardless of existing data
		pc.logger.Debug("Agent will execute (reuse=never)",
			"agent", agentName)
		return true, ""

	case ReuseAlways:
		// Never execute, always reuse existing data
		pc.logger.Info("Skipping agent execution (reuse=always)",
			"agent", agentName)
		return false, "reuse=always"

	case ReuseSkip:
		// Execute only if no data exists in the input scope
		count, err := pc.graphStore.CountByAgentInScope(ctx, agentName, policy.InputScope)
		if err != nil {
			// If count fails, log error and default to executing (fail-open)
			pc.logger.Error("Failed to count existing data, defaulting to execute",
				"agent", agentName,
				"scope", policy.InputScope,
				"error", err)
			return true, ""
		}

		if count > 0 {
			// Data exists, skip execution
			pc.logger.Info("Skipping agent execution (existing data found)",
				"agent", agentName,
				"scope", policy.InputScope,
				"node_count", count)
			return false, "existing data found"
		}

		// No data exists, execute normally
		pc.logger.Debug("Agent will execute (no existing data)",
			"agent", agentName,
			"scope", policy.InputScope)
		return true, ""

	default:
		// Invalid reuse value, log warning and default to executing
		pc.logger.Warn("Invalid reuse policy value, defaulting to execute",
			"agent", agentName,
			"reuse", policy.Reuse)
		return true, ""
	}
}
