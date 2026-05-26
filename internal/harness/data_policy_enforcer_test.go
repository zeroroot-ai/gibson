package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/contextkeys"
	"github.com/zeroroot-ai/sdk/graphrag"
)

// mockPolicySource implements PolicySource for testing
type mockPolicySource struct {
	policies map[string]*DataPolicyConfig
	err      error
}

func (m *mockPolicySource) GetDataPolicy(agentName string) (*DataPolicyConfig, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.policies[agentName], nil
}

func TestDataPolicyEnforcer_FiltersByMissionRun(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMissionRun,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context with agent name and mission_run_id
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")
	ctx = ContextWithMissionRunID(ctx, "run-123")
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-456")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, "run-123", query.MissionRunID)
	assert.Empty(t, query.MissionID, "MissionID should not be set when input_scope is mission_run")
}

func TestDataPolicyEnforcer_FiltersByMission(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMission,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context with agent name and mission_id
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-456")
	ctx = ContextWithMissionRunID(ctx, "run-123")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify
	require.NoError(t, err)
	assert.Equal(t, "mission-456", query.MissionID)
	assert.Empty(t, query.MissionRunID, "MissionRunID should not be set when input_scope is mission")
}

func TestDataPolicyEnforcer_NoFilterForGlobal(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeGlobal,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context with agent name
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-456")
	ctx = ContextWithMissionRunID(ctx, "run-123")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify
	require.NoError(t, err)
	assert.Empty(t, query.MissionID, "MissionID should not be set for global scope")
	assert.Empty(t, query.MissionRunID, "MissionRunID should not be set for global scope")
}

func TestDataPolicyEnforcer_UsesDefaults(t *testing.T) {
	// Setup - no policy configured
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context with agent name
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-456")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - default input_scope is "mission"
	require.NoError(t, err)
	assert.Equal(t, "mission-456", query.MissionID)
}

func TestDataPolicyEnforcer_RejectsMissionIDOverride(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMission,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")
	ctx = context.WithValue(ctx, contextkeys.MissionID, "mission-456")

	// Create a query with MissionID already set (agent trying to override)
	query := graphrag.NewQuery("test query")
	query.MissionID = "malicious-override"

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should return error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set MissionID on query")
}

func TestDataPolicyEnforcer_RejectsMissionRunIDOverride(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMissionRun,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")
	ctx = ContextWithMissionRunID(ctx, "run-123")

	// Create a query with MissionRunID already set (agent trying to override)
	query := graphrag.NewQuery("test query")
	query.MissionRunID = "malicious-override"

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should return error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot set MissionRunID on query")
}

func TestDataPolicyEnforcer_ErrorOnMissingMissionRunID(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMissionRun,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context WITHOUT mission_run_id
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should return error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires mission_run_id in context")
}

func TestDataPolicyEnforcer_ErrorOnMissingMissionID(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMission,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context WITHOUT mission_id
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should return error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires mission_id in context")
}

func TestDataPolicyEnforcer_SkipsEnforcementWithoutAgentName(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: ScopeMissionRun,
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context WITHOUT agent name (e.g., CLI tool query)
	ctx := context.Background()
	ctx = ContextWithMissionRunID(ctx, "run-123")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should succeed without applying any filters
	require.NoError(t, err)
	assert.Empty(t, query.MissionID)
	assert.Empty(t, query.MissionRunID)
}

func TestDataPolicyEnforcer_InvalidInputScope(t *testing.T) {
	// Setup
	policySource := &mockPolicySource{
		policies: map[string]*DataPolicyConfig{
			"test-agent": {
				InputScope: "invalid-scope",
			},
		},
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should return error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid input_scope value")
}

func TestDataPolicyEnforcer_PolicySourceError(t *testing.T) {
	// Setup with error
	policySource := &mockPolicySource{
		err: assert.AnError,
	}
	enforcer := NewDataPolicyEnforcer(policySource)

	// Create context
	ctx := context.Background()
	ctx = context.WithValue(ctx, contextkeys.AgentName, "test-agent")

	// Create a query
	query := graphrag.NewQuery("test query")

	// Apply policy
	err := enforcer.ApplyInputScope(ctx, query)

	// Verify - should propagate error
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to retrieve data policy")
}

func TestDataPolicyConfig_ScopeConstants(t *testing.T) {
	// Verify scope constants match expected values
	assert.Equal(t, "mission_run", ScopeMissionRun)
	assert.Equal(t, "mission", ScopeMission)
	assert.Equal(t, "global", ScopeGlobal)
}
