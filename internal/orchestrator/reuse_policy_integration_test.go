package orchestrator

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ────────────────────────────────────────────────────────────────────────────
// Mock Implementations
// ────────────────────────────────────────────────────────────────────────────

// mockPolicySource implements PolicySource for testing
type mockPolicySource struct {
	policies map[string]*DataPolicy
	err      error
}

func newMockPolicySource() *mockPolicySource {
	return &mockPolicySource{
		policies: make(map[string]*DataPolicy),
	}
}

func (m *mockPolicySource) SetPolicy(agentName string, policy *DataPolicy) {
	m.policies[agentName] = policy
}

func (m *mockPolicySource) SetError(err error) {
	m.err = err
}

func (m *mockPolicySource) GetDataPolicy(agentName string) (*DataPolicy, error) {
	if m.err != nil {
		return nil, m.err
	}
	policy, ok := m.policies[agentName]
	if !ok {
		return nil, nil
	}
	return policy, nil
}

// mockNodeStore implements NodeStore for testing
type mockNodeStore struct {
	counts map[string]map[string]int // agent -> scope -> count
	err    error
}

func newMockNodeStore() *mockNodeStore {
	return &mockNodeStore{
		counts: make(map[string]map[string]int),
	}
}

func (m *mockNodeStore) SetCount(agentName, scope string, count int) {
	if m.counts[agentName] == nil {
		m.counts[agentName] = make(map[string]int)
	}
	m.counts[agentName][scope] = count
}

func (m *mockNodeStore) SetError(err error) {
	m.err = err
}

func (m *mockNodeStore) CountByAgentInScope(ctx context.Context, agentName, scope string) (int, error) {
	if m.err != nil {
		return 0, m.err
	}
	if agentCounts, ok := m.counts[agentName]; ok {
		if count, ok := agentCounts[scope]; ok {
			return count, nil
		}
	}
	return 0, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Integration Test Scenarios
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_Skip_WithExistingData tests the skip policy when data exists.
// Scenario:
// 1. Agent stores data in first run
// 2. Configure reuse: skip
// 3. Simulate second mission run
// 4. Verify agent would be skipped (ShouldExecute returns false)
func TestReusePolicyIntegration_Skip_WithExistingData(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy for agent: reuse=skip, input_scope=mission
	policy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("network-recon", policy)

	// Simulate first run: agent stored 5 nodes in mission scope
	nodeStore.SetCount("network-recon", ScopeMission, 5)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute on second run
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should be skipped because data exists
	assert.False(t, shouldExecute, "Agent should be skipped when data exists and reuse=skip")
	assert.Equal(t, "existing data found", reason, "Reason should indicate existing data")
}

// TestReusePolicyIntegration_Skip_WithoutExistingData tests the skip policy when no data exists.
// Scenario:
// 1. Configure reuse: skip
// 2. No existing data in graph
// 3. Verify agent executes normally (ShouldExecute returns true)
func TestReusePolicyIntegration_Skip_WithoutExistingData(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy for agent: reuse=skip, input_scope=mission
	policy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("network-recon", policy)

	// No data stored (count = 0)
	nodeStore.SetCount("network-recon", ScopeMission, 0)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should execute because no data exists
	assert.True(t, shouldExecute, "Agent should execute when no data exists and reuse=skip")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// TestReusePolicyIntegration_Always_NeverExecutes tests the always policy.
// Scenario:
// 1. Configure reuse: always
// 2. Verify agent never executes (ShouldExecute returns false)
func TestReusePolicyIntegration_Always_NeverExecutes(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy for agent: reuse=always
	policy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseAlways,
	}
	policySource.SetPolicy("network-recon", policy)

	// Data exists in graph
	nodeStore.SetCount("network-recon", ScopeMission, 10)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should never execute with reuse=always
	assert.False(t, shouldExecute, "Agent should never execute with reuse=always")
	assert.Equal(t, "reuse=always", reason, "Reason should indicate reuse=always policy")

	// Test again with no data - should still not execute
	nodeStore.SetCount("network-recon", ScopeMission, 0)
	shouldExecute, reason = checker.ShouldExecute(ctx, "network-recon")

	assert.False(t, shouldExecute, "Agent should never execute with reuse=always, even with no data")
	assert.Equal(t, "reuse=always", reason, "Reason should indicate reuse=always policy")
}

// TestReusePolicyIntegration_Never_AlwaysExecutes tests the never policy.
// Scenario:
// 1. Configure reuse: never
// 2. Verify agent always executes (ShouldExecute returns true)
func TestReusePolicyIntegration_Never_AlwaysExecutes(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy for agent: reuse=never
	policy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseNever,
	}
	policySource.SetPolicy("network-recon", policy)

	// Data exists in graph
	nodeStore.SetCount("network-recon", ScopeMission, 10)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should always execute with reuse=never
	assert.True(t, shouldExecute, "Agent should always execute with reuse=never")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")

	// Test again with no data - should still execute
	nodeStore.SetCount("network-recon", ScopeMission, 0)
	shouldExecute, reason = checker.ShouldExecute(ctx, "network-recon")

	assert.True(t, shouldExecute, "Agent should always execute with reuse=never, even with no data")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// ────────────────────────────────────────────────────────────────────────────
// Scope Testing
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_ScopeIsolation tests that different scopes are isolated.
// Scenario:
// 1. Configure reuse: skip with input_scope=mission_run
// 2. Data exists in mission scope but not mission_run scope
// 3. Verify agent executes (checks mission_run scope only)
func TestReusePolicyIntegration_ScopeIsolation(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy: reuse=skip, input_scope=mission_run
	policy := &DataPolicy{
		OutputScope: ScopeMissionRun,
		InputScope:  ScopeMissionRun,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("network-recon", policy)

	// Data exists in mission scope (from previous runs)
	nodeStore.SetCount("network-recon", ScopeMission, 10)
	// But no data in current mission_run scope
	nodeStore.SetCount("network-recon", ScopeMissionRun, 0)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should execute because mission_run scope is empty
	assert.True(t, shouldExecute, "Agent should execute when input_scope (mission_run) has no data")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// TestReusePolicyIntegration_GlobalScope tests global scope behavior.
// Scenario:
// 1. Configure reuse: skip with input_scope=global
// 2. Data exists in global scope
// 3. Verify agent is skipped
func TestReusePolicyIntegration_GlobalScope(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy: reuse=skip, input_scope=global
	policy := &DataPolicy{
		OutputScope: ScopeGlobal,
		InputScope:  ScopeGlobal,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("network-recon", policy)

	// Data exists in global scope (across all missions)
	nodeStore.SetCount("network-recon", ScopeGlobal, 50)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should be skipped because global scope has data
	assert.False(t, shouldExecute, "Agent should be skipped when global scope has data")
	assert.Equal(t, "existing data found", reason, "Reason should indicate existing data")
}

// ────────────────────────────────────────────────────────────────────────────
// Error Handling Tests
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_PolicySourceError tests error handling when policy retrieval fails.
// Scenario:
// 1. PolicySource.GetDataPolicy returns error
// 2. Verify agent executes (fail-open behavior)
func TestReusePolicyIntegration_PolicySourceError(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure error on policy retrieval
	policySource.SetError(errors.New("policy database connection failed"))

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should execute (fail-open) when policy retrieval fails
	assert.True(t, shouldExecute, "Agent should execute when policy retrieval fails (fail-open)")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// TestReusePolicyIntegration_NodeStoreError tests error handling when node count fails.
// Scenario:
// 1. Configure reuse: skip
// 2. NodeStore.CountByAgentInScope returns error
// 3. Verify agent executes (fail-open behavior)
func TestReusePolicyIntegration_NodeStoreError(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policy: reuse=skip
	policy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("network-recon", policy)

	// Configure error on node count
	nodeStore.SetError(errors.New("graph database connection failed"))

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should execute (fail-open) when node count fails
	assert.True(t, shouldExecute, "Agent should execute when node count fails (fail-open)")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// ────────────────────────────────────────────────────────────────────────────
// Default Policy Tests
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_NoPolicyDefined tests default behavior when no policy is defined.
// Scenario:
// 1. No policy defined for agent
// 2. Verify agent executes with default policy (reuse=never)
func TestReusePolicyIntegration_NoPolicyDefined(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// No policy configured for agent
	// (policy source returns nil)

	// Data exists in mission scope
	nodeStore.SetCount("network-recon", ScopeMission, 10)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should execute with default policy (reuse=never)
	assert.True(t, shouldExecute, "Agent should execute when no policy defined (defaults to reuse=never)")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// TestReusePolicyIntegration_EmptyPolicy tests behavior with empty policy struct.
// Scenario:
// 1. Policy exists but all fields are empty (will get defaults applied)
// 2. Verify defaults are applied correctly (reuse=never, scope=mission)
func TestReusePolicyIntegration_EmptyPolicy(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure empty policy (defaults will be applied)
	policy := &DataPolicy{}
	policySource.SetPolicy("network-recon", policy)

	// Data exists in mission scope
	nodeStore.SetCount("network-recon", ScopeMission, 10)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Execute: Check if agent should execute
	shouldExecute, reason := checker.ShouldExecute(ctx, "network-recon")

	// Verify: Agent should execute with default reuse=never
	assert.True(t, shouldExecute, "Agent should execute with empty policy (defaults to reuse=never)")
	assert.Empty(t, reason, "Reason should be empty when agent should execute")
}

// ────────────────────────────────────────────────────────────────────────────
// Multi-Agent Scenario Tests
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_MultiAgent_DifferentPolicies tests multiple agents with different policies.
// Scenario:
// 1. Agent A: reuse=skip, has data -> should skip
// 2. Agent B: reuse=never, has data -> should execute
// 3. Agent C: reuse=always, no data -> should skip
func TestReusePolicyIntegration_MultiAgent_DifferentPolicies(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure Agent A: reuse=skip
	policyA := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("agent-a", policyA)
	nodeStore.SetCount("agent-a", ScopeMission, 5)

	// Configure Agent B: reuse=never
	policyB := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseNever,
	}
	policySource.SetPolicy("agent-b", policyB)
	nodeStore.SetCount("agent-b", ScopeMission, 10)

	// Configure Agent C: reuse=always
	policyC := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseAlways,
	}
	policySource.SetPolicy("agent-c", policyC)
	nodeStore.SetCount("agent-c", ScopeMission, 0)

	// Create policy checker
	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// Test Agent A: Should skip (reuse=skip, data exists)
	shouldExecuteA, reasonA := checker.ShouldExecute(ctx, "agent-a")
	assert.False(t, shouldExecuteA, "Agent A should be skipped (reuse=skip, data exists)")
	assert.Equal(t, "existing data found", reasonA)

	// Test Agent B: Should execute (reuse=never)
	shouldExecuteB, reasonB := checker.ShouldExecute(ctx, "agent-b")
	assert.True(t, shouldExecuteB, "Agent B should execute (reuse=never)")
	assert.Empty(t, reasonB)

	// Test Agent C: Should skip (reuse=always)
	shouldExecuteC, reasonC := checker.ShouldExecute(ctx, "agent-c")
	assert.False(t, shouldExecuteC, "Agent C should be skipped (reuse=always)")
	assert.Equal(t, "reuse=always", reasonC)
}

// ────────────────────────────────────────────────────────────────────────────
// Edge Cases
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_EdgeCases tests various edge cases.
func TestReusePolicyIntegration_EdgeCases(t *testing.T) {
	t.Run("nil logger", func(t *testing.T) {
		ctx := context.Background()
		policySource := newMockPolicySource()
		nodeStore := newMockNodeStore()

		// Create policy checker with nil logger (should use default)
		checker := NewPolicyChecker(policySource, nodeStore, nil)
		require.NotNil(t, checker, "Should handle nil logger gracefully")

		policy := &DataPolicy{Reuse: ReuseNever}
		policySource.SetPolicy("test-agent", policy)

		shouldExecute, reason := checker.ShouldExecute(ctx, "test-agent")
		assert.True(t, shouldExecute)
		assert.Empty(t, reason)
	})

	t.Run("empty agent name", func(t *testing.T) {
		ctx := context.Background()
		policySource := newMockPolicySource()
		nodeStore := newMockNodeStore()
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

		checker := NewPolicyChecker(policySource, nodeStore, logger)

		// Empty agent name should work (returns no policy)
		shouldExecute, reason := checker.ShouldExecute(ctx, "")
		assert.True(t, shouldExecute, "Should execute with default policy for empty agent name")
		assert.Empty(t, reason)
	})

	t.Run("invalid reuse value", func(t *testing.T) {
		ctx := context.Background()
		policySource := newMockPolicySource()
		nodeStore := newMockNodeStore()
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

		// Configure policy with invalid reuse value
		policy := &DataPolicy{
			OutputScope: ScopeMission,
			InputScope:  ScopeMission,
			Reuse:       "invalid-value",
		}
		policySource.SetPolicy("test-agent", policy)

		checker := NewPolicyChecker(policySource, nodeStore, logger)

		// Should default to execute when invalid reuse value
		shouldExecute, reason := checker.ShouldExecute(ctx, "test-agent")
		assert.True(t, shouldExecute, "Should execute with invalid reuse value (fail-open)")
		assert.Empty(t, reason)
	})

	t.Run("context cancellation", func(t *testing.T) {
		// Create cancelled context
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		policySource := newMockPolicySource()
		nodeStore := newMockNodeStore()
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

		policy := &DataPolicy{Reuse: ReuseSkip}
		policySource.SetPolicy("test-agent", policy)
		nodeStore.SetCount("test-agent", ScopeMission, 5)

		checker := NewPolicyChecker(policySource, nodeStore, logger)

		// Should still check policy even with cancelled context
		// (context is passed through but not actively checked in current implementation)
		shouldExecute, reason := checker.ShouldExecute(ctx, "test-agent")
		assert.False(t, shouldExecute)
		assert.Equal(t, "existing data found", reason)
	})
}

// ────────────────────────────────────────────────────────────────────────────
// End-to-End Mission Simulation
// ────────────────────────────────────────────────────────────────────────────

// TestReusePolicyIntegration_E2E_MissionSimulation simulates a complete mission execution.
// Scenario:
// 1. Mission Run 1: Recon agent stores data
// 2. Mission Run 2: Recon agent skipped (reuse=skip), Exploit agent runs (reuse=never)
// 3. Mission Run 3: Both agents skipped (recon: existing data, exploit: reuse=always)
func TestReusePolicyIntegration_E2E_MissionSimulation(t *testing.T) {
	ctx := context.Background()

	// Setup: Create mock implementations
	policySource := newMockPolicySource()
	nodeStore := newMockNodeStore()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Configure policies
	reconPolicy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseSkip,
	}
	policySource.SetPolicy("recon-agent", reconPolicy)

	exploitPolicy := &DataPolicy{
		OutputScope: ScopeMission,
		InputScope:  ScopeMission,
		Reuse:       ReuseNever,
	}
	policySource.SetPolicy("exploit-agent", exploitPolicy)

	checker := NewPolicyChecker(policySource, nodeStore, logger)

	// ── Mission Run 1: First execution ──
	t.Run("run 1 - initial execution", func(t *testing.T) {
		// No data exists yet
		nodeStore.SetCount("recon-agent", ScopeMission, 0)
		nodeStore.SetCount("exploit-agent", ScopeMission, 0)

		// Both agents should execute
		shouldExecuteRecon, reasonRecon := checker.ShouldExecute(ctx, "recon-agent")
		assert.True(t, shouldExecuteRecon, "Recon agent should execute on first run")
		assert.Empty(t, reasonRecon)

		shouldExecuteExploit, reasonExploit := checker.ShouldExecute(ctx, "exploit-agent")
		assert.True(t, shouldExecuteExploit, "Exploit agent should execute on first run")
		assert.Empty(t, reasonExploit)

		// Simulate agents storing data
		nodeStore.SetCount("recon-agent", ScopeMission, 10)
		nodeStore.SetCount("exploit-agent", ScopeMission, 5)
	})

	// ── Mission Run 2: Recon data exists ──
	t.Run("run 2 - recon skipped, exploit runs", func(t *testing.T) {
		// Recon data exists, exploit data exists
		// But exploit has reuse=never, so it always runs

		shouldExecuteRecon, reasonRecon := checker.ShouldExecute(ctx, "recon-agent")
		assert.False(t, shouldExecuteRecon, "Recon agent should be skipped (data exists)")
		assert.Equal(t, "existing data found", reasonRecon)

		shouldExecuteExploit, reasonExploit := checker.ShouldExecute(ctx, "exploit-agent")
		assert.True(t, shouldExecuteExploit, "Exploit agent should always execute (reuse=never)")
		assert.Empty(t, reasonExploit)

		// Exploit runs and adds more data
		nodeStore.SetCount("exploit-agent", ScopeMission, 10)
	})

	// ── Mission Run 3: Change exploit to reuse=always ──
	t.Run("run 3 - both agents skipped", func(t *testing.T) {
		// Change exploit policy to reuse=always
		exploitPolicyAlways := &DataPolicy{
			OutputScope: ScopeMission,
			InputScope:  ScopeMission,
			Reuse:       ReuseAlways,
		}
		policySource.SetPolicy("exploit-agent", exploitPolicyAlways)

		// Both should be skipped now
		shouldExecuteRecon, reasonRecon := checker.ShouldExecute(ctx, "recon-agent")
		assert.False(t, shouldExecuteRecon, "Recon agent should be skipped (data exists)")
		assert.Equal(t, "existing data found", reasonRecon)

		shouldExecuteExploit, reasonExploit := checker.ShouldExecute(ctx, "exploit-agent")
		assert.False(t, shouldExecuteExploit, "Exploit agent should be skipped (reuse=always)")
		assert.Equal(t, "reuse=always", reasonExploit)
	})
}
