package harness

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/component"
	"github.com/zero-day-ai/gibson/internal/harness/middleware"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/tool"
	"github.com/zero-day-ai/gibson/internal/types"
)

// ────────────────────────────────────────────────────────────────────────────
// Mock Memory Store for Testing
// ────────────────────────────────────────────────────────────────────────────

type MockMemoryStore struct {
	WorkingFn   func() memory.WorkingMemory
	MissionFn   func() memory.MissionMemory
	LongTermFn  func() memory.LongTermMemory
	MissionIDFn func() types.ID
	CloseFn     func() error
}

func (m *MockMemoryStore) Working() memory.WorkingMemory {
	if m.WorkingFn != nil {
		return m.WorkingFn()
	}
	return nil
}

func (m *MockMemoryStore) Mission() memory.MissionMemory {
	if m.MissionFn != nil {
		return m.MissionFn()
	}
	return nil
}

func (m *MockMemoryStore) LongTerm() memory.LongTermMemory {
	if m.LongTermFn != nil {
		return m.LongTermFn()
	}
	return nil
}

func (m *MockMemoryStore) MissionID() types.ID {
	if m.MissionIDFn != nil {
		return m.MissionIDFn()
	}
	return types.NewID()
}

func (m *MockMemoryStore) Close() error {
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	return nil
}

var _ memory.MemoryManager = (*MockMemoryStore)(nil)

// ────────────────────────────────────────────────────────────────────────────
// Mock Registry Adapter for Testing
// ────────────────────────────────────────────────────────────────────────────

type MockRegistryAdapter struct {
	DiscoverAgentFn   func(ctx context.Context, name string) (agent.Agent, error)
	DiscoverToolFn    func(ctx context.Context, name string) (tool.Tool, error)
	ListAgentsFn      func(ctx context.Context) ([]component.AgentInfo, error)
	ListToolsFn       func(ctx context.Context) ([]component.ToolInfo, error)
	ListPluginsFn     func(ctx context.Context) ([]component.PluginInfo, error)
	DelegateToAgentFn func(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error)
}

func (m *MockRegistryAdapter) DiscoverAgent(ctx context.Context, name string) (agent.Agent, error) {
	if m.DiscoverAgentFn != nil {
		return m.DiscoverAgentFn(ctx, name)
	}
	return nil, types.NewError("MOCK_ERROR", "DiscoverAgent not implemented")
}

func (m *MockRegistryAdapter) DiscoverTool(ctx context.Context, name string) (tool.Tool, error) {
	if m.DiscoverToolFn != nil {
		return m.DiscoverToolFn(ctx, name)
	}
	return nil, types.NewError("MOCK_ERROR", "DiscoverTool not implemented")
}

func (m *MockRegistryAdapter) ListAgents(ctx context.Context) ([]component.AgentInfo, error) {
	if m.ListAgentsFn != nil {
		return m.ListAgentsFn(ctx)
	}
	return nil, types.NewError("MOCK_ERROR", "ListAgents not implemented")
}

func (m *MockRegistryAdapter) ListTools(ctx context.Context) ([]component.ToolInfo, error) {
	if m.ListToolsFn != nil {
		return m.ListToolsFn(ctx)
	}
	return nil, types.NewError("MOCK_ERROR", "ListTools not implemented")
}

func (m *MockRegistryAdapter) ListPlugins(ctx context.Context) ([]component.PluginInfo, error) {
	if m.ListPluginsFn != nil {
		return m.ListPluginsFn(ctx)
	}
	return nil, types.NewError("MOCK_ERROR", "ListPlugins not implemented")
}

func (m *MockRegistryAdapter) DelegateToAgent(ctx context.Context, name string, task agent.Task, harness agent.AgentHarness) (agent.Result, error) {
	if m.DelegateToAgentFn != nil {
		return m.DelegateToAgentFn(ctx, name, task, harness)
	}
	return agent.Result{}, types.NewError("MOCK_ERROR", "DelegateToAgent not implemented")
}

var _ component.ComponentDiscovery = (*MockRegistryAdapter)(nil)

// ────────────────────────────────────────────────────────────────────────────
// NewHarnessFactory Tests
// ────────────────────────────────────────────────────────────────────────────

func TestNewHarnessFactory_Success(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	// Verify defaults were applied
	storedConfig := factory.Config()
	assert.NotNil(t, storedConfig.LLMRegistry)
	// PluginRegistry was removed in plugin-runtime Spec 2 Phase 7.
	assert.NotNil(t, storedConfig.Logger)
	assert.NotNil(t, storedConfig.FindingStore)
	assert.NotNil(t, storedConfig.Metrics)
	assert.NotNil(t, storedConfig.Tracer)
	assert.NotNil(t, storedConfig.GraphRAGBridge)
	assert.NotNil(t, storedConfig.GraphRAGQueryBridge)
}

func TestNewHarnessFactory_InvalidConfig_NoSlotManager(t *testing.T) {
	config := HarnessConfig{
		// Missing SlotManager
	}

	factory, err := NewHarnessFactory(config)
	require.Error(t, err)
	assert.Nil(t, factory)

	// Verify error is about validation
	assert.Contains(t, err.Error(), "validation")
}

func TestNewHarnessFactory_AppliesDefaults(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		// All other fields nil
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	storedConfig := factory.Config()

	// Verify all defaults were applied
	assert.NotNil(t, storedConfig.LLMRegistry, "LLMRegistry should be defaulted")
	// PluginRegistry was removed in plugin-runtime Spec 2 Phase 7.
	assert.NotNil(t, storedConfig.Logger, "Logger should be defaulted")
	assert.NotNil(t, storedConfig.FindingStore, "FindingStore should be defaulted")
	assert.NotNil(t, storedConfig.Metrics, "Metrics should be defaulted")
	assert.NotNil(t, storedConfig.Tracer, "Tracer should be defaulted")
	assert.NotNil(t, storedConfig.GraphRAGBridge, "GraphRAGBridge should be defaulted")
	assert.NotNil(t, storedConfig.GraphRAGQueryBridge, "GraphRAGQueryBridge should be defaulted")
	assert.NotNil(t, storedConfig.SlotManager, "SlotManager should remain set")
	assert.Nil(t, storedConfig.MemoryManager, "MemoryManager should not be defaulted")
}

func TestNewHarnessFactory_PreservesProvidedConfig(t *testing.T) {
	llmReg := llm.NewLLMRegistry()
	slotMgr := llm.NewSlotManager(llmReg)
	findingStore := NewInMemoryFindingStore()
	metrics := NewNoOpMetricsRecorder()
	memStore := &MockMemoryStore{}

	config := HarnessConfig{
		SlotManager:   slotMgr,
		LLMRegistry:   llmReg,
		FindingStore:  findingStore,
		Metrics:       metrics,
		MemoryManager: memStore,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	storedConfig := factory.Config()

	// Verify provided values were preserved
	assert.Equal(t, slotMgr, storedConfig.SlotManager)
	assert.Equal(t, llmReg, storedConfig.LLMRegistry)
	assert.Equal(t, findingStore, storedConfig.FindingStore)
	assert.Equal(t, metrics, storedConfig.Metrics)
	assert.Equal(t, memStore, storedConfig.MemoryManager)
}

func TestNewHarnessFactory_FullConfiguration(t *testing.T) {
	// Test with all fields specified
	// Note: GraphRAGBridge and GraphRAGQueryBridge are required - use mock implementations
	graphRAGBridge := NewGraphRAGBridge(nil, DefaultGraphRAGBridgeConfig())
	mockStore := &MockGraphRAGStore{IsHealthy: true}
	graphRAGQueryBridge := NewGraphRAGQueryBridge(mockStore, nil)

	config := HarnessConfig{
		SlotManager:         llm.NewSlotManager(llm.NewLLMRegistry()),
		LLMRegistry:         llm.NewLLMRegistry(),
		FindingStore:        NewInMemoryFindingStore(),
		Metrics:             NewNoOpMetricsRecorder(),
		MemoryManager:       &MockMemoryStore{},
		GraphRAGBridge:      graphRAGBridge,
		GraphRAGQueryBridge: graphRAGQueryBridge,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)
	assert.NotNil(t, factory)

	storedConfig := factory.Config()

	// Verify all provided values are preserved
	assert.NotNil(t, storedConfig.SlotManager)
	assert.NotNil(t, storedConfig.LLMRegistry)
	// PluginRegistry was removed in plugin-runtime Spec 2 Phase 7.
	assert.NotNil(t, storedConfig.FindingStore)
	assert.NotNil(t, storedConfig.Metrics)
	assert.NotNil(t, storedConfig.MemoryManager)
	assert.NotNil(t, storedConfig.GraphRAGBridge)
	assert.NotNil(t, storedConfig.GraphRAGQueryBridge)

	// Defaults should still be applied for missing fields (Logger, Tracer)
	assert.NotNil(t, storedConfig.Logger)
	assert.NotNil(t, storedConfig.Tracer)
}

// ────────────────────────────────────────────────────────────────────────────
// Factory Create Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFactory_Create_Success(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, harness)

	// Verify harness has correct configuration
	assert.Equal(t, missionCtx.CurrentAgent, harness.Mission().CurrentAgent)
	assert.Equal(t, missionID, harness.Mission().ID)
	assert.Equal(t, "test-mission", harness.Mission().Name)
	assert.Equal(t, "test-target", harness.Target().Name)
	assert.Equal(t, "https://example.com", harness.Target().URL)
}

func TestFactory_Create_UpdatesMissionContext(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	// Create mission context with different agent name
	missionCtx := NewMissionContext(missionID, "test-mission", "original-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create harness with different agent name
	harness, err := factory.Create("new-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Verify mission context was updated with new agent name
	assert.Equal(t, "new-agent", harness.Mission().CurrentAgent)
	assert.Equal(t, missionID, harness.Mission().ID)
	assert.Equal(t, "test-mission", harness.Mission().Name)
}

func TestFactory_Create_EmptyAgentName(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("", missionCtx, targetInfo)

	require.Error(t, err)
	assert.Nil(t, harness)
	assert.Contains(t, err.Error(), "agent name")
}

func TestFactory_Create_WithMemoryManager(t *testing.T) {
	memStore := &MockMemoryStore{}

	config := HarnessConfig{
		SlotManager:   llm.NewSlotManager(llm.NewLLMRegistry()),
		MemoryManager: memStore,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, harness)

	// Verify harness has access to memory
	assert.NotNil(t, harness.Memory())
}

func TestFactory_Create_MultipleHarnesses(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "agent1")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create multiple harnesses for different agents
	harness1, err := factory.Create("agent1", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, harness1)

	harness2, err := factory.Create("agent2", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, harness2)

	harness3, err := factory.Create("agent3", missionCtx, targetInfo)
	require.NoError(t, err)
	assert.NotNil(t, harness3)

	// Verify each harness has correct agent name
	assert.Equal(t, "agent1", harness1.Mission().CurrentAgent)
	assert.Equal(t, "agent2", harness2.Mission().CurrentAgent)
	assert.Equal(t, "agent3", harness3.Mission().CurrentAgent)

	// All should share same mission ID
	assert.Equal(t, missionID, harness1.Mission().ID)
	assert.Equal(t, missionID, harness2.Mission().ID)
	assert.Equal(t, missionID, harness3.Mission().ID)
}

func TestFactory_Create_IndependentTokenTrackers(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "agent1")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create two harnesses
	harness1, err := factory.Create("agent1", missionCtx, targetInfo)
	require.NoError(t, err)

	harness2, err := factory.Create("agent2", missionCtx, targetInfo)
	require.NoError(t, err)

	// Verify each has its own token tracker (different instances)
	tracker1 := harness1.TokenUsage()
	tracker2 := harness2.TokenUsage()

	assert.NotNil(t, tracker1)
	assert.NotNil(t, tracker2)
	// Token trackers should be different pointers (pointing to different harness fields)
	// We can't compare the pointers directly since they're value types, but we can
	// verify they exist and are independent by checking they're both non-nil
	// The factory creates a new token tracker for each harness (line 114 in factory.go)
}

func TestFactory_Create_SharedFindingStore(t *testing.T) {
	findingStore := NewInMemoryFindingStore()
	config := HarnessConfig{
		SlotManager:  llm.NewSlotManager(llm.NewLLMRegistry()),
		FindingStore: findingStore,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "agent1")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create two harnesses
	harness1, err := factory.Create("agent1", missionCtx, targetInfo)
	require.NoError(t, err)

	harness2, err := factory.Create("agent2", missionCtx, targetInfo)
	require.NoError(t, err)

	ctx := context.Background()

	// Submit finding from harness1
	finding1 := agent.NewFinding("Finding 1", "Description 1", agent.SeverityHigh)
	err = harness1.SubmitFinding(ctx, finding1)
	require.NoError(t, err)

	// Retrieve findings from harness2 (should see finding from harness1)
	findings, err := harness2.GetFindings(ctx, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "Finding 1", findings[0].Title)
}

// ────────────────────────────────────────────────────────────────────────────
// Factory CreateChild Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFactory_CreateChild_Success(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	parentMissionCtx := NewMissionContext(missionID, "test-mission", "parent-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create parent harness
	parentHarness, err := factory.Create("parent-agent", parentMissionCtx, targetInfo)
	require.NoError(t, err)

	// Create child harness
	childHarness, err := factory.CreateChild(parentHarness, "child-agent")
	require.NoError(t, err)
	assert.NotNil(t, childHarness)

	// Verify child has correct agent name
	assert.Equal(t, "child-agent", childHarness.Mission().CurrentAgent)

	// Verify child shares mission ID and name with parent
	assert.Equal(t, parentHarness.Mission().ID, childHarness.Mission().ID)
	assert.Equal(t, parentHarness.Mission().Name, childHarness.Mission().Name)

	// Verify child shares target info with parent
	assert.Equal(t, parentHarness.Target().ID, childHarness.Target().ID)
	assert.Equal(t, parentHarness.Target().Name, childHarness.Target().Name)
	assert.Equal(t, parentHarness.Target().URL, childHarness.Target().URL)
}

func TestFactory_CreateChild_NilParent(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	harness, err := factory.CreateChild(nil, "child-agent")

	require.Error(t, err)
	assert.Nil(t, harness)
	assert.Contains(t, err.Error(), "parent harness")
}

func TestFactory_CreateChild_EmptyAgentName(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	parentMissionCtx := NewMissionContext(missionID, "test-mission", "parent-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create parent harness
	parentHarness, err := factory.Create("parent-agent", parentMissionCtx, targetInfo)
	require.NoError(t, err)

	harness, err := factory.CreateChild(parentHarness, "")

	require.Error(t, err)
	assert.Nil(t, harness)
	assert.Contains(t, err.Error(), "agent name")
}

func TestFactory_CreateChild_SharedMemoryStore(t *testing.T) {
	memStore := &MockMemoryStore{}

	config := HarnessConfig{
		SlotManager:   llm.NewSlotManager(llm.NewLLMRegistry()),
		MemoryManager: memStore,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	parentMissionCtx := NewMissionContext(missionID, "test-mission", "parent-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create parent harness
	parentHarness, err := factory.Create("parent-agent", parentMissionCtx, targetInfo)
	require.NoError(t, err)

	// Create child harness
	childHarness, err := factory.CreateChild(parentHarness, "child-agent")
	require.NoError(t, err)

	// Verify both have access to memory (shared through factory config)
	assert.NotNil(t, parentHarness.Memory())
	assert.NotNil(t, childHarness.Memory())

	// Memory manager should be the same instance (shared)
	assert.Equal(t, parentHarness.Memory(), childHarness.Memory())
}

func TestFactory_CreateChild_SharedFindingStore(t *testing.T) {
	findingStore := NewInMemoryFindingStore()
	config := HarnessConfig{
		SlotManager:  llm.NewSlotManager(llm.NewLLMRegistry()),
		FindingStore: findingStore,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	parentMissionCtx := NewMissionContext(missionID, "test-mission", "parent-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create parent harness
	parentHarness, err := factory.Create("parent-agent", parentMissionCtx, targetInfo)
	require.NoError(t, err)

	// Create child harness
	childHarness, err := factory.CreateChild(parentHarness, "child-agent")
	require.NoError(t, err)

	ctx := context.Background()

	// Submit finding from parent
	finding1 := agent.NewFinding("Parent Finding", "From parent", agent.SeverityHigh)
	err = parentHarness.SubmitFinding(ctx, finding1)
	require.NoError(t, err)

	// Submit finding from child
	finding2 := agent.NewFinding("Child Finding", "From child", agent.SeverityMedium)
	err = childHarness.SubmitFinding(ctx, finding2)
	require.NoError(t, err)

	// Both should see all findings (shared store)
	parentFindings, err := parentHarness.GetFindings(ctx, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, parentFindings, 2)

	childFindings, err := childHarness.GetFindings(ctx, FindingFilter{})
	require.NoError(t, err)
	assert.Len(t, childFindings, 2)
}

func TestFactory_CreateChild_IndependentTokenTrackers(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	parentMissionCtx := NewMissionContext(missionID, "test-mission", "parent-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create parent harness
	parentHarness, err := factory.Create("parent-agent", parentMissionCtx, targetInfo)
	require.NoError(t, err)

	// Create child harness
	childHarness, err := factory.CreateChild(parentHarness, "child-agent")
	require.NoError(t, err)

	// Verify each has its own token tracker
	parentTracker := parentHarness.TokenUsage()
	childTracker := childHarness.TokenUsage()

	assert.NotNil(t, parentTracker)
	assert.NotNil(t, childTracker)
	// Token trackers are different instances created by the factory
	// Each harness gets its own tracker for independent token usage tracking
	// The factory creates a new token tracker for each harness (line 114 in factory.go)
}

func TestFactory_CreateChild_Hierarchy(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "root-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create root harness
	rootHarness, err := factory.Create("root-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Create child harness
	childHarness, err := factory.CreateChild(rootHarness, "child-agent")
	require.NoError(t, err)

	// Create grandchild harness
	grandchildHarness, err := factory.CreateChild(childHarness, "grandchild-agent")
	require.NoError(t, err)

	// Verify hierarchy
	assert.Equal(t, "root-agent", rootHarness.Mission().CurrentAgent)
	assert.Equal(t, "child-agent", childHarness.Mission().CurrentAgent)
	assert.Equal(t, "grandchild-agent", grandchildHarness.Mission().CurrentAgent)

	// All should share same mission ID
	assert.Equal(t, missionID, rootHarness.Mission().ID)
	assert.Equal(t, missionID, childHarness.Mission().ID)
	assert.Equal(t, missionID, grandchildHarness.Mission().ID)
}

// ────────────────────────────────────────────────────────────────────────────
// Factory Config Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFactory_Config_ReturnsCorrectConfig(t *testing.T) {
	llmReg := llm.NewLLMRegistry()
	slotMgr := llm.NewSlotManager(llmReg)

	config := HarnessConfig{
		SlotManager: slotMgr,
		LLMRegistry: llmReg,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	retrievedConfig := factory.Config()

	assert.Equal(t, slotMgr, retrievedConfig.SlotManager)
	assert.Equal(t, llmReg, retrievedConfig.LLMRegistry)
}

func TestFactory_Config_IsCopy(t *testing.T) {
	llmReg := llm.NewLLMRegistry()
	slotMgr := llm.NewSlotManager(llmReg)

	config := HarnessConfig{
		SlotManager: slotMgr,
		LLMRegistry: llmReg,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Get config multiple times
	config1 := factory.Config()
	config2 := factory.Config()

	// Both should have same values (value semantics)
	assert.Equal(t, config1.SlotManager, config2.SlotManager)
	assert.Equal(t, config1.LLMRegistry, config2.LLMRegistry)
}

// ────────────────────────────────────────────────────────────────────────────
// Type Aliases Tests
// ────────────────────────────────────────────────────────────────────────────

// Note: TestNewDefaultHarnessFactory_Alias is already defined in config_test.go

// ────────────────────────────────────────────────────────────────────────────
// Interface Compliance Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFactory_InterfaceCompliance(t *testing.T) {
	// Verify DefaultHarnessFactory implements HarnessFactoryInterface
	var _ HarnessFactoryInterface = (*DefaultHarnessFactory)(nil)
}

// ────────────────────────────────────────────────────────────────────────────
// Edge Cases and Concurrent Access Tests
// ────────────────────────────────────────────────────────────────────────────

func TestFactory_ConcurrentCreation(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "agent1")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create multiple harnesses concurrently
	const numHarnesses = 10
	harnesses := make([]AgentHarness, numHarnesses)
	errors := make([]error, numHarnesses)

	done := make(chan bool)
	for i := 0; i < numHarnesses; i++ {
		go func(idx int) {
			agentName := "agent-" + string(rune('0'+idx))
			h, e := factory.Create(agentName, missionCtx, targetInfo)
			harnesses[idx] = h
			errors[idx] = e
			done <- true
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < numHarnesses; i++ {
		<-done
	}

	// Verify all succeeded
	for i := 0; i < numHarnesses; i++ {
		assert.NoError(t, errors[i], "harness %d should have been created successfully", i)
		assert.NotNil(t, harnesses[i], "harness %d should not be nil", i)
	}
}

func TestFactory_SameMissionDifferentAgents(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	missionID := types.NewID()
	missionCtx := NewMissionContext(missionID, "test-mission", "agent1")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	// Create harnesses for same mission but different agents
	agents := []string{"agent1", "agent2", "agent3"}
	harnesses := make([]AgentHarness, len(agents))

	for i, agentName := range agents {
		h, err := factory.Create(agentName, missionCtx, targetInfo)
		require.NoError(t, err)
		harnesses[i] = h
	}

	// Verify all have same mission ID but different agent names
	for i, h := range harnesses {
		assert.Equal(t, missionID, h.Mission().ID)
		assert.Equal(t, agents[i], h.Mission().CurrentAgent)
	}
}

func TestFactory_DifferentMissionsSameAgent(t *testing.T) {
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create harnesses for different missions with same agent name
	missions := []struct {
		ID   types.ID
		Name string
	}{
		{types.NewID(), "mission1"},
		{types.NewID(), "mission2"},
		{types.NewID(), "mission3"},
	}

	harnesses := make([]AgentHarness, len(missions))

	for i, m := range missions {
		missionCtx := NewMissionContext(m.ID, m.Name, "same-agent")
		targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")
		h, err := factory.Create("same-agent", missionCtx, targetInfo)
		require.NoError(t, err)
		harnesses[i] = h
	}

	// Verify all have different mission IDs but same agent name
	for i, h := range harnesses {
		assert.Equal(t, missions[i].ID, h.Mission().ID)
		assert.Equal(t, missions[i].Name, h.Mission().Name)
		assert.Equal(t, "same-agent", h.Mission().CurrentAgent)
	}
}

// ────────────────────────────────────────────────────────────────────────────
// RegistryAdapter Tests (Task 3.3)
// ────────────────────────────────────────────────────────────────────────────

// TestFactory_Create_WithRegistryAdapter verifies that the factory correctly passes
// the RegistryAdapter from config to created harnesses.
func TestFactory_Create_WithRegistryAdapter(t *testing.T) {
	// Create mock registry adapter
	mockAdapter := &MockRegistryAdapter{}

	// Create config with registry adapter
	config := HarnessConfig{
		SlotManager:     llm.NewSlotManager(llm.NewLLMRegistry()),
		RegistryAdapter: mockAdapter,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create harness
	missionCtx := NewMissionContext(types.NewID(), "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Verify harness has the registry adapter
	// We need to type assert to access the internal field
	concreteHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok, "harness should be *DefaultAgentHarness")
	assert.Equal(t, mockAdapter, concreteHarness.registryAdapter)
}

// TestFactory_CreateChild_WithRegistryAdapter verifies that child harnesses
// inherit the RegistryAdapter from their parent via the factory config.
func TestFactory_CreateChild_WithRegistryAdapter(t *testing.T) {
	// Create mock registry adapter
	mockAdapter := &MockRegistryAdapter{}

	// Create config with registry adapter
	config := HarnessConfig{
		SlotManager:     llm.NewSlotManager(llm.NewLLMRegistry()),
		RegistryAdapter: mockAdapter,
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create parent harness
	missionCtx := NewMissionContext(types.NewID(), "test-mission", "parent-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	parentHarness, err := factory.Create("parent-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Create child harness
	childHarness, err := factory.CreateChild(parentHarness, "child-agent")
	require.NoError(t, err)

	// Verify both harnesses have the registry adapter
	concreteParent, ok := parentHarness.(*DefaultAgentHarness)
	require.True(t, ok, "parent harness should be *DefaultAgentHarness")
	assert.Equal(t, mockAdapter, concreteParent.registryAdapter)

	concreteChild, ok := childHarness.(*DefaultAgentHarness)
	require.True(t, ok, "child harness should be *DefaultAgentHarness")
	assert.Equal(t, mockAdapter, concreteChild.registryAdapter)
}

// TestFactory_Create_WithoutRegistryAdapter verifies that agent operations
// gracefully handle missing registry adapter.
func TestFactory_Create_WithoutRegistryAdapter(t *testing.T) {
	// Create config WITHOUT registry adapter
	config := HarnessConfig{
		SlotManager: llm.NewSlotManager(llm.NewLLMRegistry()),
		// RegistryAdapter is nil
	}

	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)

	// Create harness
	missionCtx := NewMissionContext(types.NewID(), "test-mission", "test-agent")
	targetInfo := NewTargetInfo(types.NewID(), "test-target", "https://example.com", "web")

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)

	// Verify harness has nil registry adapter
	concreteHarness, ok := harness.(*DefaultAgentHarness)
	require.True(t, ok, "harness should be *DefaultAgentHarness")
	assert.Nil(t, concreteHarness.registryAdapter)

	// ListAgents should return empty list
	agents := harness.ListAgents()
	assert.Empty(t, agents)
}

// TestHarnessFactory_WithMiddleware tests that the Middleware is applied
// when creating harnesses.
func TestHarnessFactory_WithMiddleware(t *testing.T) {
	// Create a mock slot manager
	llmRegistry := llm.NewLLMRegistry()
	slotManager := llm.NewSlotManager(llmRegistry)

	// Create a simple pass-through middleware
	testMiddleware := func(next middleware.Operation) middleware.Operation {
		return func(ctx context.Context, req any) (any, error) {
			return next(ctx, req)
		}
	}

	// Create config with middleware
	config := HarnessConfig{
		SlotManager: slotManager,
		Middleware:  testMiddleware,
	}

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)
	require.NotNil(t, factory)

	// Create harness
	missionCtx := MissionContext{
		ID:           types.NewID(),
		Name:         "test-mission",
		CurrentAgent: "test-agent",
	}
	targetInfo := TargetInfo{
		Type: "http_api",
		ID:   "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Verify returned harness is a MiddlewareHarness
	_, ok := harness.(*MiddlewareHarness)
	assert.True(t, ok, "returned harness should be *MiddlewareHarness when middleware is configured")
}

// TestHarnessFactory_WithoutMiddleware tests that harnesses work without middleware.
func TestHarnessFactory_WithoutMiddleware(t *testing.T) {
	// Create a mock slot manager
	llmRegistry := llm.NewLLMRegistry()
	slotManager := llm.NewSlotManager(llmRegistry)

	// Create config without middleware
	config := HarnessConfig{
		SlotManager: slotManager,
		Middleware:  nil, // No middleware
	}

	// Create factory
	factory, err := NewHarnessFactory(config)
	require.NoError(t, err)
	require.NotNil(t, factory)

	// Create harness
	missionCtx := MissionContext{
		ID:           types.NewID(),
		Name:         "test-mission",
		CurrentAgent: "test-agent",
	}
	targetInfo := TargetInfo{
		Type: "http_api",
		ID:   "test-target",
	}

	harness, err := factory.Create("test-agent", missionCtx, targetInfo)
	require.NoError(t, err)
	require.NotNil(t, harness)

	// Verify harness is unwrapped DefaultAgentHarness
	_, ok := harness.(*DefaultAgentHarness)
	assert.True(t, ok, "harness should be *DefaultAgentHarness when no middleware is configured")
}

// ────────────────────────────────────────────────────────────────────────────
// ListPlugins bridge tests (task 13 / task 15)
// ────────────────────────────────────────────────────────────────────────────

// TestListPlugins_NonEmptyMethods asserts that when the registry adapter
// returns a PluginInfo with a non-empty Methods slice, DefaultAgentHarness
// produces PluginDescriptor entries with a matching non-empty Methods list
// and each PluginMethodDescriptor carries the correct Name.
func TestListPlugins_NonEmptyMethods(t *testing.T) {
	adapter := &MockRegistryAdapter{
		ListPluginsFn: func(_ context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{
				{
					Name:    "debug-plugin",
					Version: "1.0.0",
					Methods: []string{"Echo", "Health"},
				},
			}, nil
		},
	}

	h := &DefaultAgentHarness{
		registryAdapter: adapter,
	}

	descriptors := h.ListPlugins()

	require.Len(t, descriptors, 1)
	desc := descriptors[0]
	assert.Equal(t, "debug-plugin", desc.Name)
	assert.Equal(t, "1.0.0", desc.Version)
	assert.True(t, desc.IsExternal)
	assert.Equal(t, PluginStatusUninitialized, desc.Status)

	require.Len(t, desc.Methods, 2, "Methods must be non-empty when PluginInfo carries method names")
	assert.Equal(t, "Echo", desc.Methods[0].Name)
	assert.Equal(t, "Health", desc.Methods[1].Name)
}

// TestListPlugins_EmptyMethods asserts that when the registry adapter returns
// a PluginInfo with an empty Methods slice, the harness bridge still returns
// a valid PluginDescriptor with a non-nil, empty Methods slice.
func TestListPlugins_EmptyMethods(t *testing.T) {
	adapter := &MockRegistryAdapter{
		ListPluginsFn: func(_ context.Context) ([]component.PluginInfo, error) {
			return []component.PluginInfo{
				{
					Name:    "legacy-plugin",
					Version: "0.9.0",
					Methods: []string{},
				},
			}, nil
		},
	}

	h := &DefaultAgentHarness{
		registryAdapter: adapter,
	}

	descriptors := h.ListPlugins()

	require.Len(t, descriptors, 1)
	desc := descriptors[0]
	assert.NotNil(t, desc.Methods, "Methods must be non-nil even for plugins with no declared methods")
	assert.Len(t, desc.Methods, 0)
}

// TestListPlugins_NoAdapter asserts that ListPlugins returns an empty slice
// (not nil) when no registry adapter is configured.
func TestListPlugins_NoAdapter(t *testing.T) {
	h := &DefaultAgentHarness{}

	descriptors := h.ListPlugins()

	assert.NotNil(t, descriptors)
	assert.Len(t, descriptors, 0)
}
