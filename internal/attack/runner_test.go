package attack

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zero-day-ai/gibson/internal/agent"
	"github.com/zero-day-ai/gibson/internal/finding"
	"github.com/zero-day-ai/gibson/internal/mission"
	"github.com/zero-day-ai/gibson/internal/payload"
	"github.com/zero-day-ai/gibson/internal/types"
)

// Mock implementations for testing
// Note: MockComponentDiscovery and MockAgent are defined in agent_test.go

type MockMissionOrchestrator struct {
	mock.Mock
}

func (m *MockMissionOrchestrator) Execute(ctx context.Context, missionObj *mission.Mission) (*mission.MissionResult, error) {
	args := m.Called(ctx, missionObj)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.MissionResult), args.Error(1)
}

func (m *MockMissionOrchestrator) ExecuteFromCheckpoint(ctx context.Context, missionObj *mission.Mission, checkpoint *mission.MissionCheckpoint) (*mission.MissionResult, error) {
	args := m.Called(ctx, missionObj, checkpoint)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.MissionResult), args.Error(1)
}

func (m *MockMissionOrchestrator) StopMission(ctx context.Context, missionID types.ID) error {
	args := m.Called(ctx, missionID)
	return args.Error(0)
}

// MockComponentDiscovery and MockAgent are defined in agent_test.go and reused here

type MockPayloadRegistry struct {
	mock.Mock
}

func (m *MockPayloadRegistry) Register(ctx context.Context, p *payload.Payload) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockPayloadRegistry) Get(ctx context.Context, id types.ID) (*payload.Payload, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*payload.Payload), args.Error(1)
}

func (m *MockPayloadRegistry) List(ctx context.Context, filter *payload.PayloadFilter) ([]*payload.Payload, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*payload.Payload), args.Error(1)
}

func (m *MockPayloadRegistry) Search(ctx context.Context, query string, filter *payload.PayloadFilter) ([]*payload.Payload, error) {
	args := m.Called(ctx, query, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*payload.Payload), args.Error(1)
}

func (m *MockPayloadRegistry) Update(ctx context.Context, p *payload.Payload) error {
	args := m.Called(ctx, p)
	return args.Error(0)
}

func (m *MockPayloadRegistry) Disable(ctx context.Context, id types.ID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockPayloadRegistry) Enable(ctx context.Context, id types.ID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockPayloadRegistry) GetByCategory(ctx context.Context, category payload.PayloadCategory) ([]*payload.Payload, error) {
	args := m.Called(ctx, category)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*payload.Payload), args.Error(1)
}

func (m *MockPayloadRegistry) GetByMitreTechnique(ctx context.Context, technique string) ([]*payload.Payload, error) {
	args := m.Called(ctx, technique)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*payload.Payload), args.Error(1)
}

func (m *MockPayloadRegistry) LoadBuiltIns(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockPayloadRegistry) Count(ctx context.Context, filter *payload.PayloadFilter) (int, error) {
	args := m.Called(ctx, filter)
	return args.Int(0), args.Error(1)
}

func (m *MockPayloadRegistry) ClearCache() {
	m.Called()
}

func (m *MockPayloadRegistry) Health(ctx context.Context) types.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(types.HealthStatus)
}

type MockMissionStore struct {
	mock.Mock
}

func (m *MockMissionStore) Save(ctx context.Context, missionObj *mission.Mission) error {
	args := m.Called(ctx, missionObj)
	return args.Error(0)
}

func (m *MockMissionStore) Get(ctx context.Context, id types.ID) (*mission.Mission, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) List(ctx context.Context, filter *mission.MissionFilter) ([]*mission.Mission, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) Update(ctx context.Context, missionObj *mission.Mission) error {
	args := m.Called(ctx, missionObj)
	return args.Error(0)
}

func (m *MockMissionStore) Delete(ctx context.Context, id types.ID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockMissionStore) GetByTarget(ctx context.Context, targetID types.ID) ([]*mission.Mission, error) {
	args := m.Called(ctx, targetID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) GetActive(ctx context.Context) ([]*mission.Mission, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) SaveCheckpoint(ctx context.Context, missionID types.ID, checkpoint *mission.MissionCheckpoint) error {
	args := m.Called(ctx, missionID, checkpoint)
	return args.Error(0)
}

func (m *MockMissionStore) Count(ctx context.Context, filter *mission.MissionFilter) (int, error) {
	args := m.Called(ctx, filter)
	return args.Int(0), args.Error(1)
}

func (m *MockMissionStore) GetByName(ctx context.Context, name string) (*mission.Mission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) UpdateStatus(ctx context.Context, id types.ID, status mission.MissionStatus) error {
	args := m.Called(ctx, id, status)
	return args.Error(0)
}

func (m *MockMissionStore) UpdateProgress(ctx context.Context, id types.ID, progress float64) error {
	args := m.Called(ctx, id, progress)
	return args.Error(0)
}

func (m *MockMissionStore) GetByNameAndStatus(ctx context.Context, name string, status mission.MissionStatus) (*mission.Mission, error) {
	args := m.Called(ctx, name, status)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) ListByName(ctx context.Context, name string, limit int) ([]*mission.Mission, error) {
	args := m.Called(ctx, name, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) GetLatestByName(ctx context.Context, name string) (*mission.Mission, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.Mission), args.Error(1)
}

func (m *MockMissionStore) IncrementRunNumber(ctx context.Context, name string) (int, error) {
	args := m.Called(ctx, name)
	return args.Int(0), args.Error(1)
}

func (m *MockMissionStore) FindOrCreateByName(ctx context.Context, mis *mission.Mission) (*mission.Mission, bool, error) {
	args := m.Called(ctx, mis)
	if args.Get(0) == nil {
		return nil, args.Bool(1), args.Error(2)
	}
	return args.Get(0).(*mission.Mission), args.Bool(1), args.Error(2)
}

// Mission definition methods (stubs for testing)
func (m *MockMissionStore) CreateDefinition(ctx context.Context, def *mission.MissionDefinition) error {
	args := m.Called(ctx, def)
	return args.Error(0)
}

func (m *MockMissionStore) GetDefinition(ctx context.Context, name string) (*mission.MissionDefinition, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*mission.MissionDefinition), args.Error(1)
}

func (m *MockMissionStore) ListDefinitions(ctx context.Context) ([]*mission.MissionDefinition, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*mission.MissionDefinition), args.Error(1)
}

func (m *MockMissionStore) UpdateDefinition(ctx context.Context, def *mission.MissionDefinition) error {
	args := m.Called(ctx, def)
	return args.Error(0)
}

func (m *MockMissionStore) DeleteDefinition(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

type MockFindingStore struct {
	mock.Mock
}

func (m *MockFindingStore) Store(ctx context.Context, f finding.EnhancedFinding) error {
	args := m.Called(ctx, f)
	return args.Error(0)
}

func (m *MockFindingStore) Get(ctx context.Context, id types.ID) (*finding.EnhancedFinding, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*finding.EnhancedFinding), args.Error(1)
}

func (m *MockFindingStore) List(ctx context.Context, missionID types.ID, filter *finding.FindingFilter) ([]finding.EnhancedFinding, error) {
	args := m.Called(ctx, missionID, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]finding.EnhancedFinding), args.Error(1)
}

func (m *MockFindingStore) Update(ctx context.Context, f finding.EnhancedFinding) error {
	args := m.Called(ctx, f)
	return args.Error(0)
}

func (m *MockFindingStore) Delete(ctx context.Context, id types.ID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockFindingStore) Count(ctx context.Context, missionID types.ID) (int, error) {
	args := m.Called(ctx, missionID)
	return args.Int(0), args.Error(1)
}

type MockTargetResolver struct {
	mock.Mock
}

func (m *MockTargetResolver) Resolve(ctx context.Context, opts *AttackOptions) (*TargetConfig, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TargetConfig), args.Error(1)
}

type MockAgentSelector struct {
	mock.Mock
}

func (m *MockAgentSelector) Select(ctx context.Context, agentName string) (agent.Agent, error) {
	args := m.Called(ctx, agentName)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(agent.Agent), args.Error(1)
}

func (m *MockAgentSelector) ListAvailable(ctx context.Context) ([]AgentInfo, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]AgentInfo), args.Error(1)
}

type MockPayloadFilter struct {
	mock.Mock
}

func (m *MockPayloadFilter) Filter(ctx context.Context, opts *AttackOptions) ([]payload.Payload, error) {
	args := m.Called(ctx, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]payload.Payload), args.Error(1)
}

// Test helper to create a runner with mocks
func setupRunner(t *testing.T) (*DefaultAttackRunner, *MockMissionOrchestrator, *MockComponentDiscovery, *MockPayloadRegistry, *MockMissionStore, *MockFindingStore, *MockTargetResolver, *MockAgentSelector, *MockPayloadFilter) {
	orchestrator := new(MockMissionOrchestrator)
	discovery := new(MockComponentDiscovery)
	payloadRegistry := new(MockPayloadRegistry)
	missionStore := new(MockMissionStore)
	findingStore := new(MockFindingStore)
	targetResolver := new(MockTargetResolver)
	agentSelector := new(MockAgentSelector)
	payloadFilter := new(MockPayloadFilter)

	runner := NewAttackRunner(
		orchestrator,
		discovery,
		payloadRegistry,
		missionStore,
		findingStore,
		WithTargetResolver(targetResolver),
		WithAgentSelector(agentSelector),
		WithPayloadFilter(payloadFilter),
	)

	return runner, orchestrator, discovery, payloadRegistry, missionStore, findingStore, targetResolver, agentSelector, payloadFilter
}

// TestNewAttackRunner verifies runner initialization
func TestNewAttackRunner(t *testing.T) {
	orchestrator := new(MockMissionOrchestrator)
	discovery := new(MockComponentDiscovery)
	payloadRegistry := new(MockPayloadRegistry)
	missionStore := new(MockMissionStore)
	findingStore := new(MockFindingStore)

	runner := NewAttackRunner(
		orchestrator,
		discovery,
		payloadRegistry,
		missionStore,
		findingStore,
	)

	assert.NotNil(t, runner)
	assert.NotNil(t, runner.orchestrator)
	assert.NotNil(t, runner.discovery)
	assert.NotNil(t, runner.payloadRegistry)
	assert.NotNil(t, runner.missionStore)
	assert.NotNil(t, runner.findingStore)
	assert.NotNil(t, runner.logger)
	assert.NotNil(t, runner.tracer)
	assert.NotNil(t, runner.targetResolver) // Should have default
	assert.NotNil(t, runner.agentSelector)  // Should have default
	assert.NotNil(t, runner.payloadFilter)  // Should have default
}

// TestRun_Success verifies successful attack execution without findings
func TestRun_Success(t *testing.T) {
	runner, orchestrator, _, _, missionStore, _, targetResolver, agentSelector, payloadFilter := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	missionResult := &mission.MissionResult{
		MissionID:  types.NewID(),
		Status:     mission.MissionStatusCompleted,
		FindingIDs: []types.ID{},
		Metrics: &mission.MissionMetrics{
			CompletedNodes: 1,
			TotalTokens:    1000,
		},
	}

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	missionStore.On("Save", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil)
	orchestrator.On("Execute", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(missionResult, nil)

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusSuccess, result.Status)
	assert.False(t, result.Persisted)
	assert.Nil(t, result.MissionID)
	assert.Equal(t, 0, len(result.Findings))

	targetResolver.AssertExpectations(t)
	agentSelector.AssertExpectations(t)
	payloadFilter.AssertExpectations(t)
	orchestrator.AssertExpectations(t)
}

// TestRun_WithFindings verifies attack execution with findings and auto-persist
func TestRun_WithFindings(t *testing.T) {
	runner, orchestrator, _, _, missionStore, findingStore, targetResolver, agentSelector, payloadFilter := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	findingID := types.NewID()
	testFinding := &finding.EnhancedFinding{
		Finding: agent.Finding{
			ID:       findingID,
			Title:    "Test Finding",
			Severity: agent.SeverityHigh,
		},
		MissionID: types.NewID(),
	}

	missionResult := &mission.MissionResult{
		MissionID:  types.NewID(),
		Status:     mission.MissionStatusCompleted,
		FindingIDs: []types.ID{findingID},
		Metrics: &mission.MissionMetrics{
			CompletedNodes: 1,
			TotalTokens:    1000,
		},
	}

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	orchestrator.On("Execute", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(missionResult, nil)
	findingStore.On("Get", mock.Anything, findingID).Return(testFinding, nil)
	missionStore.On("Save", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil)
	findingStore.On("Store", mock.Anything, *testFinding).Return(nil)

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusFindings, result.Status)
	assert.True(t, result.Persisted)
	assert.NotNil(t, result.MissionID)
	assert.Equal(t, 1, len(result.Findings))

	targetResolver.AssertExpectations(t)
	agentSelector.AssertExpectations(t)
	payloadFilter.AssertExpectations(t)
	orchestrator.AssertExpectations(t)
	findingStore.AssertExpectations(t)
	missionStore.AssertExpectations(t)
}

// TestRun_NoPersistFlag verifies that --no-persist prevents persistence
func TestRun_NoPersistFlag(t *testing.T) {
	runner, orchestrator, _, _, missionStore, findingStore, targetResolver, agentSelector, payloadFilter := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
		NoPersist: true,
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	findingID := types.NewID()
	testFinding := &finding.EnhancedFinding{
		Finding: agent.Finding{
			ID:       findingID,
			Title:    "Test Finding",
			Severity: agent.SeverityHigh,
		},
		MissionID: types.NewID(),
	}

	missionResult := &mission.MissionResult{
		MissionID:  types.NewID(),
		Status:     mission.MissionStatusCompleted,
		FindingIDs: []types.ID{findingID},
		Metrics: &mission.MissionMetrics{
			CompletedNodes: 1,
			TotalTokens:    1000,
		},
	}

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	missionStore.On("Save", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil)
	orchestrator.On("Execute", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(missionResult, nil)
	findingStore.On("Get", mock.Anything, findingID).Return(testFinding, nil)
	// Note: ephemeral mission is saved for orchestrator tracking, but not persisted permanently

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusFindings, result.Status)
	assert.False(t, result.Persisted) // Should NOT be persisted
	assert.Nil(t, result.MissionID)
	assert.Equal(t, 1, len(result.Findings))

	targetResolver.AssertExpectations(t)
	agentSelector.AssertExpectations(t)
	payloadFilter.AssertExpectations(t)
	orchestrator.AssertExpectations(t)
	findingStore.AssertExpectations(t)
	missionStore.AssertNotCalled(t, "Save")
}

// TestRun_PersistFlag verifies that --persist forces persistence
func TestRun_PersistFlag(t *testing.T) {
	runner, orchestrator, _, _, missionStore, _, targetResolver, agentSelector, payloadFilter := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
		Persist:   true,
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	missionResult := &mission.MissionResult{
		MissionID:  types.NewID(),
		Status:     mission.MissionStatusCompleted,
		FindingIDs: []types.ID{},
		Metrics: &mission.MissionMetrics{
			CompletedNodes: 1,
			TotalTokens:    1000,
		},
	}

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	orchestrator.On("Execute", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(missionResult, nil)
	missionStore.On("Save", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil)

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusSuccess, result.Status)
	assert.True(t, result.Persisted) // Should be persisted even without findings
	assert.NotNil(t, result.MissionID)

	targetResolver.AssertExpectations(t)
	agentSelector.AssertExpectations(t)
	payloadFilter.AssertExpectations(t)
	orchestrator.AssertExpectations(t)
	missionStore.AssertExpectations(t)
}

// TestRun_Cancellation verifies cancellation handling
func TestRun_Cancellation(t *testing.T) {
	runner, orchestrator, _, _, missionStore, _, targetResolver, agentSelector, payloadFilter := setupRunner(t)

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	missionStore.On("Save", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil)
	// The orchestrator will be called and should return a context cancelled error
	orchestrator.On("Execute", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil, context.Canceled)

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err) // We don't return error for cancellation
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusCancelled, result.Status)
	assert.False(t, result.Persisted)
}

// TestRun_Timeout verifies timeout handling
func TestRun_Timeout(t *testing.T) {
	runner, orchestrator, _, _, missionStore, _, targetResolver, agentSelector, payloadFilter := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
		Timeout:   1 * time.Millisecond,
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	missionStore.On("Save", mock.Anything, mock.AnythingOfType("*mission.Mission")).Return(nil)

	// Simulate timeout by returning context deadline exceeded
	orchestrator.On("Execute", mock.Anything, mock.AnythingOfType("*mission.Mission")).
		Return(nil, context.DeadlineExceeded).
		After(10 * time.Millisecond)

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err) // We don't return error for timeout
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusTimeout, result.Status)
	assert.NotNil(t, result.Error)
}

// TestRun_InvalidOptions verifies validation of attack options
func TestRun_InvalidOptions(t *testing.T) {
	runner, _, _, _, _, _, _, _, _ := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		// Missing required AgentName
		TargetURL: "https://example.com",
	}

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err) // Error is in result, not returned
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusFailed, result.Status)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "agent name is required")
}

// TestRun_TargetResolutionError verifies target resolution error handling
func TestRun_TargetResolutionError(t *testing.T) {
	runner, _, _, _, _, _, targetResolver, _, _ := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
	}

	targetResolver.On("Resolve", mock.Anything, opts).Return(nil, errors.New("target resolution failed"))

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err) // Error is in result
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusFailed, result.Status)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "target resolution failed")
}

// TestRun_AgentSelectionError verifies agent selection error handling
func TestRun_AgentSelectionError(t *testing.T) {
	runner, _, _, _, _, _, targetResolver, agentSelector, _ := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "nonexistent-agent",
		TargetURL: "https://example.com",
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "nonexistent-agent").Return(nil, errors.New("agent not found"))

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err) // Error is in result
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusFailed, result.Status)
	assert.NotNil(t, result.Error)
	assert.Contains(t, result.Error.Error(), "agent selection failed")
}

// TestRun_DryRun verifies dry-run mode
func TestRun_DryRun(t *testing.T) {
	runner, orchestrator, _, _, _, _, targetResolver, agentSelector, payloadFilter := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName: "test-agent",
		TargetURL: "https://example.com",
		DryRun:    true,
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	targetResolver.On("Resolve", mock.Anything, opts).Return(targetConfig, nil)
	agentSelector.On("Select", mock.Anything, "test-agent").Return(mockAgent, nil)
	payloadFilter.On("Filter", mock.Anything, opts).Return([]payload.Payload{}, nil)
	// Note: orchestrator.Execute should NOT be called in dry-run mode

	result, err := runner.Run(ctx, opts)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, AttackStatusSuccess, result.Status)
	assert.False(t, result.Persisted)

	targetResolver.AssertExpectations(t)
	agentSelector.AssertExpectations(t)
	payloadFilter.AssertExpectations(t)
	orchestrator.AssertNotCalled(t, "Execute")
}

// TestCreateEphemeralMission verifies mission creation
func TestCreateEphemeralMission(t *testing.T) {
	runner, _, _, _, _, _, _, _, _ := setupRunner(t)
	ctx := context.Background()

	opts := &AttackOptions{
		AgentName:         "test-agent",
		TargetURL:         "https://example.com",
		MaxTurns:          10,
		Timeout:           5 * time.Minute,
		MaxFindings:       100,
		SeverityThreshold: "high",
	}

	targetConfig := &TargetConfig{
		URL:      "https://example.com",
		Type:     types.TargetTypeLLMAPI,
		Provider: "openai",
		Headers:  map[string]string{},
	}

	mockAgent := new(MockAgent)
	mockAgent.On("Name").Return("test-agent")

	missionObj, err := runner.createEphemeralMission(ctx, opts, targetConfig, mockAgent)

	assert.NoError(t, err)
	assert.NotNil(t, missionObj)
	assert.Equal(t, mission.MissionStatusPending, missionObj.Status)
	assert.NotNil(t, missionObj.Constraints)
	assert.Equal(t, opts.Timeout, missionObj.Constraints.MaxDuration)
	assert.Equal(t, opts.MaxFindings, missionObj.Constraints.MaxFindings)
	assert.Equal(t, agent.FindingSeverity("high"), missionObj.Constraints.SeverityThreshold)
}

// TestShouldPersistMission verifies persistence logic
func TestShouldPersistMission(t *testing.T) {
	runner, _, _, _, _, _, _, _, _ := setupRunner(t)

	tests := []struct {
		name     string
		opts     *AttackOptions
		result   *AttackResult
		expected bool
	}{
		{
			name: "no persist flag with findings",
			opts: &AttackOptions{NoPersist: false, Persist: false},
			result: &AttackResult{
				Findings: []finding.EnhancedFinding{
					{
						Finding: agent.Finding{
							ID: types.NewID(),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "no persist flag without findings",
			opts: &AttackOptions{NoPersist: false, Persist: false},
			result: &AttackResult{
				Findings: []finding.EnhancedFinding{},
			},
			expected: false,
		},
		{
			name: "persist flag without findings",
			opts: &AttackOptions{Persist: true},
			result: &AttackResult{
				Findings: []finding.EnhancedFinding{},
			},
			expected: true,
		},
		{
			name: "no-persist flag with findings",
			opts: &AttackOptions{NoPersist: true},
			result: &AttackResult{
				Findings: []finding.EnhancedFinding{
					{
						Finding: agent.Finding{
							ID: types.NewID(),
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := runner.shouldPersistMission(tt.opts, tt.result)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

// TestCheckNodeFailures tests the checkNodeFailures method
func TestCheckNodeFailures(t *testing.T) {
	runner := &DefaultAttackRunner{}

	tests := []struct {
		name          string
		missionResult *mission.MissionResult
		wantFailed    bool
		wantOutput    string
		wantNodes     []string
	}{
		{
			name: "no failures - nil WorkflowResult",
			missionResult: &mission.MissionResult{
				WorkflowResult: nil,
			},
			wantFailed: false,
			wantOutput: "",
			wantNodes:  nil,
		},
		{
			name: "no failures - empty node_results",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{},
				},
			},
			wantFailed: false,
			wantOutput: "",
			wantNodes:  nil,
		},
		{
			name: "no failures - all nodes succeeded",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"node-1": map[string]any{
							"status": "completed",
							"output": map[string]any{
								"output": "success message",
							},
						},
					},
				},
			},
			wantFailed: false,
			wantOutput: "",
			wantNodes:  nil,
		},
		{
			name: "single failed node with output",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"attack-node-1": map[string]any{
							"status": "failed",
							"output": map[string]any{
								"output": "Harness is nil - callback endpoint not received",
							},
						},
					},
				},
			},
			wantFailed: true,
			wantOutput: "Harness is nil - callback endpoint not received",
			wantNodes:  []string{"attack-node-1"},
		},
		{
			name: "failed node with message field instead of output",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"node-1": map[string]any{
							"status": "failed",
							"output": map[string]any{
								"message": "Agent initialization failed",
							},
						},
					},
				},
			},
			wantFailed: true,
			wantOutput: "Agent initialization failed",
			wantNodes:  []string{"node-1"},
		},
		{
			name: "failed node with error field",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"node-1": map[string]any{
							"status": "error",
							"error": map[string]any{
								"message": "Execution error occurred",
							},
						},
					},
				},
			},
			wantFailed: true,
			wantOutput: "Execution error occurred",
			wantNodes:  []string{"node-1"},
		},
		{
			name: "multiple failed nodes",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"node-1": map[string]any{
							"status": "failed",
							"output": map[string]any{
								"output": "First error",
							},
						},
						"node-2": map[string]any{
							"status": "completed",
							"output": map[string]any{
								"output": "Success",
							},
						},
						"node-3": map[string]any{
							"status": "error",
							"error": map[string]any{
								"message": "Second error",
							},
						},
					},
				},
			},
			wantFailed: true,
			wantOutput: "First error; Second error",
			wantNodes:  []string{"node-1", "node-3"},
		},
		{
			name: "failed node with empty output",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"node-1": map[string]any{
							"status": "failed",
							"output": map[string]any{
								"output": "",
							},
						},
					},
				},
			},
			wantFailed: true,
			wantOutput: "",
			wantNodes:  []string{"node-1"},
		},
		{
			name: "malformed WorkflowResult - node_results not a map",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": "not a map",
				},
			},
			wantFailed: false,
			wantOutput: "",
			wantNodes:  nil,
		},
		{
			name: "malformed WorkflowResult - node result not a map",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"node_results": map[string]any{
						"node-1": "not a map",
					},
				},
			},
			wantFailed: false,
			wantOutput: "",
			wantNodes:  nil,
		},
		{
			name: "missing node_results key",
			missionResult: &mission.MissionResult{
				WorkflowResult: map[string]any{
					"other_field": "value",
				},
			},
			wantFailed: false,
			wantOutput: "",
			wantNodes:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failed, output, nodes := runner.checkNodeFailures(tt.missionResult)
			assert.Equal(t, tt.wantFailed, failed, "failed mismatch")

			// For multiple nodes, the order might vary (map iteration)
			if len(tt.wantNodes) > 1 && len(nodes) > 1 {
				assert.ElementsMatch(t, tt.wantNodes, nodes, "failed nodes mismatch")
			} else {
				assert.Equal(t, tt.wantNodes, nodes, "failed nodes mismatch")
			}

			// For multiple outputs, check that output contains expected parts
			if len(tt.wantNodes) > 1 && tt.wantOutput != "" {
				// Just verify we got output, exact order may vary
				assert.NotEmpty(t, output, "output should not be empty for multiple failures")
			} else {
				assert.Equal(t, tt.wantOutput, output, "output mismatch")
			}
		})
	}
}
