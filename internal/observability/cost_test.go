package observability

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// MockTokenTracker is a mock implementation of llm.TokenTracker for testing
type MockTokenTracker struct {
	mu      sync.RWMutex
	usage   map[string]*llm.UsageRecord
	budgets map[string]llm.Budget
	pricing *llm.PricingConfig
}

// NewMockTokenTracker creates a new MockTokenTracker with default pricing
func NewMockTokenTracker() *MockTokenTracker {
	return &MockTokenTracker{
		usage:   make(map[string]*llm.UsageRecord),
		budgets: make(map[string]llm.Budget),
		pricing: llm.DefaultPricing(),
	}
}

func (m *MockTokenTracker) RecordUsage(scope llm.UsageScope, provider string, model string, usage llm.TokenUsage) error {
	// Calculate cost
	cost, err := m.pricing.CalculateCost(provider, model, usage)
	if err != nil {
		cost = 0
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := scope.Key()
	record, exists := m.usage[key]
	if !exists {
		record = &llm.UsageRecord{
			Scope: scope,
		}
		m.usage[key] = record
	}

	record.InputTokens += usage.InputTokens
	record.OutputTokens += usage.OutputTokens
	record.TotalCost += cost
	record.CallCount++

	return nil
}

func (m *MockTokenTracker) GetUsage(scope llm.UsageScope) (llm.UsageRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := scope.Key()
	record, exists := m.usage[key]
	if !exists {
		return llm.UsageRecord{}, types.NewError(
			llm.ErrUsageNotFound,
			fmt.Sprintf("no usage found for scope %s", scope.String()),
		)
	}

	return *record, nil
}

func (m *MockTokenTracker) GetCost(scope llm.UsageScope) (float64, error) {
	record, err := m.GetUsage(scope)
	if err != nil {
		return 0, err
	}
	return record.TotalCost, nil
}

func (m *MockTokenTracker) SetBudget(scope llm.UsageScope, budget llm.Budget) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.budgets[scope.Key()] = budget
	return nil
}

func (m *MockTokenTracker) CheckBudget(scope llm.UsageScope, provider string, model string, usage llm.TokenUsage) error {
	// Not needed for cost tracker tests
	return nil
}

func (m *MockTokenTracker) GetBudget(scope llm.UsageScope) (llm.Budget, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	budget, exists := m.budgets[scope.Key()]
	if !exists {
		return llm.Budget{}, nil
	}
	return budget, nil
}

func (m *MockTokenTracker) Reset(scope llm.UsageScope) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.usage, scope.Key())
	return nil
}

func TestNewCostTracker(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")

	tracker := NewCostTracker(mockTracker, logger)

	assert.NotNil(t, tracker)
	assert.NotNil(t, tracker.tokenTracker)
	assert.NotNil(t, tracker.logger)
	assert.NotNil(t, tracker.thresholds)
}

func TestCalculateCost(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	tests := []struct {
		name         string
		provider     string
		model        string
		inputTokens  int
		outputTokens int
		expectedCost float64
	}{
		{
			name:         "OpenAI GPT-4",
			provider:     "openai",
			model:        "gpt-4",
			inputTokens:  1000000,       // 1M tokens
			outputTokens: 500000,        // 500K tokens
			expectedCost: 30.00 + 30.00, // 1M * $30/1M + 0.5M * $60/1M
		},
		{
			name:         "Anthropic Claude 3 Opus",
			provider:     "anthropic",
			model:        "claude-3-opus",
			inputTokens:  1000000,       // 1M tokens
			outputTokens: 1000000,       // 1M tokens
			expectedCost: 15.00 + 75.00, // 1M * $15/1M + 1M * $75/1M
		},
		{
			name:         "Anthropic Claude 3 Haiku",
			provider:     "anthropic",
			model:        "claude-3-haiku",
			inputTokens:  10000000,    // 10M tokens
			outputTokens: 5000000,     // 5M tokens
			expectedCost: 2.50 + 6.25, // 10M * $0.25/1M + 5M * $1.25/1M
		},
		{
			name:         "Google Gemini 1.5 Flash",
			provider:     "google",
			model:        "gemini-1.5-flash",
			inputTokens:  1000000,     // 1M tokens
			outputTokens: 1000000,     // 1M tokens
			expectedCost: 0.35 + 1.05, // 1M * $0.35/1M + 1M * $1.05/1M
		},
		{
			name:         "Unknown provider/model returns zero",
			provider:     "unknown",
			model:        "unknown-model",
			inputTokens:  1000000,
			outputTokens: 1000000,
			expectedCost: 0.0,
		},
		{
			name:         "Zero tokens",
			provider:     "openai",
			model:        "gpt-4",
			inputTokens:  0,
			outputTokens: 0,
			expectedCost: 0.0,
		},
		{
			name:         "Small token counts",
			provider:     "openai",
			model:        "gpt-3.5-turbo",
			inputTokens:  1000,           // 1K tokens
			outputTokens: 2000,           // 2K tokens
			expectedCost: 0.0005 + 0.003, // 0.001M * $0.50/1M + 0.002M * $1.50/1M
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := tracker.CalculateCost(tt.provider, tt.model, tt.inputTokens, tt.outputTokens)
			assert.InDelta(t, tt.expectedCost, cost, 0.001, "cost mismatch")
		})
	}
}

func TestRecordCostOnSpan(t *testing.T) {
	// Set up in-memory span exporter
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
	)
	otel.SetTracerProvider(tp)

	tracer := tp.Tracer("test")
	ctx := context.Background()

	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Create a span
	ctx, span := tracer.Start(ctx, "test-operation")

	// Record cost on span
	cost := 1.2345
	tracker.RecordCostOnSpan(span, cost)

	// End span
	span.End()

	// Verify the span has the cost attribute
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)

	found := false
	for _, attr := range spans[0].Attributes {
		if attr.Key == attribute.Key(GibsonLLMCost) {
			found = true
			assert.Equal(t, cost, attr.Value.AsFloat64())
		}
	}
	assert.True(t, found, "cost attribute not found on span")
}

func TestGetMissionCost(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Create test mission ID
	missionID := types.NewID()

	// Record some usage
	scope := llm.UsageScope{
		MissionID: missionID,
	}

	usage := llm.TokenUsage{
		InputTokens:  100000,
		OutputTokens: 50000,
	}

	err := mockTracker.RecordUsage(scope, "openai", "gpt-4", usage)
	require.NoError(t, err)

	// Get mission cost
	cost, err := tracker.GetMissionCost(missionID.String())
	require.NoError(t, err)
	assert.Greater(t, cost, 0.0)

	// Verify the cost is correct
	expectedCost := tracker.CalculateCost("openai", "gpt-4", 100000, 50000)
	assert.InDelta(t, expectedCost, cost, 0.001)
}

func TestGetMissionCost_InvalidID(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Try to get cost with invalid mission ID
	_, err := tracker.GetMissionCost("invalid-id")
	require.Error(t, err)
}

func TestGetMissionCost_NoUsage(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Create mission ID with no usage
	missionID := types.NewID()

	// Try to get cost for mission with no usage
	_, err := tracker.GetMissionCost(missionID.String())
	require.Error(t, err)
}

func TestGetAgentCost(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Create test mission ID
	missionID := types.NewID()
	agentName := "test-agent"

	// Record some usage
	scope := llm.UsageScope{
		MissionID: missionID,
		AgentName: agentName,
	}

	usage := llm.TokenUsage{
		InputTokens:  50000,
		OutputTokens: 25000,
	}

	err := mockTracker.RecordUsage(scope, "anthropic", "claude-3-opus", usage)
	require.NoError(t, err)

	// Get agent cost
	cost, err := tracker.GetAgentCost(missionID.String(), agentName)
	require.NoError(t, err)
	assert.Greater(t, cost, 0.0)

	// Verify the cost is correct
	expectedCost := tracker.CalculateCost("anthropic", "claude-3-opus", 50000, 25000)
	assert.InDelta(t, expectedCost, cost, 0.001)
}

func TestGetAgentCost_InvalidID(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Try to get cost with invalid mission ID
	_, err := tracker.GetAgentCost("invalid-id", "test-agent")
	require.Error(t, err)
}

func TestGetAgentCost_NoUsage(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Create mission ID with no usage
	missionID := types.NewID()

	// Try to get cost for agent with no usage
	_, err := tracker.GetAgentCost(missionID.String(), "test-agent")
	require.Error(t, err)
}

func TestSetThreshold(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	// Set threshold
	err := tracker.SetThreshold(missionID.String(), 10.0)
	require.NoError(t, err)

	// Verify threshold was set
	threshold, exists := tracker.GetThreshold(missionID.String())
	assert.True(t, exists)
	assert.Equal(t, 10.0, threshold)
}

func TestSetThreshold_InvalidID(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	// Try to set threshold with invalid mission ID
	err := tracker.SetThreshold("invalid-id", 10.0)
	require.Error(t, err)
}

func TestSetThreshold_InvalidValue(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	tests := []struct {
		name      string
		threshold float64
	}{
		{"zero threshold", 0.0},
		{"negative threshold", -5.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tracker.SetThreshold(missionID.String(), tt.threshold)
			require.Error(t, err)
		})
	}
}

func TestCheckThreshold(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	// Set threshold
	err := tracker.SetThreshold(missionID.String(), 10.0)
	require.NoError(t, err)

	tests := []struct {
		name        string
		currentCost float64
		expected    bool
	}{
		{"below threshold", 5.0, false},
		{"at threshold", 10.0, false},
		{"above threshold", 15.0, true},
		{"significantly above threshold", 100.0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceeded := tracker.CheckThreshold(missionID.String(), tt.currentCost)
			assert.Equal(t, tt.expected, exceeded)
		})
	}
}

func TestCheckThreshold_NoThresholdSet(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	// Check threshold without setting one
	exceeded := tracker.CheckThreshold(missionID.String(), 100.0)
	assert.False(t, exceeded, "should not exceed when no threshold is set")
}

func TestGetThreshold(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	// Get threshold that doesn't exist
	threshold, exists := tracker.GetThreshold(missionID.String())
	assert.False(t, exists)
	assert.Equal(t, 0.0, threshold)

	// Set and get threshold
	err := tracker.SetThreshold(missionID.String(), 25.5)
	require.NoError(t, err)

	threshold, exists = tracker.GetThreshold(missionID.String())
	assert.True(t, exists)
	assert.Equal(t, 25.5, threshold)
}

func TestRemoveThreshold(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	// Set threshold
	err := tracker.SetThreshold(missionID.String(), 10.0)
	require.NoError(t, err)

	// Verify it exists
	_, exists := tracker.GetThreshold(missionID.String())
	assert.True(t, exists)

	// Remove threshold
	tracker.RemoveThreshold(missionID.String())

	// Verify it's gone
	_, exists = tracker.GetThreshold(missionID.String())
	assert.False(t, exists)
}

func TestCostTracker_ConcurrentAccess(t *testing.T) {
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()

	// Concurrent threshold operations
	var wg sync.WaitGroup
	iterations := 100

	// Concurrent sets
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(val float64) {
			defer wg.Done()
			_ = tracker.SetThreshold(missionID.String(), val)
		}(float64(i + 1))
	}

	// Concurrent gets
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tracker.GetThreshold(missionID.String())
		}()
	}

	// Concurrent checks
	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func(cost float64) {
			defer wg.Done()
			tracker.CheckThreshold(missionID.String(), cost)
		}(float64(i))
	}

	wg.Wait()

	// Should have a threshold set (last one wins)
	threshold, exists := tracker.GetThreshold(missionID.String())
	assert.True(t, exists)
	assert.Greater(t, threshold, 0.0)
}

func TestCostTracking_Integration(t *testing.T) {
	// Integration test showing full cost tracking mission
	mockTracker := NewMockTokenTracker()
	logger := NewLogger(Config{Level: slog.LevelDebug, Output: os.Stdout, RedactSensitive: true}).WithMission("test-mission", "").WithAgent("test-agent")
	tracker := NewCostTracker(mockTracker, logger)

	missionID := types.NewID()
	agent1 := "researcher"
	agent2 := "analyzer"

	// Set mission threshold
	err := tracker.SetThreshold(missionID.String(), 5.0)
	require.NoError(t, err)

	// Record usage for agent 1
	scope1 := llm.UsageScope{
		MissionID: missionID,
		AgentName: agent1,
	}
	err = mockTracker.RecordUsage(scope1, "openai", "gpt-4", llm.TokenUsage{
		InputTokens:  50000,
		OutputTokens: 25000,
	})
	require.NoError(t, err)

	// Check agent 1 cost
	agent1Cost, err := tracker.GetAgentCost(missionID.String(), agent1)
	require.NoError(t, err)
	assert.Greater(t, agent1Cost, 0.0)

	// Record usage for agent 2
	scope2 := llm.UsageScope{
		MissionID: missionID,
		AgentName: agent2,
	}
	err = mockTracker.RecordUsage(scope2, "anthropic", "claude-3-haiku", llm.TokenUsage{
		InputTokens:  100000,
		OutputTokens: 50000,
	})
	require.NoError(t, err)

	// Check agent 2 cost
	agent2Cost, err := tracker.GetAgentCost(missionID.String(), agent2)
	require.NoError(t, err)
	assert.Greater(t, agent2Cost, 0.0)

	// Check mission cost (should be sum of both agents in our mock)
	// Note: In the real DefaultTokenTracker, it aggregates automatically,
	// but our mock doesn't. For this test, we'll just verify each agent cost separately.
	assert.NotEqual(t, agent1Cost, agent2Cost, "different agents should have different costs")

	// Check threshold - with our current usage, we shouldn't exceed 5.0
	// Agent1: 50K input * $30/1M + 25K output * $60/1M = 1.5 + 1.5 = 3.0
	// Agent2: 100K input * $0.25/1M + 50K output * $1.25/1M = 0.025 + 0.0625 = 0.0875
	exceeded := tracker.CheckThreshold(missionID.String(), agent1Cost)
	assert.False(t, exceeded)

	// Add more usage to exceed threshold
	err = mockTracker.RecordUsage(scope1, "openai", "gpt-4", llm.TokenUsage{
		InputTokens:  100000,
		OutputTokens: 50000,
	})
	require.NoError(t, err)

	// Get new mission cost
	newAgent1Cost, err := tracker.GetAgentCost(missionID.String(), agent1)
	require.NoError(t, err)
	assert.Greater(t, newAgent1Cost, agent1Cost, "cost should increase")

	// Check threshold again - should now exceed
	exceeded = tracker.CheckThreshold(missionID.String(), newAgent1Cost)
	assert.True(t, exceeded, "should exceed threshold now")
}
