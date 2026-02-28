package orchestrator

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/memory"
	"github.com/zero-day-ai/gibson/internal/types"
)

// MockMissionMemory is a mock implementation of memory.MissionMemory.
type MockMissionMemory struct {
	mock.Mock
}

func (m *MockMissionMemory) Store(ctx context.Context, key string, value any, metadata map[string]any) error {
	args := m.Called(ctx, key, value, metadata)
	return args.Error(0)
}

func (m *MockMissionMemory) Retrieve(ctx context.Context, key string) (*memory.MemoryItem, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*memory.MemoryItem), args.Error(1)
}

func (m *MockMissionMemory) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockMissionMemory) Search(ctx context.Context, query string, limit int) ([]memory.MemoryResult, error) {
	args := m.Called(ctx, query, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]memory.MemoryResult), args.Error(1)
}

func (m *MockMissionMemory) History(ctx context.Context, limit int) ([]memory.MemoryItem, error) {
	args := m.Called(ctx, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]memory.MemoryItem), args.Error(1)
}

func (m *MockMissionMemory) Keys(ctx context.Context) ([]string, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockMissionMemory) MissionID() types.ID {
	args := m.Called()
	return args.Get(0).(types.ID)
}

func (m *MockMissionMemory) ContinuityMode() memory.MemoryContinuityMode {
	args := m.Called()
	return args.Get(0).(memory.MemoryContinuityMode)
}

func (m *MockMissionMemory) GetPreviousRunValue(ctx context.Context, key string) (any, error) {
	args := m.Called(ctx, key)
	return args.Get(0), args.Error(1)
}

func (m *MockMissionMemory) GetValueHistory(ctx context.Context, key string) ([]memory.HistoricalValue, error) {
	args := m.Called(ctx, key)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]memory.HistoricalValue), args.Error(1)
}

// MockLongTermMemory is a mock implementation of memory.LongTermMemory.
type MockLongTermMemory struct {
	mock.Mock
}

func (m *MockLongTermMemory) Store(ctx context.Context, id string, content string, metadata map[string]any) error {
	args := m.Called(ctx, id, content, metadata)
	return args.Error(0)
}

func (m *MockLongTermMemory) Search(ctx context.Context, query string, topK int, filters map[string]any) ([]memory.MemoryResult, error) {
	args := m.Called(ctx, query, topK, filters)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]memory.MemoryResult), args.Error(1)
}

func (m *MockLongTermMemory) SimilarFindings(ctx context.Context, content string, topK int) ([]memory.MemoryResult, error) {
	args := m.Called(ctx, content, topK)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]memory.MemoryResult), args.Error(1)
}

func (m *MockLongTermMemory) SimilarPatterns(ctx context.Context, pattern string, topK int) ([]memory.MemoryResult, error) {
	args := m.Called(ctx, pattern, topK)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]memory.MemoryResult), args.Error(1)
}

func (m *MockLongTermMemory) Delete(ctx context.Context, id string) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockLongTermMemory) Health(ctx context.Context) types.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(types.HealthStatus)
}

func TestRecallQuery_Validate(t *testing.T) {
	tests := []struct {
		name    string
		query   RecallQuery
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid mission tier query",
			query: RecallQuery{
				Query:      "SQL injection",
				MemoryTier: "mission",
				MissionID:  "mission-123",
				MaxResults: 10,
			},
			wantErr: false,
		},
		{
			name: "valid long_term tier query",
			query: RecallQuery{
				Query:      "XSS vulnerability",
				MemoryTier: "long_term",
				MissionID:  "mission-456",
				MaxResults: 5,
			},
			wantErr: false,
		},
		{
			name: "valid both tier query",
			query: RecallQuery{
				Query:      "authentication bypass",
				MemoryTier: "both",
				MissionID:  "mission-789",
			},
			wantErr: false,
		},
		{
			name: "empty query",
			query: RecallQuery{
				Query:      "",
				MemoryTier: "mission",
				MissionID:  "mission-123",
			},
			wantErr: true,
			errMsg:  "query cannot be empty",
		},
		{
			name: "empty memory tier",
			query: RecallQuery{
				Query:     "test",
				MissionID: "mission-123",
			},
			wantErr: true,
			errMsg:  "memory_tier is required",
		},
		{
			name: "invalid memory tier",
			query: RecallQuery{
				Query:      "test",
				MemoryTier: "invalid",
				MissionID:  "mission-123",
			},
			wantErr: true,
			errMsg:  "invalid memory_tier",
		},
		{
			name: "negative max results",
			query: RecallQuery{
				Query:      "test",
				MemoryTier: "mission",
				MissionID:  "mission-123",
				MaxResults: -5,
			},
			wantErr: true,
			errMsg:  "max_results cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.query.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// MockEventBusForRecall is a simple mock for testing recall events.
type MockEventBusForRecall struct {
	Events []events.Event
}

func (m *MockEventBusForRecall) Publish(event events.Event) {
	m.Events = append(m.Events, event)
}

func (m *MockEventBusForRecall) Subscribe(filter events.Filter) <-chan events.Event {
	return nil
}

func TestDefaultMemoryRecaller_Recall_MissionTier(t *testing.T) {
	ctx := context.Background()

	// Create mock mission memory
	mockMission := new(MockMissionMemory)
	mockEventBus := &MockEventBusForRecall{}

	// Setup expectations
	now := time.Now()
	expectedResults := []memory.MemoryResult{
		{
			Item: memory.MemoryItem{
				Key:       "scan_results",
				Value:     "Found open ports 80, 443",
				CreatedAt: now.Add(-1 * time.Hour),
			},
			Score: 0.95,
		},
		{
			Item: memory.MemoryItem{
				Key:       "vulnerability_scan",
				Value:     "SQL injection detected",
				CreatedAt: now.Add(-2 * time.Hour),
			},
			Score: 0.88,
		},
	}

	mockMission.On("Search", mock.Anything, "SQL injection", 10).Return(expectedResults, nil)

	// Create recaller
	recaller := NewDefaultMemoryRecaller(mockMission, nil, mockEventBus)

	// Execute recall
	query := RecallQuery{
		Query:      "SQL injection",
		MemoryTier: "mission",
		MissionID:  "mission-123",
		MaxResults: 10,
	}

	result, err := recaller.Recall(ctx, query)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.MissionResults, 2)
	assert.Len(t, result.LongTermResults, 0)

	// Check first result
	assert.Equal(t, "scan_results", result.MissionResults[0].Key)
	assert.Equal(t, "Found open ports 80, 443", result.MissionResults[0].Value)
	assert.Equal(t, "mission", result.MissionResults[0].Source)
	assert.Equal(t, 0.95, result.MissionResults[0].Score)

	// Check formatted context
	assert.Contains(t, result.FormattedContext, "Mission Memory Results (2 entries)")
	assert.Contains(t, result.FormattedContext, "scan_results")
	assert.Contains(t, result.FormattedContext, "Found open ports 80, 443")

	// Check query time (can be 0 for very fast operations)
	assert.GreaterOrEqual(t, result.QueryTimeMs, int64(0))

	// Verify events
	assert.Len(t, mockEventBus.Events, 2)
	assert.Equal(t, events.EventRecallStarted, mockEventBus.Events[0].Type)
	assert.Equal(t, events.EventRecallCompleted, mockEventBus.Events[1].Type)

	mockMission.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_LongTermTier(t *testing.T) {
	ctx := context.Background()

	// Create mock long-term memory
	mockLongTerm := new(MockLongTermMemory)
	mockEventBus := &MockEventBusForRecall{}

	// Setup expectations
	now := time.Now()
	expectedResults := []memory.MemoryResult{
		{
			Item: memory.MemoryItem{
				Key:       "finding-123",
				Value:     "Previous XSS vulnerability found in login form",
				CreatedAt: now.Add(-7 * 24 * time.Hour),
			},
			Score: 0.92,
		},
	}

	mockLongTerm.On("Search", mock.Anything, "XSS vulnerability", 5, mock.Anything).Return(expectedResults, nil)

	// Create recaller
	recaller := NewDefaultMemoryRecaller(nil, mockLongTerm, mockEventBus)

	// Execute recall
	query := RecallQuery{
		Query:      "XSS vulnerability",
		MemoryTier: "long_term",
		MissionID:  "mission-456",
		MaxResults: 5,
		Filters:    map[string]string{"target": "example.com"},
	}

	result, err := recaller.Recall(ctx, query)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.MissionResults, 0)
	assert.Len(t, result.LongTermResults, 1)

	// Check result
	assert.Equal(t, "finding-123", result.LongTermResults[0].Key)
	assert.Contains(t, result.LongTermResults[0].Value, "Previous XSS vulnerability")
	assert.Equal(t, "long_term", result.LongTermResults[0].Source)
	assert.Equal(t, 0.92, result.LongTermResults[0].Score)

	// Check formatted context
	assert.Contains(t, result.FormattedContext, "Long-term Memory Results (1 entries)")
	assert.Contains(t, result.FormattedContext, "Score: 0.92")

	mockLongTerm.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_BothTiers(t *testing.T) {
	ctx := context.Background()

	// Create mocks
	mockMission := new(MockMissionMemory)
	mockLongTerm := new(MockLongTermMemory)
	mockEventBus := &MockEventBusForRecall{}

	// Setup mission memory expectations
	now := time.Now()
	missionResults := []memory.MemoryResult{
		{
			Item: memory.MemoryItem{
				Key:       "recent_scan",
				Value:     "Current scan results",
				CreatedAt: now.Add(-1 * time.Hour),
			},
			Score: 0.95,
		},
	}

	// Setup long-term memory expectations
	longTermResults := []memory.MemoryResult{
		{
			Item: memory.MemoryItem{
				Key:       "historical_finding",
				Value:     "Historical context",
				CreatedAt: now.Add(-30 * 24 * time.Hour),
			},
			Score: 0.88,
		},
	}

	mockMission.On("Search", mock.Anything, "vulnerability scan", 15).Return(missionResults, nil)
	mockLongTerm.On("Search", mock.Anything, "vulnerability scan", 15, mock.Anything).Return(longTermResults, nil)

	// Create recaller
	recaller := NewDefaultMemoryRecaller(mockMission, mockLongTerm, mockEventBus)

	// Execute recall
	query := RecallQuery{
		Query:      "vulnerability scan",
		MemoryTier: "both",
		MissionID:  "mission-789",
		MaxResults: 15,
	}

	result, err := recaller.Recall(ctx, query)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.MissionResults, 1)
	assert.Len(t, result.LongTermResults, 1)

	// Check formatted context includes both sections
	assert.Contains(t, result.FormattedContext, "Mission Memory Results (1 entries)")
	assert.Contains(t, result.FormattedContext, "Long-term Memory Results (1 entries)")
	assert.Contains(t, result.FormattedContext, "recent_scan")
	assert.Contains(t, result.FormattedContext, "Historical context") // Long-term results show value, not key

	// Verify event payload
	completedEvent := mockEventBus.Events[1]
	assert.Equal(t, events.EventRecallCompleted, completedEvent.Type)
	payload := completedEvent.Payload.(map[string]any)
	assert.Equal(t, 1, payload["mission_results"])
	assert.Equal(t, 1, payload["long_term_results"])
	assert.Equal(t, 2, payload["total_results"])

	mockMission.AssertExpectations(t)
	mockLongTerm.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_EmptyResults(t *testing.T) {
	ctx := context.Background()

	// Create mock mission memory with no results
	mockMission := new(MockMissionMemory)
	mockEventBus := &MockEventBusForRecall{}

	mockMission.On("Search", mock.Anything, "nonexistent", 10).Return([]memory.MemoryResult{}, nil)

	// Create recaller
	recaller := NewDefaultMemoryRecaller(mockMission, nil, mockEventBus)

	// Execute recall
	query := RecallQuery{
		Query:      "nonexistent",
		MemoryTier: "mission",
		MissionID:  "mission-123",
		MaxResults: 10,
	}

	result, err := recaller.Recall(ctx, query)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.MissionResults, 0)
	assert.Len(t, result.LongTermResults, 0)

	// Check formatted context handles empty results
	assert.Contains(t, result.FormattedContext, "No relevant context found in memory")

	mockMission.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_PartialFailure(t *testing.T) {
	ctx := context.Background()

	// Create mocks
	mockMission := new(MockMissionMemory)
	mockLongTerm := new(MockLongTermMemory)
	mockEventBus := &MockEventBusForRecall{}

	// Mission memory fails
	mockMission.On("Search", mock.Anything, "test", 10).Return(nil, errors.New("mission memory unavailable"))

	// Long-term memory succeeds
	longTermResults := []memory.MemoryResult{
		{
			Item: memory.MemoryItem{
				Key:   "lt-result",
				Value: "Long-term result",
			},
			Score: 0.85,
		},
	}
	mockLongTerm.On("Search", mock.Anything, "test", 10, mock.Anything).Return(longTermResults, nil)

	// Create recaller
	recaller := NewDefaultMemoryRecaller(mockMission, mockLongTerm, mockEventBus)

	// Execute recall with both tiers
	query := RecallQuery{
		Query:      "test",
		MemoryTier: "both",
		MissionID:  "mission-123",
		MaxResults: 10,
	}

	result, err := recaller.Recall(ctx, query)

	// Should not error - partial results are acceptable
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Len(t, result.MissionResults, 0) // Failed
	assert.Len(t, result.LongTermResults, 1) // Succeeded

	mockMission.AssertExpectations(t)
	mockLongTerm.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_DefaultMaxResults(t *testing.T) {
	ctx := context.Background()

	mockMission := new(MockMissionMemory)
	mockEventBus := &MockEventBusForRecall{}

	// Expect limit of 10 (default)
	mockMission.On("Search", mock.Anything, "test", 10).Return([]memory.MemoryResult{}, nil)

	recaller := NewDefaultMemoryRecaller(mockMission, nil, mockEventBus)

	// Don't specify MaxResults
	query := RecallQuery{
		Query:      "test",
		MemoryTier: "mission",
		MissionID:  "mission-123",
	}

	_, err := recaller.Recall(ctx, query)

	assert.NoError(t, err)
	mockMission.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_InvalidQuery(t *testing.T) {
	ctx := context.Background()

	recaller := NewDefaultMemoryRecaller(nil, nil, nil)

	// Invalid query (empty query string)
	query := RecallQuery{
		Query:      "",
		MemoryTier: "mission",
		MissionID:  "mission-123",
	}

	result, err := recaller.Recall(ctx, query)

	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "invalid recall query")
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected string
	}{
		{
			name:     "nil value",
			value:    nil,
			expected: "(empty)",
		},
		{
			name:     "string value",
			value:    "test string",
			expected: "test string",
		},
		{
			name: "map value",
			value: map[string]interface{}{
				"key1": "value1",
				"key2": 42,
			},
			expected: "key", // Contains key since map iteration is non-deterministic
		},
		{
			name:     "array value",
			value:    []interface{}{"item1", "item2", "item3"},
			expected: "item1, item2, item3",
		},
		{
			name:     "number value",
			value:    42,
			expected: "42",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatValue(tt.value)
			assert.Contains(t, result, tt.expected)
		})
	}
}

func TestFormatContext_Truncation(t *testing.T) {
	ctx := context.Background()

	mockMission := new(MockMissionMemory)
	mockEventBus := &MockEventBusForRecall{}

	// Create a result with a very long value
	longValue := strings.Repeat("A", 300)
	missionResults := []memory.MemoryResult{
		{
			Item: memory.MemoryItem{
				Key:       "long_value",
				Value:     longValue,
				CreatedAt: time.Now(),
			},
			Score: 0.95,
		},
	}

	mockMission.On("Search", mock.Anything, "test", 10).Return(missionResults, nil)

	recaller := NewDefaultMemoryRecaller(mockMission, nil, mockEventBus)

	query := RecallQuery{
		Query:      "test",
		MemoryTier: "mission",
		MissionID:  "mission-123",
		MaxResults: 10,
	}

	result, err := recaller.Recall(ctx, query)

	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Check that value is truncated with ellipsis
	assert.Contains(t, result.FormattedContext, "...")
	assert.NotContains(t, result.FormattedContext, strings.Repeat("A", 300))

	mockMission.AssertExpectations(t)
}

func TestDefaultMemoryRecaller_Recall_WithoutEventBus(t *testing.T) {
	ctx := context.Background()

	mockMission := new(MockMissionMemory)

	mockMission.On("Search", mock.Anything, "test", 10).Return([]memory.MemoryResult{}, nil)

	// Create recaller without event bus
	recaller := NewDefaultMemoryRecaller(mockMission, nil, nil)

	query := RecallQuery{
		Query:      "test",
		MemoryTier: "mission",
		MissionID:  "mission-123",
		MaxResults: 10,
	}

	result, err := recaller.Recall(ctx, query)

	// Should work fine without event bus
	assert.NoError(t, err)
	assert.NotNil(t, result)

	mockMission.AssertExpectations(t)
}
