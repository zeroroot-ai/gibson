package orchestrator

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/events"
	"github.com/zero-day-ai/gibson/internal/graphrag/graph"
	"github.com/zero-day-ai/gibson/internal/llm"
)

// MockLLMClient is a mock implementation of LLMClient for testing.
type MockLLMClient struct {
	mock.Mock
}

func (m *MockLLMClient) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	args := m.Called(ctx, slot, messages, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*llm.CompletionResponse), args.Error(1)
}

func (m *MockLLMClient) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	args := m.Called(ctx, slot, messages, schemaType, opts)
	return args.Get(0), args.Error(1)
}

func (m *MockLLMClient) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	args := m.Called(ctx, slot, messages, schemaType, opts)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*StructuredCompletionResult), args.Error(1)
}

// MockEventBus is a mock implementation of EventBus for testing.
type MockEventBus struct {
	events []events.Event
}

func (m *MockEventBus) Publish(event events.Event) {
	m.events = append(m.events, event)
}

func (m *MockEventBus) Subscribe(filter events.Filter) <-chan events.Event {
	return nil
}

func TestReflectionScope_IsValid(t *testing.T) {
	tests := []struct {
		name  string
		scope ReflectionScope
		valid bool
	}{
		{
			name:  "mission scope is valid",
			scope: ReflectionScopeMission,
			valid: true,
		},
		{
			name:  "recent decisions scope is valid",
			scope: ReflectionScopeRecentDecisions,
			valid: true,
		},
		{
			name:  "specific node scope is valid",
			scope: ReflectionScopeSpecificNode,
			valid: true,
		},
		{
			name:  "invalid scope",
			scope: ReflectionScope("invalid"),
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.scope.IsValid())
		})
	}
}

func TestReflectionResult_Validate(t *testing.T) {
	tests := []struct {
		name    string
		result  *ReflectionResult
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid result",
			result: &ReflectionResult{
				Assessment:           "Good progress",
				IssuesIdentified:     []string{"Issue 1"},
				SuggestedChanges:     []string{"Change 1"},
				ConfidenceInApproach: 0.75,
				TokensUsed:           100,
			},
			wantErr: false,
		},
		{
			name: "missing assessment",
			result: &ReflectionResult{
				IssuesIdentified:     []string{"Issue 1"},
				SuggestedChanges:     []string{"Change 1"},
				ConfidenceInApproach: 0.75,
			},
			wantErr: true,
			errMsg:  "assessment is required",
		},
		{
			name: "confidence too low",
			result: &ReflectionResult{
				Assessment:           "Good progress",
				ConfidenceInApproach: -0.1,
			},
			wantErr: true,
			errMsg:  "confidence must be between 0.0 and 1.0",
		},
		{
			name: "confidence too high",
			result: &ReflectionResult{
				Assessment:           "Good progress",
				ConfidenceInApproach: 1.5,
			},
			wantErr: true,
			errMsg:  "confidence must be between 0.0 and 1.0",
		},
		{
			name: "nil slices are initialized",
			result: &ReflectionResult{
				Assessment:           "Good progress",
				ConfidenceInApproach: 0.5,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				// Check that slices are initialized
				assert.NotNil(t, tt.result.IssuesIdentified)
				assert.NotNil(t, tt.result.SuggestedChanges)
			}
		})
	}
}

func TestNewLLMReflectionEngine(t *testing.T) {
	mockLLM := &MockLLMClient{}
	mockGraph := graph.NewMockGraphClient()
	mockBus := &MockEventBus{}

	tests := []struct {
		name    string
		opts    []ReflectionEngineOption
		wantSlot string
		wantTemp float64
	}{
		{
			name:     "default configuration",
			opts:     nil,
			wantSlot: "primary",
			wantTemp: 0.3,
		},
		{
			name: "custom slot",
			opts: []ReflectionEngineOption{
				WithReflectionSlot("reflection"),
			},
			wantSlot: "reflection",
			wantTemp: 0.3,
		},
		{
			name: "custom temperature",
			opts: []ReflectionEngineOption{
				WithReflectionTemperature(0.5),
			},
			wantSlot: "primary",
			wantTemp: 0.5,
		},
		{
			name: "invalid temperature is ignored",
			opts: []ReflectionEngineOption{
				WithReflectionTemperature(1.5),
			},
			wantSlot: "primary",
			wantTemp: 0.3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewLLMReflectionEngine(mockLLM, mockGraph, mockBus, tt.opts...)
			assert.NotNil(t, engine)
			assert.Equal(t, tt.wantSlot, engine.slotName)
			assert.Equal(t, tt.wantTemp, engine.temperature)
		})
	}
}

func TestLLMReflectionEngine_Reflect_StructuredOutput(t *testing.T) {
	mockLLM := &MockLLMClient{}
	mockGraph := graph.NewMockGraphClient()
	mockBus := &MockEventBus{}

	// Connect the mock graph client
	err := mockGraph.Connect(context.Background())
	require.NoError(t, err)

	engine := NewLLMReflectionEngine(mockLLM, mockGraph, mockBus)

	ctx := context.Background()
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:        "mission-123",
			Name:      "Test Mission",
			Objective: "Test objective",
		},
		GraphSummary: GraphSummary{
			TotalNodes:     5,
			CompletedNodes: 2,
		},
	}

	// Mock structured output success
	expectedResult := &ReflectionResult{
		Assessment:           "Current strategy is working well",
		IssuesIdentified:     []string{"Minor timing issue"},
		SuggestedChanges:     []string{"Reduce scan intensity"},
		ConfidenceInApproach: 0.8,
	}

	mockLLM.On("CompleteStructuredAnyWithUsage",
		mock.Anything,
		"primary",
		mock.MatchedBy(func(msgs []llm.Message) bool {
			return len(msgs) == 2 && msgs[0].Role == llm.RoleSystem && msgs[1].Role == llm.RoleUser
		}),
		mock.AnythingOfType("orchestrator.ReflectionResult"),
		mock.Anything,
	).Return(&StructuredCompletionResult{
		Result:           expectedResult,
		Model:            "claude-opus-4-5",
		PromptTokens:     500,
		CompletionTokens: 200,
		TotalTokens:      700,
	}, nil)

	// Mock graph query to store insight - use AddQueryResult
	mockGraph.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{"id": "insight-123"},
		},
	})

	result, err := engine.Reflect(ctx, ReflectionScopeMission, "Focus on timing", state)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Current strategy is working well", result.Assessment)
	assert.Len(t, result.IssuesIdentified, 1)
	assert.Len(t, result.SuggestedChanges, 1)
	assert.Equal(t, 0.8, result.ConfidenceInApproach)
	assert.Equal(t, 700, result.TokensUsed)

	// Verify events were published
	assert.Len(t, mockBus.events, 2)
	assert.Equal(t, events.EventReflectionStarted, mockBus.events[0].Type)
	assert.Equal(t, events.EventReflectionCompleted, mockBus.events[1].Type)

	// Verify graph was called to store insight
	queryCalls := mockGraph.GetCallsByMethod("Query")
	assert.Len(t, queryCalls, 1)

	mockLLM.AssertExpectations(t)
}

func TestLLMReflectionEngine_Reflect_TextOutput(t *testing.T) {
	mockLLM := &MockLLMClient{}
	mockGraph := graph.NewMockGraphClient()
	mockBus := &MockEventBus{}

	// Connect the mock graph client
	err := mockGraph.Connect(context.Background())
	require.NoError(t, err)

	engine := NewLLMReflectionEngine(mockLLM, mockGraph, mockBus)

	ctx := context.Background()
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:   "mission-123",
			Name: "Test Mission",
		},
		GraphSummary: GraphSummary{
			TotalNodes: 3,
		},
	}

	// Mock structured output failure, text success
	mockLLM.On("CompleteStructuredAnyWithUsage", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(nil, assert.AnError)

	responseJSON := `{
		"assessment": "Strategy needs adjustment",
		"issues_identified": ["Timeout errors", "Blocked nodes"],
		"suggested_changes": ["Use alternative tools"],
		"confidence_in_approach": 0.5
	}`

	mockLLM.On("Complete", mock.Anything, "primary", mock.Anything, mock.Anything).
		Return(&llm.CompletionResponse{
			Message: llm.Message{
				Role:    llm.RoleAssistant,
				Content: responseJSON,
			},
			Usage: llm.CompletionTokenUsage{
				PromptTokens:     400,
				CompletionTokens: 150,
				TotalTokens:      550,
			},
		}, nil)

	result, err := engine.Reflect(ctx, ReflectionScopeRecentDecisions, "", state)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "Strategy needs adjustment", result.Assessment)
	assert.Len(t, result.IssuesIdentified, 2)
	assert.Len(t, result.SuggestedChanges, 1)
	assert.Equal(t, 0.5, result.ConfidenceInApproach)
	assert.Equal(t, 550, result.TokensUsed)

	mockLLM.AssertExpectations(t)
}

func TestLLMReflectionEngine_Reflect_InvalidScope(t *testing.T) {
	mockLLM := &MockLLMClient{}
	mockGraph := graph.NewMockGraphClient()
	mockBus := &MockEventBus{}

	engine := NewLLMReflectionEngine(mockLLM, mockGraph, mockBus)

	ctx := context.Background()
	state := &ObservationState{
		MissionInfo: MissionInfo{ID: "mission-123"},
	}

	_, err := engine.Reflect(ctx, ReflectionScope("invalid"), "", state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid reflection scope")
}

func TestLLMReflectionEngine_GetRecentInsights(t *testing.T) {
	mockLLM := &MockLLMClient{}
	mockGraph := graph.NewMockGraphClient()
	mockBus := &MockEventBus{}

	// Connect the mock graph client
	err := mockGraph.Connect(context.Background())
	require.NoError(t, err)

	engine := NewLLMReflectionEngine(mockLLM, mockGraph, mockBus)

	ctx := context.Background()
	missionID := "mission-123"

	// Mock graph query response using AddQueryResult
	mockGraph.AddQueryResult(graph.QueryResult{
		Records: []map[string]any{
			{
				"id":               "insight-1",
				"mission_id":       missionID,
				"created_at":       time.Now().Format(time.RFC3339),
				"scope":            "mission",
				"assessment":       "Good progress",
				"issues_json":      `["Issue 1", "Issue 2"]`,
				"suggestions_json": `["Suggestion 1"]`,
				"confidence":       0.8,
				"tokens_used":      int64(500),
			},
			{
				"id":               "insight-2",
				"mission_id":       missionID,
				"created_at":       time.Now().Add(-1 * time.Hour).Format(time.RFC3339),
				"scope":            "recent_decisions",
				"assessment":       "Needs improvement",
				"issues_json":      `["Issue A"]`,
				"suggestions_json": `[]`,
				"confidence":       0.4,
				"tokens_used":      int64(450),
			},
		},
	})

	insights, err := engine.GetRecentInsights(ctx, missionID, 5)

	require.NoError(t, err)
	assert.Len(t, insights, 2)

	// Check first insight
	assert.Equal(t, "insight-1", insights[0].ID)
	assert.Equal(t, missionID, insights[0].MissionID)
	assert.Equal(t, ReflectionScopeMission, insights[0].Scope)
	assert.Equal(t, "Good progress", insights[0].Assessment)
	assert.Len(t, insights[0].Issues, 2)
	assert.Len(t, insights[0].Suggestions, 1)
	assert.Equal(t, 0.8, insights[0].Confidence)
	assert.Equal(t, 500, insights[0].TokensUsed)

	// Check second insight
	assert.Equal(t, "insight-2", insights[1].ID)
	assert.Equal(t, ReflectionScopeRecentDecisions, insights[1].Scope)
	assert.Equal(t, 0.4, insights[1].Confidence)

	// Verify graph was called
	queryCalls := mockGraph.GetCallsByMethod("Query")
	assert.Len(t, queryCalls, 1)
}

func TestLLMReflectionEngine_GetRecentInsights_DefaultLimit(t *testing.T) {
	mockLLM := &MockLLMClient{}
	mockGraph := graph.NewMockGraphClient()
	mockBus := &MockEventBus{}

	// Connect the mock graph client
	err := mockGraph.Connect(context.Background())
	require.NoError(t, err)

	engine := NewLLMReflectionEngine(mockLLM, mockGraph, mockBus)

	ctx := context.Background()

	// Mock with default limit of 5 - empty result
	mockGraph.AddQueryResult(graph.QueryResult{Records: []map[string]any{}})

	insights, err := engine.GetRecentInsights(ctx, "mission-123", 0)

	require.NoError(t, err)
	assert.Empty(t, insights)
}

func TestBuildReflectionSystemPrompt(t *testing.T) {
	prompt := buildReflectionSystemPrompt()

	assert.NotEmpty(t, prompt)
	assert.Contains(t, prompt, "Strategic Evaluator")
	assert.Contains(t, prompt, "assessment")
	assert.Contains(t, prompt, "issues_identified")
	assert.Contains(t, prompt, "suggested_changes")
	assert.Contains(t, prompt, "confidence_in_approach")
}

func TestBuildReflectionUserPrompt(t *testing.T) {
	state := &ObservationState{
		MissionInfo: MissionInfo{
			ID:          "mission-123",
			Name:        "Test Mission",
			Objective:   "Test objective",
			TimeElapsed: "5m",
		},
		GraphSummary: GraphSummary{
			TotalNodes:     10,
			CompletedNodes: 3,
		},
	}

	tests := []struct {
		name           string
		scope          ReflectionScope
		prompt         string
		checkContains  []string
	}{
		{
			name:   "mission scope",
			scope:  ReflectionScopeMission,
			prompt: "",
			checkContains: []string{
				"overall mission strategy",
				"Test Mission",
				"Test objective",
			},
		},
		{
			name:   "recent decisions scope",
			scope:  ReflectionScopeRecentDecisions,
			prompt: "",
			checkContains: []string{
				"recent orchestrator decisions",
			},
		},
		{
			name:   "specific node scope",
			scope:  ReflectionScopeSpecificNode,
			prompt: "",
			checkContains: []string{
				"specific workflow node",
			},
		},
		{
			name:   "with custom prompt",
			scope:  ReflectionScopeMission,
			prompt: "Focus on timing issues",
			checkContains: []string{
				"Focus on timing issues",
				"Guidance",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildReflectionUserPrompt(tt.scope, tt.prompt, state)
			assert.NotEmpty(t, result)
			for _, expected := range tt.checkContains {
				assert.Contains(t, result, expected)
			}
		})
	}
}

func TestReflectionInsight_Serialization(t *testing.T) {
	insight := ReflectionInsight{
		ID:          "insight-123",
		MissionID:   "mission-456",
		CreatedAt:   time.Now(),
		Scope:       ReflectionScopeMission,
		Assessment:  "Good progress",
		Issues:      []string{"Issue 1", "Issue 2"},
		Suggestions: []string{"Suggestion 1"},
		Confidence:  0.75,
		TokensUsed:  500,
	}

	// Test JSON serialization
	data, err := json.Marshal(insight)
	require.NoError(t, err)

	var decoded ReflectionInsight
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, insight.ID, decoded.ID)
	assert.Equal(t, insight.MissionID, decoded.MissionID)
	assert.Equal(t, insight.Scope, decoded.Scope)
	assert.Equal(t, insight.Assessment, decoded.Assessment)
	assert.Equal(t, insight.Issues, decoded.Issues)
	assert.Equal(t, insight.Suggestions, decoded.Suggestions)
	assert.Equal(t, insight.Confidence, decoded.Confidence)
	assert.Equal(t, insight.TokensUsed, decoded.TokensUsed)
}

// Helper function for string matching in mocks
func containsString(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && (s == substr || len(s) > len(substr))
}
