package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/llm"
)

// mockLLMClient is a test double for LLMClient.
type mockLLMClient struct {
	completeFunc                func(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error)
	completeStructuredFunc      func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error)
	completeStructuredUsageFunc func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error)
	callCount                   int
}

func (m *mockLLMClient) Complete(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
	m.callCount++
	if m.completeFunc != nil {
		return m.completeFunc(ctx, slot, messages, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *mockLLMClient) CompleteStructuredAny(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
	m.callCount++
	if m.completeStructuredFunc != nil {
		return m.completeStructuredFunc(ctx, slot, messages, schemaType, opts...)
	}
	return nil, errors.New("not implemented")
}

func (m *mockLLMClient) CompleteStructuredAnyWithUsage(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
	m.callCount++
	if m.completeStructuredUsageFunc != nil {
		return m.completeStructuredUsageFunc(ctx, slot, messages, schemaType, opts...)
	}
	// Fall back to the old func and wrap the result
	if m.completeStructuredFunc != nil {
		result, err := m.completeStructuredFunc(ctx, slot, messages, schemaType, opts...)
		if err != nil {
			return nil, err
		}
		return &StructuredCompletionResult{
			Result:           result,
			Model:            "mock-model",
			RawJSON:          "{}",
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		}, nil
	}
	return nil, errors.New("not implemented")
}

// Test helper to create a valid observation state
func createTestObservationState() *ObservationState {
	now := time.Now()
	return &ObservationState{
		MissionInfo: MissionInfo{
			ID:          "mission-123",
			Name:        "Test Security Assessment",
			Objective:   "Discover security vulnerabilities in web application",
			Status:      "running",
			StartedAt:   now.Add(-5 * time.Minute),
			TimeElapsed: "5.0m",
		},
		GraphSummary: GraphSummary{
			TotalNodes:      5,
			CompletedNodes:  2,
			FailedNodes:     0,
			PendingNodes:    3,
			TotalDecisions:  2,
			TotalExecutions: 2,
		},
		ReadyNodes: []NodeSummary{
			{
				ID:          "exploit-1",
				Name:        "Exploit Port 443",
				Type:        "agent",
				Description: "Test HTTPS service for vulnerabilities",
				AgentName:   "exploiter",
				Status:      "ready",
			},
			{
				ID:          "exploit-2",
				Name:        "Exploit Port 80",
				Type:        "agent",
				Description: "Test HTTP service for vulnerabilities",
				AgentName:   "exploiter",
				Status:      "ready",
			},
		},
		RunningNodes: []NodeSummary{},
		CompletedNodes: []CompletedNodeSummary{
			{
				NodeSummary: NodeSummary{
					ID:          "recon",
					Name:        "Reconnaissance",
					Type:        "agent",
					Description: "Initial reconnaissance",
					AgentName:   "reconnaissance",
					Status:      "completed",
				},
			},
		},
		FailedNodes: []NodeSummary{},
		RecentDecisions: []DecisionSummary{
			{
				Iteration:  1,
				Action:     "execute_agent",
				Target:     "recon",
				Reasoning:  "Starting with reconnaissance",
				Confidence: 0.9,
				Timestamp:  now.Add(-4 * time.Minute).Format(time.RFC3339),
			},
		},
		ResourceConstraints: ResourceConstraints{
			MaxConcurrent:   2,
			CurrentRunning:  0,
			TimeElapsed:     5 * time.Minute,
			TotalIterations: 2,
		},
		ObservedAt: now,
	}
}

func TestNewThinker(t *testing.T) {
	client := &mockLLMClient{}

	tests := []struct {
		name    string
		options []ThinkerOption
		verify  func(t *testing.T, thinker *Thinker)
	}{
		{
			name:    "default configuration",
			options: nil,
			verify: func(t *testing.T, thinker *Thinker) {
				assert.Equal(t, "primary", thinker.slotName)
				assert.Equal(t, 3, thinker.maxRetries)
				assert.Equal(t, 0.2, thinker.temperature)
			},
		},
		{
			name: "with custom max retries",
			options: []ThinkerOption{
				WithMaxRetries(5),
			},
			verify: func(t *testing.T, thinker *Thinker) {
				assert.Equal(t, 5, thinker.maxRetries)
			},
		},
		{
			name: "with custom temperature",
			options: []ThinkerOption{
				WithThinkerTemperature(0.5),
			},
			verify: func(t *testing.T, thinker *Thinker) {
				assert.Equal(t, 0.5, thinker.temperature)
			},
		},
		{
			name: "with custom model",
			options: []ThinkerOption{
				WithModel("gpt-4"),
			},
			verify: func(t *testing.T, thinker *Thinker) {
				assert.Equal(t, "gpt-4", thinker.model)
			},
		},
		{
			name: "with all options",
			options: []ThinkerOption{
				WithMaxRetries(10),
				WithModel("claude-3"),
				WithThinkerTemperature(0.7),
			},
			verify: func(t *testing.T, thinker *Thinker) {
				assert.Equal(t, 10, thinker.maxRetries)
				assert.Equal(t, "claude-3", thinker.model)
				assert.Equal(t, 0.7, thinker.temperature)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thinker := NewThinker(client, tt.options...)
			require.NotNil(t, thinker)
			assert.Equal(t, client, thinker.llmClient)
			tt.verify(t, thinker)
		})
	}
}

func TestThinker_Think_Success(t *testing.T) {
	validDecision := &Decision{
		Reasoning:    "Should execute the exploit node to test discovered vulnerabilities",
		Action:       ActionExecuteAgent,
		TargetNodeID: "exploit",
		Confidence:   0.85,
	}

	tests := []struct {
		name           string
		setupClient    func() *mockLLMClient
		expectedResult func(t *testing.T, result *ThinkResult)
	}{
		{
			name: "structured output success",
			setupClient: func() *mockLLMClient {
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return validDecision, nil
					},
				}
			},
			expectedResult: func(t *testing.T, result *ThinkResult) {
				assert.NotNil(t, result.Decision)
				assert.Equal(t, ActionExecuteAgent, result.Decision.Action)
				assert.Equal(t, "exploit", result.Decision.TargetNodeID)
				assert.Equal(t, 0.85, result.Decision.Confidence)
				assert.Equal(t, 0, result.RetryCount)
			},
		},
		{
			name: "text output with valid JSON",
			setupClient: func() *mockLLMClient {
				decisionJSON, _ := json.Marshal(validDecision)
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return nil, errors.New("structured output not supported")
					},
					completeFunc: func(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
						return &llm.CompletionResponse{
							ID:    "resp-123",
							Model: "test-model",
							Message: llm.Message{
								Role:    llm.RoleAssistant,
								Content: string(decisionJSON),
							},
							Usage: llm.CompletionTokenUsage{
								PromptTokens:     500,
								CompletionTokens: 200,
								TotalTokens:      700,
							},
						}, nil
					},
				}
			},
			expectedResult: func(t *testing.T, result *ThinkResult) {
				assert.NotNil(t, result.Decision)
				assert.Equal(t, ActionExecuteAgent, result.Decision.Action)
				assert.Equal(t, 500, result.PromptTokens)
				assert.Equal(t, 200, result.CompletionTokens)
				assert.Equal(t, 700, result.TotalTokens)
				assert.Greater(t, result.Latency, time.Duration(0))
			},
		},
		{
			name: "complete action decision",
			setupClient: func() *mockLLMClient {
				completeDecision := &Decision{
					Reasoning:  "All nodes executed successfully with good findings",
					Action:     ActionComplete,
					Confidence: 0.95,
					StopReason: "Goal achieved - discovered 5 vulnerabilities",
				}
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return completeDecision, nil
					},
				}
			},
			expectedResult: func(t *testing.T, result *ThinkResult) {
				assert.NotNil(t, result.Decision)
				assert.Equal(t, ActionComplete, result.Decision.Action)
				assert.NotEmpty(t, result.Decision.StopReason)
				assert.True(t, result.Decision.IsTerminal())
			},
		},
		{
			name: "skip agent decision",
			setupClient: func() *mockLLMClient {
				skipDecision := &Decision{
					Reasoning:    "This node is unlikely to yield findings for this target type",
					Action:       ActionSkipAgent,
					TargetNodeID: "unnecessary-node",
					Confidence:   0.8,
				}
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return skipDecision, nil
					},
				}
			},
			expectedResult: func(t *testing.T, result *ThinkResult) {
				assert.Equal(t, ActionSkipAgent, result.Decision.Action)
				assert.Equal(t, "unnecessary-node", result.Decision.TargetNodeID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			thinker := NewThinker(client)
			state := createTestObservationState()

			result, err := thinker.Think(context.Background(), state)

			require.NoError(t, err)
			require.NotNil(t, result)
			tt.expectedResult(t, result)
		})
	}
}

func TestThinker_Think_Retries(t *testing.T) {
	t.Run("retry on parse error then succeed", func(t *testing.T) {
		validDecision := &Decision{
			Reasoning:    "Valid decision after retry",
			Action:       ActionExecuteAgent,
			TargetNodeID: "node-1",
			Confidence:   0.9,
		}
		validJSON, _ := json.Marshal(validDecision)

		var callCount int
		client := &mockLLMClient{
			completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
				return nil, errors.New("structured not supported")
			},
			completeFunc: func(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
				callCount++
				// Fail first two times, succeed on third
				if callCount <= 2 {
					return &llm.CompletionResponse{
						Message: llm.Message{
							Role:    llm.RoleAssistant,
							Content: "Invalid JSON {{{",
						},
						Usage: llm.CompletionTokenUsage{TotalTokens: 100},
					}, nil
				}
				return &llm.CompletionResponse{
					Message: llm.Message{
						Role:    llm.RoleAssistant,
						Content: string(validJSON),
					},
					Usage: llm.CompletionTokenUsage{
						PromptTokens:     500,
						CompletionTokens: 200,
						TotalTokens:      700,
					},
				}, nil
			},
		}

		thinker := NewThinker(client, WithMaxRetries(3))
		state := createTestObservationState()

		result, err := thinker.Think(context.Background(), state)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, ActionExecuteAgent, result.Decision.Action)
		assert.Equal(t, 2, result.RetryCount) // Succeeded on 3rd attempt (retry count 2)
		assert.GreaterOrEqual(t, callCount, 3)
	})

	t.Run("exhaust retries", func(t *testing.T) {
		client := &mockLLMClient{
			completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
				return nil, errors.New("structured not supported")
			},
			completeFunc: func(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
				// Always return invalid JSON
				return &llm.CompletionResponse{
					Message: llm.Message{
						Role:    llm.RoleAssistant,
						Content: "Invalid JSON response",
					},
					Usage: llm.CompletionTokenUsage{TotalTokens: 100},
				}, nil
			},
		}

		thinker := NewThinker(client, WithMaxRetries(2))
		state := createTestObservationState()

		result, err := thinker.Think(context.Background(), state)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed after")
		// Each retry attempt calls both structured output (CompleteStructuredAny) and
		// text fallback (Complete), so 3 attempts * 2 calls each = 6 total calls
		assert.Equal(t, 6, client.callCount)
	})
}

func TestThinker_Think_Errors(t *testing.T) {
	tests := []struct {
		name        string
		state       *ObservationState
		setupClient func() *mockLLMClient
		wantError   string
	}{
		{
			name:  "nil observation state",
			state: nil,
			setupClient: func() *mockLLMClient {
				return &mockLLMClient{}
			},
			wantError: "observation state is nil",
		},
		{
			name:  "LLM call fails",
			state: createTestObservationState(),
			setupClient: func() *mockLLMClient {
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return nil, errors.New("structured not supported")
					},
					completeFunc: func(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
						return nil, errors.New("API error: rate limit exceeded")
					},
				}
			},
			wantError: "rate limit exceeded",
		},
		{
			name:  "context cancelled",
			state: createTestObservationState(),
			setupClient: func() *mockLLMClient {
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return nil, ctx.Err()
					},
					completeFunc: func(ctx context.Context, slot string, messages []llm.Message, opts ...CompletionOption) (*llm.CompletionResponse, error) {
						return nil, ctx.Err()
					},
				}
			},
			wantError: "context",
		},
		{
			name:  "invalid decision - missing required field",
			state: createTestObservationState(),
			setupClient: func() *mockLLMClient {
				invalidDecision := &Decision{
					Reasoning:  "Missing action field",
					Confidence: 0.8,
					// Action is missing!
				}
				return &mockLLMClient{
					completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
						return invalidDecision, nil
					},
				}
			},
			wantError: "invalid decision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := tt.setupClient()
			thinker := NewThinker(client, WithMaxRetries(1))

			ctx := context.Background()
			if tt.name == "context cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel() // Cancel immediately
			}

			result, err := thinker.Think(ctx, tt.state)

			assert.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), tt.wantError)
		})
	}
}

func TestThinker_Think_DecisionValidation(t *testing.T) {
	tests := []struct {
		name      string
		decision  *Decision
		wantError bool
	}{
		{
			name: "valid execute_agent",
			decision: &Decision{
				Reasoning:    "Should run this agent",
				Action:       ActionExecuteAgent,
				TargetNodeID: "node-1",
				Confidence:   0.9,
			},
			wantError: false,
		},
		{
			name: "invalid - missing target_node_id for execute_agent",
			decision: &Decision{
				Reasoning:  "Invalid decision",
				Action:     ActionExecuteAgent,
				Confidence: 0.9,
			},
			wantError: true,
		},
		{
			name: "invalid - confidence out of range",
			decision: &Decision{
				Reasoning:    "Invalid confidence",
				Action:       ActionExecuteAgent,
				TargetNodeID: "node-1",
				Confidence:   1.5, // > 1.0
			},
			wantError: true,
		},
		{
			name: "valid complete with stop_reason",
			decision: &Decision{
				Reasoning:  "All done",
				Action:     ActionComplete,
				Confidence: 0.95,
				StopReason: "Goal achieved",
			},
			wantError: false,
		},
		{
			name: "invalid - complete without stop_reason",
			decision: &Decision{
				Reasoning:  "All done",
				Action:     ActionComplete,
				Confidence: 0.95,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockLLMClient{
				completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
					return tt.decision, nil
				},
			}

			thinker := NewThinker(client)
			state := createTestObservationState()

			result, err := thinker.Think(context.Background(), state)

			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestThinker_buildPrompt(t *testing.T) {
	client := &mockLLMClient{}
	thinker := NewThinker(client)
	state := createTestObservationState()

	prompt, err := thinker.buildPrompt(state, 0)

	require.NoError(t, err)
	assert.NotEmpty(t, prompt)

	// Verify prompt contains key information
	assert.Contains(t, prompt, state.MissionInfo.Objective)
	assert.Contains(t, prompt, state.MissionInfo.Name) // Name is included in prompt, not ID
	assert.Contains(t, prompt, "MISSION CONTEXT")
	assert.Contains(t, prompt, "MISSION PROGRESS")
	assert.Contains(t, prompt, "Response Format")

	// Verify nodes are included
	assert.Contains(t, prompt, "recon")
	assert.Contains(t, prompt, "exploit-1")

	t.Run("retry attempt adds note", func(t *testing.T) {
		promptRetry, err := thinker.buildPrompt(state, 1)
		require.NoError(t, err)
		assert.Contains(t, promptRetry, "retry attempt 2")
		assert.Contains(t, promptRetry, "invalid or could not be parsed")
	})
}

func TestDecisionJSONSchema(t *testing.T) {
	schema := DecisionJSONSchema()

	require.NotNil(t, schema)
	assert.Equal(t, "object", schema["type"])

	properties, ok := schema["properties"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, properties, "reasoning")
	assert.Contains(t, properties, "action")
	assert.Contains(t, properties, "confidence")
	assert.Contains(t, properties, "target_node_id")
	assert.Contains(t, properties, "spawn_config")

	// Verify action enum
	actionProp := properties["action"].(map[string]interface{})
	enum := actionProp["enum"].([]string)
	assert.Contains(t, enum, "execute_agent")
	assert.Contains(t, enum, "complete")

	// Verify confidence constraints
	confidenceProp := properties["confidence"].(map[string]interface{})
	assert.Equal(t, 0.0, confidenceProp["minimum"])
	assert.Equal(t, 1.0, confidenceProp["maximum"])
}

func TestCompletionOptions(t *testing.T) {
	opts := &CompletionOptions{}

	WithTemperature(0.5)(opts)
	assert.Equal(t, 0.5, opts.Temperature)

	WithMaxTokens(1000)(opts)
	assert.Equal(t, 1000, opts.MaxTokens)

	WithTopP(0.9)(opts)
	assert.Equal(t, 0.9, opts.TopP)
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		retryable bool
	}{
		{
			name:      "nil error",
			err:       nil,
			retryable: false,
		},
		{
			name:      "parse error",
			err:       &parseError{msg: "failed to parse"},
			retryable: true,
		},
		{
			name:      "json unmarshal error",
			err:       errors.New("failed to unmarshal JSON"),
			retryable: true,
		},
		{
			name:      "invalid format error",
			err:       errors.New("invalid decision format"),
			retryable: true,
		},
		{
			name:      "API error",
			err:       errors.New("API rate limit exceeded"),
			retryable: false,
		},
		{
			name:      "context cancelled",
			err:       context.Canceled,
			retryable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRetryableError(tt.err)
			assert.Equal(t, tt.retryable, result)
		})
	}
}

func TestThinkResult_ContainsFullPrompt(t *testing.T) {
	// Create a mock LLM client that returns a valid decision
	validDecision := &Decision{
		Reasoning:    "Should execute the recon agent to gather information",
		Action:       ActionExecuteAgent,
		TargetNodeID: "exploit-1",
		Confidence:   0.9,
	}

	client := &mockLLMClient{
		completeStructuredUsageFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (*StructuredCompletionResult, error) {
			return &StructuredCompletionResult{
				Result:           validDecision,
				Model:            "gpt-4",
				RawJSON:          `{"reasoning":"test","action":"execute_agent","target_node_id":"exploit-1","confidence":0.9}`,
				PromptTokens:     500,
				CompletionTokens: 150,
				TotalTokens:      650,
			}, nil
		},
	}

	thinker := NewThinker(client)
	state := createTestObservationState()

	result, err := thinker.Think(context.Background(), state)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify SystemPrompt is populated
	assert.NotEmpty(t, result.SystemPrompt, "SystemPrompt should be populated")
	assert.Contains(t, result.SystemPrompt, "Orchestrator", "SystemPrompt should mention orchestrator role")

	// Verify UserPrompt is populated and contains observation state information
	assert.NotEmpty(t, result.UserPrompt, "UserPrompt should be populated")
	assert.Contains(t, result.UserPrompt, state.MissionInfo.Name, "UserPrompt should contain mission name")
	assert.Contains(t, result.UserPrompt, state.MissionInfo.Objective, "UserPrompt should contain mission objective")

	// Verify Messages array is populated with system and user messages
	assert.Len(t, result.Messages, 2, "Messages should contain 2 messages (system + user)")
	assert.Equal(t, llm.RoleSystem, result.Messages[0].Role, "First message should be system role")
	assert.Equal(t, llm.RoleUser, result.Messages[1].Role, "Second message should be user role")
	assert.Equal(t, result.SystemPrompt, result.Messages[0].Content, "First message content should match SystemPrompt")
	assert.Equal(t, result.UserPrompt, result.Messages[1].Content, "Second message content should match UserPrompt")

	// Verify RequestConfig is populated
	assert.Equal(t, "primary", result.RequestConfig.SlotName, "RequestConfig should have default slot name")
	assert.Equal(t, 0.2, result.RequestConfig.Temperature, "RequestConfig should have default temperature")
	assert.Equal(t, 2000, result.RequestConfig.MaxTokens, "RequestConfig should have max tokens")

	// Verify decision is correct
	assert.NotNil(t, result.Decision)
	assert.Equal(t, ActionExecuteAgent, result.Decision.Action)
	assert.Equal(t, "exploit-1", result.Decision.TargetNodeID)
}

// Benchmark tests
func BenchmarkThinker_Think(b *testing.B) {
	validDecision := &Decision{
		Reasoning:    "Benchmark decision",
		Action:       ActionExecuteAgent,
		TargetNodeID: "node-1",
		Confidence:   0.9,
	}

	client := &mockLLMClient{
		completeStructuredFunc: func(ctx context.Context, slot string, messages []llm.Message, schemaType any, opts ...CompletionOption) (any, error) {
			return validDecision, nil
		},
	}

	thinker := NewThinker(client)
	state := createTestObservationState()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := thinker.Think(ctx, state)
		if err != nil {
			b.Fatal(err)
		}
	}
}
