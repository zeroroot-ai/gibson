package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/langchaingo/llms"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/sdk/schema"
)

func TestToSchemaTools(t *testing.T) {
	tests := []struct {
		name     string
		tools    []llm.ToolDef
		expected []llms.Tool
	}{
		{
			name:     "nil tools",
			tools:    nil,
			expected: nil,
		},
		{
			name:     "empty tools",
			tools:    []llm.ToolDef{},
			expected: nil,
		},
		{
			name: "single tool",
			tools: []llm.ToolDef{
				{
					Name:        "get_weather",
					Description: "Get the current weather for a location",
					Parameters: schema.JSON{
						Type: "object",
						Properties: map[string]schema.JSON{
							"location": {
								Type:        "string",
								Description: "The city and state, e.g. San Francisco, CA",
							},
							"unit": {
								Type:        "string",
								Description: "Temperature unit",
								Enum:        []any{"celsius", "fahrenheit"},
							},
						},
						Required: []string{"location"},
					},
				},
			},
			expected: []llms.Tool{
				{
					Type: "function",
					Function: &llms.FunctionDefinition{
						Name:        "get_weather",
						Description: "Get the current weather for a location",
						Parameters: schema.JSON{
							Type: "object",
							Properties: map[string]schema.JSON{
								"location": {
									Type:        "string",
									Description: "The city and state, e.g. San Francisco, CA",
								},
								"unit": {
									Type:        "string",
									Description: "Temperature unit",
									Enum:        []any{"celsius", "fahrenheit"},
								},
							},
							Required: []string{"location"},
						},
					},
				},
			},
		},
		{
			name: "multiple tools",
			tools: []llm.ToolDef{
				{
					Name:        "get_weather",
					Description: "Get weather",
					Parameters: schema.JSON{
						Type: "object",
					},
				},
				{
					Name:        "search_web",
					Description: "Search the web",
					Parameters: schema.JSON{
						Type: "object",
					},
				},
			},
			expected: []llms.Tool{
				{
					Type: "function",
					Function: &llms.FunctionDefinition{
						Name:        "get_weather",
						Description: "Get weather",
						Parameters: schema.JSON{
							Type: "object",
						},
					},
				},
				{
					Type: "function",
					Function: &llms.FunctionDefinition{
						Name:        "search_web",
						Description: "Search the web",
						Parameters: schema.JSON{
							Type: "object",
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := toSchemaTools(tt.tools)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildCallOptionsWithTools(t *testing.T) {
	tests := []struct {
		name            string
		req             llm.CompletionRequest
		tools           []llm.ToolDef
		expectToolsOpt  bool
		expectedOptions int
	}{
		{
			name: "no tools",
			req: llm.CompletionRequest{
				Model:       "test-model",
				Temperature: 0.7,
				MaxTokens:   100,
			},
			tools:          nil,
			expectToolsOpt: false,
			// temperature, max_tokens, model = 3 options
			expectedOptions: 3,
		},
		{
			name: "with tools",
			req: llm.CompletionRequest{
				Model:       "test-model",
				Temperature: 0.7,
			},
			tools: []llm.ToolDef{
				{
					Name:        "test_tool",
					Description: "Test tool",
					Parameters: schema.JSON{
						Type: "object",
					},
				},
			},
			expectToolsOpt: true,
			// temperature, model, tools = 3 options
			expectedOptions: 3,
		},
		{
			name: "empty tools array",
			req: llm.CompletionRequest{
				Model: "test-model",
			},
			tools:           []llm.ToolDef{},
			expectToolsOpt:  false,
			expectedOptions: 1, // just model
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := buildCallOptionsWithTools(tt.req, tt.tools)
			assert.Len(t, opts, tt.expectedOptions)
		})
	}
}

func TestFromLangchainResponse_WithToolCalls(t *testing.T) {
	tests := []struct {
		name     string
		resp     *llms.ContentResponse
		model    string
		expected *llm.CompletionResponse
	}{
		{
			name:  "nil response",
			resp:  nil,
			model: "test-model",
			expected: &llm.CompletionResponse{
				Model: "test-model",
				Message: llm.Message{
					Role: "",
				},
			},
		},
		{
			name: "response with content only",
			resp: &llms.ContentResponse{
				Choices: []*llms.ContentChoice{
					{
						Content:    "Hello, how can I help?",
						StopReason: "stop",
					},
				},
			},
			model: "test-model",
			expected: &llm.CompletionResponse{
				Model: "test-model",
				Message: llm.Message{
					Role:    llm.RoleAssistant,
					Content: "Hello, how can I help?",
				},
				FinishReason: llm.FinishReasonStop,
			},
		},
		{
			name: "response with tool calls",
			resp: &llms.ContentResponse{
				Choices: []*llms.ContentChoice{
					{
						Content:    "Let me check the weather for you.",
						StopReason: "tool_calls",
						ToolCalls: []llms.ToolCall{
							{
								ID:   "call_123",
								Type: "function",
								FunctionCall: &llms.FunctionCall{
									Name:      "get_weather",
									Arguments: `{"location":"San Francisco, CA"}`,
								},
							},
						},
					},
				},
			},
			model: "test-model",
			expected: &llm.CompletionResponse{
				Model: "test-model",
				Message: llm.Message{
					Role:    llm.RoleAssistant,
					Content: "Let me check the weather for you.",
					ToolCalls: []llm.ToolCall{
						{
							ID:        "call_123",
							Type:      "function",
							Name:      "get_weather",
							Arguments: `{"location":"San Francisco, CA"}`,
						},
					},
				},
				FinishReason: llm.FinishReasonToolCalls,
			},
		},
		{
			name: "response with multiple tool calls",
			resp: &llms.ContentResponse{
				Choices: []*llms.ContentChoice{
					{
						StopReason: "tool_calls",
						ToolCalls: []llms.ToolCall{
							{
								ID:   "call_1",
								Type: "function",
								FunctionCall: &llms.FunctionCall{
									Name:      "get_weather",
									Arguments: `{"location":"NYC"}`,
								},
							},
							{
								ID:   "call_2",
								Type: "function",
								FunctionCall: &llms.FunctionCall{
									Name:      "get_time",
									Arguments: `{"timezone":"EST"}`,
								},
							},
						},
					},
				},
			},
			model: "test-model",
			expected: &llm.CompletionResponse{
				Model: "test-model",
				Message: llm.Message{
					Role: llm.RoleAssistant,
					ToolCalls: []llm.ToolCall{
						{
							ID:        "call_1",
							Type:      "function",
							Name:      "get_weather",
							Arguments: `{"location":"NYC"}`,
						},
						{
							ID:        "call_2",
							Type:      "function",
							Name:      "get_time",
							Arguments: `{"timezone":"EST"}`,
						},
					},
				},
				FinishReason: llm.FinishReasonToolCalls,
			},
		},
		{
			name: "tool calls without explicit stop reason",
			resp: &llms.ContentResponse{
				Choices: []*llms.ContentChoice{
					{
						Content: "Using tools",
						ToolCalls: []llms.ToolCall{
							{
								ID:   "call_abc",
								Type: "function",
								FunctionCall: &llms.FunctionCall{
									Name:      "test_tool",
									Arguments: `{}`,
								},
							},
						},
					},
				},
			},
			model: "test-model",
			expected: &llm.CompletionResponse{
				Model: "test-model",
				Message: llm.Message{
					Role:    llm.RoleAssistant,
					Content: "Using tools",
					ToolCalls: []llm.ToolCall{
						{
							ID:        "call_abc",
							Type:      "function",
							Name:      "test_tool",
							Arguments: `{}`,
						},
					},
				},
				FinishReason: llm.FinishReasonToolCalls,
			},
		},
		{
			name: "empty choices",
			resp: &llms.ContentResponse{
				Choices: []*llms.ContentChoice{},
			},
			model: "test-model",
			expected: &llm.CompletionResponse{
				Model: "test-model",
				Message: llm.Message{
					Role: llm.RoleAssistant,
				},
				FinishReason: llm.FinishReasonStop,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fromLangchainResponse(tt.resp, tt.model)
			require.NotNil(t, result)

			// Don't compare IDs since they're generated
			assert.Equal(t, tt.expected.Model, result.Model)

			// Only check Role if it's set in expected (to handle nil response case)
			if tt.expected.Message.Role != "" {
				assert.Equal(t, tt.expected.Message.Role, result.Message.Role)
			}

			assert.Equal(t, tt.expected.Message.Content, result.Message.Content)
			assert.Equal(t, tt.expected.Message.ToolCalls, result.Message.ToolCalls)
			assert.Equal(t, tt.expected.FinishReason, result.FinishReason)
		})
	}
}

func TestFromLangchainResponse_StopReasons(t *testing.T) {
	tests := []struct {
		name                 string
		stopReason           string
		hasToolCalls         bool
		expectedFinishReason llm.FinishReason
	}{
		{
			name:                 "stop",
			stopReason:           "stop",
			hasToolCalls:         false,
			expectedFinishReason: llm.FinishReasonStop,
		},
		{
			name:                 "length",
			stopReason:           "length",
			hasToolCalls:         false,
			expectedFinishReason: llm.FinishReasonLength,
		},
		{
			name:                 "max_tokens",
			stopReason:           "max_tokens",
			hasToolCalls:         false,
			expectedFinishReason: llm.FinishReasonLength,
		},
		{
			name:                 "tool_calls",
			stopReason:           "tool_calls",
			hasToolCalls:         true,
			expectedFinishReason: llm.FinishReasonToolCalls,
		},
		{
			name:                 "function_call",
			stopReason:           "function_call",
			hasToolCalls:         true,
			expectedFinishReason: llm.FinishReasonToolCalls,
		},
		{
			name:                 "content_filter",
			stopReason:           "content_filter",
			hasToolCalls:         false,
			expectedFinishReason: llm.FinishReasonContentFilter,
		},
		{
			name:                 "unknown reason defaults to stop",
			stopReason:           "unknown",
			hasToolCalls:         false,
			expectedFinishReason: llm.FinishReasonStop,
		},
		{
			name:                 "tool calls without explicit reason",
			stopReason:           "",
			hasToolCalls:         true,
			expectedFinishReason: llm.FinishReasonToolCalls,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &llms.ContentResponse{
				Choices: []*llms.ContentChoice{
					{
						Content:    "test",
						StopReason: tt.stopReason,
					},
				},
			}

			if tt.hasToolCalls {
				resp.Choices[0].ToolCalls = []llms.ToolCall{
					{
						ID:   "call_123",
						Type: "function",
						FunctionCall: &llms.FunctionCall{
							Name:      "test",
							Arguments: "{}",
						},
					},
				}
			}

			result := fromLangchainResponse(resp, "test-model")
			assert.Equal(t, tt.expectedFinishReason, result.FinishReason)
		})
	}
}
