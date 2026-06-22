package observability

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"go.opentelemetry.io/otel/attribute"
)

func TestRequestAttributes(t *testing.T) {
	tests := []struct {
		name     string
		req      *llm.CompletionRequest
		provider string
		want     map[string]any
	}{
		{
			name: "basic request",
			req: &llm.CompletionRequest{
				Model: "gpt-4",
			},
			provider: "openai",
			want: map[string]any{
				GenAISystem:       "openai",
				GenAIRequestModel: "gpt-4",
			},
		},
		{
			name: "request with temperature",
			req: &llm.CompletionRequest{
				Model:       "claude-3-opus",
				Temperature: 0.7,
			},
			provider: "anthropic",
			want: map[string]any{
				GenAISystem:             "anthropic",
				GenAIRequestModel:       "claude-3-opus",
				GenAIRequestTemperature: 0.7,
			},
		},
		{
			name: "request with max tokens",
			req: &llm.CompletionRequest{
				Model:     "llama2",
				MaxTokens: 2048,
			},
			provider: "ollama",
			want: map[string]any{
				GenAISystem:           "ollama",
				GenAIRequestModel:     "llama2",
				GenAIRequestMaxTokens: int64(2048),
			},
		},
		{
			name: "request with top_p",
			req: &llm.CompletionRequest{
				Model: "gpt-3.5-turbo",
				TopP:  0.95,
			},
			provider: "openai",
			want: map[string]any{
				GenAISystem:       "openai",
				GenAIRequestModel: "gpt-3.5-turbo",
				GenAIRequestTopP:  0.95,
			},
		},
		{
			name: "full request with all parameters",
			req: &llm.CompletionRequest{
				Model:       "gpt-4-turbo",
				Temperature: 0.8,
				MaxTokens:   4096,
				TopP:        0.9,
			},
			provider: "openai",
			want: map[string]any{
				GenAISystem:             "openai",
				GenAIRequestModel:       "gpt-4-turbo",
				GenAIRequestTemperature: 0.8,
				GenAIRequestMaxTokens:   int64(4096),
				GenAIRequestTopP:        0.9,
			},
		},
		{
			name:     "nil request",
			req:      nil,
			provider: "openai",
			want:     map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := RequestAttributes(tt.req, tt.provider)

			// Convert attributes to map for easier comparison
			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestResponseAttributes(t *testing.T) {
	tests := []struct {
		name string
		resp *llm.CompletionResponse
		want map[string]any
	}{
		{
			name: "basic response",
			resp: &llm.CompletionResponse{
				Model:        "gpt-4",
				FinishReason: llm.FinishReasonStop,
				Message: llm.Message{
					Role:    llm.RoleAssistant,
					Content: "Hello, world!",
				},
			},
			want: map[string]any{
				GenAIResponseModel:        "gpt-4",
				GenAIResponseFinishReason: "stop",
				GenAICompletion:           "Hello, world!",
			},
		},
		{
			name: "response with tool calls finish reason",
			resp: &llm.CompletionResponse{
				Model:        "gpt-4-turbo",
				FinishReason: llm.FinishReasonToolCalls,
				Message: llm.Message{
					Role: llm.RoleAssistant,
				},
			},
			want: map[string]any{
				GenAIResponseModel:        "gpt-4-turbo",
				GenAIResponseFinishReason: "tool_calls",
			},
		},
		{
			name: "response with length finish reason",
			resp: &llm.CompletionResponse{
				Model:        "claude-3-sonnet",
				FinishReason: llm.FinishReasonLength,
				Message: llm.Message{
					Role:    llm.RoleAssistant,
					Content: "This is a partial response...",
				},
			},
			want: map[string]any{
				GenAIResponseModel:        "claude-3-sonnet",
				GenAIResponseFinishReason: "length",
				GenAICompletion:           "This is a partial response...",
			},
		},
		{
			name: "response with content filter",
			resp: &llm.CompletionResponse{
				Model:        "gpt-4",
				FinishReason: llm.FinishReasonContentFilter,
				Message: llm.Message{
					Role: llm.RoleAssistant,
				},
			},
			want: map[string]any{
				GenAIResponseModel:        "gpt-4",
				GenAIResponseFinishReason: "content_filter",
			},
		},
		{
			name: "nil response",
			resp: nil,
			want: map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ResponseAttributes(tt.resp)

			// Convert attributes to map for easier comparison
			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUsageAttributes(t *testing.T) {
	tests := []struct {
		name  string
		usage llm.CompletionTokenUsage
		want  map[string]any
	}{
		{
			name: "basic usage",
			usage: llm.CompletionTokenUsage{
				PromptTokens:     100,
				CompletionTokens: 50,
				TotalTokens:      150,
			},
			want: map[string]any{
				GenAIUsageInputTokens:  int64(100),
				GenAIUsageOutputTokens: int64(50),
			},
		},
		{
			name: "large usage",
			usage: llm.CompletionTokenUsage{
				PromptTokens:     8192,
				CompletionTokens: 4096,
				TotalTokens:      12288,
			},
			want: map[string]any{
				GenAIUsageInputTokens:  int64(8192),
				GenAIUsageOutputTokens: int64(4096),
			},
		},
		{
			name: "zero usage",
			usage: llm.CompletionTokenUsage{
				PromptTokens:     0,
				CompletionTokens: 0,
				TotalTokens:      0,
			},
			want: map[string]any{
				GenAIUsageInputTokens:  int64(0),
				GenAIUsageOutputTokens: int64(0),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := UsageAttributes(tt.usage)

			// Convert attributes to map for easier comparison
			got := make(map[string]any)
			for _, attr := range attrs {
				got[string(attr.Key)] = attr.Value.AsInterface()
			}

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPromptAttributes(t *testing.T) {
	tests := []struct {
		name string
		req  *llm.CompletionRequest
		want string
	}{
		{
			name: "single message",
			req: &llm.CompletionRequest{
				Messages: []llm.Message{
					{Role: llm.RoleUser, Content: "Hello"},
				},
			},
			want: "[user] Hello",
		},
		{
			name: "multiple messages",
			req: &llm.CompletionRequest{
				Messages: []llm.Message{
					{Role: llm.RoleSystem, Content: "You are a helpful assistant"},
					{Role: llm.RoleUser, Content: "What is Go?"},
					{Role: llm.RoleAssistant, Content: "Go is a programming language"},
				},
			},
			want: "[system] You are a helpful assistant\n[user] What is Go?\n[assistant] Go is a programming language",
		},
		{
			name: "nil request",
			req:  nil,
			want: "",
		},
		{
			name: "empty messages",
			req: &llm.CompletionRequest{
				Messages: []llm.Message{},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := PromptAttributes(tt.req)

			if tt.want == "" {
				assert.Empty(t, attrs)
				return
			}

			require.Len(t, attrs, 1)
			assert.Equal(t, GenAIPrompt, string(attrs[0].Key))
			assert.Equal(t, tt.want, attrs[0].Value.AsString())
		})
	}
}

func TestGenAIAttributeKeyConstants(t *testing.T) {
	// Test that attribute keys follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"GenAI System", GenAISystem, "gen_ai.system"},
		{"GenAI Request Model", GenAIRequestModel, "gen_ai.request.model"},
		{"GenAI Request Temperature", GenAIRequestTemperature, "gen_ai.request.temperature"},
		{"GenAI Request Max Tokens", GenAIRequestMaxTokens, "gen_ai.request.max_tokens"},
		{"GenAI Request Top P", GenAIRequestTopP, "gen_ai.request.top_p"},
		{"GenAI Response Model", GenAIResponseModel, "gen_ai.response.model"},
		{"GenAI Response Finish Reason", GenAIResponseFinishReason, "gen_ai.response.finish_reason"},
		{"GenAI Usage Input Tokens", GenAIUsageInputTokens, "gen_ai.usage.input_tokens"},
		{"GenAI Usage Output Tokens", GenAIUsageOutputTokens, "gen_ai.usage.output_tokens"},
		{"GenAI Prompt", GenAIPrompt, "gen_ai.prompt"},
		{"GenAI Completion", GenAICompletion, "gen_ai.completion"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestGenAISpanNameConstants(t *testing.T) {
	// Test that span names follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Chat Span", SpanGenAIChat, "gen_ai.chat"},
		{"Chat Stream Span", SpanGenAIChatStream, "gen_ai.chat.stream"},
		{"Tool Span", SpanGenAITool, "gen_ai.tool"},
		{"Embeddings Span", SpanGenAIEmbeddings, "gen_ai.embeddings"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestRequestAttributesTypes(t *testing.T) {
	// Verify that attributes have the correct types
	req := &llm.CompletionRequest{
		Model:       "gpt-4",
		Temperature: 0.7,
		MaxTokens:   1000,
		TopP:        0.9,
	}

	attrs := RequestAttributes(req, "openai")

	// Build a type map
	typeMap := make(map[string]attribute.Type)
	for _, attr := range attrs {
		typeMap[string(attr.Key)] = attr.Value.Type()
	}

	assert.Equal(t, attribute.STRING, typeMap[GenAISystem])
	assert.Equal(t, attribute.STRING, typeMap[GenAIRequestModel])
	assert.Equal(t, attribute.FLOAT64, typeMap[GenAIRequestTemperature])
	assert.Equal(t, attribute.INT64, typeMap[GenAIRequestMaxTokens])
	assert.Equal(t, attribute.FLOAT64, typeMap[GenAIRequestTopP])
}

func TestResponseAttributesTypes(t *testing.T) {
	// Verify that attributes have the correct types
	resp := &llm.CompletionResponse{
		Model:        "gpt-4",
		FinishReason: llm.FinishReasonStop,
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: "Test",
		},
	}

	attrs := ResponseAttributes(resp)

	// Build a type map
	typeMap := make(map[string]attribute.Type)
	for _, attr := range attrs {
		typeMap[string(attr.Key)] = attr.Value.Type()
	}

	assert.Equal(t, attribute.STRING, typeMap[GenAIResponseModel])
	assert.Equal(t, attribute.STRING, typeMap[GenAIResponseFinishReason])
	assert.Equal(t, attribute.STRING, typeMap[GenAICompletion])
}

func TestUsageAttributesTypes(t *testing.T) {
	// Verify that attributes have the correct types
	usage := llm.CompletionTokenUsage{
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
	}

	attrs := UsageAttributes(usage)

	// Build a type map
	typeMap := make(map[string]attribute.Type)
	for _, attr := range attrs {
		typeMap[string(attr.Key)] = attr.Value.Type()
	}

	assert.Equal(t, attribute.INT64, typeMap[GenAIUsageInputTokens])
	assert.Equal(t, attribute.INT64, typeMap[GenAIUsageOutputTokens])
}

func TestToolCallAttributes(t *testing.T) {
	tests := []struct {
		name      string
		toolCalls []llm.ToolCall
		wantCount int
		wantKeys  []string
	}{
		{
			name:      "empty tool calls",
			toolCalls: []llm.ToolCall{},
			wantCount: 0,
			wantKeys:  []string{},
		},
		{
			name:      "nil tool calls",
			toolCalls: nil,
			wantCount: 0,
			wantKeys:  []string{},
		},
		{
			name: "single tool call",
			toolCalls: []llm.ToolCall{
				{ID: "call_1", Name: "get_weather", Arguments: `{"location": "NYC"}`},
			},
			wantCount: 3,
			wantKeys: []string{
				GenAIToolsProvided,
				GenAIToolCallID + ".0",
				GenAIToolCallName + ".0",
			},
		},
		{
			name: "multiple tool calls",
			toolCalls: []llm.ToolCall{
				{ID: "call_1", Name: "get_weather", Arguments: `{"location": "NYC"}`},
				{ID: "call_2", Name: "get_time", Arguments: `{"timezone": "UTC"}`},
				{ID: "call_3", Name: "calculate", Arguments: `{"expression": "2+2"}`},
			},
			wantCount: 7, // tools_provided + (id + name) * 3
			wantKeys: []string{
				GenAIToolsProvided,
				GenAIToolCallID + ".0",
				GenAIToolCallName + ".0",
				GenAIToolCallID + ".1",
				GenAIToolCallName + ".1",
				GenAIToolCallID + ".2",
				GenAIToolCallName + ".2",
			},
		},
		{
			name: "more than 3 tool calls - only first 3 included",
			toolCalls: []llm.ToolCall{
				{ID: "call_1", Name: "tool1", Arguments: "{}"},
				{ID: "call_2", Name: "tool2", Arguments: "{}"},
				{ID: "call_3", Name: "tool3", Arguments: "{}"},
				{ID: "call_4", Name: "tool4", Arguments: "{}"},
				{ID: "call_5", Name: "tool5", Arguments: "{}"},
			},
			wantCount: 7, // tools_provided (count=5) + (id + name) * 3 (only first 3)
			wantKeys: []string{
				GenAIToolsProvided,
				GenAIToolCallID + ".0",
				GenAIToolCallName + ".0",
				GenAIToolCallID + ".1",
				GenAIToolCallName + ".1",
				GenAIToolCallID + ".2",
				GenAIToolCallName + ".2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ToolCallAttributes(tt.toolCalls)
			assert.Len(t, attrs, tt.wantCount)

			if tt.wantCount > 0 {
				// Verify the keys exist
				attrMap := make(map[string]any)
				for _, attr := range attrs {
					attrMap[string(attr.Key)] = attr.Value.AsInterface()
				}

				for _, key := range tt.wantKeys {
					assert.Contains(t, attrMap, key, "missing expected key: %s", key)
				}

				// Verify tools_provided count
				if len(tt.toolCalls) > 0 {
					assert.Equal(t, int64(len(tt.toolCalls)), attrMap[GenAIToolsProvided])
				}
			}
		})
	}
}

func TestToolChoiceAttributes(t *testing.T) {
	tests := []struct {
		name       string
		toolChoice string
		wantCount  int
		wantValue  string
	}{
		{
			name:       "auto choice",
			toolChoice: "auto",
			wantCount:  1,
			wantValue:  "auto",
		},
		{
			name:       "none choice",
			toolChoice: "none",
			wantCount:  1,
			wantValue:  "none",
		},
		{
			name:       "required choice",
			toolChoice: "required",
			wantCount:  1,
			wantValue:  "required",
		},
		{
			name:       "specific tool name",
			toolChoice: "get_weather",
			wantCount:  1,
			wantValue:  "get_weather",
		},
		{
			name:       "empty tool choice",
			toolChoice: "",
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ToolChoiceAttributes(tt.toolChoice)
			assert.Len(t, attrs, tt.wantCount)

			if tt.wantCount > 0 {
				assert.Equal(t, GenAIToolChoice, string(attrs[0].Key))
				assert.Equal(t, tt.wantValue, attrs[0].Value.AsString())
			}
		})
	}
}

func TestSingleToolCallAttributes(t *testing.T) {
	tests := []struct {
		name      string
		id        string
		toolName  string
		arguments string
		wantCount int
		wantKeys  []string
	}{
		{
			name:      "basic tool call",
			id:        "call_123",
			toolName:  "get_weather",
			arguments: `{"location": "NYC"}`,
			wantCount: 3,
			wantKeys:  []string{GenAIToolCallID, GenAIToolCallName, GenAIToolCallArguments},
		},
		{
			name:      "tool call without arguments",
			id:        "call_456",
			toolName:  "get_time",
			arguments: "",
			wantCount: 2,
			wantKeys:  []string{GenAIToolCallID, GenAIToolCallName},
		},
		{
			name:      "tool call with large arguments - should be truncated",
			id:        "call_789",
			toolName:  "process_data",
			arguments: string(make([]byte, 2000)), // 2KB of data
			wantCount: 3,
			wantKeys:  []string{GenAIToolCallID, GenAIToolCallName, GenAIToolCallArguments},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := SingleToolCallAttributes(tt.id, tt.toolName, tt.arguments)
			assert.Len(t, attrs, tt.wantCount)

			// Verify keys
			attrMap := make(map[string]any)
			for _, attr := range attrs {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			for _, key := range tt.wantKeys {
				assert.Contains(t, attrMap, key, "missing expected key: %s", key)
			}

			// Verify values
			assert.Equal(t, tt.id, attrMap[GenAIToolCallID])
			assert.Equal(t, tt.toolName, attrMap[GenAIToolCallName])

			// If arguments were provided, check truncation
			if tt.arguments != "" && len(tt.arguments) > 1024 {
				argValue := attrMap[GenAIToolCallArguments].(string)
				assert.Contains(t, argValue, "[truncated]")
				assert.LessOrEqual(t, len(argValue), 1024+20) // Allow for truncation message
			}
		})
	}
}

func TestToolResultAttributes(t *testing.T) {
	tests := []struct {
		name       string
		id         string
		toolName   string
		result     string
		truncated  bool
		wantCount  int
		wantKeys   []string
		checkTrunc bool
	}{
		{
			name:      "basic tool result",
			id:        "call_123",
			toolName:  "get_weather",
			result:    `{"temperature": 72, "condition": "sunny"}`,
			truncated: false,
			wantCount: 3,
			wantKeys:  []string{GenAIToolCallID, GenAIToolCallName, GenAIToolCallResult},
		},
		{
			name:       "tool result already truncated",
			id:         "call_456",
			toolName:   "fetch_data",
			result:     "Large result... [truncated]",
			truncated:  true,
			wantCount:  4,
			wantKeys:   []string{GenAIToolCallID, GenAIToolCallName, GenAIToolCallResult, "gen_ai.tool_call.result_truncated"},
			checkTrunc: true,
		},
		{
			name:       "tool result that needs truncation",
			id:         "call_789",
			toolName:   "process_data",
			result:     string(make([]byte, 3000)), // 3KB of data
			truncated:  false,
			wantCount:  4,
			wantKeys:   []string{GenAIToolCallID, GenAIToolCallName, GenAIToolCallResult, "gen_ai.tool_call.result_truncated"},
			checkTrunc: true,
		},
		{
			name:      "empty result",
			id:        "call_999",
			toolName:  "no_op",
			result:    "",
			truncated: false,
			wantCount: 2,
			wantKeys:  []string{GenAIToolCallID, GenAIToolCallName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs := ToolResultAttributes(tt.id, tt.toolName, tt.result, tt.truncated)
			assert.Len(t, attrs, tt.wantCount)

			// Verify keys
			attrMap := make(map[string]any)
			for _, attr := range attrs {
				attrMap[string(attr.Key)] = attr.Value.AsInterface()
			}

			for _, key := range tt.wantKeys {
				assert.Contains(t, attrMap, key, "missing expected key: %s", key)
			}

			// Verify values
			assert.Equal(t, tt.id, attrMap[GenAIToolCallID])
			assert.Equal(t, tt.toolName, attrMap[GenAIToolCallName])

			// Check truncation indicator if needed
			if tt.checkTrunc {
				assert.True(t, attrMap["gen_ai.tool_call.result_truncated"].(bool))
				if tt.result != "" && len(tt.result) > 2048 && !tt.truncated {
					resultValue := attrMap[GenAIToolCallResult].(string)
					assert.Contains(t, resultValue, "[truncated]")
				}
			}
		})
	}
}

func TestToolAttributeConstants(t *testing.T) {
	// Test that tool-related attribute keys follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"GenAI Tools Provided", GenAIToolsProvided, "gen_ai.request.tools_provided"},
		{"GenAI Tool Choice", GenAIToolChoice, "gen_ai.request.tool_choice"},
		{"GenAI Tool Call ID", GenAIToolCallID, "gen_ai.tool_call.id"},
		{"GenAI Tool Call Name", GenAIToolCallName, "gen_ai.tool_call.name"},
		{"GenAI Tool Call Arguments", GenAIToolCallArguments, "gen_ai.tool_call.arguments"},
		{"GenAI Tool Call Result", GenAIToolCallResult, "gen_ai.tool_call.result"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}

func TestEventNameConstants(t *testing.T) {
	// Test that event name constants follow the correct naming convention
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"Event GenAI Content Prompt", EventGenAIContentPrompt, "gen_ai.content.prompt"},
		{"Event GenAI Content Completion", EventGenAIContentCompletion, "gen_ai.content.completion"},
		{"Event GenAI Tool Call Input", EventGenAIToolCallInput, "gen_ai.tool_call.input"},
		{"Event GenAI Tool Call Output", EventGenAIToolCallOutput, "gen_ai.tool_call.output"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.constant)
		})
	}
}
