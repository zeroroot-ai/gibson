package llm

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRole_String(t *testing.T) {
	tests := []struct {
		role     Role
		expected string
	}{
		{RoleSystem, "system"},
		{RoleUser, "user"},
		{RoleAssistant, "assistant"},
		{RoleTool, "tool"},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.role.String())
		})
	}
}

func TestRole_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		expected bool
	}{
		{"valid system", RoleSystem, true},
		{"valid user", RoleUser, true},
		{"valid assistant", RoleAssistant, true},
		{"valid tool", RoleTool, true},
		{"invalid empty", Role(""), false},
		{"invalid unknown", Role("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.role.IsValid())
		})
	}
}

func TestRole_MarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		expected string
	}{
		{"system", RoleSystem, `"system"`},
		{"user", RoleUser, `"user"`},
		{"assistant", RoleAssistant, `"assistant"`},
		{"tool", RoleTool, `"tool"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.role)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(data))
		})
	}
}

func TestRole_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		expected  Role
		expectErr bool
	}{
		{"valid system", `"system"`, RoleSystem, false},
		{"valid user", `"user"`, RoleUser, false},
		{"valid assistant", `"assistant"`, RoleAssistant, false},
		{"valid tool", `"tool"`, RoleTool, false},
		{"invalid role", `"invalid"`, "", true},
		{"invalid json", `invalid`, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var role Role
			err := json.Unmarshal([]byte(tt.data), &role)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, role)
			}
		})
	}
}

func TestNewSystemMessage(t *testing.T) {
	msg := NewSystemMessage("You are a helpful assistant")
	assert.Equal(t, RoleSystem, msg.Role)
	assert.Equal(t, "You are a helpful assistant", msg.Content)
	assert.Empty(t, msg.Name)
	assert.Empty(t, msg.ToolCalls)
	assert.Empty(t, msg.ToolCallID)
}

func TestNewUserMessage(t *testing.T) {
	msg := NewUserMessage("Hello!")
	assert.Equal(t, RoleUser, msg.Role)
	assert.Equal(t, "Hello!", msg.Content)
	assert.Empty(t, msg.Name)
	assert.Empty(t, msg.ToolCalls)
	assert.Empty(t, msg.ToolCallID)
}

func TestNewAssistantMessage(t *testing.T) {
	msg := NewAssistantMessage("Hi there!")
	assert.Equal(t, RoleAssistant, msg.Role)
	assert.Equal(t, "Hi there!", msg.Content)
	assert.Empty(t, msg.Name)
	assert.Empty(t, msg.ToolCalls)
	assert.Empty(t, msg.ToolCallID)
}

func TestNewToolResultMessage(t *testing.T) {
	msg := NewToolResultMessage("call-123", "result content")
	assert.Equal(t, RoleTool, msg.Role)
	assert.Equal(t, "result content", msg.Content)
	assert.Equal(t, "call-123", msg.ToolCallID)
	assert.Empty(t, msg.Name)
	assert.Empty(t, msg.ToolCalls)
}

func TestMessage_WithName(t *testing.T) {
	msg := NewUserMessage("Hello").WithName("Alice")
	assert.Equal(t, "Alice", msg.Name)
	assert.Equal(t, RoleUser, msg.Role)
	assert.Equal(t, "Hello", msg.Content)
}

func TestMessage_WithMetadata(t *testing.T) {
	msg := NewUserMessage("Hello").
		WithMetadata("source", "api").
		WithMetadata("timestamp", 123456)

	assert.Equal(t, "api", msg.Metadata["source"])
	assert.Equal(t, 123456, msg.Metadata["timestamp"])
}

func TestMessage_Validate(t *testing.T) {
	tests := []struct {
		name      string
		message   Message
		expectErr bool
		errMsg    string
	}{
		{
			name:      "valid system message",
			message:   NewSystemMessage("test"),
			expectErr: false,
		},
		{
			name:      "valid user message",
			message:   NewUserMessage("test"),
			expectErr: false,
		},
		{
			name:      "valid assistant message with content",
			message:   NewAssistantMessage("test"),
			expectErr: false,
		},
		{
			name: "valid assistant message with tool calls",
			message: Message{
				Role: RoleAssistant,
				ToolCalls: []ToolCall{
					{ID: "1", Name: "test", Arguments: "{}"},
				},
			},
			expectErr: false,
		},
		{
			name: "valid assistant message with content and tool calls",
			message: Message{
				Role:    RoleAssistant,
				Content: "Let me call a tool",
				ToolCalls: []ToolCall{
					{ID: "1", Name: "test", Arguments: "{}"},
				},
			},
			expectErr: false,
		},
		{
			name:      "valid tool message",
			message:   NewToolResultMessage("call-123", "result"),
			expectErr: false,
		},
		{
			name: "invalid role",
			message: Message{
				Role:    Role("invalid"),
				Content: "test",
			},
			expectErr: true,
			errMsg:    "invalid role",
		},
		{
			name: "system message without content",
			message: Message{
				Role: RoleSystem,
			},
			expectErr: true,
			errMsg:    "system message must have content",
		},
		{
			name: "user message without content",
			message: Message{
				Role: RoleUser,
			},
			expectErr: true,
			errMsg:    "user message must have content",
		},
		{
			name: "system message with tool calls",
			message: Message{
				Role:      RoleSystem,
				Content:   "test",
				ToolCalls: []ToolCall{{ID: "1", Name: "test", Arguments: "{}"}},
			},
			expectErr: true,
			errMsg:    "system message cannot have tool calls",
		},
		{
			name: "user message with tool_call_id",
			message: Message{
				Role:       RoleUser,
				Content:    "test",
				ToolCallID: "call-123",
			},
			expectErr: true,
			errMsg:    "user message cannot have tool_call_id",
		},
		{
			name: "assistant message without content or tool calls",
			message: Message{
				Role: RoleAssistant,
			},
			expectErr: true,
			errMsg:    "assistant message must have content or tool calls",
		},
		{
			name: "assistant message with tool_call_id",
			message: Message{
				Role:       RoleAssistant,
				Content:    "test",
				ToolCallID: "call-123",
			},
			expectErr: true,
			errMsg:    "assistant message cannot have tool_call_id",
		},
		{
			name: "tool message without content",
			message: Message{
				Role:       RoleTool,
				ToolCallID: "call-123",
			},
			expectErr: true,
			errMsg:    "tool message must have content",
		},
		{
			name: "tool message without tool_call_id",
			message: Message{
				Role:    RoleTool,
				Content: "result",
			},
			expectErr: true,
			errMsg:    "tool message must have tool_call_id",
		},
		{
			name: "tool message with tool calls",
			message: Message{
				Role:       RoleTool,
				Content:    "result",
				ToolCallID: "call-123",
				ToolCalls:  []ToolCall{{ID: "1", Name: "test", Arguments: "{}"}},
			},
			expectErr: true,
			errMsg:    "tool message cannot have tool calls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.message.Validate()

			if tt.expectErr {
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

func TestCompletionRequest_Validate(t *testing.T) {
	tests := []struct {
		name      string
		request   CompletionRequest
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid request",
			request: CompletionRequest{
				Model:       "gpt-4",
				Messages:    []Message{NewUserMessage("test")},
				Temperature: 0.7,
				MaxTokens:   100,
				TopP:        0.9,
			},
			expectErr: false,
		},
		{
			name: "missing model",
			request: CompletionRequest{
				Messages: []Message{NewUserMessage("test")},
			},
			expectErr: true,
			errMsg:    "model is required",
		},
		{
			name: "missing messages",
			request: CompletionRequest{
				Model:    "gpt-4",
				Messages: []Message{},
			},
			expectErr: true,
			errMsg:    "at least one message is required",
		},
		{
			name: "invalid message",
			request: CompletionRequest{
				Model: "gpt-4",
				Messages: []Message{
					{Role: RoleUser}, // missing content
				},
			},
			expectErr: true,
			errMsg:    "message 0",
		},
		{
			name: "temperature too low",
			request: CompletionRequest{
				Model:       "gpt-4",
				Messages:    []Message{NewUserMessage("test")},
				Temperature: -0.1,
			},
			expectErr: true,
			errMsg:    "temperature must be between 0 and 1",
		},
		{
			name: "temperature too high",
			request: CompletionRequest{
				Model:       "gpt-4",
				Messages:    []Message{NewUserMessage("test")},
				Temperature: 1.1,
			},
			expectErr: true,
			errMsg:    "temperature must be between 0 and 1",
		},
		{
			name: "top_p too low",
			request: CompletionRequest{
				Model:    "gpt-4",
				Messages: []Message{NewUserMessage("test")},
				TopP:     -0.1,
			},
			expectErr: true,
			errMsg:    "top_p must be between 0 and 1",
		},
		{
			name: "top_p too high",
			request: CompletionRequest{
				Model:    "gpt-4",
				Messages: []Message{NewUserMessage("test")},
				TopP:     1.1,
			},
			expectErr: true,
			errMsg:    "top_p must be between 0 and 1",
		},
		{
			name: "negative max_tokens",
			request: CompletionRequest{
				Model:     "gpt-4",
				Messages:  []Message{NewUserMessage("test")},
				MaxTokens: -1,
			},
			expectErr: true,
			errMsg:    "max_tokens must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()

			if tt.expectErr {
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

func TestCompletionRequest_WithMetadata(t *testing.T) {
	req := CompletionRequest{
		Model:    "gpt-4",
		Messages: []Message{NewUserMessage("test")},
	}

	req = req.WithMetadata("key1", "value1")
	req = req.WithMetadata("key2", 123)

	assert.Equal(t, "value1", req.Metadata["key1"])
	assert.Equal(t, 123, req.Metadata["key2"])
}

func TestFinishReason_String(t *testing.T) {
	tests := []struct {
		reason   FinishReason
		expected string
	}{
		{FinishReasonStop, "stop"},
		{FinishReasonLength, "length"},
		{FinishReasonToolCalls, "tool_calls"},
		{FinishReasonContentFilter, "content_filter"},
		{FinishReasonError, "error"},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.reason.String())
		})
	}
}

func TestFinishReason_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		reason   FinishReason
		expected bool
	}{
		{"valid stop", FinishReasonStop, true},
		{"valid length", FinishReasonLength, true},
		{"valid tool_calls", FinishReasonToolCalls, true},
		{"valid content_filter", FinishReasonContentFilter, true},
		{"valid error", FinishReasonError, true},
		{"invalid empty", FinishReason(""), false},
		{"invalid unknown", FinishReason("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.reason.IsValid())
		})
	}
}
