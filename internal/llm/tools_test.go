package llm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/sdk/schema"
)

func TestToolDef_Validate(t *testing.T) {
	tests := []struct {
		name      string
		tool      ToolDef
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid tool",
			tool: ToolDef{
				Name:        "get_weather",
				Description: "Get weather information",
				Parameters: schema.JSON{
					Type: "object",
				},
			},
			expectErr: false,
		},
		{
			name: "missing name",
			tool: ToolDef{
				Description: "Get weather information",
				Parameters:  schema.JSON{Type: "object"},
			},
			expectErr: true,
			errMsg:    "tool name is required",
		},
		{
			name: "missing description",
			tool: ToolDef{
				Name:       "get_weather",
				Parameters: schema.JSON{Type: "object"},
			},
			expectErr: true,
			errMsg:    "tool description is required",
		},
		{
			name: "invalid parameters type",
			tool: ToolDef{
				Name:        "get_weather",
				Description: "Get weather information",
				Parameters: schema.JSON{
					Type: "string",
				},
			},
			expectErr: true,
			errMsg:    "tool parameters must be an object schema",
		},
		{
			name: "empty parameters type (valid)",
			tool: ToolDef{
				Name:        "get_weather",
				Description: "Get weather information",
				Parameters:  schema.JSON{},
			},
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.tool.Validate()

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

func TestToolCall_ParseArguments(t *testing.T) {
	type WeatherArgs struct {
		Location string `json:"location"`
		Unit     string `json:"unit"`
	}

	tests := []struct {
		name      string
		toolCall  ToolCall
		expectErr bool
		validate  func(t *testing.T, args WeatherArgs)
	}{
		{
			name: "valid arguments",
			toolCall: ToolCall{
				ID:        "call-123",
				Name:      "get_weather",
				Arguments: `{"location":"San Francisco","unit":"celsius"}`,
			},
			expectErr: false,
			validate: func(t *testing.T, args WeatherArgs) {
				assert.Equal(t, "San Francisco", args.Location)
				assert.Equal(t, "celsius", args.Unit)
			},
		},
		{
			name: "empty arguments",
			toolCall: ToolCall{
				ID:        "call-123",
				Name:      "get_weather",
				Arguments: "",
			},
			expectErr: true,
		},
		{
			name: "invalid JSON",
			toolCall: ToolCall{
				ID:        "call-123",
				Name:      "get_weather",
				Arguments: `{"invalid":}`,
			},
			expectErr: true,
		},
		{
			name: "mismatched type",
			toolCall: ToolCall{
				ID:        "call-123",
				Name:      "get_weather",
				Arguments: `{"location":123,"unit":"celsius"}`,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args WeatherArgs
			err := tt.toolCall.ParseArguments(&args)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, args)
				}
			}
		})
	}
}

func TestToolCall_Validate(t *testing.T) {
	tests := []struct {
		name      string
		toolCall  ToolCall
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid tool call",
			toolCall: ToolCall{
				ID:        "call-123",
				Type:      "function",
				Name:      "get_weather",
				Arguments: `{"location":"SF"}`,
			},
			expectErr: false,
		},
		{
			name: "missing ID",
			toolCall: ToolCall{
				Name:      "get_weather",
				Arguments: `{"location":"SF"}`,
			},
			expectErr: true,
			errMsg:    "tool call ID is required",
		},
		{
			name: "missing name",
			toolCall: ToolCall{
				ID:        "call-123",
				Arguments: `{"location":"SF"}`,
			},
			expectErr: true,
			errMsg:    "tool call name is required",
		},
		{
			name: "missing arguments",
			toolCall: ToolCall{
				ID:   "call-123",
				Name: "get_weather",
			},
			expectErr: true,
			errMsg:    "tool call arguments are required",
		},
		{
			name: "invalid JSON arguments",
			toolCall: ToolCall{
				ID:        "call-123",
				Name:      "get_weather",
				Arguments: `{invalid}`,
			},
			expectErr: true,
			errMsg:    "tool call arguments must be valid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.toolCall.Validate()

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

func TestNewToolResult(t *testing.T) {
	result := NewToolResult("call-123", "Weather is sunny")

	assert.Equal(t, "call-123", result.ToolCallID)
	assert.Equal(t, "Weather is sunny", result.Content)
	assert.False(t, result.IsError)
}

func TestNewToolError(t *testing.T) {
	result := NewToolError("call-123", "API error")

	assert.Equal(t, "call-123", result.ToolCallID)
	assert.Equal(t, "API error", result.Content)
	assert.True(t, result.IsError)
}

func TestToolResult_Validate(t *testing.T) {
	tests := []struct {
		name      string
		result    ToolResult
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid result",
			result: ToolResult{
				ToolCallID: "call-123",
				Content:    "result",
			},
			expectErr: false,
		},
		{
			name: "missing tool call ID",
			result: ToolResult{
				Content: "result",
			},
			expectErr: true,
			errMsg:    "tool call ID is required",
		},
		{
			name: "missing content",
			result: ToolResult{
				ToolCallID: "call-123",
			},
			expectErr: true,
			errMsg:    "tool result content is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.Validate()

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

func TestNewToolDef(t *testing.T) {
	params := schema.JSON{
		Type: "object",
		Properties: map[string]schema.JSON{
			"location": {Type: "string", Description: "The location"},
		},
		Required: []string{"location"},
	}

	tool := NewToolDef("get_weather", "Get weather information", params)

	assert.Equal(t, "get_weather", tool.Name)
	assert.Equal(t, "Get weather information", tool.Description)
	assert.Equal(t, "object", tool.Parameters.Type)
	assert.NotNil(t, tool.Parameters.Properties)
}

func TestNewToolDef_EnsuresObjectType(t *testing.T) {
	// Create a schema without Type set
	params := schema.JSON{
		Properties: map[string]schema.JSON{
			"location": {Type: "string", Description: "The location"},
		},
	}

	tool := NewToolDef("get_weather", "Get weather information", params)

	// Should automatically set Type to "object"
	assert.Equal(t, "object", tool.Parameters.Type)
}
