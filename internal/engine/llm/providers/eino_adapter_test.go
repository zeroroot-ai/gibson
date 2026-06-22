package providers

import (
	"testing"

	einoschema "github.com/cloudwego/eino/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	sdkschema "github.com/zeroroot-ai/sdk/schema"
)

// ---------------------------------------------------------------------------
// toEinoMessages
// ---------------------------------------------------------------------------

func TestToEinoMessages_RoleMapping(t *testing.T) {
	tests := []struct {
		role     llm.Role
		wantRole einoschema.RoleType
	}{
		{llm.RoleSystem, einoschema.System},
		{llm.RoleUser, einoschema.User},
		{llm.RoleAssistant, einoschema.Assistant},
		{llm.RoleTool, einoschema.Tool},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			msgs := toEinoMessages([]llm.Message{{Role: tt.role, Content: "hello"}})
			require.Len(t, msgs, 1)
			assert.Equal(t, tt.wantRole, msgs[0].Role)
			assert.Equal(t, "hello", msgs[0].Content)
		})
	}
}

func TestToEinoMessages_UnknownRoleFallsBackToUser(t *testing.T) {
	msgs := toEinoMessages([]llm.Message{{Role: "bogus", Content: "x"}})
	require.Len(t, msgs, 1)
	assert.Equal(t, einoschema.User, msgs[0].Role)
}

func TestToEinoMessages_ToolCallID(t *testing.T) {
	msg := llm.Message{Role: llm.RoleTool, Content: "result", ToolCallID: "call-42"}
	out := toEinoMessages([]llm.Message{msg})
	require.Len(t, out, 1)
	assert.Equal(t, "call-42", out[0].ToolCallID)
}

func TestToEinoMessages_AssistantWithToolCalls(t *testing.T) {
	msg := llm.Message{
		Role:    llm.RoleAssistant,
		Content: "",
		ToolCalls: []llm.ToolCall{
			{ID: "tc1", Name: "my_fn", Arguments: `{"x":1}`},
		},
	}
	out := toEinoMessages([]llm.Message{msg})
	require.Len(t, out, 1)
	require.Len(t, out[0].ToolCalls, 1)
	assert.Equal(t, "tc1", out[0].ToolCalls[0].ID)
	assert.Equal(t, "my_fn", out[0].ToolCalls[0].Function.Name)
	assert.Equal(t, `{"x":1}`, out[0].ToolCalls[0].Function.Arguments)
}

// ---------------------------------------------------------------------------
// fromEinoMessage
// ---------------------------------------------------------------------------

func TestFromEinoMessage_NilReturnsEmpty(t *testing.T) {
	resp := fromEinoMessage(nil, "test-model")
	require.NotNil(t, resp)
	assert.Equal(t, "test-model", resp.Model)
	assert.Empty(t, resp.Message.Content)
}

func TestFromEinoMessage_TextContent(t *testing.T) {
	msg := &einoschema.Message{
		Role:    einoschema.Assistant,
		Content: "hello world",
	}
	resp := fromEinoMessage(msg, "gpt-4")
	assert.Equal(t, "hello world", resp.Message.Content)
	assert.Equal(t, llm.RoleAssistant, resp.Message.Role)
	assert.Equal(t, "gpt-4", resp.Model)
	assert.Equal(t, llm.FinishReasonStop, resp.FinishReason)
}

func TestFromEinoMessage_TokenUsage(t *testing.T) {
	msg := &einoschema.Message{
		Role:    einoschema.Assistant,
		Content: "hi",
		ResponseMeta: &einoschema.ResponseMeta{
			FinishReason: "stop",
			Usage: &einoschema.TokenUsage{
				PromptTokens:     10,
				CompletionTokens: 5,
				TotalTokens:      15,
			},
		},
	}
	resp := fromEinoMessage(msg, "claude")
	assert.Equal(t, 10, resp.Usage.PromptTokens)
	assert.Equal(t, 5, resp.Usage.CompletionTokens)
	assert.Equal(t, 15, resp.Usage.TotalTokens)
	assert.Equal(t, llm.FinishReasonStop, resp.FinishReason)
}

func TestFromEinoMessage_ToolCalls(t *testing.T) {
	msg := &einoschema.Message{
		Role: einoschema.Assistant,
		ToolCalls: []einoschema.ToolCall{
			{ID: "tc1", Function: einoschema.FunctionCall{Name: "fn", Arguments: `{}`}},
		},
		ResponseMeta: &einoschema.ResponseMeta{FinishReason: "tool_calls"},
	}
	resp := fromEinoMessage(msg, "gpt-4o")
	require.Len(t, resp.Message.ToolCalls, 1)
	assert.Equal(t, "tc1", resp.Message.ToolCalls[0].ID)
	assert.Equal(t, "fn", resp.Message.ToolCalls[0].Name)
	assert.Equal(t, llm.FinishReasonToolCalls, resp.FinishReason)
}

func TestFromEinoMessage_FinishReasonMapping(t *testing.T) {
	cases := []struct {
		eino string
		want llm.FinishReason
	}{
		{"stop", llm.FinishReasonStop},
		{"end_turn", llm.FinishReasonStop},
		{"length", llm.FinishReasonLength},
		{"max_tokens", llm.FinishReasonLength},
		{"tool_calls", llm.FinishReasonToolCalls},
		{"tool_use", llm.FinishReasonToolCalls},
		{"content_filter", llm.FinishReasonContentFilter},
		{"unknown_future_value", llm.FinishReasonStop},
	}
	for _, c := range cases {
		t.Run(c.eino, func(t *testing.T) {
			got := finishReasonFromEino(c.eino, llm.FinishReasonStop)
			assert.Equal(t, c.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// toEinoToolInfos
// ---------------------------------------------------------------------------

func TestToEinoToolInfos_Empty(t *testing.T) {
	out, err := toEinoToolInfos(nil)
	require.NoError(t, err)
	assert.Nil(t, out)
}

func TestToEinoToolInfos_BasicTool(t *testing.T) {
	tool := llm.ToolDef{
		Name:        "get_weather",
		Description: "Get current weather",
		Parameters: sdkschema.JSON{
			Type: "object",
			Properties: map[string]sdkschema.JSON{
				"location": {Type: "string", Description: "City name"},
			},
			Required: []string{"location"},
		},
	}
	out, err := toEinoToolInfos([]llm.ToolDef{tool})
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "get_weather", out[0].Name)
	assert.Equal(t, "Get current weather", out[0].Desc)
	assert.NotNil(t, out[0].ParamsOneOf)
}

func TestToEinoToolInfos_MultipleTools(t *testing.T) {
	tools := []llm.ToolDef{
		{Name: "fn1", Description: "first", Parameters: sdkschema.JSON{Type: "object"}},
		{Name: "fn2", Description: "second", Parameters: sdkschema.JSON{Type: "object"}},
	}
	out, err := toEinoToolInfos(tools)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, "fn1", out[0].Name)
	assert.Equal(t, "fn2", out[1].Name)
}
