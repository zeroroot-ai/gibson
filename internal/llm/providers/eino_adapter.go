package providers

import (
	"encoding/json"
	"fmt"

	einomodel "github.com/cloudwego/eino/components/model"
	einoschema "github.com/cloudwego/eino/schema"
	einojsonschema "github.com/eino-contrib/jsonschema"
	"github.com/google/uuid"

	"github.com/zeroroot-ai/gibson/internal/llm"
)

// toEinoMessages converts Gibson messages to the Eino schema slice expected
// by every ChatModel.Generate / Stream call.
func toEinoMessages(msgs []llm.Message) []*einoschema.Message {
	out := make([]*einoschema.Message, 0, len(msgs))
	for _, m := range msgs {
		out = append(out, toEinoMessage(m))
	}
	return out
}

func toEinoMessage(m llm.Message) *einoschema.Message {
	switch m.Role {
	case llm.RoleSystem:
		return einoschema.SystemMessage(m.Content)
	case llm.RoleUser:
		return einoschema.UserMessage(m.Content)
	case llm.RoleAssistant:
		var toolCalls []einoschema.ToolCall
		for _, tc := range m.ToolCalls {
			toolCalls = append(toolCalls, toEinoToolCall(tc))
		}
		return einoschema.AssistantMessage(m.Content, toolCalls)
	case llm.RoleTool:
		return einoschema.ToolMessage(m.Content, m.ToolCallID)
	default:
		return einoschema.UserMessage(m.Content)
	}
}

func toEinoToolCall(tc llm.ToolCall) einoschema.ToolCall {
	return einoschema.ToolCall{
		ID:   tc.ID,
		Type: "function",
		Function: einoschema.FunctionCall{
			Name:      tc.Name,
			Arguments: tc.Arguments,
		},
	}
}

// fromEinoMessage converts an Eino response message to a Gibson CompletionResponse.
// model is the model identifier to embed in the response.
func fromEinoMessage(msg *einoschema.Message, model string) *llm.CompletionResponse {
	if msg == nil {
		return &llm.CompletionResponse{
			ID:    uuid.New().String(),
			Model: model,
		}
	}

	resp := &llm.CompletionResponse{
		ID:    uuid.New().String(),
		Model: model,
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: msg.Content,
		},
		FinishReason: llm.FinishReasonStop,
	}

	// Extract tool calls.
	if len(msg.ToolCalls) > 0 {
		resp.Message.ToolCalls = make([]llm.ToolCall, 0, len(msg.ToolCalls))
		for _, tc := range msg.ToolCalls {
			resp.Message.ToolCalls = append(resp.Message.ToolCalls, llm.ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
		}
		resp.FinishReason = llm.FinishReasonToolCalls
	}

	// Extract token usage and finish reason from ResponseMeta.
	if meta := msg.ResponseMeta; meta != nil {
		resp.FinishReason = finishReasonFromEino(meta.FinishReason, resp.FinishReason)
		if meta.Usage != nil {
			resp.Usage = llm.CompletionTokenUsage{
				PromptTokens:     meta.Usage.PromptTokens,
				CompletionTokens: meta.Usage.CompletionTokens,
				TotalTokens:      meta.Usage.TotalTokens,
			}
		}
	}

	return resp
}

func finishReasonFromEino(eino string, fallback llm.FinishReason) llm.FinishReason {
	switch eino {
	case "stop", "end_turn":
		return llm.FinishReasonStop
	case "length", "max_tokens":
		return llm.FinishReasonLength
	case "tool_calls", "tool_use":
		return llm.FinishReasonToolCalls
	case "content_filter":
		return llm.FinishReasonContentFilter
	case "":
		return fallback
	default:
		return llm.FinishReasonStop
	}
}

// toEinoToolInfos converts Gibson ToolDef slice to Eino ToolInfo slice.
func toEinoToolInfos(tools []llm.ToolDef) ([]*einoschema.ToolInfo, error) {
	if len(tools) == 0 {
		return nil, nil
	}
	out := make([]*einoschema.ToolInfo, 0, len(tools))
	for _, t := range tools {
		info, err := toEinoToolInfo(t)
		if err != nil {
			return nil, fmt.Errorf("tool %q: %w", t.Name, err)
		}
		out = append(out, info)
	}
	return out, nil
}

// toEinoToolInfo converts a single Gibson ToolDef to an Eino ToolInfo.
// The parameter schema is round-tripped through JSON so that our sdk/schema.JSON
// format (standard JSON Schema) maps cleanly into eino-contrib/jsonschema.Schema.
func toEinoToolInfo(tool llm.ToolDef) (*einoschema.ToolInfo, error) {
	raw, err := json.Marshal(tool.Parameters)
	if err != nil {
		return nil, fmt.Errorf("marshal parameters: %w", err)
	}
	var js einojsonschema.Schema
	if err := json.Unmarshal(raw, &js); err != nil {
		return nil, fmt.Errorf("unmarshal jsonschema: %w", err)
	}
	return &einoschema.ToolInfo{
		Name:        tool.Name,
		Desc:        tool.Description,
		ParamsOneOf: einoschema.NewParamsOneOfByJSONSchema(&js),
	}, nil
}

// accumulateStreamChunks reads all chunks from an Eino StreamReader and
// concatenates content into a single CompletionResponse. Used by providers
// that need a blocking Complete() on top of a streaming Eino client.
func accumulateStreamChunks(sr *einoschema.StreamReader[*einoschema.Message], model string) (*llm.CompletionResponse, error) {
	defer sr.Close()

	var combined einoschema.Message
	for {
		chunk, err := sr.Recv()
		if err != nil {
			// io.EOF signals normal end-of-stream; return what we have.
			if isEOF(err) {
				break
			}
			return nil, err
		}
		if chunk == nil {
			continue
		}
		combined.Content += chunk.Content
		combined.ToolCalls = append(combined.ToolCalls, chunk.ToolCalls...)
		if chunk.ResponseMeta != nil {
			combined.ResponseMeta = chunk.ResponseMeta
		}
	}
	return fromEinoMessage(&combined, model), nil
}

func isEOF(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return s == "EOF" || s == "io: read/write on closed pipe"
}

// buildEinoOptions converts per-call CompletionRequest parameters into Eino
// model options. Zero values are omitted so the model's own defaults apply.
func buildEinoOptions(req llm.CompletionRequest) []einomodel.Option {
	var opts []einomodel.Option
	if req.Model != "" {
		opts = append(opts, einomodel.WithModel(req.Model))
	}
	if req.Temperature != 0 {
		t := float32(req.Temperature)
		opts = append(opts, einomodel.WithTemperature(t))
	}
	if req.MaxTokens != 0 {
		opts = append(opts, einomodel.WithMaxTokens(req.MaxTokens))
	}
	if len(req.StopSequences) > 0 {
		opts = append(opts, einomodel.WithStop(req.StopSequences))
	}
	return opts
}

// buildEinoOptionsWithTools builds Eino options including tool definitions.
func buildEinoOptionsWithTools(req llm.CompletionRequest, tools []llm.ToolDef) ([]einomodel.Option, error) {
	opts := buildEinoOptions(req)
	toolInfos, err := toEinoToolInfos(tools)
	if err != nil {
		return nil, err
	}
	if len(toolInfos) > 0 {
		opts = append(opts, einomodel.WithTools(toolInfos))
	}
	return opts, nil
}

// streamToChannel drains an Eino StreamReader[*schema.Message] into a
// StreamChunk channel. translateErr maps raw Eino errors to Gibson errors;
// pass nil to use the identity function.
func streamToChannel(
	sr *einoschema.StreamReader[*einoschema.Message],
	translateErr func(error) error,
) <-chan llm.StreamChunk {
	if translateErr == nil {
		translateErr = func(e error) error { return e }
	}
	ch := make(chan llm.StreamChunk, 10)
	go func() {
		defer close(ch)
		defer sr.Close()
		for {
			chunk, err := sr.Recv()
			if isEOF(err) {
				return
			}
			if err != nil {
				ch <- llm.StreamChunk{Error: translateErr(err)}
				return
			}
			if chunk != nil && chunk.Content != "" {
				ch <- llm.StreamChunk{Delta: llm.StreamDelta{Content: chunk.Content}}
			}
		}
	}()
	return ch
}
