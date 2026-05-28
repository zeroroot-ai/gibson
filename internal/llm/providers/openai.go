package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	einoopenai "github.com/cloudwego/eino-ext/components/model/openai"
	einoschema "github.com/cloudwego/eino/schema"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
)

// OpenAIProvider implements LLMProvider for OpenAI's GPT models using the
// Eino framework. Every code path — including structured output — goes through
// the single Eino ChatModel; structured output injects OpenAI's native
// response_format via a per-call request-payload modifier, so there is no
// hand-rolled HTTP client and no second code path to maintain.
type OpenAIProvider struct {
	model  *einoopenai.ChatModel
	config llm.ProviderConfig
}

// NewOpenAIProvider creates a new OpenAI provider
func NewOpenAIProvider(cfg llm.ProviderConfig) (*OpenAIProvider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}

	if apiKey == "" {
		return nil, llm.NewAuthError("openai", nil)
	}

	ctx := context.Background()
	model, err := einoopenai.NewChatModel(ctx, &einoopenai.ChatModelConfig{
		APIKey:  apiKey,
		Model:   cfg.DefaultModel,
		BaseURL: cfg.BaseURL,
	})
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}

	return &OpenAIProvider{
		model:  model,
		config: cfg,
	}, nil
}

// Name returns the provider name
func (p *OpenAIProvider) Name() string {
	return "openai"
}

// Models returns information about available models
func (p *OpenAIProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	models := []llm.ModelInfo{
		{
			Name:          "gpt-4-turbo",
			ContextWindow: 128000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "gpt-4",
			ContextWindow: 8192,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools"},
		},
		{
			Name:          "gpt-3.5-turbo",
			ContextWindow: 16385,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "json_mode"},
		},
	}
	return models, nil
}

// Complete sends a completion request
func (p *OpenAIProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *OpenAIProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *OpenAIProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}
	return streamToChannel(sr, func(e error) error { return llm.TranslateError("openai", e) }), nil
}

// Health checks the provider health
func (p *OpenAIProvider) Health(ctx context.Context) types.HealthStatus {
	req := llm.CompletionRequest{
		Model: p.config.DefaultModel,
		Messages: []llm.Message{
			llm.NewUserMessage("test"),
		},
		MaxTokens: 1,
	}

	_, err := p.Complete(ctx, req)
	if err != nil {
		return types.NewHealthStatus(types.HealthStateUnhealthy, err.Error())
	}

	return types.NewHealthStatus(types.HealthStateHealthy, "")
}

// SupportsStructuredOutput returns true for json_object and json_schema formats.
// OpenAI supports both natively via the response_format parameter.
func (p *OpenAIProvider) SupportsStructuredOutput(format types.ResponseFormatType) bool {
	return format == types.ResponseFormatJSONObject || format == types.ResponseFormatJSONSchema
}

// CompleteStructured performs a completion with OpenAI's native response_format.
// It goes through the same Eino ChatModel as Complete; the response_format field
// is injected into the serialized request via Eino's WithRequestPayloadModifier
// option, so structured output shares one code path with regular completions.
// For json_schema format it sets response_format: {type: "json_schema", json_schema: {...}};
// for json_object format it sets response_format: {type: "json_object"}.
func (p *OpenAIProvider) CompleteStructured(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if req.ResponseFormat == nil {
		return nil, llm.NewStructuredOutputError("complete", "openai", "", llm.ErrSchemaRequiredSentinel)
	}

	// Validate the response format
	if err := req.ResponseFormat.Validate(); err != nil {
		return nil, llm.NewInvalidRequestError(fmt.Sprintf("invalid response format: %v", err))
	}

	// Check if we support this format type
	if !p.SupportsStructuredOutput(req.ResponseFormat.Type) {
		return nil, llm.NewStructuredOutputError("complete", "openai", "",
			fmt.Errorf("unsupported format type: %s", req.ResponseFormat.Type))
	}

	responseFormat, err := buildResponseFormat(req.ResponseFormat)
	if err != nil {
		return nil, err
	}

	opts := buildEinoOptions(req)
	opts = append(opts, einoopenai.WithRequestPayloadModifier(injectResponseFormat(responseFormat)))

	out, err := p.model.Generate(ctx, toEinoMessages(req.Messages), opts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}

	resp := fromEinoMessage(out, req.Model)

	// Parse the returned JSON so consumers receive StructuredData / RawJSON.
	rawJSON := resp.Message.Content
	if rawJSON != "" {
		var structuredData any
		if err := json.Unmarshal([]byte(rawJSON), &structuredData); err != nil {
			return nil, llm.NewParseError("openai", rawJSON, 0, err)
		}
		resp.StructuredData = structuredData
		resp.RawJSON = rawJSON
	}

	return resp, nil
}

// buildResponseFormat builds OpenAI's response_format object from a Gibson
// ResponseFormat. The result is marshalled into the request payload by
// injectResponseFormat.
func buildResponseFormat(rf *types.ResponseFormat) (map[string]any, error) {
	switch rf.Type {
	case types.ResponseFormatJSONObject:
		return map[string]any{"type": "json_object"}, nil
	case types.ResponseFormatJSONSchema:
		schemaMap, err := jsonSchemaToMap(rf.Schema)
		if err != nil {
			return nil, llm.NewInvalidRequestError(fmt.Sprintf("invalid schema: %v", err))
		}
		return map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   rf.Name,
				"schema": schemaMap,
				"strict": rf.Strict,
			},
		}, nil
	default:
		return nil, llm.NewStructuredOutputError("complete", "openai", "",
			fmt.Errorf("unsupported format type: %s", rf.Type))
	}
}

// injectResponseFormat returns an Eino request-payload modifier that adds the
// OpenAI response_format field to the serialized chat-completions request.
// Eino still performs the HTTP call; this only augments the outgoing body.
func injectResponseFormat(responseFormat map[string]any) einoopenai.RequestPayloadModifier {
	return func(_ context.Context, _ []*einoschema.Message, rawBody []byte) ([]byte, error) {
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(rawBody, &payload); err != nil {
			return nil, fmt.Errorf("openai: decode request payload: %w", err)
		}
		rf, err := json.Marshal(responseFormat)
		if err != nil {
			return nil, fmt.Errorf("openai: encode response_format: %w", err)
		}
		payload["response_format"] = rf
		return json.Marshal(payload)
	}
}

// jsonSchemaToMap converts JSONSchema to map[string]interface{} for OpenAI API
func jsonSchemaToMap(schema *types.JSONSchema) (map[string]interface{}, error) {
	if schema == nil {
		return nil, fmt.Errorf("schema is nil")
	}

	// Marshal to JSON then unmarshal to map
	data, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}
