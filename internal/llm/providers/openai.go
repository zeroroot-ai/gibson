package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/zeroroot-ai/gibson/internal/llm"
	"github.com/zeroroot-ai/gibson/internal/types"
	"github.com/zeroroot-ai/langchaingo/llms/openai"
)

// OpenAIProvider implements LLMProvider for OpenAI's GPT models
type OpenAIProvider struct {
	client     *openai.LLM
	config     llm.ProviderConfig
	httpClient *http.Client
	apiKey     string
	baseURL    string
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

	opts := []openai.Option{
		openai.WithToken(apiKey),
	}

	if cfg.DefaultModel != "" {
		opts = append(opts, openai.WithModel(cfg.DefaultModel))
	}

	if cfg.BaseURL != "" {
		opts = append(opts, openai.WithBaseURL(cfg.BaseURL))
	}

	client, err := openai.New(opts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}

	return &OpenAIProvider{
		client:     client,
		config:     cfg,
		httpClient: &http.Client{},
		apiKey:     apiKey,
		baseURL:    baseURL,
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
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptions(req)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *OpenAIProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	messages := toSchemaMessages(req.Messages)
	callOpts := buildCallOptionsWithTools(req, tools)

	resp, err := p.client.GenerateContent(ctx, messages, callOpts...)
	if err != nil {
		return nil, llm.TranslateError("openai", err)
	}

	return fromLangchainResponse(resp, req.Model), nil
}

// Stream sends a streaming completion request
func (p *OpenAIProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	chunkChan := make(chan llm.StreamChunk, 10)

	messages := toSchemaMessages(req.Messages)
	callOpts := buildStreamingCallOptions(req, func(ctx context.Context, chunk []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunkChan <- llm.StreamChunk{
			Delta: llm.StreamDelta{
				Content: string(chunk),
			},
		}:
			return nil
		}
	})

	go func() {
		defer close(chunkChan)
		_, err := p.client.GenerateContent(ctx, messages, callOpts...)
		if err != nil {
			chunkChan <- llm.StreamChunk{
				Error: llm.TranslateError("openai", err),
			}
		}
	}()

	return chunkChan, nil
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

// CompleteStructured performs a completion with response_format for structured output.
// This method uses OpenAI's native response_format parameter to enforce JSON output.
// For json_schema format, it sets response_format: {type: "json_schema", json_schema: {...}}
// For json_object format, it sets response_format: {type: "json_object"}
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

	// Use direct HTTP client for structured output as langchaingo doesn't support json_schema
	return p.completeStructuredDirect(ctx, req)
}

// openAIMessage represents an OpenAI API message
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIResponseFormat represents OpenAI's response_format parameter
type openAIResponseFormat struct {
	Type       string            `json:"type"`
	JSONSchema *openAIJSONSchema `json:"json_schema,omitempty"`
}

// openAIJSONSchema represents OpenAI's json_schema configuration
type openAIJSONSchema struct {
	Name   string                 `json:"name"`
	Schema map[string]interface{} `json:"schema"`
	Strict bool                   `json:"strict"`
}

// openAIRequest represents a direct OpenAI API request
type openAIRequest struct {
	Model          string                `json:"model"`
	Messages       []openAIMessage       `json:"messages"`
	Temperature    float64               `json:"temperature,omitempty"`
	MaxTokens      int                   `json:"max_tokens,omitempty"`
	TopP           float64               `json:"top_p,omitempty"`
	Stop           []string              `json:"stop,omitempty"`
	ResponseFormat *openAIResponseFormat `json:"response_format,omitempty"`
}

// openAIResponse represents a direct OpenAI API response
type openAIResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// openAIErrorResponse represents an OpenAI API error response
type openAIErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}

// completeStructuredDirect makes a direct HTTP call to OpenAI API with response_format
func (p *OpenAIProvider) completeStructuredDirect(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	// Convert Gibson messages to OpenAI format
	messages := make([]openAIMessage, 0, len(req.Messages))
	for _, msg := range req.Messages {
		messages = append(messages, openAIMessage{
			Role:    string(msg.Role),
			Content: msg.Content,
		})
	}

	// Build response_format parameter
	var responseFormat *openAIResponseFormat
	switch req.ResponseFormat.Type {
	case types.ResponseFormatJSONObject:
		responseFormat = &openAIResponseFormat{
			Type: "json_object",
		}
	case types.ResponseFormatJSONSchema:
		// Convert JSONSchema to map[string]interface{}
		schemaMap, err := jsonSchemaToMap(req.ResponseFormat.Schema)
		if err != nil {
			return nil, llm.NewInvalidRequestError(fmt.Sprintf("invalid schema: %v", err))
		}

		responseFormat = &openAIResponseFormat{
			Type: "json_schema",
			JSONSchema: &openAIJSONSchema{
				Name:   req.ResponseFormat.Name,
				Schema: schemaMap,
				Strict: req.ResponseFormat.Strict,
			},
		}
	}

	// Build OpenAI API request
	apiReq := openAIRequest{
		Model:          req.Model,
		Messages:       messages,
		Temperature:    req.Temperature,
		MaxTokens:      req.MaxTokens,
		TopP:           req.TopP,
		Stop:           req.StopSequences,
		ResponseFormat: responseFormat,
	}

	// Serialize request
	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, llm.NewInvalidRequestError(fmt.Sprintf("failed to marshal request: %v", err))
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL+"/chat/completions", bytes.NewReader(reqBody))
	if err != nil {
		return nil, llm.NewNetworkError("failed to create request", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	// Send request
	httpResp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, llm.NewNetworkError("failed to send request", err)
	}
	defer httpResp.Body.Close()

	// Read response body
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, llm.NewNetworkError("failed to read response", err)
	}

	// Check for error response
	if httpResp.StatusCode != http.StatusOK {
		var errResp openAIErrorResponse
		if err := json.Unmarshal(respBody, &errResp); err != nil {
			return nil, llm.NewCompletionError(fmt.Sprintf("API error (status %d): %s", httpResp.StatusCode, string(respBody)), nil)
		}
		return nil, llm.NewCompletionError(fmt.Sprintf("API error: %s (type: %s, code: %s)",
			errResp.Error.Message, errResp.Error.Type, errResp.Error.Code), nil)
	}

	// Parse successful response
	var apiResp openAIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, llm.NewParseError("openai", string(respBody), 0, err)
	}

	// Extract content
	if len(apiResp.Choices) == 0 {
		return nil, llm.NewCompletionError("no choices in response", nil)
	}

	choice := apiResp.Choices[0]
	rawJSON := choice.Message.Content

	// Parse JSON from content
	var structuredData interface{}
	if err := json.Unmarshal([]byte(rawJSON), &structuredData); err != nil {
		return nil, llm.NewParseError("openai", rawJSON, 0, err)
	}

	// Convert finish reason
	finishReason := llm.FinishReasonStop
	switch choice.FinishReason {
	case "stop":
		finishReason = llm.FinishReasonStop
	case "length", "max_tokens":
		finishReason = llm.FinishReasonLength
	case "content_filter":
		finishReason = llm.FinishReasonContentFilter
	}

	return &llm.CompletionResponse{
		ID:    apiResp.ID,
		Model: apiResp.Model,
		Message: llm.Message{
			Role:    llm.RoleAssistant,
			Content: rawJSON,
		},
		FinishReason:   finishReason,
		StructuredData: structuredData,
		RawJSON:        rawJSON,
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     apiResp.Usage.PromptTokens,
			CompletionTokens: apiResp.Usage.CompletionTokens,
			TotalTokens:      apiResp.Usage.TotalTokens,
		},
	}, nil
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
