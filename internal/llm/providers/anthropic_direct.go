package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/zero-day-ai/gibson/internal/llm"
)

const (
	anthropicAPIURL     = "https://api.anthropic.com/v1/messages"
	anthropicAPIVersion = "2023-06-01"
)

// AnthropicDirectClient is a direct HTTP client for Anthropic's API
// that properly supports tools and tool_choice for structured output.
// This bypasses langchaingo which lacks tool_choice support.
type AnthropicDirectClient struct {
	apiKey     string
	httpClient *http.Client
}

// NewAnthropicDirectClient creates a new direct Anthropic client
func NewAnthropicDirectClient(apiKey string) *AnthropicDirectClient {
	if apiKey == "" {
		apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	return &AnthropicDirectClient{
		apiKey:     apiKey,
		httpClient: &http.Client{},
	}
}

// Anthropic API request/response types

// anthropicMessage represents a message in the Anthropic API format
type anthropicMessage struct {
	Role    string                 `json:"role"`
	Content []anthropicContentPart `json:"content"`
}

// anthropicContentPart represents a content part (text or tool_use)
type anthropicContentPart struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   string          `json:"content,omitempty"`
}

// anthropicTool represents a tool definition for Anthropic
type anthropicTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// anthropicToolChoice specifies which tool to use
type anthropicToolChoice struct {
	Type string `json:"type"`           // "auto", "any", or "tool"
	Name string `json:"name,omitempty"` // Only for type="tool"
}

// anthropicRequest is the request format for Anthropic's messages API
type anthropicRequest struct {
	Model       string               `json:"model"`
	MaxTokens   int                  `json:"max_tokens"`
	System      string               `json:"system,omitempty"`
	Messages    []anthropicMessage   `json:"messages"`
	Tools       []anthropicTool      `json:"tools,omitempty"`
	ToolChoice  *anthropicToolChoice `json:"tool_choice,omitempty"`
	Temperature *float64             `json:"temperature,omitempty"`
	TopP        *float64             `json:"top_p,omitempty"`
	StopSeqs    []string             `json:"stop_sequences,omitempty"`
}

// anthropicResponse is the response format from Anthropic's messages API
type anthropicResponse struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Role         string                 `json:"role"`
	Content      []anthropicContentPart `json:"content"`
	Model        string                 `json:"model"`
	StopReason   string                 `json:"stop_reason"`
	StopSequence string                 `json:"stop_sequence,omitempty"`
	Usage        anthropicUsage         `json:"usage"`
}

// anthropicUsage contains token usage information
type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// anthropicError is the error format from Anthropic's API
type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// anthropicErrorResponse wraps the error
type anthropicErrorResponse struct {
	Error anthropicError `json:"error"`
}

// CompleteWithForcedTool sends a completion request with tool_choice forcing a specific tool.
// This is the key method that langchaingo doesn't properly support.
func (c *AnthropicDirectClient) CompleteWithForcedTool(ctx context.Context, req llm.CompletionRequest, tool llm.ToolDef) (*llm.CompletionResponse, error) {
	if c.apiKey == "" {
		return nil, llm.NewAuthError("anthropic", nil)
	}

	// Build the request
	anthropicReq, err := c.buildRequest(req, tool)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// Make the HTTP request
	respBody, err := c.doRequest(ctx, anthropicReq)
	if err != nil {
		return nil, err
	}

	// Parse the response
	return c.parseResponse(respBody, req.Model)
}

// buildRequest constructs the Anthropic API request
func (c *AnthropicDirectClient) buildRequest(req llm.CompletionRequest, tool llm.ToolDef) (*anthropicRequest, error) {
	// Convert messages
	var system string
	messages := make([]anthropicMessage, 0, len(req.Messages))

	for _, msg := range req.Messages {
		switch msg.Role {
		case llm.RoleSystem:
			// Anthropic uses a separate system field
			system = msg.Content
		case llm.RoleUser:
			messages = append(messages, anthropicMessage{
				Role: "user",
				Content: []anthropicContentPart{
					{Type: "text", Text: msg.Content},
				},
			})
		case llm.RoleAssistant:
			messages = append(messages, anthropicMessage{
				Role: "assistant",
				Content: []anthropicContentPart{
					{Type: "text", Text: msg.Content},
				},
			})
		case llm.RoleTool:
			// Tool results are sent as user messages with tool_result content
			messages = append(messages, anthropicMessage{
				Role: "user",
				Content: []anthropicContentPart{
					{Type: "tool_result", ToolUseID: msg.Name, Content: msg.Content},
				},
			})
		}
	}

	// Convert tool parameters to JSON
	paramsJSON, err := json.Marshal(tool.Parameters)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tool parameters: %w", err)
	}

	// Build the anthropic tool
	anthropicTools := []anthropicTool{
		{
			Name:        tool.Name,
			Description: tool.Description,
			InputSchema: paramsJSON,
		},
	}

	// Build tool_choice to force this specific tool
	toolChoice := &anthropicToolChoice{
		Type: "tool",
		Name: tool.Name,
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 4096 // Default
	}

	anthropicReq := &anthropicRequest{
		Model:      req.Model,
		MaxTokens:  maxTokens,
		System:     system,
		Messages:   messages,
		Tools:      anthropicTools,
		ToolChoice: toolChoice,
		StopSeqs:   req.StopSequences,
	}

	if req.Temperature > 0 {
		temp := req.Temperature
		anthropicReq.Temperature = &temp
	}

	if req.TopP > 0 {
		topP := req.TopP
		anthropicReq.TopP = &topP
	}

	return anthropicReq, nil
}

// doRequest makes the HTTP request to Anthropic's API
func (c *AnthropicDirectClient) doRequest(ctx context.Context, anthropicReq *anthropicRequest) ([]byte, error) {
	reqBody, err := json.Marshal(anthropicReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", anthropicAPIURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Check for API errors
	if resp.StatusCode != http.StatusOK {
		var errResp anthropicErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("anthropic API error (%d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// parseResponse converts the Anthropic API response to Gibson's format
func (c *AnthropicDirectClient) parseResponse(body []byte, model string) (*llm.CompletionResponse, error) {
	var anthropicResp anthropicResponse
	if err := json.Unmarshal(body, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract content and tool calls
	var content string
	var toolCalls []llm.ToolCall

	for _, part := range anthropicResp.Content {
		switch part.Type {
		case "text":
			content = part.Text
		case "tool_use":
			// Convert the input to a string
			inputStr := string(part.Input)
			toolCalls = append(toolCalls, llm.ToolCall{
				ID:        part.ID,
				Type:      "function",
				Name:      part.Name,
				Arguments: inputStr,
			})
		}
	}

	// Determine finish reason
	finishReason := llm.FinishReasonStop
	switch anthropicResp.StopReason {
	case "end_turn", "stop":
		finishReason = llm.FinishReasonStop
	case "max_tokens":
		finishReason = llm.FinishReasonLength
	case "tool_use":
		finishReason = llm.FinishReasonToolCalls
	}

	return &llm.CompletionResponse{
		ID:    uuid.New().String(),
		Model: model,
		Message: llm.Message{
			Role:      llm.RoleAssistant,
			Content:   content,
			ToolCalls: toolCalls,
		},
		FinishReason: finishReason,
		Usage: llm.CompletionTokenUsage{
			PromptTokens:     anthropicResp.Usage.InputTokens,
			CompletionTokens: anthropicResp.Usage.OutputTokens,
			TotalTokens:      anthropicResp.Usage.InputTokens + anthropicResp.Usage.OutputTokens,
		},
	}, nil
}
