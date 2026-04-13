package providers

import (
	"context"
	"os"
	"testing"

	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/schema"
)

func TestAnthropicDirectClient_CompleteWithForcedTool(t *testing.T) {
	// Skip if no API key
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set")
	}

	client := NewAnthropicDirectClient(apiKey)

	// Create a simple tool definition
	tool := llm.ToolDef{
		Name:        "test_response",
		Description: "Provide a structured response",
		Parameters: schema.JSON{
			Type: "object",
			Properties: map[string]schema.JSON{
				"message": {
					Type:        "string",
					Description: "A test message",
				},
				"confidence": {
					Type:        "number",
					Description: "Confidence level from 0 to 1",
				},
			},
			Required: []string{"message", "confidence"},
		},
	}

	req := llm.CompletionRequest{
		Model: "claude-sonnet-4-5-20250929",
		Messages: []llm.Message{
			llm.NewSystemMessage("You are a helpful assistant that provides structured responses."),
			llm.NewUserMessage("Say hello and give me a confidence rating."),
		},
		MaxTokens: 1024,
	}

	resp, err := client.CompleteWithForcedTool(context.Background(), req, tool)
	if err != nil {
		t.Fatalf("CompleteWithForcedTool failed: %v", err)
	}

	// Verify we got a tool call back
	if len(resp.Message.ToolCalls) == 0 {
		t.Fatal("Expected at least one tool call in response")
	}

	toolCall := resp.Message.ToolCalls[0]
	if toolCall.Name != "test_response" {
		t.Errorf("Expected tool name 'test_response', got '%s'", toolCall.Name)
	}

	if toolCall.Arguments == "" {
		t.Error("Expected non-empty tool arguments")
	}

	t.Logf("Tool call ID: %s", toolCall.ID)
	t.Logf("Tool call arguments: %s", toolCall.Arguments)
	t.Logf("Finish reason: %s", resp.FinishReason)
	t.Logf("Token usage: prompt=%d, completion=%d", resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
}

func TestAnthropicProvider_CompleteStructured(t *testing.T) {
	// Skip if no API key
	apiKey := os.Getenv("ANTHROPIC_API_KEY")
	if apiKey == "" {
		t.Skip("ANTHROPIC_API_KEY not set")
	}

	// Create provider
	cfg := llm.ProviderConfig{
		Type:         "anthropic",
		APIKey:       apiKey,
		DefaultModel: "claude-sonnet-4-5-20250929",
	}

	provider, err := NewAnthropicProvider(cfg)
	if err != nil {
		t.Fatalf("Failed to create provider: %v", err)
	}

	// Create a structured request
	req := llm.CompletionRequest{
		Model: "claude-sonnet-4-5-20250929",
		Messages: []llm.Message{
			llm.NewSystemMessage("You are a helpful assistant."),
			llm.NewUserMessage("Analyze this IP: 192.168.1.1"),
		},
		MaxTokens: 1024,
		ResponseFormat: &types.ResponseFormat{
			Type: types.ResponseFormatJSONSchema,
			Name: "ip_analysis",
			Schema: &types.JSONSchema{
				Type: "object",
				Properties: map[string]*types.JSONSchema{
					"ip_address": {
						Type:        "string",
						Description: "The IP address analyzed",
					},
					"is_private": {
						Type:        "boolean",
						Description: "Whether this is a private IP address",
					},
					"network_class": {
						Type:        "string",
						Description: "The network class (A, B, C, etc.)",
					},
				},
				Required: []string{"ip_address", "is_private"},
			},
		},
	}

	resp, err := provider.CompleteStructured(context.Background(), req)
	if err != nil {
		t.Fatalf("CompleteStructured failed: %v", err)
	}

	if resp.RawJSON == "" {
		t.Error("Expected non-empty RawJSON")
	}

	if resp.StructuredData == nil {
		t.Error("Expected non-nil StructuredData")
	}

	t.Logf("Raw JSON response: %s", resp.RawJSON)
	t.Logf("Structured data: %+v", resp.StructuredData)
}
