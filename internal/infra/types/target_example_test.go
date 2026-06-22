package types_test

import (
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// Example_createTarget demonstrates creating a new target
func Example_createTarget() {
	target := types.NewTarget(
		"OpenAI GPT-4",
		"https://api.openai.com/v1/chat/completions",
		types.TargetTypeLLMAPI,
	)

	target.Provider = types.ProviderOpenAI
	target.Model = "gpt-4"
	target.AuthType = types.AuthTypeBearer
	target.Description = "OpenAI GPT-4 API endpoint"
	target.Tags = []string{"openai", "production"}
	target.Capabilities = []string{"chat", "completion"}

	// Validate the target
	if err := target.Validate(); err != nil {
		fmt.Printf("Validation failed: %v\n", err)
		return
	}

	fmt.Printf("Created target: %s\n", target.Name)
	fmt.Printf("Type: %s\n", target.Type)
	fmt.Printf("Provider: %s\n", target.Provider)
	fmt.Printf("Status: %s\n", target.Status)

	// Output:
	// Created target: OpenAI GPT-4
	// Type: llm_api
	// Provider: openai
	// Status: active
}

// Example_targetJSON demonstrates JSON serialization
func Example_targetJSON() {
	target := types.NewTarget(
		"Claude API",
		"https://api.anthropic.com/v1/messages",
		types.TargetTypeLLMAPI,
	)

	target.Provider = types.ProviderAnthropic
	target.Model = "claude-3-opus-20240229"
	target.AuthType = types.AuthTypeAPIKey

	// Marshal to JSON
	data, err := json.MarshalIndent(target, "", "  ")
	if err != nil {
		fmt.Printf("Marshal failed: %v\n", err)
		return
	}

	fmt.Printf("JSON representation:\n%s\n", string(data))
}

// Example_targetFilter demonstrates using filters
func Example_targetFilter() {
	// Create a filter for active OpenAI targets
	filter := types.NewTargetFilter().
		WithProvider(types.ProviderOpenAI).
		WithStatus(types.TargetStatusActive).
		WithType(string(types.TargetTypeLLMAPI)).
		WithTags([]string{"production"}).
		WithLimit(50).
		WithOffset(0)

	fmt.Printf("Provider filter: %s\n", *filter.Provider)
	fmt.Printf("Status filter: %s\n", *filter.Status)
	fmt.Printf("Type filter: %s\n", *filter.Type)
	fmt.Printf("Tags: %v\n", filter.Tags)
	fmt.Printf("Limit: %d, Offset: %d\n", filter.Limit, filter.Offset)

	// Output:
	// Provider filter: openai
	// Status filter: active
	// Type filter: llm_api
	// Tags: [production]
	// Limit: 50, Offset: 0
}

// Example_targetTypes demonstrates all target types
func Example_targetTypes() {
	types := []types.TargetType{
		types.TargetTypeLLMChat,
		types.TargetTypeLLMAPI,
		types.TargetTypeRAG,
		types.TargetTypeAgent,
		types.TargetTypeEmbedding,
		types.TargetTypeMultimodal,
	}

	fmt.Println("Available target types:")
	for _, t := range types {
		fmt.Printf("- %s\n", t)
	}

	// Output:
	// Available target types:
	// - llm_chat
	// - llm_api
	// - rag
	// - agent
	// - embedding
	// - multimodal
}

// Example_providers demonstrates all providers
func Example_providers() {
	providers := []types.Provider{
		types.ProviderOpenAI,
		types.ProviderAnthropic,
		types.ProviderGoogle,
		types.ProviderAzure,
		types.ProviderOllama,
		types.ProviderCustom,
	}

	fmt.Println("Available providers:")
	for _, p := range providers {
		fmt.Printf("- %s\n", p)
	}

	// Output:
	// Available providers:
	// - openai
	// - anthropic
	// - google
	// - azure
	// - ollama
	// - custom
}

// Example_authTypes demonstrates all auth types
func Example_authTypes() {
	authTypes := []types.AuthType{
		types.AuthTypeNone,
		types.AuthTypeAPIKey,
		types.AuthTypeBearer,
		types.AuthTypeBasic,
		types.AuthTypeOAuth,
	}

	fmt.Println("Available auth types:")
	for _, a := range authTypes {
		fmt.Printf("- %s\n", a)
	}

	// Output:
	// Available auth types:
	// - none
	// - api_key
	// - bearer
	// - basic
	// - oauth
}

// Example_ragTarget demonstrates creating a RAG target
func Example_ragTarget() {
	target := types.NewTarget(
		"Internal Knowledge Base",
		"https://rag.internal.com/api/query",
		types.TargetTypeRAG,
	)

	target.Provider = types.ProviderCustom
	target.AuthType = types.AuthTypeBearer
	target.Description = "Internal RAG system with company knowledge"
	target.Tags = []string{"internal", "rag", "knowledge-base"}
	target.Capabilities = []string{"semantic-search", "question-answering"}

	// Add custom configuration
	target.Config = map[string]interface{}{
		"retrieval_mode": "hybrid",
		"top_k":          5,
		"rerank":         true,
	}

	// Add custom headers
	target.Headers = map[string]string{
		"X-API-Version": "v2",
		"X-Client-ID":   "gibson-framework",
	}

	fmt.Printf("RAG Target: %s\n", target.Name)
	fmt.Printf("Type: %s\n", target.Type)
	fmt.Printf("Capabilities: %v\n", target.Capabilities)
	fmt.Printf("Config keys: %d\n", len(target.Config))
	fmt.Printf("Headers: %d\n", len(target.Headers))

	// Output:
	// RAG Target: Internal Knowledge Base
	// Type: rag
	// Capabilities: [semantic-search question-answering]
	// Config keys: 3
	// Headers: 2
}

// Example_agentTarget demonstrates creating an agent target
func Example_agentTarget() {
	target := types.NewTarget(
		"Code Assistant Agent",
		"https://agents.example.com/code-assistant",
		types.TargetTypeAgent,
	)

	target.Provider = types.ProviderCustom
	target.AuthType = types.AuthTypeOAuth
	target.Description = "Autonomous coding agent with tool access"
	target.Tags = []string{"agent", "code", "autonomous"}
	target.Capabilities = []string{
		"code-generation",
		"code-review",
		"debugging",
		"tool-use",
		"multi-step-reasoning",
	}

	fmt.Printf("Agent Target: %s\n", target.Name)
	fmt.Printf("Type: %s\n", target.Type)
	fmt.Printf("Number of capabilities: %d\n", len(target.Capabilities))

	// Output:
	// Agent Target: Code Assistant Agent
	// Type: agent
	// Number of capabilities: 5
}
