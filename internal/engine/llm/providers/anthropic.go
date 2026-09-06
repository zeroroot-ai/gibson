// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	einoclaude "github.com/cloudwego/eino-ext/components/model/claude"
	einomodel "github.com/cloudwego/eino/components/model"
	einoschema "github.com/cloudwego/eino/schema"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// AnthropicProvider implements LLMProvider for Anthropic's Claude models
// using the Eino framework.
type AnthropicProvider struct {
	model  *einoclaude.ChatModel
	config llm.ProviderConfig
	// name is the provider name reported to the registry and to error
	// translation. Anthropic's models reach a tenant through four routes —
	// the Anthropic API, Amazon Bedrock, Google Vertex and Microsoft Foundry
	// — and three of them drive the same Claude client with a different
	// credential (ADR-0019 decision 4). They are one provider with three
	// constructors, not three copies of the completion path. Empty means
	// "anthropic".
	name string
}

// NewAnthropicProvider creates a new Anthropic provider.
//
// The credential comes from cfg.APIKey — the caller's own key. The
// ANTHROPIC_API_KEY environment variable is consulted only when the dev
// env-var fallback is explicitly enabled (see devEnvCredential); otherwise a
// config with no key is rejected rather than quietly constructed on the
// daemon's ambient key.
func NewAnthropicProvider(cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	apiKey := cfg.APIKey
	if apiKey == "" {
		apiKey = devEnvCredential("ANTHROPIC_API_KEY")
	}

	if apiKey == "" {
		return nil, llm.NewAuthError("anthropic", nil)
	}

	ctx := context.Background()
	model, err := einoclaude.NewChatModel(ctx, &einoclaude.Config{
		APIKey:     apiKey,
		Model:      cfg.DefaultModel,
		HTTPClient: guardedHTTPClient(cfg),
	})
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}

	return &AnthropicProvider{
		model:  model,
		config: cfg,
		name:   string(llm.ProviderAnthropic),
	}, nil
}

// NewVertexProvider creates a Claude provider that reaches the models through
// Google Vertex (ADR-0019 decision 4, the third login shape). The credential is
// a Google service-account JSON the tenant configured, plus the project and the
// region. It drives the same Claude client as the Anthropic route.
//
// The service-account JSON reaches the Google auth library the way that library
// reads it: from a file named by GOOGLE_APPLICATION_CREDENTIALS. The daemon
// never writes that file — a sandboxed Claude Code member's driver does, from
// the variable the launcher injects. In the daemon the credential is expected
// to be present in the ambient environment already, so a config that names
// neither is refused rather than constructed on whatever the pod happens to
// carry.
func NewVertexProvider(ctx context.Context, cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	project := firstNonEmpty(cfg.Extra["vertex_project_id"], devEnvCredential("ANTHROPIC_VERTEX_PROJECT_ID"))
	region := firstNonEmpty(cfg.Extra["vertex_region"], devEnvCredential("CLOUD_ML_REGION"))
	if project == "" || region == "" {
		return nil, fmt.Errorf("construct the vertex provider: %w", llm.NewAuthError(string(llm.ProviderVertex),
			errors.New("vertex_project_id and vertex_region are both required")))
	}

	model, err := newVertexChatModel(ctx, project, region, cfg)
	if err != nil {
		return nil, err
	}
	return &AnthropicProvider{model: model, config: cfg, name: string(llm.ProviderVertex)}, nil
}

// newVertexChatModel builds the Vertex-backed Claude client.
//
// It exists to contain a panic. The Google auth the Vertex client uses resolves
// Application Default Credentials eagerly and PANICS when it finds none — so a
// tenant that configured Vertex on a daemon with no reachable Google credential
// would take the process down rather than have its launch refused. The recover
// is at this one boundary and turns the panic into the same auth error every
// other provider returns.
func newVertexChatModel(ctx context.Context, project, region string, cfg llm.ProviderConfig) (model *einoclaude.ChatModel, err error) {
	defer func() {
		if r := recover(); r != nil {
			model = nil
			err = fmt.Errorf("construct the vertex provider: %w",
				llm.NewAuthError(string(llm.ProviderVertex),
					fmt.Errorf("google application default credentials are not available: %v", r)))
		}
	}()
	model, err = einoclaude.NewChatModel(ctx, &einoclaude.Config{
		ByVertex:        true,
		VertexProjectID: project,
		VertexRegion:    region,
		Model:           cfg.DefaultModel,
		HTTPClient:      guardedHTTPClient(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("construct the vertex provider: %w", llm.TranslateError(string(llm.ProviderVertex), err))
	}
	return model, nil
}

// NewFoundryProvider creates a Claude provider that reaches the models through
// Microsoft Foundry (ADR-0019 decision 4). Foundry serves the Anthropic API
// shape at a per-resource endpoint, so it is the Anthropic client pointed at
// that endpoint with the tenant's Foundry key.
func NewFoundryProvider(ctx context.Context, cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	apiKey := firstNonEmpty(cfg.Extra["foundry_api_key"], cfg.APIKey, devEnvCredential("ANTHROPIC_FOUNDRY_API_KEY"))
	if apiKey == "" {
		return nil, fmt.Errorf("construct the foundry provider: %w", llm.NewAuthError(string(llm.ProviderFoundry), nil))
	}
	resource := firstNonEmpty(cfg.Extra["foundry_resource"], devEnvCredential("ANTHROPIC_FOUNDRY_RESOURCE"))
	baseURL := cfg.BaseURL
	if baseURL == "" {
		if resource == "" {
			return nil, fmt.Errorf("construct the foundry provider: %w", llm.NewAuthError(string(llm.ProviderFoundry),
				errors.New("foundry_resource is required when no base_url is configured")))
		}
		baseURL = "https://" + resource + ".services.ai.azure.com/anthropic"
	}

	model, err := einoclaude.NewChatModel(ctx, &einoclaude.Config{
		APIKey:     apiKey,
		BaseURL:    &baseURL,
		Model:      cfg.DefaultModel,
		HTTPClient: guardedHTTPClient(cfg),
	})
	if err != nil {
		return nil, fmt.Errorf("construct the foundry provider: %w", llm.TranslateError(string(llm.ProviderFoundry), err))
	}
	return &AnthropicProvider{model: model, config: cfg, name: string(llm.ProviderFoundry)}, nil
}

// VertexCredentialSchema is the form schema for a Google Vertex provider.
func VertexCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "vertex_project_id", Label: "Google Cloud Project ID", Required: true, Help: "The project the Vertex models are served from."},
		{Key: "vertex_region", Label: "Vertex Region", Required: true, Placeholder: "us-east5"},
		{Key: "google_application_credentials_json", Label: "Service Account JSON", Required: true, Secret: true, Help: "The whole service-account key document. It is written to a file inside the sandbox, never on the daemon."},
	}
}

// FoundryCredentialSchema is the form schema for a Microsoft Foundry provider.
func FoundryCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "foundry_api_key", Label: "Foundry API Key", Required: true, Secret: true},
		{Key: "foundry_resource", Label: "Foundry Resource Name", Required: true, Help: "The resource that serves the endpoint, e.g. my-resource in my-resource.services.ai.azure.com."},
	}
}

// Name returns the provider name.
func (p *AnthropicProvider) Name() string {
	if p.name == "" {
		return string(llm.ProviderAnthropic)
	}
	return p.name
}

// Models returns information about available models
func (p *AnthropicProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	models := []llm.ModelInfo{
		{
			Name:          "claude-sonnet-4-5-20250929",
			ContextWindow: 200000,
			MaxOutput:     8192,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "claude-opus-4-20250514",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "claude-sonnet-4-20250514",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
		{
			Name:          "claude-3-haiku-20240307",
			ContextWindow: 200000,
			MaxOutput:     4096,
			Features:      []string{"chat", "streaming", "tools", "vision", "json_mode"},
		},
	}
	return models, nil
}

// Complete sends a completion request
func (p *AnthropicProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *AnthropicProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := p.model.Stream(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return streamToChannel(sr, req.Model, func(e error) error { return llm.TranslateError("anthropic", e) }), nil
}

// Health checks the provider health
func (p *AnthropicProvider) Health(ctx context.Context) types.HealthStatus {
	// Try a simple API call to check health
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

// SupportsStructuredOutput returns true for json_schema format.
// Anthropic uses the tool_use pattern which effectively supports json_schema.
func (p *AnthropicProvider) SupportsStructuredOutput(format types.ResponseFormatType) bool {
	return format == types.ResponseFormatJSONSchema
}

// CompleteStructured performs a completion using the tool_use pattern for structured output.
// It converts the response schema to a tool definition and forces the model to use it via
// Eino's forced tool choice, guaranteeing structured JSON output matching the schema.
//
// Requirement 2.1: Anthropic provider uses tool_use pattern with single tool matching response schema
func (p *AnthropicProvider) CompleteStructured(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	if req.ResponseFormat == nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", llm.ErrSchemaRequiredSentinel)
	}
	if err := req.ResponseFormat.Validate(); err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}
	if !p.SupportsStructuredOutput(req.ResponseFormat.Type) {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", llm.ErrStructuredOutputNotSupportedSentinel)
	}

	// Convert ResponseFormat schema to a ToolDef (tool_use pattern for structured output)
	toolDef := convertResponseFormatToTool(req.ResponseFormat)
	toolInfo, err := toEinoToolInfo(toolDef)
	if err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}

	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	opts = append(opts,
		einomodel.WithTools([]*einoschema.ToolInfo{toolInfo}),
		einomodel.WithToolChoice(einoschema.ToolChoiceForced, toolDef.Name),
	)
	out, err := p.model.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", "", err)
	}

	if len(out.ToolCalls) == 0 {
		return nil, llm.NewStructuredOutputError("complete", "anthropic", out.Content,
			fmt.Errorf("no tool call in response despite forced tool choice"))
	}
	rawJSON := out.ToolCalls[0].Function.Arguments
	var structuredData any
	if err := json.Unmarshal([]byte(rawJSON), &structuredData); err != nil {
		return nil, llm.NewParseError("anthropic", rawJSON, 0, err)
	}
	resp := fromEinoMessage(out, req.Model)
	resp.RawJSON = rawJSON
	resp.StructuredData = structuredData
	resp.Message.Content = rawJSON
	return resp, nil
}
