// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

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
	// credential (ADR-0119). They are one provider with three
	// constructors, not three copies of the completion path. Empty means
	// "anthropic".
	name string

	// listClient, listBase and listKey drive the model list call
	// (GET {listBase}/v1/models). listBase is empty on the Vertex route,
	// which has no such call.
	listClient *http.Client
	listBase   string
	listKey    string
	cache      modelCache
}

// anthropicVersionHeader is the API version that the list call sends.
const anthropicVersionHeader = "2023-06-01"

// defaultAnthropicBaseURL is the Anthropic API root when the config sets no
// base URL.
const defaultAnthropicBaseURL = "https://api.anthropic.com"

// NewAnthropicProvider creates a new Anthropic provider.
//
// The credential comes from cfg.APIKey — the caller's own key, which the
// tenant provider resolver took from the secrets broker. A config with no
// key is rejected: the daemon's environment is never a credential source.
func NewAnthropicProvider(cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	apiKey := cfg.APIKey

	if apiKey == "" {
		return nil, llm.NewAuthError("anthropic", nil)
	}

	baseURL := defaultAnthropicBaseURL
	claudeCfg := &einoclaude.Config{
		APIKey: apiKey,
		Model:  cfg.DefaultModel,
	}
	if cfg.BaseURL != "" {
		if err := validateLLMEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
			return nil, err
		}
		baseURL = cfg.BaseURL
		claudeCfg.BaseURL = &baseURL
	}
	client := guardedHTTPClient(cfg)
	claudeCfg.HTTPClient = client

	// The client library refuses to build without a model. The credential test
	// names none, so the client stays nil and only the model list call works.
	var model *einoclaude.ChatModel
	if claudeCfg.Model != "" {
		var err error
		model, err = einoclaude.NewChatModel(context.Background(), claudeCfg)
		if err != nil {
			return nil, fmt.Errorf("construct the anthropic provider: %w", llm.TranslateError("anthropic", err))
		}
	}

	return &AnthropicProvider{
		model:      model,
		config:     cfg,
		name:       string(llm.ProviderAnthropic),
		listClient: client,
		listBase:   baseURL,
		listKey:    apiKey,
	}, nil
}

// NewVertexProvider creates a Claude provider that reaches the models through
// Google Vertex (ADR-0119, the third login shape). The credential is
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
	project := cfg.Extra["vertex_project_id"]
	region := cfg.Extra["vertex_region"]
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
// Microsoft Foundry (ADR-0119). Foundry serves the Anthropic API
// shape at a per-resource endpoint, so it is the Anthropic client pointed at
// that endpoint with the tenant's Foundry key.
func NewFoundryProvider(ctx context.Context, cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	apiKey := firstNonEmpty(cfg.Extra["foundry_api_key"], cfg.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("construct the foundry provider: %w", llm.NewAuthError(string(llm.ProviderFoundry), nil))
	}
	resource := cfg.Extra["foundry_resource"]
	baseURL := cfg.BaseURL
	if baseURL == "" {
		if resource == "" {
			return nil, fmt.Errorf("construct the foundry provider: %w", llm.NewAuthError(string(llm.ProviderFoundry),
				errors.New("foundry_resource is required when no base_url is configured")))
		}
		baseURL = "https://" + resource + ".services.ai.azure.com/anthropic"
	}

	client := guardedHTTPClient(cfg)
	var model *einoclaude.ChatModel
	if cfg.DefaultModel != "" {
		var err error
		model, err = einoclaude.NewChatModel(ctx, &einoclaude.Config{
			APIKey:     apiKey,
			BaseURL:    &baseURL,
			Model:      cfg.DefaultModel,
			HTTPClient: client,
		})
		if err != nil {
			return nil, fmt.Errorf("construct the foundry provider: %w", llm.TranslateError(string(llm.ProviderFoundry), err))
		}
	}
	return &AnthropicProvider{
		model:      model,
		config:     cfg,
		name:       string(llm.ProviderFoundry),
		listClient: client,
		listBase:   baseURL,
		listKey:    apiKey,
	}, nil
}

// VertexCredentialSchema is the form schema for a Google Vertex provider.
func VertexCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "vertex_project_id", Label: "Google Cloud Project ID", Required: true, Help: "The project the Vertex models are served from.", Type: llm.FieldText},
		{Key: "vertex_region", Label: "Vertex Region", Required: true, Placeholder: "us-east5", Type: llm.FieldRegion},
		{Key: "google_application_credentials_json", Label: "Service Account JSON", Required: true, Secret: true, Help: "The whole service-account key document. It is written to a file inside the sandbox, never on the daemon.", Type: llm.FieldPassword},
	}
}

// FoundryCredentialSchema is the form schema for a Microsoft Foundry provider.
func FoundryCredentialSchema() []llm.CredentialField {
	return []llm.CredentialField{
		{Key: "foundry_api_key", Label: "Foundry API Key", Required: true, Secret: true, Type: llm.FieldPassword},
		{Key: "foundry_resource", Label: "Foundry Resource Name", Required: true, Help: "The resource that serves the endpoint, e.g. my-resource in my-resource.services.ai.azure.com.", Type: llm.FieldText},
	}
}

// Name returns the provider name.
// chatModel returns the Claude client. It is nil when the config names no
// default model: the credential test builds such a provider, because the model
// list call needs no model.
func (p *AnthropicProvider) chatModel() (*einoclaude.ChatModel, error) {
	if p.model == nil {
		return nil, fmt.Errorf("complete: %w", llm.NewInvalidInputError(p.Name(), "no model is configured for this provider"))
	}
	return p.model, nil
}

// Name returns the provider name.
func (p *AnthropicProvider) Name() string {
	if p.name == "" {
		return string(llm.ProviderAnthropic)
	}
	return p.name
}

// Models asks the Anthropic list endpoint (GET {base}/v1/models) for the models
// of the configured account. It follows has_more and last_id until the list
// ends. The Vertex route has no such call, so it returns an error.
func (p *AnthropicProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	if p.listBase == "" {
		return nil, fmt.Errorf("list models: %w", llm.NewProviderError(p.Name(), errors.New("this provider route has no model list call")))
	}
	return p.cache.get(func() ([]llm.ModelInfo, error) {
		header := http.Header{}
		header.Set("x-api-key", p.listKey)
		header.Set("anthropic-version", anthropicVersionHeader)

		var models []llm.ModelInfo
		afterID := ""
		for range maxModelListPages {
			q := url.Values{"limit": {"1000"}}
			if afterID != "" {
				q.Set("after_id", afterID)
			}
			var page struct {
				Data []struct {
					ID             string `json:"id"`
					MaxInputTokens int    `json:"max_input_tokens"`
					MaxTokens      int    `json:"max_tokens"`
					Capabilities   *struct {
						ImageInput *struct {
							Supported bool `json:"supported"`
						} `json:"image_input"`
					} `json:"capabilities"`
				} `json:"data"`
				HasMore bool   `json:"has_more"`
				LastID  string `json:"last_id"`
			}
			endpoint := strings.TrimRight(p.listBase, "/") + "/v1/models?" + q.Encode()
			if err := getJSON(ctx, p.listClient, p.Name(), endpoint, header, &page); err != nil {
				return nil, err
			}
			for _, m := range page.Data {
				if m.ID == "" {
					continue
				}
				info := llm.ModelInfo{Name: m.ID, ContextWindow: m.MaxInputTokens, MaxOutput: m.MaxTokens, Features: []string{"chat"}}
				if c := m.Capabilities; c != nil && c.ImageInput != nil && c.ImageInput.Supported {
					info.Features = append(info.Features, "vision")
				}
				models = append(models, info)
			}
			if !page.HasMore || page.LastID == "" || page.LastID == afterID {
				return models, nil
			}
			afterID = page.LastID
		}
		return models, nil
	})
}

// Complete sends a completion request
func (p *AnthropicProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	chat, chatErr := p.chatModel()
	if chatErr != nil {
		return nil, chatErr
	}
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	out, err := chat.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// CompleteWithTools sends a completion request with tool definitions
func (p *AnthropicProvider) CompleteWithTools(ctx context.Context, req llm.CompletionRequest, tools []llm.ToolDef) (*llm.CompletionResponse, error) {
	chat, chatErr := p.chatModel()
	if chatErr != nil {
		return nil, chatErr
	}
	msgs := toEinoMessages(req.Messages)
	opts, err := buildEinoOptionsWithTools(req, tools)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	out, err := chat.Generate(ctx, msgs, opts...)
	if err != nil {
		return nil, llm.TranslateError("anthropic", err)
	}
	return fromEinoMessage(out, req.Model), nil
}

// Stream sends a streaming completion request
func (p *AnthropicProvider) Stream(ctx context.Context, req llm.CompletionRequest) (<-chan llm.StreamChunk, error) {
	chat, chatErr := p.chatModel()
	if chatErr != nil {
		return nil, chatErr
	}
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	sr, err := chat.Stream(ctx, msgs, opts...)
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

	chat, chatErr := p.chatModel()
	if chatErr != nil {
		return nil, chatErr
	}
	msgs := toEinoMessages(req.Messages)
	opts := buildEinoOptions(req)
	opts = append(opts,
		einomodel.WithTools([]*einoschema.ToolInfo{toolInfo}),
		einomodel.WithToolChoice(einoschema.ToolChoiceForced, toolDef.Name),
	)
	out, err := chat.Generate(ctx, msgs, opts...)
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
