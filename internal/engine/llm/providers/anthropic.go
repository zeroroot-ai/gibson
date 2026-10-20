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
	"sync"

	einoclaude "github.com/cloudwego/eino-ext/components/model/claude"
	einomodel "github.com/cloudwego/eino/components/model"
	einoschema "github.com/cloudwego/eino/schema"

	"github.com/zeroroot-ai/gibson/internal/engine/llm"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
)

// AnthropicProvider implements LLMProvider for Anthropic's Claude models
// using the Eino framework.
type AnthropicProvider struct {
	config llm.ProviderConfig
	// name is the provider name reported to the registry and to error
	// translation. Anthropic's models reach a tenant through four routes —
	// the Anthropic API, Amazon Bedrock, Google Vertex and Microsoft Foundry
	// — and three of them drive the same Claude client with a different
	// credential (ADR-0119). They are one provider with three
	// constructors, not three copies of the completion path. Empty means
	// "anthropic".
	name string

	// buildChat makes the Claude client for one model. The client library
	// refuses to build without a model, so a client exists per model: the
	// request model, else the saved default model.
	buildChat func(ctx context.Context, model string) (*einoclaude.ChatModel, error)
	chatMu    sync.Mutex
	chats     map[string]*einoclaude.ChatModel

	// list makes the model list call of the route. It is nil on a route with
	// no list call (Foundry).
	list  func(ctx context.Context) ([]llm.ModelInfo, error)
	cache modelCache
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
	if cfg.BaseURL != "" {
		if err := validateLLMEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
			return nil, err
		}
		baseURL = cfg.BaseURL
	}
	client, err := withCustomHeaders(guardedHTTPClient(cfg), cfg.Extra[llm.CustomHeadersKey])
	if err != nil {
		return nil, fmt.Errorf("construct the anthropic provider: %w", llm.NewAuthError("anthropic", err))
	}

	p := &AnthropicProvider{config: cfg, name: string(llm.ProviderAnthropic)}
	p.buildChat = func(ctx context.Context, model string) (*einoclaude.ChatModel, error) {
		claudeCfg := &einoclaude.Config{APIKey: apiKey, Model: model, HTTPClient: client}
		if cfg.BaseURL != "" {
			claudeCfg.BaseURL = &baseURL
		}
		return einoclaude.NewChatModel(ctx, claudeCfg)
	}
	p.list = func(ctx context.Context) ([]llm.ModelInfo, error) {
		return listAnthropicModels(ctx, client, p.Name(), baseURL, apiKey)
	}
	if err := p.seedDefaultChat(context.Background(), "anthropic"); err != nil {
		return nil, err
	}
	return p, nil
}

// seedDefaultChat builds the client for the saved default model at
// construction, so a bad config is refused when it is built and not on the
// first request. With no saved model nothing is built: the credential test
// names none, and a request names its own.
func (p *AnthropicProvider) seedDefaultChat(ctx context.Context, label string) error {
	if p.config.DefaultModel == "" {
		return nil
	}
	if _, err := p.chatModel(ctx, ""); err != nil {
		return fmt.Errorf("construct the %s provider: %w", label, err)
	}
	return nil
}

// NewVertexProvider creates a Claude provider that reaches the models through
// Google Vertex (ADR-0119, the third login shape). The credential is
// a Google service-account JSON the tenant configured, plus the project and the
// region. It drives the same Claude client as the Anthropic route.
//
// The chat client is built from the service-account JSON of the config and from
// nothing else. A config with no service-account JSON is refused. The
// Application Default Credentials of the daemon are never a credential of a
// tenant, so the client must never look for them.
func NewVertexProvider(ctx context.Context, cfg llm.ProviderConfig) (*AnthropicProvider, error) {
	return newVertexProvider(ctx, cfg, serviceAccountToken)
}

// newVertexProvider is NewVertexProvider with the token source injected, so a
// test can mint a fixed token.
func newVertexProvider(ctx context.Context, cfg llm.ProviderConfig, token vertexTokenFunc) (*AnthropicProvider, error) {
	project := cfg.Extra["vertex_project_id"]
	region := cfg.Extra["vertex_region"]
	if project == "" || region == "" {
		return nil, fmt.Errorf("construct the vertex provider: %w", llm.NewAuthError(string(llm.ProviderVertex),
			errors.New("vertex_project_id and vertex_region are both required")))
	}
	serviceAccount := cfg.Extra["google_application_credentials_json"]
	if serviceAccount == "" {
		return nil, fmt.Errorf("construct the vertex provider: %w", llm.NewAuthError(string(llm.ProviderVertex),
			errors.New("google_application_credentials_json is required: the daemon's own Google credentials are never used")))
	}
	if cfg.BaseURL != "" {
		if err := validateLLMEndpoint(cfg.BaseURL, cfg.AllowPrivateEndpoint); err != nil {
			return nil, err
		}
	}
	client := guardedHTTPClient(cfg)

	p := &AnthropicProvider{config: cfg, name: string(llm.ProviderVertex)}
	p.buildChat = func(ctx context.Context, model string) (*einoclaude.ChatModel, error) {
		return newVertexChatModel(ctx, project, region, model, serviceAccount, client)
	}
	p.list = func(ctx context.Context) ([]llm.ModelInfo, error) {
		return listVertexModels(ctx, client, vertexListBase(cfg.BaseURL, region), project,
			cfg.Extra["google_application_credentials_json"], token)
	}
	if err := p.seedDefaultChat(ctx, "vertex"); err != nil {
		return nil, err
	}
	return p, nil
}

// newVertexChatModel builds the Vertex-backed Claude client from the service
// account JSON of the tenant. With the JSON set, the client builds its
// credentials in memory and never looks for Application Default Credentials.
func newVertexChatModel(
	ctx context.Context, project, region, modelID, serviceAccount string, client *http.Client,
) (*einoclaude.ChatModel, error) {
	if serviceAccount == "" {
		return nil, llm.NewAuthError(string(llm.ProviderVertex), errors.New("no service account JSON"))
	}
	model, err := einoclaude.NewChatModel(ctx, &einoclaude.Config{
		ByVertex:                 true,
		VertexProjectID:          project,
		VertexRegion:             region,
		VertexServiceAccountJSON: []byte(serviceAccount),
		Model:                    modelID,
		HTTPClient:               client,
	})
	if err != nil {
		return nil, fmt.Errorf("build the vertex client: %w", llm.TranslateError(string(llm.ProviderVertex), err))
	}
	return model, nil
}

// NewFoundryProvider creates a Claude provider that reaches the models through
// Microsoft Foundry (ADR-0119). Foundry serves the Anthropic API
// shape at a per-resource endpoint, so it is the Anthropic client pointed at
// that endpoint with the tenant's Foundry key.
//
// Foundry has no model list call: its Models API is not supported (see
// https://platform.claude.com/docs/en/build-with-claude/claude-in-microsoft-foundry,
// "Claude features not supported"). The model name is the deployment name that
// the person typed, so the credential test completes one token against it.
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
	p := &AnthropicProvider{config: cfg, name: string(llm.ProviderFoundry)}
	p.buildChat = func(ctx context.Context, model string) (*einoclaude.ChatModel, error) {
		return einoclaude.NewChatModel(ctx, &einoclaude.Config{
			APIKey:     apiKey,
			BaseURL:    &baseURL,
			Model:      model,
			HTTPClient: client,
		})
	}
	if err := p.seedDefaultChat(ctx, "foundry"); err != nil {
		return nil, err
	}
	return p, nil
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

// chatModel returns the Claude client for the model. The request model wins,
// then the saved default model. With neither it fails with a clear error.
func (p *AnthropicProvider) chatModel(ctx context.Context, requestModel string) (*einoclaude.ChatModel, error) {
	model := firstNonEmpty(requestModel, p.config.DefaultModel)
	if model == "" {
		return nil, fmt.Errorf("choose a model: %w", llm.NewInvalidInputError(p.Name(),
			"no model: the request names none and no default model is saved for this provider"))
	}
	p.chatMu.Lock()
	defer p.chatMu.Unlock()
	if m, ok := p.chats[model]; ok {
		return m, nil
	}
	m, err := p.buildChat(ctx, model)
	if err != nil {
		return nil, fmt.Errorf("build the claude client: %w", llm.TranslateError(p.Name(), err))
	}
	if p.chats == nil {
		p.chats = make(map[string]*einoclaude.ChatModel)
	}
	p.chats[model] = m
	return m, nil
}

// DefaultModel returns the default model saved for this provider, or "".
func (p *AnthropicProvider) DefaultModel() string { return p.config.DefaultModel }

// Name returns the provider name.
func (p *AnthropicProvider) Name() string {
	if p.name == "" {
		return string(llm.ProviderAnthropic)
	}
	return p.name
}

// Models returns the models of the account from the list call of the route.
// A route with no list call returns llm.ErrModelListUnsupported.
func (p *AnthropicProvider) Models(ctx context.Context) ([]llm.ModelInfo, error) {
	if p.list == nil {
		return nil, fmt.Errorf("list models: %w", llm.ErrModelListUnsupported)
	}
	return p.cache.get(ctx, p.Name(), p.list)
}

// ProbeModel checks the credentials with a one-token completion against the
// named model. The credential test uses it on a route with no list call.
func (p *AnthropicProvider) ProbeModel(ctx context.Context, model string) error {
	_, err := p.Complete(ctx, llm.CompletionRequest{
		Model:     model,
		Messages:  []llm.Message{llm.NewUserMessage("ping")},
		MaxTokens: 1,
	})
	return err
}

// listAnthropicModels calls GET {base}/v1/models (see
// https://docs.anthropic.com/en/api/models-list). It follows has_more and
// last_id until the list ends.
func listAnthropicModels(ctx context.Context, client *http.Client, provider, base, key string) ([]llm.ModelInfo, error) {
	header := http.Header{}
	header.Set("x-api-key", key)
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
		endpoint := strings.TrimRight(base, "/") + "/v1/models?" + q.Encode()
		if err := getJSON(ctx, client, provider, endpoint, header, &page); err != nil {
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
}

// Complete sends a completion request
func (p *AnthropicProvider) Complete(ctx context.Context, req llm.CompletionRequest) (*llm.CompletionResponse, error) {
	chat, chatErr := p.chatModel(ctx, req.Model)
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
	chat, chatErr := p.chatModel(ctx, req.Model)
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
	chat, chatErr := p.chatModel(ctx, req.Model)
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

	chat, chatErr := p.chatModel(ctx, req.Model)
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

// DefaultModelContextWindow returns the context window stored with the saved
// default model, or 0 when none is stored.
func (p *AnthropicProvider) DefaultModelContextWindow() int {
	return p.config.DefaultModelContextWindow
}
