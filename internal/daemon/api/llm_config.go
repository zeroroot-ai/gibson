package api

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/llm/providers"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

const (
	// Redis key patterns for LLM provider configuration
	llmProviderKeyPrefix = "gibson:llm:provider:"
	llmProvidersSetKey   = "gibson:llm:providers"
	llmDefaultKey        = "gibson:llm:default"
)

// JSONStore provides JSON storage operations for the LLM config handler.
// This interface allows for mocking in tests where RedisJSON is not available.
type JSONStore interface {
	JSONSet(ctx context.Context, key, path string, value any) error
	JSONGet(ctx context.Context, key, path string, dest any) error
	JSONDel(ctx context.Context, key, path string) error
	Client() redis.UniversalClient
}

// LLMConfigHandler provides LLM provider configuration management for the daemon.
// It stores provider configs in Redis and uses the existing provider factory
// for connection testing.
type LLMConfigHandler struct {
	jsonStore         JSONStore
	credentialHandler *CredentialHandler
}

// NewLLMConfigHandler creates a new LLM config handler.
func NewLLMConfigHandler(stateClient *state.StateClient, credentialHandler *CredentialHandler) (*LLMConfigHandler, error) {
	if stateClient == nil {
		return nil, fmt.Errorf("state client cannot be nil")
	}
	if credentialHandler == nil {
		return nil, fmt.Errorf("credential handler cannot be nil")
	}

	return &LLMConfigHandler{
		jsonStore:         stateClient,
		credentialHandler: credentialHandler,
	}, nil
}

// NewLLMConfigHandlerWithStore creates a new LLM config handler with a custom JSON store.
// This is primarily used for testing with mock stores.
func NewLLMConfigHandlerWithStore(jsonStore JSONStore, credentialHandler *CredentialHandler) (*LLMConfigHandler, error) {
	if jsonStore == nil {
		return nil, fmt.Errorf("JSON store cannot be nil")
	}
	if credentialHandler == nil {
		return nil, fmt.Errorf("credential handler cannot be nil")
	}

	return &LLMConfigHandler{
		jsonStore:         jsonStore,
		credentialHandler: credentialHandler,
	}, nil
}

// ProviderConfigStored represents the provider configuration stored in Redis.
// It references credentials by name rather than embedding API keys.
type ProviderConfigStored struct {
	Name           string                 `json:"name"`
	Type           llm.ProviderType       `json:"type"`
	CredentialName string                 `json:"credential_name"` // Reference to credential by name
	BaseURL        string                 `json:"base_url,omitempty"`
	DefaultModel   string                 `json:"default_model"`
	Models         map[string]llm.ModelConfig `json:"models,omitempty"`
	Options        map[string]interface{} `json:"options,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// ProviderResponse is the response for provider operations.
type ProviderResponse struct {
	Name           string                 `json:"name"`
	Type           llm.ProviderType       `json:"type"`
	CredentialName string                 `json:"credential_name"`
	BaseURL        string                 `json:"base_url,omitempty"`
	DefaultModel   string                 `json:"default_model"`
	Models         map[string]llm.ModelConfig `json:"models,omitempty"`
	Options        map[string]interface{} `json:"options,omitempty"`
	IsDefault      bool                   `json:"is_default"`
	Health         *HealthInfo            `json:"health,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// HealthInfo contains provider health status.
type HealthInfo struct {
	State       types.HealthState `json:"state"`
	LastCheck   time.Time         `json:"last_check"`
	Message     string            `json:"message,omitempty"`
}

// ProviderCreateRequest contains the data needed to create a provider config.
type ProviderCreateRequest struct {
	Name           string
	Type           llm.ProviderType
	CredentialName string // Name of the credential containing the API key
	BaseURL        string
	DefaultModel   string
	Models         map[string]llm.ModelConfig
	Options        map[string]interface{}
}

// ProviderUpdateRequest contains the data for updating a provider config.
type ProviderUpdateRequest struct {
	Name           string // The provider name (used as key)
	Type           *llm.ProviderType
	CredentialName *string
	BaseURL        *string
	DefaultModel   *string
	Models         map[string]llm.ModelConfig
	Options        map[string]interface{}
}

// TestConnectionResult contains the result of a provider connection test.
type TestConnectionResult struct {
	Success   bool          `json:"success"`
	LatencyMs int64         `json:"latency_ms,omitempty"`
	Error     string        `json:"error,omitempty"`
	Model     string        `json:"model_tested,omitempty"`
}

// ListProviders returns all configured LLM providers.
func (h *LLMConfigHandler) ListProviders(ctx context.Context) ([]*ProviderResponse, error) {
	// Get all provider names from the set
	names, err := h.jsonStore.Client().SMembers(ctx, llmProvidersSetKey).Result()
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to list providers", err)
	}

	// Get default provider
	defaultProvider, _ := h.jsonStore.Client().Get(ctx, llmDefaultKey).Result()

	responses := make([]*ProviderResponse, 0, len(names))
	for _, name := range names {
		stored, err := h.getStored(ctx, name)
		if err != nil {
			continue // Skip providers that fail to load
		}

		responses = append(responses, h.toResponse(stored, name == defaultProvider))
	}

	return responses, nil
}

// GetProvider retrieves a provider configuration by name.
func (h *LLMConfigHandler) GetProvider(ctx context.Context, name string) (*ProviderResponse, error) {
	stored, err := h.getStored(ctx, name)
	if err != nil {
		return nil, err
	}

	defaultProvider, _ := h.jsonStore.Client().Get(ctx, llmDefaultKey).Result()
	return h.toResponse(stored, name == defaultProvider), nil
}

// CreateOrUpdateProvider creates or updates a provider configuration.
func (h *LLMConfigHandler) CreateOrUpdateProvider(ctx context.Context, req ProviderCreateRequest) (*ProviderResponse, error) {
	if req.Name == "" {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED, "provider name cannot be empty")
	}
	if req.CredentialName == "" {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED, "credential name cannot be empty")
	}
	if req.DefaultModel == "" {
		return nil, types.NewError(types.CONFIG_VALIDATION_FAILED, "default model cannot be empty")
	}

	// Verify the credential exists
	_, err := h.credentialHandler.GetByName(ctx, req.CredentialName)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "referenced credential not found", err)
	}

	now := time.Now()

	// Check if provider already exists
	existing, _ := h.getStored(ctx, req.Name)

	stored := &ProviderConfigStored{
		Name:           req.Name,
		Type:           req.Type,
		CredentialName: req.CredentialName,
		BaseURL:        req.BaseURL,
		DefaultModel:   req.DefaultModel,
		Models:         req.Models,
		Options:        req.Options,
		UpdatedAt:      now,
	}

	if existing != nil {
		stored.CreatedAt = existing.CreatedAt
	} else {
		stored.CreatedAt = now
	}

	// Store the provider config
	key := llmProviderKeyPrefix + req.Name
	if err := h.jsonStore.JSONSet(ctx, key, "$", stored); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to save provider config", err)
	}

	// Add to providers set
	if err := h.jsonStore.Client().SAdd(ctx, llmProvidersSetKey, req.Name).Err(); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to update providers set", err)
	}

	defaultProvider, _ := h.jsonStore.Client().Get(ctx, llmDefaultKey).Result()
	return h.toResponse(stored, req.Name == defaultProvider), nil
}

// UpdateProvider updates an existing provider configuration.
func (h *LLMConfigHandler) UpdateProvider(ctx context.Context, req ProviderUpdateRequest) (*ProviderResponse, error) {
	// Get existing provider
	stored, err := h.getStored(ctx, req.Name)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if req.Type != nil {
		stored.Type = *req.Type
	}
	if req.CredentialName != nil {
		// Verify the new credential exists
		_, err := h.credentialHandler.GetByName(ctx, *req.CredentialName)
		if err != nil {
			return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "referenced credential not found", err)
		}
		stored.CredentialName = *req.CredentialName
	}
	if req.BaseURL != nil {
		stored.BaseURL = *req.BaseURL
	}
	if req.DefaultModel != nil {
		stored.DefaultModel = *req.DefaultModel
	}
	if req.Models != nil {
		stored.Models = req.Models
	}
	if req.Options != nil {
		stored.Options = req.Options
	}
	stored.UpdatedAt = time.Now()

	// Save
	key := llmProviderKeyPrefix + req.Name
	if err := h.jsonStore.JSONSet(ctx, key, "$", stored); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to update provider config", err)
	}

	defaultProvider, _ := h.jsonStore.Client().Get(ctx, llmDefaultKey).Result()
	return h.toResponse(stored, req.Name == defaultProvider), nil
}

// DeleteProvider deletes a provider configuration.
func (h *LLMConfigHandler) DeleteProvider(ctx context.Context, name string) error {
	key := llmProviderKeyPrefix + name

	// Check if provider exists
	exists, err := h.jsonStore.Client().Exists(ctx, key).Result()
	if err != nil {
		return types.WrapError(types.DB_QUERY_FAILED, "failed to check provider existence", err)
	}
	if exists == 0 {
		return types.NewError(types.CONFIG_NOT_FOUND, fmt.Sprintf("provider not found: %s", name))
	}

	// Delete the provider config
	if err := h.jsonStore.JSONDel(ctx, key, "$"); err != nil {
		return types.WrapError(types.DB_QUERY_FAILED, "failed to delete provider config", err)
	}

	// Remove from providers set
	if err := h.jsonStore.Client().SRem(ctx, llmProvidersSetKey, name).Err(); err != nil {
		return types.WrapError(types.DB_QUERY_FAILED, "failed to update providers set", err)
	}

	// If this was the default, clear the default
	defaultProvider, _ := h.jsonStore.Client().Get(ctx, llmDefaultKey).Result()
	if defaultProvider == name {
		h.jsonStore.Client().Del(ctx, llmDefaultKey)
	}

	return nil
}

// SetDefaultProvider sets the default LLM provider.
func (h *LLMConfigHandler) SetDefaultProvider(ctx context.Context, name string) error {
	// Verify provider exists
	_, err := h.getStored(ctx, name)
	if err != nil {
		return err
	}

	if err := h.jsonStore.Client().Set(ctx, llmDefaultKey, name, 0).Err(); err != nil {
		return types.WrapError(types.DB_QUERY_FAILED, "failed to set default provider", err)
	}

	return nil
}

// GetDefaultProvider returns the default provider name.
func (h *LLMConfigHandler) GetDefaultProvider(ctx context.Context) (string, error) {
	name, err := h.jsonStore.Client().Get(ctx, llmDefaultKey).Result()
	if err != nil {
		return "", types.WrapError(types.CONFIG_NOT_FOUND, "no default provider set", err)
	}
	return name, nil
}

// TestConnection tests connectivity to a provider.
func (h *LLMConfigHandler) TestConnection(ctx context.Context, name string) (*TestConnectionResult, error) {
	// Get provider config
	stored, err := h.getStored(ctx, name)
	if err != nil {
		return nil, err
	}

	// Get decrypted API key
	_, apiKey, err := h.credentialHandler.GetDecrypted(ctx, stored.CredentialName)
	if err != nil {
		return &TestConnectionResult{
			Success: false,
			Error:   fmt.Sprintf("failed to get API key: %v", err),
		}, nil
	}

	// Build provider config
	providerConfig := llm.ProviderConfig{
		Type:         stored.Type,
		APIKey:       apiKey,
		BaseURL:      stored.BaseURL,
		DefaultModel: stored.DefaultModel,
		Models:       stored.Models,
		Options:      stored.Options,
	}

	// Create provider using factory
	provider, err := providers.NewProvider(providerConfig)
	if err != nil {
		return &TestConnectionResult{
			Success: false,
			Error:   fmt.Sprintf("failed to create provider: %v", err),
		}, nil
	}

	// Test with a simple completion
	start := time.Now()

	// Use a minimal test request
	req := llm.CompletionRequest{
		Model: stored.DefaultModel,
		Messages: []llm.Message{
			{Role: "user", Content: "Say 'ok'"},
		},
		MaxTokens: 10,
	}

	_, err = provider.Complete(ctx, req)

	latency := time.Since(start).Milliseconds()

	if err != nil {
		return &TestConnectionResult{
			Success:   false,
			LatencyMs: latency,
			Error:     fmt.Sprintf("connection test failed: %v", err),
			Model:     stored.DefaultModel,
		}, nil
	}

	return &TestConnectionResult{
		Success:   true,
		LatencyMs: latency,
		Model:     stored.DefaultModel,
	}, nil
}

// GetProviderHealth returns the health status of a provider.
func (h *LLMConfigHandler) GetProviderHealth(ctx context.Context, name string) (*HealthInfo, error) {
	result, err := h.TestConnection(ctx, name)
	if err != nil {
		return nil, err
	}

	health := &HealthInfo{
		LastCheck: time.Now(),
	}

	if result.Success {
		health.State = types.HealthStateHealthy
		health.Message = fmt.Sprintf("Connection successful, latency: %dms", result.LatencyMs)
	} else {
		health.State = types.HealthStateUnhealthy
		health.Message = result.Error
	}

	return health, nil
}

// getStored retrieves a provider config from Redis.
func (h *LLMConfigHandler) getStored(ctx context.Context, name string) (*ProviderConfigStored, error) {
	key := llmProviderKeyPrefix + name

	var stored ProviderConfigStored
	if err := h.jsonStore.JSONGet(ctx, key, "$", &stored); err != nil {
		return nil, types.NewError(types.CONFIG_NOT_FOUND, fmt.Sprintf("provider not found: %s", name))
	}

	return &stored, nil
}

// toResponse converts a stored config to a response.
func (h *LLMConfigHandler) toResponse(stored *ProviderConfigStored, isDefault bool) *ProviderResponse {
	return &ProviderResponse{
		Name:           stored.Name,
		Type:           stored.Type,
		CredentialName: stored.CredentialName,
		BaseURL:        stored.BaseURL,
		DefaultModel:   stored.DefaultModel,
		Models:         stored.Models,
		Options:        stored.Options,
		IsDefault:      isDefault,
		CreatedAt:      stored.CreatedAt,
		UpdatedAt:      stored.UpdatedAt,
	}
}

// GetProviderConfig builds an llm.ProviderConfig for use by agents.
// This retrieves the stored config and decrypts the API key.
func (h *LLMConfigHandler) GetProviderConfig(ctx context.Context, name string) (*llm.ProviderConfig, error) {
	stored, err := h.getStored(ctx, name)
	if err != nil {
		return nil, err
	}

	// Get decrypted API key
	_, apiKey, err := h.credentialHandler.GetDecrypted(ctx, stored.CredentialName)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "failed to get credential", err)
	}

	return &llm.ProviderConfig{
		Type:         stored.Type,
		APIKey:       apiKey,
		BaseURL:      stored.BaseURL,
		DefaultModel: stored.DefaultModel,
		Models:       stored.Models,
		Options:      stored.Options,
	}, nil
}

// ExportConfig exports the LLM configuration for use elsewhere.
// This is useful for integrating with existing config systems.
func (h *LLMConfigHandler) ExportConfig(ctx context.Context) (*llm.LLMConfig, error) {
	providerResponses, err := h.ListProviders(ctx)
	if err != nil {
		return nil, err
	}

	defaultProvider, _ := h.GetDefaultProvider(ctx)

	config := &llm.LLMConfig{
		DefaultProvider: defaultProvider,
		Providers:       make(map[string]llm.ProviderConfig),
	}

	for _, resp := range providerResponses {
		// Get the full config with decrypted key
		providerConfig, err := h.GetProviderConfig(ctx, resp.Name)
		if err != nil {
			continue // Skip providers with missing credentials
		}
		config.Providers[resp.Name] = *providerConfig
	}

	return config, nil
}

// Ensure provider models are serializable
var _ json.Marshaler = (*ProviderConfigStored)(nil)

func (p *ProviderConfigStored) MarshalJSON() ([]byte, error) {
	type Alias ProviderConfigStored
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(p),
	})
}
