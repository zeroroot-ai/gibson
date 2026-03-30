package api

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/llm"
	"github.com/zero-day-ai/gibson/internal/state"
	"github.com/zero-day-ai/gibson/internal/types"
)

// mockJSONStore is a mock implementation of JSONStore for testing.
type mockJSONStore struct {
	mu     sync.RWMutex
	data   map[string][]byte
	client redis.UniversalClient
}

func newMockJSONStore(mr *miniredis.Miniredis) *mockJSONStore {
	return &mockJSONStore{
		data: make(map[string][]byte),
		client: redis.NewClient(&redis.Options{
			Addr: mr.Addr(),
		}),
	}
}

func (m *mockJSONStore) JSONSet(ctx context.Context, key, path string, value any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	m.data[key] = data

	// Also set a regular key so Exists() works
	m.client.Set(ctx, key, "1", 0)
	return nil
}

func (m *mockJSONStore) JSONGet(ctx context.Context, key, path string, dest any) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	data, ok := m.data[key]
	if !ok {
		return state.ErrNotFound
	}
	return json.Unmarshal(data, dest)
}

func (m *mockJSONStore) JSONDel(ctx context.Context, key, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.data, key)
	m.client.Del(ctx, key)
	return nil
}

func (m *mockJSONStore) Client() redis.UniversalClient {
	return m.client
}

// setupTestLLMConfigHandler creates a test LLM config handler with mock JSON store.
func setupTestLLMConfigHandler(t *testing.T) (*LLMConfigHandler, *CredentialHandler, *miniredis.Miniredis) {
	t.Helper()

	// Start miniredis
	mr, err := miniredis.Run()
	require.NoError(t, err)

	// Create mock JSON store
	jsonStore := newMockJSONStore(mr)

	// Create credential handler
	dao := newMockCredentialDAO()
	keyProvider := newMockKeyProvider()
	credHandler, err := NewCredentialHandler(dao, keyProvider)
	require.NoError(t, err)

	// Create LLM config handler with mock store
	handler, err := NewLLMConfigHandlerWithStore(jsonStore, credHandler)
	require.NoError(t, err)

	t.Cleanup(func() {
		jsonStore.client.Close()
		mr.Close()
	})

	return handler, credHandler, mr
}

func TestNewLLMConfigHandler(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()

	cfg := &state.Config{URL: "redis://" + mr.Addr()}
	stateClient, _ := state.NewStateClient(cfg)
	defer stateClient.Close()

	dao := newMockCredentialDAO()
	keyProvider := newMockKeyProvider()
	credHandler, _ := NewCredentialHandler(dao, keyProvider)

	t.Run("success", func(t *testing.T) {
		handler, err := NewLLMConfigHandler(stateClient, credHandler)
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})

	t.Run("nil state client", func(t *testing.T) {
		_, err := NewLLMConfigHandler(nil, credHandler)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "state client cannot be nil")
	})

	t.Run("nil credential handler", func(t *testing.T) {
		_, err := NewLLMConfigHandler(stateClient, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential handler cannot be nil")
	})
}

func TestLLMConfigHandler_CreateOrUpdateProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// First create a credential
		_, err := credHandler.Create(ctx, CredentialCreateRequest{
			Name:     "anthropic-key",
			Type:     types.CredentialTypeAPIKey,
			Provider: "anthropic",
			APIKey:   "sk-ant-api03-test",
		})
		require.NoError(t, err)

		// Create provider
		resp, err := handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name:           "anthropic",
			Type:           llm.ProviderAnthropic,
			CredentialName: "anthropic-key",
			DefaultModel:   "claude-sonnet-4-20250514",
		})
		require.NoError(t, err)
		assert.Equal(t, "anthropic", resp.Name)
		assert.Equal(t, llm.ProviderAnthropic, resp.Type)
		assert.Equal(t, "anthropic-key", resp.CredentialName)
		assert.Equal(t, "claude-sonnet-4-20250514", resp.DefaultModel)
	})

	t.Run("empty name", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		_, err := handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name:           "",
			Type:           llm.ProviderAnthropic,
			CredentialName: "test",
			DefaultModel:   "model",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("empty credential name", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		_, err := handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name:           "test",
			Type:           llm.ProviderAnthropic,
			CredentialName: "",
			DefaultModel:   "model",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential name cannot be empty")
	})

	t.Run("credential not found", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		_, err := handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name:           "test",
			Type:           llm.ProviderAnthropic,
			CredentialName: "nonexistent",
			DefaultModel:   "model",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "credential not found")
	})
}

func TestLLMConfigHandler_GetProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// Create credential
		_, err := credHandler.Create(ctx, CredentialCreateRequest{
			Name: "test-key", Type: types.CredentialTypeAPIKey, APIKey: "sk-test",
		})
		require.NoError(t, err)

		// Create provider
		_, err = handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name:           "test-provider",
			Type:           llm.ProviderOpenAI,
			CredentialName: "test-key",
			DefaultModel:   "gpt-4",
		})
		require.NoError(t, err)

		// Get provider
		resp, err := handler.GetProvider(ctx, "test-provider")
		require.NoError(t, err)
		assert.Equal(t, "test-provider", resp.Name)
		assert.Equal(t, llm.ProviderOpenAI, resp.Type)
	})

	t.Run("not found", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		_, err := handler.GetProvider(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestLLMConfigHandler_ListProviders(t *testing.T) {
	ctx := context.Background()

	t.Run("empty list", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		resp, err := handler.ListProviders(ctx)
		require.NoError(t, err)
		assert.Empty(t, resp)
	})

	t.Run("multiple providers", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// Create credentials
		credHandler.Create(ctx, CredentialCreateRequest{
			Name: "key1", Type: types.CredentialTypeAPIKey, APIKey: "sk-1",
		})
		credHandler.Create(ctx, CredentialCreateRequest{
			Name: "key2", Type: types.CredentialTypeAPIKey, APIKey: "sk-2",
		})

		// Create providers
		handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name: "provider1", Type: llm.ProviderAnthropic, CredentialName: "key1", DefaultModel: "model1",
		})
		handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name: "provider2", Type: llm.ProviderOpenAI, CredentialName: "key2", DefaultModel: "model2",
		})

		resp, err := handler.ListProviders(ctx)
		require.NoError(t, err)
		assert.Len(t, resp, 2)
	})
}

func TestLLMConfigHandler_UpdateProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("update default model", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// Setup
		credHandler.Create(ctx, CredentialCreateRequest{
			Name: "key", Type: types.CredentialTypeAPIKey, APIKey: "sk-test",
		})
		handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name: "test", Type: llm.ProviderAnthropic, CredentialName: "key", DefaultModel: "old-model",
		})

		// Update
		newModel := "new-model"
		resp, err := handler.UpdateProvider(ctx, ProviderUpdateRequest{
			Name:         "test",
			DefaultModel: &newModel,
		})
		require.NoError(t, err)
		assert.Equal(t, "new-model", resp.DefaultModel)
	})

	t.Run("not found", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		newModel := "model"
		_, err := handler.UpdateProvider(ctx, ProviderUpdateRequest{
			Name:         "nonexistent",
			DefaultModel: &newModel,
		})
		assert.Error(t, err)
	})
}

func TestLLMConfigHandler_DeleteProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// Setup
		credHandler.Create(ctx, CredentialCreateRequest{
			Name: "key", Type: types.CredentialTypeAPIKey, APIKey: "sk-test",
		})
		handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name: "to-delete", Type: llm.ProviderAnthropic, CredentialName: "key", DefaultModel: "model",
		})

		// Delete
		err := handler.DeleteProvider(ctx, "to-delete")
		require.NoError(t, err)

		// Verify gone
		_, err = handler.GetProvider(ctx, "to-delete")
		assert.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		err := handler.DeleteProvider(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestLLMConfigHandler_DefaultProvider(t *testing.T) {
	ctx := context.Background()

	t.Run("set and get default", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// Setup
		credHandler.Create(ctx, CredentialCreateRequest{
			Name: "key", Type: types.CredentialTypeAPIKey, APIKey: "sk-test",
		})
		handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name: "main-provider", Type: llm.ProviderAnthropic, CredentialName: "key", DefaultModel: "model",
		})

		// Set default
		err := handler.SetDefaultProvider(ctx, "main-provider")
		require.NoError(t, err)

		// Get default
		name, err := handler.GetDefaultProvider(ctx)
		require.NoError(t, err)
		assert.Equal(t, "main-provider", name)
	})

	t.Run("no default set", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		_, err := handler.GetDefaultProvider(ctx)
		assert.Error(t, err)
	})

	t.Run("set default for nonexistent provider", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		err := handler.SetDefaultProvider(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestLLMConfigHandler_GetProviderConfig(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		handler, credHandler, _ := setupTestLLMConfigHandler(t)

		// Create credential with API key
		apiKey := "sk-ant-api03-secret"
		credHandler.Create(ctx, CredentialCreateRequest{
			Name: "secret-key", Type: types.CredentialTypeAPIKey, Provider: "anthropic", APIKey: apiKey,
		})

		// Create provider
		handler.CreateOrUpdateProvider(ctx, ProviderCreateRequest{
			Name:           "anthropic",
			Type:           llm.ProviderAnthropic,
			CredentialName: "secret-key",
			DefaultModel:   "claude-sonnet-4-20250514",
			BaseURL:        "https://custom.api.anthropic.com",
		})

		// Get provider config (includes decrypted API key)
		cfg, err := handler.GetProviderConfig(ctx, "anthropic")
		require.NoError(t, err)
		assert.Equal(t, llm.ProviderAnthropic, cfg.Type)
		assert.Equal(t, apiKey, cfg.APIKey) // Decrypted!
		assert.Equal(t, "claude-sonnet-4-20250514", cfg.DefaultModel)
		assert.Equal(t, "https://custom.api.anthropic.com", cfg.BaseURL)
	})
}

func TestProviderConfigStored_JSON(t *testing.T) {
	now := time.Now()
	stored := &ProviderConfigStored{
		Name:           "test",
		Type:           llm.ProviderAnthropic,
		CredentialName: "my-cred",
		BaseURL:        "https://api.anthropic.com",
		DefaultModel:   "claude-sonnet-4-20250514",
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// Test marshaling
	data, err := stored.MarshalJSON()
	require.NoError(t, err)
	assert.Contains(t, string(data), "test")
	assert.Contains(t, string(data), "anthropic")
}
