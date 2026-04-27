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
	"github.com/zero-day-ai/sdk/auth"
)

// testContextWithTenant returns a context carrying a test tenant identity.
// Required by CredentialHandler methods which resolve the tenant from context.
func testContextWithTenant() context.Context {
	tid, _ := auth.NewTenantID("test-tenant")
	identity := auth.Identity{
		Tenant:  tid,
		Subject: "test-user",
	}
	return auth.WithIdentity(context.Background(), identity)
}

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
	ctx := testContextWithTenant()

	t.Run("success", func(t *testing.T) {
		// Requires a real per-tenant Postgres database (data-plane pool).
		// The pool stub returns ErrAdminPoolNotConfigured on For(), so this
		// test cannot pass in unit-test mode. Integration tests cover this path.
		t.Skip("requires data-plane Postgres — run as integration test")
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
	ctx := testContextWithTenant()

	t.Run("success", func(t *testing.T) {
		t.Skip("requires data-plane Postgres — run as integration test")
	})

	t.Run("not found", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		_, err := handler.GetProvider(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestLLMConfigHandler_ListProviders(t *testing.T) {
	ctx := testContextWithTenant()

	t.Run("empty list", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		resp, err := handler.ListProviders(ctx)
		require.NoError(t, err)
		assert.Empty(t, resp)
	})

	t.Run("multiple providers", func(t *testing.T) {
		t.Skip("requires data-plane Postgres — run as integration test")
	})
}

func TestLLMConfigHandler_UpdateProvider(t *testing.T) {
	ctx := testContextWithTenant()

	t.Run("update default model", func(t *testing.T) {
		t.Skip("requires data-plane Postgres — run as integration test")
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
	ctx := testContextWithTenant()

	t.Run("success", func(t *testing.T) {
		t.Skip("requires data-plane Postgres — run as integration test")
	})

	t.Run("not found", func(t *testing.T) {
		handler, _, _ := setupTestLLMConfigHandler(t)

		err := handler.DeleteProvider(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestLLMConfigHandler_DefaultProvider(t *testing.T) {
	ctx := testContextWithTenant()

	t.Run("set and get default", func(t *testing.T) {
		t.Skip("requires data-plane Postgres — run as integration test")
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
	t.Run("success", func(t *testing.T) {
		t.Skip("requires data-plane Postgres — run as integration test")
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
