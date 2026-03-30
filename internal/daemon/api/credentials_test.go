package api

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zero-day-ai/gibson/internal/types"
)

// mockCredentialDAO implements database.CredentialDAO for testing.
type mockCredentialDAO struct {
	credentials map[string]*types.Credential
	byName      map[string]types.ID
	createErr   error
	getErr      error
	listErr     error
	updateErr   error
	deleteErr   error
}

func newMockCredentialDAO() *mockCredentialDAO {
	return &mockCredentialDAO{
		credentials: make(map[string]*types.Credential),
		byName:      make(map[string]types.ID),
	}
}

func (m *mockCredentialDAO) Create(ctx context.Context, cred *types.Credential) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.credentials[cred.ID.String()] = cred
	m.byName[cred.Name] = cred.ID
	return nil
}

func (m *mockCredentialDAO) Get(ctx context.Context, id types.ID) (*types.Credential, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	cred, ok := m.credentials[id.String()]
	if !ok {
		return nil, types.NewError(types.CREDENTIAL_NOT_FOUND, "credential not found")
	}
	return cred, nil
}

func (m *mockCredentialDAO) GetByName(ctx context.Context, name string) (*types.Credential, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	id, ok := m.byName[name]
	if !ok {
		return nil, types.NewError(types.CREDENTIAL_NOT_FOUND, "credential not found")
	}
	return m.credentials[id.String()], nil
}

func (m *mockCredentialDAO) List(ctx context.Context, filter *types.CredentialFilter) ([]*types.Credential, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	result := make([]*types.Credential, 0, len(m.credentials))
	for _, cred := range m.credentials {
		// Apply basic filtering
		if filter != nil {
			if filter.Provider != nil && cred.Provider != *filter.Provider {
				continue
			}
			if filter.Type != nil && cred.Type != *filter.Type {
				continue
			}
			if filter.Status != nil && cred.Status != *filter.Status {
				continue
			}
		}
		result = append(result, cred)
	}
	return result, nil
}

func (m *mockCredentialDAO) Update(ctx context.Context, cred *types.Credential) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.credentials[cred.ID.String()]; !ok {
		return types.NewError(types.CREDENTIAL_NOT_FOUND, "credential not found")
	}
	// Update name mapping if name changed
	for name, id := range m.byName {
		if id == cred.ID && name != cred.Name {
			delete(m.byName, name)
			m.byName[cred.Name] = cred.ID
			break
		}
	}
	m.credentials[cred.ID.String()] = cred
	return nil
}

func (m *mockCredentialDAO) Delete(ctx context.Context, id types.ID) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	cred, ok := m.credentials[id.String()]
	if !ok {
		return types.NewError(types.CREDENTIAL_NOT_FOUND, "credential not found")
	}
	delete(m.byName, cred.Name)
	delete(m.credentials, id.String())
	return nil
}

func (m *mockCredentialDAO) DeleteByName(ctx context.Context, name string) error {
	id, ok := m.byName[name]
	if !ok {
		return types.NewError(types.CREDENTIAL_NOT_FOUND, "credential not found")
	}
	return m.Delete(ctx, id)
}

func (m *mockCredentialDAO) Exists(ctx context.Context, name string) (bool, error) {
	_, ok := m.byName[name]
	return ok, nil
}

func (m *mockCredentialDAO) UpdateLastUsed(ctx context.Context, id types.ID, lastUsed time.Time) error {
	cred, ok := m.credentials[id.String()]
	if !ok {
		return types.NewError(types.CREDENTIAL_NOT_FOUND, "credential not found")
	}
	cred.LastUsed = &lastUsed
	return nil
}

// mockKeyProvider implements crypto.KeyProvider for testing.
type mockKeyProvider struct {
	key []byte
	err error
}

func newMockKeyProvider() *mockKeyProvider {
	return &mockKeyProvider{
		key: []byte("test-encryption-key-32-bytes!!!!"),
	}
}

func (m *mockKeyProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.key, nil
}

func (m *mockKeyProvider) Name() string {
	return "mock"
}

func (m *mockKeyProvider) Health(ctx context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy}
}

func (m *mockKeyProvider) Close() error {
	return nil
}

func TestNewCredentialHandler(t *testing.T) {
	dao := newMockCredentialDAO()
	keyProvider := newMockKeyProvider()

	t.Run("success", func(t *testing.T) {
		handler, err := NewCredentialHandler(dao, keyProvider)
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})

	t.Run("nil DAO", func(t *testing.T) {
		_, err := NewCredentialHandler(nil, keyProvider)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "DAO cannot be nil")
	})

	t.Run("nil key provider", func(t *testing.T) {
		_, err := NewCredentialHandler(dao, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key provider cannot be nil")
	})
}

func TestCredentialHandler_Create(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, err := NewCredentialHandler(dao, keyProvider)
		require.NoError(t, err)

		req := CredentialCreateRequest{
			Name:        "test-credential",
			Type:        types.CredentialTypeAPIKey,
			Provider:    "anthropic",
			APIKey:      "sk-ant-api03-test-key-12345678",
			Description: "Test credential",
			Tags:        []string{"test", "dev"},
		}

		resp, err := handler.Create(ctx, req)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		assert.Equal(t, "test-credential", resp.Name)
		assert.Equal(t, types.CredentialTypeAPIKey, resp.Type)
		assert.Equal(t, "anthropic", resp.Provider)
		assert.Equal(t, types.CredentialStatusActive, resp.Status)
		assert.Equal(t, "sk-a****5678", resp.MaskedKey)
		assert.Equal(t, []string{"test", "dev"}, resp.Tags)
		assert.False(t, resp.NeedsRotation)
	})

	t.Run("empty name", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		req := CredentialCreateRequest{
			Name:   "",
			Type:   types.CredentialTypeAPIKey,
			APIKey: "sk-test",
		}

		_, err := handler.Create(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "name cannot be empty")
	})

	t.Run("empty API key", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		req := CredentialCreateRequest{
			Name:   "test",
			Type:   types.CredentialTypeAPIKey,
			APIKey: "",
		}

		_, err := handler.Create(ctx, req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "API key cannot be empty")
	})
}

func TestCredentialHandler_Get(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		// Create a credential first
		req := CredentialCreateRequest{
			Name:     "test-cred",
			Type:     types.CredentialTypeAPIKey,
			Provider: "openai",
			APIKey:   "sk-openai-test-key-abcdefgh",
		}
		created, err := handler.Create(ctx, req)
		require.NoError(t, err)

		// Get it
		resp, err := handler.Get(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.ID, resp.ID)
		assert.Equal(t, "test-cred", resp.Name)
		assert.Equal(t, "sk-o****efgh", resp.MaskedKey)
	})

	t.Run("not found", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		_, err := handler.Get(ctx, types.NewID())
		assert.Error(t, err)
	})
}

func TestCredentialHandler_GetByName(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		// Create a credential
		req := CredentialCreateRequest{
			Name:     "my-api-key",
			Type:     types.CredentialTypeAPIKey,
			Provider: "anthropic",
			APIKey:   "sk-ant-test-1234567890",
		}
		_, err := handler.Create(ctx, req)
		require.NoError(t, err)

		// Get by name
		resp, err := handler.GetByName(ctx, "my-api-key")
		require.NoError(t, err)
		assert.Equal(t, "my-api-key", resp.Name)
		assert.Equal(t, "anthropic", resp.Provider)
	})

	t.Run("not found", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		_, err := handler.GetByName(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestCredentialHandler_List(t *testing.T) {
	ctx := context.Background()

	t.Run("list all", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		// Create multiple credentials
		handler.Create(ctx, CredentialCreateRequest{
			Name: "cred1", Type: types.CredentialTypeAPIKey, Provider: "anthropic", APIKey: "sk-test1234",
		})
		handler.Create(ctx, CredentialCreateRequest{
			Name: "cred2", Type: types.CredentialTypeAPIKey, Provider: "openai", APIKey: "sk-test5678",
		})

		// List all
		resp, err := handler.List(ctx, nil)
		require.NoError(t, err)
		assert.Len(t, resp, 2)
	})

	t.Run("filter by provider", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		handler.Create(ctx, CredentialCreateRequest{
			Name: "cred1", Type: types.CredentialTypeAPIKey, Provider: "anthropic", APIKey: "sk-test1234",
		})
		handler.Create(ctx, CredentialCreateRequest{
			Name: "cred2", Type: types.CredentialTypeAPIKey, Provider: "openai", APIKey: "sk-test5678",
		})

		provider := "anthropic"
		resp, err := handler.List(ctx, &types.CredentialFilter{Provider: &provider})
		require.NoError(t, err)
		assert.Len(t, resp, 1)
		assert.Equal(t, "anthropic", resp[0].Provider)
	})
}

func TestCredentialHandler_Update(t *testing.T) {
	ctx := context.Background()

	t.Run("update description", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		created, err := handler.Create(ctx, CredentialCreateRequest{
			Name: "test", Type: types.CredentialTypeAPIKey, Provider: "test", APIKey: "sk-test1234",
		})
		require.NoError(t, err)

		newDesc := "Updated description"
		resp, err := handler.Update(ctx, CredentialUpdateRequest{
			ID:          created.ID,
			Description: &newDesc,
		})
		require.NoError(t, err)
		assert.Equal(t, "Updated description", resp.Description)
	})

	t.Run("update API key", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		created, err := handler.Create(ctx, CredentialCreateRequest{
			Name: "test", Type: types.CredentialTypeAPIKey, Provider: "test", APIKey: "sk-old-key-12345678",
		})
		require.NoError(t, err)
		assert.Equal(t, "sk-o****5678", created.MaskedKey)

		newKey := "sk-new-key-abcdefgh"
		resp, err := handler.Update(ctx, CredentialUpdateRequest{
			ID:     created.ID,
			APIKey: &newKey,
		})
		require.NoError(t, err)
		assert.Equal(t, "sk-n****efgh", resp.MaskedKey)
	})

	t.Run("not found", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		_, err := handler.Update(ctx, CredentialUpdateRequest{
			ID: types.NewID(),
		})
		assert.Error(t, err)
	})
}

func TestCredentialHandler_Delete(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		created, err := handler.Create(ctx, CredentialCreateRequest{
			Name: "to-delete", Type: types.CredentialTypeAPIKey, Provider: "test", APIKey: "sk-test",
		})
		require.NoError(t, err)

		err = handler.Delete(ctx, created.ID)
		require.NoError(t, err)

		// Verify it's gone
		_, err = handler.Get(ctx, created.ID)
		assert.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		err := handler.Delete(ctx, types.NewID())
		assert.Error(t, err)
	})
}

func TestCredentialHandler_GetDecrypted(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		dao := newMockCredentialDAO()
		keyProvider := newMockKeyProvider()
		handler, _ := NewCredentialHandler(dao, keyProvider)

		originalKey := "sk-ant-api03-secret-key-xyz"
		_, err := handler.Create(ctx, CredentialCreateRequest{
			Name: "secret-cred", Type: types.CredentialTypeAPIKey, Provider: "anthropic", APIKey: originalKey,
		})
		require.NoError(t, err)

		cred, decrypted, err := handler.GetDecrypted(ctx, "secret-cred")
		require.NoError(t, err)
		assert.Equal(t, "secret-cred", cred.Name)
		assert.Equal(t, originalKey, decrypted)
	})
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		expected string
	}{
		{"empty", "", ""},
		{"short 3 chars", "abc", "***"},
		{"short 8 chars", "12345678", "********"},
		{"normal key", "sk-ant-api03-abcd", "sk-a****abcd"},
		{"long key", "sk-ant-api03-very-long-key-here", "sk-a****here"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := maskAPIKey(tc.key)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNeedsRotation(t *testing.T) {
	t.Run("fresh credential", func(t *testing.T) {
		cred := types.NewCredential("test", types.CredentialTypeAPIKey)
		assert.False(t, needsRotation(cred))
	})

	t.Run("old credential", func(t *testing.T) {
		cred := types.NewCredential("test", types.CredentialTypeAPIKey)
		cred.CreatedAt = time.Now().Add(-100 * 24 * time.Hour) // 100 days ago
		assert.True(t, needsRotation(cred))
	})
}
