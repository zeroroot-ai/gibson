package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/auth"
)

// stubPool is a minimal datapool.Pool for CredentialHandler tests.
// For() always returns an error so tests can verify the tenant-not-found path.
type stubPool struct{}

func (s *stubPool) For(_ context.Context, _ auth.TenantID) (*datapool.Conn, error) {
	return nil, datapool.ErrAdminPoolNotConfigured
}
func (s *stubPool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, datapool.ErrAdminPoolNotConfigured
}
func (s *stubPool) SetAdminPool(_ datapool.AdminAcquirer) {}
func (s *stubPool) Close() error                          { return nil }

var _ datapool.Pool = (*stubPool)(nil)

// newMockCredentialDAO returns a stub Pool for backward-compat with
// llm_config_test.go which still references this name. The name is preserved
// so we don't have to change that test file.
func newMockCredentialDAO() *stubPool { return &stubPool{} }

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

func (m *mockKeyProvider) GetEncryptionKey(_ context.Context) ([]byte, error) {
	return m.key, m.err
}
func (m *mockKeyProvider) Name() string { return "mock" }
func (m *mockKeyProvider) Health(_ context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy}
}
func (m *mockKeyProvider) Close() error { return nil }

func TestNewCredentialHandler(t *testing.T) {
	pool := &stubPool{}
	kp := newMockKeyProvider()

	t.Run("success", func(t *testing.T) {
		handler, err := NewCredentialHandler(pool, kp)
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})

	t.Run("nil pool", func(t *testing.T) {
		_, err := NewCredentialHandler(nil, kp)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "pool must not be nil")
	})

	t.Run("nil key provider", func(t *testing.T) {
		_, err := NewCredentialHandler(pool, nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "keyProvider must not be nil")
	})
}

// TestCredentialHandler_Create_NoTenant verifies that Create rejects calls
// with no tenant in context (pool.For will fail after tenant check).
func TestCredentialHandler_Create_NoTenant(t *testing.T) {
	pool := &stubPool{}
	kp := newMockKeyProvider()
	handler, err := NewCredentialHandler(pool, kp)
	require.NoError(t, err)

	// No tenant in context.
	ctx := context.Background()
	_, err = handler.Create(ctx, CredentialCreateRequest{
		Name:   "my-cred",
		Type:   types.CredentialTypeAPIKey,
		APIKey: "sk-test",
	})
	assert.Error(t, err)
}

// TestCredentialHandler_Create_EmptyName verifies input validation.
func TestCredentialHandler_Create_EmptyName(t *testing.T) {
	pool := &stubPool{}
	kp := newMockKeyProvider()
	handler, err := NewCredentialHandler(pool, kp)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = handler.Create(ctx, CredentialCreateRequest{
		Name:   "",
		Type:   types.CredentialTypeAPIKey,
		APIKey: "sk-test",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name cannot be empty")
}

// TestCredentialHandler_Create_EmptyAPIKey verifies input validation.
func TestCredentialHandler_Create_EmptyAPIKey(t *testing.T) {
	pool := &stubPool{}
	kp := newMockKeyProvider()
	handler, err := NewCredentialHandler(pool, kp)
	require.NoError(t, err)

	ctx := context.Background()
	_, err = handler.Create(ctx, CredentialCreateRequest{
		Name:   "my-cred",
		Type:   types.CredentialTypeAPIKey,
		APIKey: "",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "API key cannot be empty")
}

// TestMaskAPIKey exercises the masking helper.
func TestMaskAPIKey(t *testing.T) {
	assert.Equal(t, "", maskAPIKey(""))
	assert.Equal(t, "***", maskAPIKey("abc"))
	assert.Equal(t, "sk-a****5678", maskAPIKey("sk-ant-api03-12345678"))
}
