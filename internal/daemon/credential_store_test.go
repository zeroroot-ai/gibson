package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/auth"
)

// MockKeyProvider is a mock implementation of crypto.KeyProvider for testing.
type MockKeyProvider struct {
	mock.Mock
}

func (m *MockKeyProvider) GetEncryptionKey(ctx context.Context) ([]byte, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockKeyProvider) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockKeyProvider) Health(ctx context.Context) types.HealthStatus {
	args := m.Called(ctx)
	return args.Get(0).(types.HealthStatus)
}

func (m *MockKeyProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

// stubPool is a minimal datapool.Pool for tests that returns an error on For().
type stubPool struct{}

func (s *stubPool) For(_ context.Context, _ auth.TenantID) (*datapool.Conn, error) {
	return nil, datapool.ErrAdminPoolNotConfigured // any error is fine for tests
}
func (s *stubPool) Admin(_ context.Context) (*datapool.AdminConn, error) {
	return nil, datapool.ErrAdminPoolNotConfigured
}
func (s *stubPool) SetAdminPool(_ datapool.AdminAcquirer) {}
func (s *stubPool) Close() error                          { return nil }

var _ datapool.Pool = (*stubPool)(nil)

// newMockPool returns a Pool stub sufficient for constructor-level tests.
func newMockPool(_ *testing.T) datapool.Pool {
	return &stubPool{}
}

// TestNewDaemonCredentialStore_NilPool verifies that a nil pool is rejected.
func TestNewDaemonCredentialStore_NilPool(t *testing.T) {
	mockKP := new(MockKeyProvider)
	store, err := NewDaemonCredentialStore(nil, mockKP)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "pool must not be nil")
}

// TestNewDaemonCredentialStore_NilKeyProvider verifies that a nil key provider is rejected.
func TestNewDaemonCredentialStore_NilKeyProvider(t *testing.T) {
	mp := newMockPool(t)
	store, err := NewDaemonCredentialStore(mp, nil)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "keyProvider must not be nil")
}

// TestDaemonCredentialStore_GetCredential_NoTenant verifies that a missing tenant returns an error.
func TestDaemonCredentialStore_GetCredential_NoTenant(t *testing.T) {
	mp := newMockPool(t)
	mockKP := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(mp, mockKP)
	assert.NoError(t, err)

	// Context without a tenant — TenantFromContext returns (zero, false).
	_, _, err = store.GetCredential(context.Background(), "test-cred")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no tenant in context")
}

// TestDaemonCredentialStore_Health delegates to the key provider.
func TestDaemonCredentialStore_Health(t *testing.T) {
	mp := newMockPool(t)
	mockKP := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(mp, mockKP)
	assert.NoError(t, err)

	ctx := context.Background()
	expected := types.HealthStatus{State: types.HealthStateHealthy, Message: "ok"}
	mockKP.On("Health", ctx).Return(expected)

	health := store.Health(ctx)
	assert.Equal(t, expected, health)
	mockKP.AssertExpectations(t)
}

// TestDaemonCredentialStore_Close delegates to the key provider.
func TestDaemonCredentialStore_Close(t *testing.T) {
	mp := newMockPool(t)
	mockKP := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(mp, mockKP)
	assert.NoError(t, err)

	mockKP.On("Close").Return(nil)
	assert.NoError(t, store.Close())
	mockKP.AssertExpectations(t)
}

// TestDaemonCredentialStore_ImplementsInterface is a compile-time check via assertion.
func TestDaemonCredentialStore_ImplementsInterface(t *testing.T) {
	mp := newMockPool(t)
	mockKP := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(mp, mockKP)
	assert.NoError(t, err)
	assert.NotNil(t, store)
	assert.Implements(t, (*interface {
		GetCredential(ctx context.Context, name string) (*types.Credential, string, error)
		Health(ctx context.Context) types.HealthStatus
		Close() error
	})(nil), store)
}
