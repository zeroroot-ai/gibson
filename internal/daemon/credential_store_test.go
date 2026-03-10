package daemon

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/zero-day-ai/gibson/internal/types"
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

// MockCredentialDAO is a mock implementation of database.CredentialDAO for testing.
type MockCredentialDAO struct {
	mock.Mock
}

func (m *MockCredentialDAO) GetByName(ctx context.Context, name string) (*types.Credential, error) {
	args := m.Called(ctx, name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Credential), args.Error(1)
}

func (m *MockCredentialDAO) Create(ctx context.Context, cred *types.Credential) error {
	args := m.Called(ctx, cred)
	return args.Error(0)
}

func (m *MockCredentialDAO) Update(ctx context.Context, cred *types.Credential) error {
	args := m.Called(ctx, cred)
	return args.Error(0)
}

func (m *MockCredentialDAO) Delete(ctx context.Context, id types.ID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockCredentialDAO) DeleteByName(ctx context.Context, name string) error {
	args := m.Called(ctx, name)
	return args.Error(0)
}

func (m *MockCredentialDAO) Exists(ctx context.Context, name string) (bool, error) {
	args := m.Called(ctx, name)
	return args.Bool(0), args.Error(1)
}

func (m *MockCredentialDAO) Get(ctx context.Context, id types.ID) (*types.Credential, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Credential), args.Error(1)
}

func (m *MockCredentialDAO) List(ctx context.Context, filter *types.CredentialFilter) ([]*types.Credential, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*types.Credential), args.Error(1)
}

func (m *MockCredentialDAO) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewDaemonCredentialStore_NilDAO(t *testing.T) {
	mockKeyProvider := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(nil, mockKeyProvider)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "DAO cannot be nil")
}

func TestNewDaemonCredentialStore_NilKeyProvider(t *testing.T) {
	mockDAO := new(MockCredentialDAO)

	store, err := NewDaemonCredentialStore(mockDAO, nil)
	assert.Error(t, err)
	assert.Nil(t, store)
	assert.Contains(t, err.Error(), "key provider cannot be nil")
}

func TestNewDaemonCredentialStore_Success(t *testing.T) {
	mockDAO := new(MockCredentialDAO)
	mockKeyProvider := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(mockDAO, mockKeyProvider)
	assert.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, mockDAO, store.dao)
	assert.Equal(t, mockKeyProvider, store.keyProvider)
	assert.NotNil(t, store.encryptor)
}

func TestDaemonCredentialStore_GetCredential_DAOError(t *testing.T) {
	mockDAO := new(MockCredentialDAO)
	mockKeyProvider := new(MockKeyProvider)

	store, _ := NewDaemonCredentialStore(mockDAO, mockKeyProvider)

	ctx := context.Background()
	mockDAO.On("GetByName", ctx, "test-cred").Return(nil, assert.AnError)

	cred, secret, err := store.GetCredential(ctx, "test-cred")
	assert.Error(t, err)
	assert.Nil(t, cred)
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "not found")

	mockDAO.AssertExpectations(t)
}

func TestDaemonCredentialStore_GetCredential_KeyProviderError(t *testing.T) {
	mockDAO := new(MockCredentialDAO)
	mockKeyProvider := new(MockKeyProvider)

	store, _ := NewDaemonCredentialStore(mockDAO, mockKeyProvider)

	ctx := context.Background()
	testCred := &types.Credential{
		Name:              "test-cred",
		Type:              "generic",
		EncryptedValue:    []byte("encrypted"),
		EncryptionIV:      []byte("iv"),
		KeyDerivationSalt: []byte("salt"),
	}

	mockDAO.On("GetByName", ctx, "test-cred").Return(testCred, nil)
	mockKeyProvider.On("GetEncryptionKey", ctx).Return(nil, assert.AnError)

	cred, secret, err := store.GetCredential(ctx, "test-cred")
	assert.Error(t, err)
	assert.Nil(t, cred)
	assert.Empty(t, secret)
	assert.Contains(t, err.Error(), "failed to get encryption key")

	mockDAO.AssertExpectations(t)
	mockKeyProvider.AssertExpectations(t)
}

func TestDaemonCredentialStore_Health(t *testing.T) {
	mockDAO := new(MockCredentialDAO)
	mockKeyProvider := new(MockKeyProvider)

	store, _ := NewDaemonCredentialStore(mockDAO, mockKeyProvider)

	ctx := context.Background()
	expectedHealth := types.HealthStatus{
		State:   types.HealthStateHealthy,
		Message: "key provider is healthy",
	}

	mockKeyProvider.On("Health", ctx).Return(expectedHealth)

	health := store.Health(ctx)
	assert.Equal(t, expectedHealth, health)

	mockKeyProvider.AssertExpectations(t)
}

func TestDaemonCredentialStore_Close(t *testing.T) {
	mockDAO := new(MockCredentialDAO)
	mockKeyProvider := new(MockKeyProvider)

	store, _ := NewDaemonCredentialStore(mockDAO, mockKeyProvider)

	mockKeyProvider.On("Close").Return(nil)

	err := store.Close()
	assert.NoError(t, err)

	mockKeyProvider.AssertExpectations(t)
}

func TestDaemonCredentialStore_ImplementsInterface(t *testing.T) {
	// Compile-time check that DaemonCredentialStore implements harness.CredentialStore
	// This is already verified in the source file, but we can test it here too
	mockDAO := new(MockCredentialDAO)
	mockKeyProvider := new(MockKeyProvider)

	store, err := NewDaemonCredentialStore(mockDAO, mockKeyProvider)
	assert.NoError(t, err)
	assert.NotNil(t, store)

	// The store should have the required methods
	assert.Implements(t, (*interface {
		GetCredential(ctx context.Context, name string) (*types.Credential, string, error)
		Health(ctx context.Context) types.HealthStatus
		Close() error
	})(nil), store)
}
