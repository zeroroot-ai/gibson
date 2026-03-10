package daemon

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DaemonCredentialStore implements harness.CredentialStore using the
// daemon's database and key provider for secure credential retrieval.
// It supports both SQLite and Redis credential DAOs via the CredentialDAO interface.
type DaemonCredentialStore struct {
	dao         database.CredentialDAO
	encryptor   *crypto.AESGCMEncryptor
	keyProvider crypto.KeyProvider
}

// NewDaemonCredentialStore creates a new credential store for the daemon.
// It uses the provided KeyProvider to retrieve the master encryption key.
// The dao parameter accepts any CredentialDAO implementation (SQLite or Redis).
// The keyProvider parameter retrieves keys from Kubernetes Secrets, Vault, or other secret stores.
func NewDaemonCredentialStore(dao database.CredentialDAO, keyProvider crypto.KeyProvider) (*DaemonCredentialStore, error) {
	if dao == nil {
		return nil, fmt.Errorf("credential DAO cannot be nil")
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("key provider cannot be nil")
	}

	return &DaemonCredentialStore{
		dao:         dao,
		encryptor:   crypto.NewAESGCMEncryptor(),
		keyProvider: keyProvider,
	}, nil
}

// GetCredential retrieves a credential by name and decrypts its value.
// Returns the credential metadata and the decrypted secret value.
func (s *DaemonCredentialStore) GetCredential(ctx context.Context, name string) (*types.Credential, string, error) {
	// Fetch credential from database
	cred, err := s.dao.GetByName(ctx, name)
	if err != nil {
		return nil, "", fmt.Errorf("credential %q not found: %w", name, err)
	}

	// Get master key from provider
	masterKey, err := s.keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get encryption key: %w", err)
	}

	// Decrypt the credential value
	decryptedValue, err := s.encryptor.Decrypt(
		cred.EncryptedValue,
		cred.EncryptionIV,
		cred.KeyDerivationSalt,
		masterKey,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt credential: %w", err)
	}

	return cred, string(decryptedValue), nil
}

// Health returns the health status of the credential store.
func (s *DaemonCredentialStore) Health(ctx context.Context) types.HealthStatus {
	return s.keyProvider.Health(ctx)
}

// Close releases resources.
func (s *DaemonCredentialStore) Close() error {
	return s.keyProvider.Close()
}

// Ensure DaemonCredentialStore implements harness.CredentialStore
var _ harness.CredentialStore = (*DaemonCredentialStore)(nil)
