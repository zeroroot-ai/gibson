package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/zero-day-ai/gibson/internal/config"
	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/types"
)

// DaemonCredentialStore implements harness.CredentialStore using the
// daemon's database and master key for secure credential retrieval.
// It supports both SQLite and Redis credential DAOs via the CredentialDAO interface.
type DaemonCredentialStore struct {
	dao       database.CredentialDAO
	encryptor *crypto.AESGCMEncryptor
	masterKey []byte
	homeDir   string
}

// NewDaemonCredentialStore creates a new credential store for the daemon.
// It loads the master key from the Gibson home directory.
// The dao parameter accepts any CredentialDAO implementation (SQLite or Redis).
func NewDaemonCredentialStore(dao database.CredentialDAO, homeDir string) (*DaemonCredentialStore, error) {
	if homeDir == "" {
		homeDir = os.Getenv("GIBSON_HOME")
	}
	if homeDir == "" {
		homeDir = config.DefaultHomeDir()
	}

	// Load master key
	keyPath := filepath.Join(homeDir, "master.key")
	keyManager := crypto.NewFileKeyManager()

	if !keyManager.KeyExists(keyPath) {
		return nil, fmt.Errorf("master key not found at %s (run 'gibson init')", keyPath)
	}

	masterKey, err := keyManager.LoadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load master key: %w", err)
	}

	return &DaemonCredentialStore{
		dao:       dao,
		encryptor: crypto.NewAESGCMEncryptor(),
		masterKey: masterKey,
		homeDir:   homeDir,
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

	// Decrypt the credential value
	decryptedValue, err := s.encryptor.Decrypt(
		cred.EncryptedValue,
		cred.EncryptionIV,
		cred.KeyDerivationSalt,
		s.masterKey,
	)
	if err != nil {
		return nil, "", fmt.Errorf("failed to decrypt credential: %w", err)
	}

	return cred, string(decryptedValue), nil
}

// Ensure DaemonCredentialStore implements harness.CredentialStore
var _ harness.CredentialStore = (*DaemonCredentialStore)(nil)
