package keyprovider

import "context"

// KeyProvider defines the interface for encryption key management.
// Implementations should handle key retrieval, rotation, and lifecycle management.
type KeyProvider interface {
	// GetKey retrieves the current encryption key for encrypting new data.
	// Returns an error if the key cannot be retrieved or is unavailable.
	GetKey(ctx context.Context) ([]byte, error)

	// GetKeyByID retrieves a specific encryption key by its identifier.
	// This is used for decrypting data that was encrypted with a previous key.
	// Returns an error if the key ID is invalid or the key is unavailable.
	GetKeyByID(ctx context.Context, keyID string) ([]byte, error)

	// CurrentKeyID returns the identifier of the current encryption key.
	// This ID is included in encrypted payloads to support key rotation.
	CurrentKeyID() string
}
