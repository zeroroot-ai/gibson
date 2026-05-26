package checkpoint

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/zeroroot-ai/gibson/internal/checkpoint/keyprovider"
)

// EncryptionService defines the interface for encrypting and decrypting checkpoint data.
// Implementations should provide authenticated encryption to ensure data confidentiality
// and integrity.
type EncryptionService interface {
	// Encrypt encrypts the provided data and returns an encrypted payload
	// containing the ciphertext, nonce, and key identifier.
	Encrypt(ctx context.Context, data []byte) (*EncryptedPayload, error)

	// Decrypt decrypts an encrypted payload and returns the original plaintext data.
	// Returns an error if decryption fails due to invalid data, wrong key, or tampering.
	Decrypt(ctx context.Context, payload *EncryptedPayload) ([]byte, error)
}

// EncryptedPayload represents encrypted data with metadata required for decryption.
// It includes the key identifier for key rotation support and the nonce for GCM mode.
type EncryptedPayload struct {
	KeyID      string `json:"key_id" msgpack:"key_id"`
	Nonce      []byte `json:"nonce" msgpack:"nonce"`
	Ciphertext []byte `json:"ciphertext" msgpack:"ciphertext"`
}

// AESGCMEncryptionService implements EncryptionService using AES-256-GCM authenticated encryption.
// It provides confidentiality and integrity protection for checkpoint data.
type AESGCMEncryptionService struct {
	keyProvider keyprovider.KeyProvider
}

// NewAESGCMEncryptionService creates a new AES-GCM encryption service with the provided key provider.
// The key provider must supply 32-byte keys for AES-256 encryption.
func NewAESGCMEncryptionService(keyProvider keyprovider.KeyProvider) *AESGCMEncryptionService {
	return &AESGCMEncryptionService{
		keyProvider: keyProvider,
	}
}

// Encrypt encrypts the provided data using AES-256-GCM with the current encryption key.
// It generates a random 12-byte nonce for each encryption operation and includes the
// key ID in the payload to support key rotation.
func (s *AESGCMEncryptionService) Encrypt(ctx context.Context, data []byte) (*EncryptedPayload, error) {
	// Retrieve the current encryption key
	key, err := s.keyProvider.GetKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve encryption key: %w", err)
	}

	// Validate key length for AES-256
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes for AES-256, got %d bytes", len(key))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce (12 bytes is standard for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate the data
	ciphertext := gcm.Seal(nil, nonce, data, nil)

	return &EncryptedPayload{
		KeyID:      s.keyProvider.CurrentKeyID(),
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts an encrypted payload using the key identified by the payload's KeyID.
// It verifies the authentication tag to ensure data integrity and detects tampering.
func (s *AESGCMEncryptionService) Decrypt(ctx context.Context, payload *EncryptedPayload) ([]byte, error) {
	if payload == nil {
		return nil, fmt.Errorf("encrypted payload is nil")
	}

	// Validate payload structure
	if payload.KeyID == "" {
		return nil, fmt.Errorf("payload missing key ID")
	}
	if len(payload.Nonce) == 0 {
		return nil, fmt.Errorf("payload missing nonce")
	}
	if len(payload.Ciphertext) == 0 {
		return nil, fmt.Errorf("payload missing ciphertext")
	}

	// Retrieve the encryption key by ID to support key rotation
	key, err := s.keyProvider.GetKeyByID(ctx, payload.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve encryption key for key ID %s: %w", payload.KeyID, err)
	}

	// Validate key length for AES-256
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32 bytes for AES-256, got %d bytes", len(key))
	}

	// Create AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Validate nonce size
	if len(payload.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid nonce size: expected %d bytes, got %d bytes", gcm.NonceSize(), len(payload.Nonce))
	}

	// Decrypt and verify authentication tag
	plaintext, err := gcm.Open(nil, payload.Nonce, payload.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt payload: %w", err)
	}

	return plaintext, nil
}
