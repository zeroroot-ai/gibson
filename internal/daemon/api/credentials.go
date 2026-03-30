package api

import (
	"context"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/crypto"
	"github.com/zero-day-ai/gibson/internal/database"
	"github.com/zero-day-ai/gibson/internal/types"
)

// CredentialHandler provides credential management operations for the daemon.
// It wraps the CredentialDAO and crypto infrastructure to provide secure
// API key storage and retrieval for LLM providers.
type CredentialHandler struct {
	dao         database.CredentialDAO
	encryptor   *crypto.AESGCMEncryptor
	keyProvider crypto.KeyProvider
}

// NewCredentialHandler creates a new credential handler.
func NewCredentialHandler(dao database.CredentialDAO, keyProvider crypto.KeyProvider) (*CredentialHandler, error) {
	if dao == nil {
		return nil, fmt.Errorf("credential DAO cannot be nil")
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("key provider cannot be nil")
	}

	return &CredentialHandler{
		dao:         dao,
		encryptor:   crypto.NewAESGCMEncryptor(),
		keyProvider: keyProvider,
	}, nil
}

// CredentialCreateRequest contains the data needed to create a credential.
type CredentialCreateRequest struct {
	Name        string
	Type        types.CredentialType
	Provider    string
	APIKey      string // The plaintext API key to encrypt
	Description string
	Tags        []string
}

// CredentialResponse is the response for credential operations.
// It never includes the decrypted API key.
type CredentialResponse struct {
	ID            types.ID
	Name          string
	Type          types.CredentialType
	Provider      string
	Status        types.CredentialStatus
	Description   string
	MaskedKey     string
	Tags          []string
	NeedsRotation bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	LastUsed      *time.Time
}

// CredentialUpdateRequest contains the data for updating a credential.
type CredentialUpdateRequest struct {
	ID          types.ID
	Name        *string // Optional, nil means no change
	Description *string
	APIKey      *string // Optional, nil means no change to the encrypted value
	Tags        []string
	Status      *types.CredentialStatus
}

// Create creates a new credential with encrypted API key.
func (h *CredentialHandler) Create(ctx context.Context, req CredentialCreateRequest) (*CredentialResponse, error) {
	if req.Name == "" {
		return nil, types.NewError(types.CREDENTIAL_INVALID, "credential name cannot be empty")
	}
	if req.APIKey == "" {
		return nil, types.NewError(types.CREDENTIAL_INVALID, "API key cannot be empty")
	}
	if !req.Type.IsValid() {
		return nil, types.NewError(types.CREDENTIAL_INVALID, fmt.Sprintf("invalid credential type: %s", req.Type))
	}

	// Get master encryption key
	masterKey, err := h.keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return nil, types.WrapError(types.CRYPTO_KEY_NOT_FOUND, "failed to get encryption key", err)
	}

	// Encrypt the API key
	ciphertext, iv, salt, err := h.encryptor.Encrypt([]byte(req.APIKey), masterKey)
	if err != nil {
		return nil, types.WrapError(types.CRYPTO_ENCRYPT_FAILED, "failed to encrypt API key", err)
	}

	// Create credential with encrypted data
	cred := types.NewCredential(req.Name, req.Type)
	cred.Provider = req.Provider
	cred.Description = req.Description
	cred.EncryptedValue = ciphertext
	cred.EncryptionIV = iv
	cred.KeyDerivationSalt = salt

	if req.Tags != nil {
		cred.Tags = req.Tags
	}

	// Store in database
	if err := h.dao.Create(ctx, cred); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to create credential", err)
	}

	return h.toResponse(cred, req.APIKey), nil
}

// Get retrieves a credential by ID.
func (h *CredentialHandler) Get(ctx context.Context, id types.ID) (*CredentialResponse, error) {
	cred, err := h.dao.Get(ctx, id)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

	// We need to decrypt to create the masked key
	decrypted, err := h.decrypt(ctx, cred)
	if err != nil {
		// If decryption fails, return with empty masked key
		return h.toResponse(cred, ""), nil
	}

	return h.toResponse(cred, decrypted), nil
}

// GetByName retrieves a credential by name.
func (h *CredentialHandler) GetByName(ctx context.Context, name string) (*CredentialResponse, error) {
	cred, err := h.dao.GetByName(ctx, name)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

	decrypted, err := h.decrypt(ctx, cred)
	if err != nil {
		return h.toResponse(cred, ""), nil
	}

	return h.toResponse(cred, decrypted), nil
}

// List retrieves credentials with optional filtering.
func (h *CredentialHandler) List(ctx context.Context, filter *types.CredentialFilter) ([]*CredentialResponse, error) {
	creds, err := h.dao.List(ctx, filter)
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to list credentials", err)
	}

	responses := make([]*CredentialResponse, 0, len(creds))
	for _, cred := range creds {
		decrypted, _ := h.decrypt(ctx, cred)
		responses = append(responses, h.toResponse(cred, decrypted))
	}

	return responses, nil
}

// Update updates an existing credential.
func (h *CredentialHandler) Update(ctx context.Context, req CredentialUpdateRequest) (*CredentialResponse, error) {
	// Get existing credential
	cred, err := h.dao.Get(ctx, req.ID)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

	// Apply updates
	if req.Name != nil {
		cred.Name = *req.Name
	}
	if req.Description != nil {
		cred.Description = *req.Description
	}
	if req.Tags != nil {
		cred.Tags = req.Tags
	}
	if req.Status != nil {
		cred.Status = *req.Status
	}

	// If API key is being updated, re-encrypt
	var decryptedKey string
	if req.APIKey != nil {
		masterKey, err := h.keyProvider.GetEncryptionKey(ctx)
		if err != nil {
			return nil, types.WrapError(types.CRYPTO_KEY_NOT_FOUND, "failed to get encryption key", err)
		}

		ciphertext, iv, salt, err := h.encryptor.Encrypt([]byte(*req.APIKey), masterKey)
		if err != nil {
			return nil, types.WrapError(types.CRYPTO_ENCRYPT_FAILED, "failed to encrypt API key", err)
		}

		cred.EncryptedValue = ciphertext
		cred.EncryptionIV = iv
		cred.KeyDerivationSalt = salt
		decryptedKey = *req.APIKey
	} else {
		// Decrypt existing key for masking
		decryptedKey, _ = h.decrypt(ctx, cred)
	}

	cred.UpdatedAt = time.Now()

	// Update in database
	if err := h.dao.Update(ctx, cred); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to update credential", err)
	}

	return h.toResponse(cred, decryptedKey), nil
}

// Delete deletes a credential by ID.
func (h *CredentialHandler) Delete(ctx context.Context, id types.ID) error {
	if err := h.dao.Delete(ctx, id); err != nil {
		return types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}
	return nil
}

// GetDecrypted retrieves a credential with its decrypted value.
// This is for internal use only - never expose via API.
func (h *CredentialHandler) GetDecrypted(ctx context.Context, name string) (*types.Credential, string, error) {
	cred, err := h.dao.GetByName(ctx, name)
	if err != nil {
		return nil, "", types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

	decrypted, err := h.decrypt(ctx, cred)
	if err != nil {
		return nil, "", err
	}

	return cred, decrypted, nil
}

// decrypt decrypts a credential's value.
func (h *CredentialHandler) decrypt(ctx context.Context, cred *types.Credential) (string, error) {
	masterKey, err := h.keyProvider.GetEncryptionKey(ctx)
	if err != nil {
		return "", types.WrapError(types.CRYPTO_KEY_NOT_FOUND, "failed to get encryption key", err)
	}

	plaintext, err := h.encryptor.Decrypt(cred.EncryptedValue, cred.EncryptionIV, cred.KeyDerivationSalt, masterKey)
	if err != nil {
		return "", types.WrapError(types.CRYPTO_DECRYPT_FAILED, "failed to decrypt credential", err)
	}

	return string(plaintext), nil
}

// toResponse converts a Credential to a CredentialResponse.
func (h *CredentialHandler) toResponse(cred *types.Credential, decryptedKey string) *CredentialResponse {
	return &CredentialResponse{
		ID:            cred.ID,
		Name:          cred.Name,
		Type:          cred.Type,
		Provider:      cred.Provider,
		Status:        cred.Status,
		Description:   cred.Description,
		MaskedKey:     maskAPIKey(decryptedKey),
		Tags:          cred.Tags,
		NeedsRotation: needsRotation(cred),
		CreatedAt:     cred.CreatedAt,
		UpdatedAt:     cred.UpdatedAt,
		LastUsed:      cred.LastUsed,
	}
}

// maskAPIKey masks an API key for display, showing only prefix and suffix.
// Format: first 4 chars + **** + last 4 chars
// For keys <= 8 chars, returns all asterisks.
func maskAPIKey(key string) string {
	if key == "" {
		return ""
	}

	if len(key) <= 8 {
		masked := ""
		for i := 0; i < len(key); i++ {
			masked += "*"
		}
		return masked
	}

	prefix := key[:4]
	suffix := key[len(key)-4:]
	return prefix + "****" + suffix
}

// needsRotation checks if a credential needs rotation (older than 90 days).
func needsRotation(cred *types.Credential) bool {
	rotationThreshold := 90 * 24 * time.Hour
	return time.Since(cred.CreatedAt) > rotationThreshold
}
