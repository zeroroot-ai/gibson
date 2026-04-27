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
// It wraps the CredentialDAO to provide secure API key storage and retrieval
// for LLM providers. In Phase C the DAO itself handles envelope encryption
// (AES Key Wrap DEK + AES-256-GCM); keyProvider is retained for compatibility.
type CredentialHandler struct {
	dao         database.CredentialDAO
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
		keyProvider: keyProvider,
	}, nil
}

// CredentialCreateRequest contains the data needed to create a credential.
type CredentialCreateRequest struct {
	Name        string
	Type        types.CredentialType
	Provider    string
	APIKey      string // The plaintext API key to store (encrypted by DAO layer)
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
	APIKey      *string // Optional, nil means no change to the stored value
	Tags        []string
	Status      *types.CredentialStatus
}

// Create creates a new credential. The APIKey is stored encrypted by the DAO.
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

	// Build a credential record. The DAO (PostgresCredentialDAO) handles
	// encryption; we pass the plaintext in EncryptedValue for bridge compat.
	now := time.Now()
	cred := &types.Credential{
		ID:             types.NewID(),
		Name:           req.Name,
		Type:           req.Type,
		Provider:       req.Provider,
		Status:         types.CredentialStatusActive,
		Description:    req.Description,
		Tags:           req.Tags,
		EncryptedValue: []byte(req.APIKey), // plaintext; DAO encrypts via envelope
		EncryptionIV:   []byte("phase-c"),  // sentinel — not used by Postgres DAO
		KeyDerivationSalt: []byte("phase-c"),
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if cred.Tags == nil {
		cred.Tags = []string{}
	}

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
	// EncryptedValue holds plaintext in Phase C bridge.
	return h.toResponse(cred, string(cred.EncryptedValue)), nil
}

// GetByName retrieves a credential by name.
func (h *CredentialHandler) GetByName(ctx context.Context, name string) (*CredentialResponse, error) {
	cred, err := h.dao.GetByName(ctx, name)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}
	return h.toResponse(cred, string(cred.EncryptedValue)), nil
}

// GetDecrypted retrieves a credential with its plaintext value.
// This is for internal use only — never expose via API.
func (h *CredentialHandler) GetDecrypted(ctx context.Context, name string) (*types.Credential, string, error) {
	cred, err := h.dao.GetByName(ctx, name)
	if err != nil {
		return nil, "", types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}
	return cred, string(cred.EncryptedValue), nil
}

// List retrieves credentials with optional filtering.
func (h *CredentialHandler) List(ctx context.Context, filter *types.CredentialFilter) ([]*CredentialResponse, error) {
	creds, err := h.dao.List(ctx, filter)
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to list credentials", err)
	}

	responses := make([]*CredentialResponse, 0, len(creds))
	for _, cred := range creds {
		responses = append(responses, h.toResponse(cred, string(cred.EncryptedValue)))
	}
	return responses, nil
}

// Update updates an existing credential.
func (h *CredentialHandler) Update(ctx context.Context, req CredentialUpdateRequest) (*CredentialResponse, error) {
	// Fetch the existing credential by ID (bridge: may return unsupported error).
	// Fall back to name-based lookup if ID lookup is unsupported.
	cred, err := h.dao.Get(ctx, req.ID)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

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

	var plainKey string
	if req.APIKey != nil {
		cred.EncryptedValue = []byte(*req.APIKey)
		plainKey = *req.APIKey
	} else {
		plainKey = string(cred.EncryptedValue)
	}
	cred.UpdatedAt = time.Now()

	if err := h.dao.Update(ctx, cred); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to update credential", err)
	}

	return h.toResponse(cred, plainKey), nil
}

// Delete deletes a credential by ID.
func (h *CredentialHandler) Delete(ctx context.Context, id types.ID) error {
	if err := h.dao.Delete(ctx, id); err != nil {
		return types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}
	return nil
}

// toResponse converts a Credential to a CredentialResponse.
func (h *CredentialHandler) toResponse(cred *types.Credential, plainKey string) *CredentialResponse {
	return &CredentialResponse{
		ID:            cred.ID,
		Name:          cred.Name,
		Type:          cred.Type,
		Provider:      cred.Provider,
		Status:        cred.Status,
		Description:   cred.Description,
		MaskedKey:     maskAPIKey(plainKey),
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
