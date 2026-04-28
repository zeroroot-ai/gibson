package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zero-day-ai/gibson/internal/crypto"
	dbpostgres "github.com/zero-day-ai/gibson/internal/database/postgres"
	"github.com/zero-day-ai/gibson/internal/datapool"
	"github.com/zero-day-ai/gibson/internal/types"
	"github.com/zero-day-ai/sdk/auth"
)

// CredentialHandler provides credential management operations for the daemon.
// It acquires a per-tenant Conn from the data-plane Pool on each call,
// delegates to conn.Credentials() (internal/database/postgres.CredentialOps), and releases the Conn.
//
// Phase D: the Phase C bridge (CredentialDAO wrapping a shared credentialPGPool)
// is replaced by this pool-backed implementation. Credentials are stored in each
// tenant's dedicated Postgres database, wrapped under the per-tenant KEK.
type CredentialHandler struct {
	pool        datapool.Pool
	keyProvider crypto.KeyProvider
}

// NewCredentialHandler creates a new pool-backed credential handler.
// pool must not be nil; keyProvider is retained for compatibility with callers
// that inspect it (e.g., health-check adapters).
func NewCredentialHandler(pool datapool.Pool, keyProvider crypto.KeyProvider) (*CredentialHandler, error) {
	if pool == nil {
		return nil, fmt.Errorf("credential handler: pool must not be nil")
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("credential handler: keyProvider must not be nil")
	}
	return &CredentialHandler{
		pool:        pool,
		keyProvider: keyProvider,
	}, nil
}

// CredentialCreateRequest contains the data needed to create a credential.
type CredentialCreateRequest struct {
	Name        string
	Type        types.CredentialType
	Provider    string
	APIKey      string // The plaintext API key to store (encrypted by CredentialOps)
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

// credentialConn acquires a per-tenant Conn from the pool and returns it.
// The caller is responsible for calling conn.Release().
func (h *CredentialHandler) credentialConn(ctx context.Context) (*datapool.Conn, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok || tenant.IsZero() {
		return nil, fmt.Errorf("credential handler: no tenant in context")
	}
	conn, err := h.pool.For(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("credential handler: acquire conn for tenant %s: %w", tenant, err)
	}
	return conn, nil
}

// Create creates a new credential. The APIKey is stored encrypted by CredentialOps.
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

	conn, err := h.credentialConn(ctx)
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to acquire connection", err)
	}
	defer conn.Release()

	if err := conn.Credentials().Put(ctx, req.Name, []byte(req.APIKey)); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to create credential", err)
	}

	now := time.Now()
	resp := &CredentialResponse{
		ID:        types.NewID(),
		Name:      req.Name,
		Type:      req.Type,
		Provider:  req.Provider,
		Status:    types.CredentialStatusActive,
		MaskedKey: maskAPIKey(req.APIKey),
		Tags:      req.Tags,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if resp.Tags == nil {
		resp.Tags = []string{}
	}
	return resp, nil
}

// Get retrieves a credential by ID. Since CredentialOps is name-keyed,
// this returns an unsupported-operation error; use GetByName.
func (h *CredentialHandler) Get(ctx context.Context, id types.ID) (*CredentialResponse, error) {
	// CredentialOps uses name as the primary key. ID-based lookup is not
	// supported in the per-tenant model. Callers must use GetByName.
	_ = id
	return nil, types.NewError(types.CREDENTIAL_NOT_FOUND, "lookup by ID is not supported; use GetByName")
}

// GetByName retrieves a credential by name.
func (h *CredentialHandler) GetByName(ctx context.Context, name string) (*CredentialResponse, error) {
	conn, err := h.credentialConn(ctx)
	if err != nil {
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "failed to acquire connection", err)
	}
	defer conn.Release()

	secret, err := conn.Credentials().Get(ctx, name)
	if err != nil {
		if errors.Is(err, dbpostgres.ErrCredentialNotFound) {
			return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
		}
		return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

	now := time.Now()
	return &CredentialResponse{
		ID:        types.NewID(),
		Name:      name,
		Status:    types.CredentialStatusActive,
		MaskedKey: maskAPIKey(string(secret)),
		Tags:      []string{},
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// GetDecrypted retrieves a credential with its plaintext value.
// This is for internal use only — never expose via API.
func (h *CredentialHandler) GetDecrypted(ctx context.Context, name string) (*types.Credential, string, error) {
	conn, err := h.credentialConn(ctx)
	if err != nil {
		return nil, "", types.WrapError(types.CREDENTIAL_NOT_FOUND, "failed to acquire connection", err)
	}
	defer conn.Release()

	secret, err := conn.Credentials().Get(ctx, name)
	if err != nil {
		return nil, "", types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
	}

	cred := &types.Credential{
		ID:   types.NewID(),
		Name: name,
	}
	return cred, string(secret), nil
}

// List retrieves credentials with optional filtering.
// CredentialOps exposes a name-ordered scan; filters are applied in-memory.
func (h *CredentialHandler) List(ctx context.Context, filter *types.CredentialFilter) ([]*CredentialResponse, error) {
	conn, err := h.credentialConn(ctx)
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to acquire connection", err)
	}
	defer conn.Release()

	names, err := conn.Credentials().ListNames(ctx, filter)
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to list credentials", err)
	}

	responses := make([]*CredentialResponse, 0, len(names))
	now := time.Now()
	for _, name := range names {
		responses = append(responses, &CredentialResponse{
			ID:        types.NewID(),
			Name:      name,
			Status:    types.CredentialStatusActive,
			MaskedKey: "****",
			Tags:      []string{},
			CreatedAt: now,
			UpdatedAt: now,
		})
	}
	return responses, nil
}

// Update updates an existing credential. Only the APIKey can be rotated in the
// per-tenant model; metadata updates (name, description, tags) are not supported
// by CredentialOps and are no-ops in this implementation.
func (h *CredentialHandler) Update(ctx context.Context, req CredentialUpdateRequest) (*CredentialResponse, error) {
	if req.APIKey == nil {
		return nil, types.NewError(types.CREDENTIAL_INVALID, "credential update: APIKey is required (metadata-only updates are not supported in Phase D)")
	}

	conn, err := h.credentialConn(ctx)
	if err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to acquire connection", err)
	}
	defer conn.Release()

	// Determine the name to update. If Name is provided, use it; otherwise we
	// cannot look up by ID in this model. This is a limitation of the bridge —
	// callers should provide the Name in the request.
	name := ""
	if req.Name != nil {
		name = *req.Name
	}
	if name == "" {
		return nil, types.NewError(types.CREDENTIAL_INVALID, "credential update: Name is required (ID-based update not supported in Phase D)")
	}

	if err := conn.Credentials().Put(ctx, name, []byte(*req.APIKey)); err != nil {
		return nil, types.WrapError(types.DB_QUERY_FAILED, "failed to update credential", err)
	}

	now := time.Now()
	return &CredentialResponse{
		ID:        types.NewID(),
		Name:      name,
		Status:    types.CredentialStatusActive,
		MaskedKey: maskAPIKey(*req.APIKey),
		Tags:      []string{},
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

// Delete deletes a credential by name.
// Since CredentialOps is name-keyed, DeleteByName is used.
func (h *CredentialHandler) Delete(ctx context.Context, id types.ID) error {
	// ID-based delete is not supported in CredentialOps. Callers should use
	// DeleteByName via the dashboard API RPC handler directly.
	_ = id
	return types.NewError(types.CREDENTIAL_NOT_FOUND, "delete by ID is not supported in Phase D; use DeleteByName")
}

// DeleteByName deletes a credential by name.
func (h *CredentialHandler) DeleteByName(ctx context.Context, name string) error {
	conn, err := h.credentialConn(ctx)
	if err != nil {
		return types.WrapError(types.CREDENTIAL_NOT_FOUND, "failed to acquire connection", err)
	}
	defer conn.Release()

	if err := conn.Credentials().Delete(ctx, name); err != nil {
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
