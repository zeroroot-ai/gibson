package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/types"
	sdksecrets "github.com/zeroroot-ai/platform-clients/secrets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CredentialHandler provides credential management operations for the daemon
// dashboard API. All operations delegate to secrets.Service which routes
// through the broker registry → circuit breaker → provider → audit pipeline.
//
// Phase 10 (secrets-broker, Task 27): refactored from pool-and-Conn direct
// call to secrets.Service. The TODO planted during Phase 2 is resolved.
type CredentialHandler struct {
	service *secrets.Service
}

// NewCredentialHandler creates a new broker-backed credential handler.
// service must not be nil.
func NewCredentialHandler(service *secrets.Service) (*CredentialHandler, error) {
	if service == nil {
		return nil, fmt.Errorf("credential handler: service must not be nil")
	}
	return &CredentialHandler{service: service}, nil
}

// CredentialCreateRequest contains the data needed to create a credential.
type CredentialCreateRequest struct {
	Name        string
	Type        types.CredentialType
	Provider    string
	APIKey      string // The plaintext API key to store (encrypted by the broker)
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

// Create creates a new credential. The APIKey is stored encrypted by the broker.
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

	if err := h.service.Put(ctx, req.Name, []byte(req.APIKey)); err != nil {
		return nil, mapServiceError(err, "failed to create credential")
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

// Get retrieves a credential by ID. Since the broker is name-keyed,
// this returns an unsupported-operation error; use GetByName.
func (h *CredentialHandler) Get(_ context.Context, _ types.ID) (*CredentialResponse, error) {
	return nil, types.NewError(types.CREDENTIAL_NOT_FOUND, "lookup by ID is not supported; use GetByName")
}

// GetByName retrieves a credential by name. The returned MaskedKey shows only
// prefix + suffix; the plaintext is not included in CredentialResponse.
func (h *CredentialHandler) GetByName(ctx context.Context, name string) (*CredentialResponse, error) {
	secret, err := h.service.Resolve(ctx, name)
	if err != nil {
		if isNotFound(err) {
			return nil, types.WrapError(types.CREDENTIAL_NOT_FOUND, "credential not found", err)
		}
		return nil, mapServiceError(err, "credential not found")
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
// This method is for internal/dashboard operator use only — access is gated
// by the existing FGA roles on the calling dashboard user's RPC path.
//
// SECURITY: never log or persist the returned secret string.
func (h *CredentialHandler) GetDecrypted(ctx context.Context, name string) (*types.Credential, string, error) {
	secret, err := h.service.Resolve(ctx, name)
	if err != nil {
		return nil, "", mapServiceError(err, "credential not found")
	}

	cred := &types.Credential{
		ID:   types.NewID(),
		Name: name,
	}
	return cred, string(secret), nil
}

// List retrieves credential names with optional filtering.
func (h *CredentialHandler) List(ctx context.Context, filter *types.CredentialFilter) ([]*CredentialResponse, error) {
	f := sdksecrets.Filter{}
	if filter != nil {
		f.Limit = filter.Limit
		f.Offset = filter.Offset
	}

	names, err := h.service.List(ctx, f)
	if err != nil {
		return nil, mapServiceError(err, "failed to list credentials")
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

// Update updates an existing credential. Only the APIKey can be rotated.
// If the underlying provider declares CanPut=false, a structured error is
// returned indicating that Update is not supported on this provider.
func (h *CredentialHandler) Update(ctx context.Context, req CredentialUpdateRequest) (*CredentialResponse, error) {
	if req.APIKey == nil {
		return nil, types.NewError(types.CREDENTIAL_INVALID, "credential update: APIKey is required (metadata-only updates are not supported)")
	}

	name := ""
	if req.Name != nil {
		name = *req.Name
	}
	if name == "" {
		return nil, types.NewError(types.CREDENTIAL_INVALID, "credential update: Name is required (ID-based update not supported)")
	}

	if err := h.service.Put(ctx, name, []byte(*req.APIKey)); err != nil {
		// Surface capability-level errors as a user-friendly message.
		if isUnsupported(err) {
			return nil, types.NewError(types.CREDENTIAL_INVALID, "Update not supported on read-only provider")
		}
		return nil, mapServiceError(err, "failed to update credential")
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

// Delete deletes a credential by ID. Use DeleteByName instead.
func (h *CredentialHandler) Delete(_ context.Context, _ types.ID) error {
	return types.NewError(types.CREDENTIAL_NOT_FOUND, "delete by ID is not supported; use DeleteByName")
}

// DeleteByName deletes a credential by name.
func (h *CredentialHandler) DeleteByName(ctx context.Context, name string) error {
	if err := h.service.Delete(ctx, name); err != nil {
		return mapServiceError(err, "credential not found")
	}
	return nil
}

// Exists returns true when a credential with the given name exists in the broker.
func (h *CredentialHandler) Exists(ctx context.Context, name string) (bool, error) {
	_, err := h.service.Resolve(ctx, name)
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, mapServiceError(err, "exists check failed")
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// mapServiceError translates a secrets.Service gRPC status error to a types.Error.
// The op string is used only in the wrapper message; credential material must
// never appear in op.
func mapServiceError(err error, op string) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return types.WrapError(types.CREDENTIAL_NOT_FOUND, op, err)
		case codes.FailedPrecondition:
			return types.WrapError(types.CREDENTIAL_INVALID, op, err)
		default:
			return types.WrapError(types.DB_QUERY_FAILED, op, err)
		}
	}
	return types.WrapError(types.DB_QUERY_FAILED, op, err)
}

// isNotFound reports whether err signals a not-found condition from secrets.Service.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.NotFound
	}
	return errors.Is(err, sdksecrets.ErrNotFound)
}

// isUnsupported reports whether err signals an unsupported operation from secrets.Service.
func isUnsupported(err error) bool {
	if err == nil {
		return false
	}
	if st, ok := status.FromError(err); ok {
		return st.Code() == codes.FailedPrecondition
	}
	return errors.Is(err, sdksecrets.ErrUnsupported)
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
