package component

// secrets_credential_store.go provides a broker-backed implementation of the
// component.CredentialStore interface. It delegates to secrets.Service.Resolve,
// wraps the returned plaintext bytes in a credential JSON envelope, and returns
// the bytes to satisfy the component wire format.
//
// Wire format: the credential_json field in GetCredentialResponse is a JSON
// object with fields id, name, and value (plaintext string). The ADK parses
// this envelope to extract the secret. SECURITY: this is the only path that
// legitimately exposes the plaintext to a plugin/agent.
//
// Phase 10 (secrets-broker, Task 26).

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// credentialJSONEnvelope is the JSON shape written to GetCredentialResponse.credential_json.
// The value field carries the plaintext secret. The ADK and legacy component
// clients read this shape — do not change field names.
type credentialJSONEnvelope struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Value string `json:"value"` // plaintext — SECURITY: never log this field
}

// SecretsCredentialStore implements component.CredentialStore by delegating
// to secrets.Service.Resolve. The explicit tenant parameter is accepted for
// interface compatibility but is not forwarded to the service — tenant is
// extracted from the request context by secrets.Service directly, which
// prevents callers from bypassing tenant isolation.
type SecretsCredentialStore struct {
	service *secrets.Service
}

// NewSecretsCredentialStore constructs a SecretsCredentialStore.
// service must not be nil.
func NewSecretsCredentialStore(service *secrets.Service) (*SecretsCredentialStore, error) {
	if service == nil {
		return nil, fmt.Errorf("component credential store: service must not be nil")
	}
	return &SecretsCredentialStore{service: service}, nil
}

// GetCredential resolves the named secret for the tenant in ctx and returns a
// JSON-encoded types.Credential containing the plaintext value.
//
// The tenant parameter is accepted for interface compatibility. The actual
// tenant resolution is performed inside secrets.Service from the context,
// which is the authoritative source and cannot be spoofed by callers.
//
// SECURITY: the returned JSON contains the plaintext secret. Do not log it.
func (s *SecretsCredentialStore) GetCredential(ctx context.Context, _ string, name string) ([]byte, error) {
	secretBytes, err := s.service.Resolve(ctx, name)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			if st.Code() == codes.NotFound {
				return nil, fmt.Errorf("credential %q not found", name)
			}
		}
		return nil, fmt.Errorf("component credential store: resolve %q: %w", name, err)
	}

	// Wrap the plaintext bytes in the credential JSON envelope and marshal.
	// SECURITY: the returned JSON contains the plaintext. Do not log it.
	envelope := credentialJSONEnvelope{
		ID:    types.NewID().String(),
		Name:  name,
		Value: string(secretBytes),
	}
	out, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("component credential store: marshal credential %q: %w", name, err)
	}
	return out, nil
}

// Ensure SecretsCredentialStore implements CredentialStore.
var _ CredentialStore = (*SecretsCredentialStore)(nil)
