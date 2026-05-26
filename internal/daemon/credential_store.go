package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/harness"
	"github.com/zeroroot-ai/gibson/internal/secrets"
	"github.com/zeroroot-ai/gibson/internal/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DaemonCredentialStore implements harness.CredentialStore by delegating to
// secrets.Service.Resolve. All broker routing (registry → circuit breaker →
// provider → audit) happens inside the service; this type is a thin adapter
// that maps the gRPC status errors returned by the service to the error shape
// the harness expects.
//
// Phase 10 (secrets-broker, Task 24): refactored from pool-and-Conn direct
// call to secrets.Service.Resolve.
type DaemonCredentialStore struct {
	service *secrets.Service
}

// NewDaemonCredentialStore creates a new service-backed credential store.
// service must not be nil.
func NewDaemonCredentialStore(service *secrets.Service) (*DaemonCredentialStore, error) {
	if service == nil {
		return nil, fmt.Errorf("credential store: service must not be nil")
	}
	return &DaemonCredentialStore{service: service}, nil
}

// userSecretPrefix is the Vault KV sub-path under which user-supplied secrets
// are stored. It must stay in sync with admin.userPrefix in
// internal/admin/secrets_admin.go. The Vault ACL enforced by tenant-operator#271
// separates "user/*" (plugin-readable creds) from "infra/*" (operator-only).
//
// Spec: secrets-blast-radius-reduction / gibson#404.
const userSecretPrefix = "user/"

// GetCredential retrieves a credential by name for the tenant in context.
// The caller-facing name (e.g. "cred:openai-prod") is stored in Vault under
// "user/<name>" (e.g. "user/cred:openai-prod"). The prefix is prepended here
// so that plugin GetCredential calls resolve from the correct Vault path.
// It delegates to secrets.Service.Resolve and wraps the returned bytes as a
// types.Credential value. The decrypted plaintext secret is returned as the
// second return value.
//
// SECURITY: never log or persist the returned secret string.
func (s *DaemonCredentialStore) GetCredential(ctx context.Context, name string) (*types.Credential, string, error) {
	// Prepend "user/" when the name carries a known user-secret category prefix
	// but hasn't already been stored-form-encoded. Infra secrets (e.g.
	// "infra/postgres") do not carry "cred:" / "provider_config:" so they pass
	// through unchanged — the broker serves them from their root mount path.
	storedName := name
	if !hasUserPrefix(name) && isUserSecretName(name) {
		storedName = userSecretPrefix + name
	}
	secretBytes, err := s.service.Resolve(ctx, storedName)
	if err != nil {
		// secrets.Service returns gRPC status errors. Map NotFound to a
		// user-facing message; surface others directly.
		if st, ok := status.FromError(err); ok {
			if st.Code() == codes.NotFound {
				return nil, "", fmt.Errorf("credential %q not found", name)
			}
			return nil, "", fmt.Errorf("credential store: %s: %v", st.Code(), st.Message())
		}
		return nil, "", fmt.Errorf("credential store: resolve %q: %w", name, err)
	}

	// Build a minimal Credential for the harness API.
	// Return the caller-facing name (not the stored form with "user/") so the
	// harness and plugins see the name they originally provided.
	cred := &types.Credential{
		ID:   types.NewID(),
		Name: name,
	}
	return cred, string(secretBytes), nil
}

// hasUserPrefix reports whether name already starts with the userSecretPrefix.
func hasUserPrefix(name string) bool {
	return len(name) > len(userSecretPrefix) && name[:len(userSecretPrefix)] == userSecretPrefix
}

// isUserSecretName reports whether name should be namespaced under "user/" in
// Vault. Only names that start with known user-secret category prefixes qualify;
// infra paths (e.g. "infra/postgres") do not.
func isUserSecretName(name string) bool {
	return len(name) > 5 && (name[:5] == "cred:" || hasProviderConfigPrefix(name))
}

// hasProviderConfigPrefix reports whether name starts with "provider_config:".
func hasProviderConfigPrefix(name string) bool {
	const p = "provider_config:"
	return len(name) >= len(p) && name[:len(p)] == p
}

// Health returns a healthy status. The broker stack's health is tracked
// separately via the registry; this store is a pass-through.
func (s *DaemonCredentialStore) Health(_ context.Context) types.HealthStatus {
	return types.HealthStatus{State: types.HealthStateHealthy, Message: "broker-backed"}
}

// Close is a no-op. The secrets.Service lifecycle is managed by the daemon.
func (s *DaemonCredentialStore) Close() error {
	return nil
}

// Ensure DaemonCredentialStore implements harness.CredentialStore.
var _ harness.CredentialStore = (*DaemonCredentialStore)(nil)
