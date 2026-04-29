package daemon

import (
	"context"
	"fmt"

	"github.com/zero-day-ai/gibson/internal/harness"
	"github.com/zero-day-ai/gibson/internal/secrets"
	"github.com/zero-day-ai/gibson/internal/types"
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

// GetCredential retrieves a credential by name for the tenant in context.
// It delegates to secrets.Service.Resolve and wraps the returned bytes as a
// types.Credential value. The decrypted plaintext secret is returned as the
// second return value.
//
// SECURITY: never log or persist the returned secret string.
func (s *DaemonCredentialStore) GetCredential(ctx context.Context, name string) (*types.Credential, string, error) {
	secretBytes, err := s.service.Resolve(ctx, name)
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
	// The harness only uses Name and the plaintext secret; other fields
	// are not required by the CredentialStore interface contract.
	cred := &types.Credential{
		ID:   types.NewID(),
		Name: name,
	}
	return cred, string(secretBytes), nil
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
