// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"fmt"

	"github.com/zeroroot-ai/gibson/internal/engine/harness"
	"github.com/zeroroot-ai/gibson/internal/infra/types"
	"github.com/zeroroot-ai/gibson/internal/platform/secrets"
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
// The caller-facing name (e.g. "cred:openai-prod") is the stored name:
// tenant secrets live colon-flat at the KV root, the layout SetSecret writes
// and ComponentService's SecretsCredentialStore reads (gibson#1106). This
// store used to prepend the retired "user/" sub-path, so every plugin's
// startup secret resolved to a key nothing wrote and the first plugin on
// kind died with "credential not found" seconds after SetSecret succeeded
// (gibson#154, run 35635251315).
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
	// Return the caller-facing name (not the stored form with "user/") so the
	// harness and plugins see the name they originally provided.
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
