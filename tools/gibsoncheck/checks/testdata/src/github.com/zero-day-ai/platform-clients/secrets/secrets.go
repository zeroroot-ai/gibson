// Package secrets is a stub for analysistest fixtures used by the
// secretsnolog analyzer tests (platform-clients surface).
package secrets

import "context"

// TenantID is a stub type matching auth.TenantID.
type TenantID string

// SecretsBroker is a stub matching the real platform-clients secrets interface.
// The test fixtures depend on this type to give the type checker enough
// information for the secretsnolog analyzer to resolve Get call sites.
type SecretsBroker interface {
	Get(ctx context.Context, tenant TenantID, name string) ([]byte, error)
	Put(ctx context.Context, tenant TenantID, name string, value []byte) error
}

// Service is a stub for the platform-clients secrets.Service type.
type Service struct{}

// Resolve is a stub for Service.Resolve.
func (s *Service) Resolve(ctx context.Context, name string) ([]byte, error) {
	return nil, nil
}
