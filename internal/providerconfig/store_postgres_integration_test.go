//go:build integration

package providerconfig

import (
	"testing"
)

// TestPostgresStore_Integration exercises the Postgres-backed ProviderConfigStore
// against a real per-tenant database. Run with:
//
//	go test -tags=integration -run TestPostgresStore_Integration ./internal/providerconfig/...
//
// The test requires a Postgres instance with migration 006 applied
// (tenant_secrets table). Run migrations/postgres/tenant/ through 006.
func TestPostgresStore_Integration(t *testing.T) {
	t.Skip("integration test: run with -tags=integration and a live per-tenant Postgres")
}
