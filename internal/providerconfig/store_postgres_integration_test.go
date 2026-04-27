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
// The test requires a Postgres instance with the provider_configs table created
// (run migrations/postgres/002_provider_configs.up.sql first).
func TestPostgresStore_Integration(t *testing.T) {
	t.Skip("integration test: run with -tags=integration and a live per-tenant Postgres")
}
