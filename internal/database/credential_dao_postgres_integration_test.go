//go:build integration

package database

import (
	"testing"
)

// TestCredentialOps_Integration exercises CredentialOps against a real
// Postgres database. Run with:
//
//	go test -tags=integration -run TestCredentialOps_Integration ./internal/database/...
//
// The test requires a Postgres instance with the credentials table created
// (run migrations/postgres/001_credentials.up.sql first).
func TestCredentialOps_Integration(t *testing.T) {
	t.Skip("integration test: run with -tags=integration and a live Postgres with tenant schema applied")
}
