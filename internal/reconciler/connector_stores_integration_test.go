//go:build integration
// +build integration

// Package reconciler — connector_stores_integration_test.go
//
// Integration tests for the Postgres connector manifest store and sandbox
// inventory (gibson#722) against a real Postgres container (testcontainers-go
// over TLS, matching the rest of the daemon's DB tests). Skipped gracefully
// when Docker is unavailable.
//
// Run with:
//
//	go test -tags integration ./internal/reconciler/...
package reconciler

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"

	"github.com/zeroroot-ai/gibson/tests/testhelpers"
	"github.com/zeroroot-ai/sdk/auth"
)

const (
	pgUser     = "testuser"
	pgPassword = "testpassword"
	pgDB       = "testconnector"
)

// setupConnectorPostgres starts an ephemeral Postgres, creates the connector
// tables (migrations 012/013), and returns a ready *sql.DB.
func setupConnectorPostgres(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	pg := testhelpers.StartPostgresTLS(t, testhelpers.PostgresOptions{
		User:     pgUser,
		Password: pgPassword,
		Database: pgDB,
	})

	db, err := sql.Open("postgres", pg.DSN)
	require.NoError(t, err, "open Postgres connection")
	t.Cleanup(func() { _ = db.Close() })

	require.Eventually(t, func() bool {
		return db.PingContext(ctx) == nil
	}, 30*time.Second, 200*time.Millisecond, "Postgres did not become ready")

	// Migrations 012 + 013 (kept in sync with
	// pkg/platform/migrations/postgres/platform/012_*, 013_*).
	for _, ddl := range []string{
		`CREATE TABLE connector_manifest (
			tenant_id      TEXT NOT NULL,
			connector_name TEXT NOT NULL,
			manifest_yaml  BYTEA NOT NULL,
			updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, connector_name))`,
		`CREATE TABLE connector_sandbox (
			tenant_id      TEXT NOT NULL,
			connector_name TEXT NOT NULL,
			sandbox_id     TEXT NOT NULL,
			launched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (tenant_id, connector_name))`,
	} {
		_, err := db.ExecContext(ctx, ddl)
		require.NoError(t, err, "create connector tables")
	}
	return db
}

func TestPostgresManifestStore_PutGetAndUpsert(t *testing.T) {
	ctx := context.Background()
	db := setupConnectorPostgres(t)
	store := NewPostgresConnectorManifestStore(db)
	acme := auth.MustNewTenantID("acme")

	// Absent → not found.
	_, found, err := store.ConnectorManifest(ctx, acme, "connector-gitlab")
	require.NoError(t, err)
	require.False(t, found, "no manifest should be on record yet")

	// Put → found, exact bytes.
	require.NoError(t, store.Put(ctx, acme, "connector-gitlab", []byte("v1")))
	got, found, err := store.ConnectorManifest(ctx, acme, "connector-gitlab")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, []byte("v1"), got)

	// Re-Put upserts (one row, latest value).
	require.NoError(t, store.Put(ctx, acme, "connector-gitlab", []byte("v2")))
	got, _, err = store.ConnectorManifest(ctx, acme, "connector-gitlab")
	require.NoError(t, err)
	require.Equal(t, []byte("v2"), got)
}

func TestPostgresManifestStore_SystemFallbackForSharedConnector(t *testing.T) {
	ctx := context.Background()
	db := setupConnectorPostgres(t)
	store := NewPostgresConnectorManifestStore(db)

	// Seed a shared definition under the _system owner directly (a real
	// shared publish writes this row, gibson#725). A tenant with no row of
	// its own resolves the manifest via the _system fallback.
	_, err := db.ExecContext(ctx,
		`INSERT INTO connector_manifest (tenant_id, connector_name, manifest_yaml) VALUES ($1,$2,$3)`,
		systemTenantID, "connector-shared", []byte("shared-def"))
	require.NoError(t, err)

	got, found, err := store.ConnectorManifest(ctx, auth.MustNewTenantID("globex"), "connector-shared")
	require.NoError(t, err)
	require.True(t, found, "shared connector must resolve via _system fallback")
	require.Equal(t, []byte("shared-def"), got)
}

func TestPostgresSandboxInventory_IdempotentAndSurvivesReopen(t *testing.T) {
	ctx := context.Background()
	db := setupConnectorPostgres(t)
	inv := NewPostgresConnectorSandboxInventory(db)
	acme := auth.MustNewTenantID("acme")

	// First launch recorded.
	require.NoError(t, inv.Put(ctx, InventoryEntry{Tenant: acme, Connector: "connector-gitlab", SandboxID: "sb-1"}))
	// Re-Put the same pair (e.g. a re-launch) upserts, not duplicates.
	require.NoError(t, inv.Put(ctx, InventoryEntry{Tenant: acme, Connector: "connector-gitlab", SandboxID: "sb-2"}))

	list, err := inv.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1, "one row per (tenant, connector)")
	require.Equal(t, "sb-2", list[0].SandboxID)

	// A fresh store over the same DB (simulating a daemon restart) reads it
	// back — the inventory is durable, not in-memory.
	reopened := NewPostgresConnectorSandboxInventory(db)
	list, err = reopened.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Equal(t, acme.String(), list[0].Tenant.String())
}
