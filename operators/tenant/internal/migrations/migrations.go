// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package migrations runs the operator's platform-side Postgres
// schema migrations at startup, before the controller-runtime manager
// begins reconciling. The migration source is embed.FS-bundled so
// nothing outside the binary needs to be kept in sync.
//
// What "platform" means here: schema on the operator's dedicated
// control-plane Postgres (PLATFORM_PG_DSN → gibson_platform database),
// NOT the per-tenant databases and NOT the postgres default admin DB.
// Per-tenant migrations are run by internal/dataplane/postgres.go
// against the SDK's gibson/pkg/platform/migrations.Tenant embed.FS.
//
// Migration tracking uses MigrationsTable ("platform_op_schema_migrations")
// to avoid colliding with the dataplane provisioner's own schema_migrations
// table that already exists in gibson_platform at version 4.
//
// PRD module: zeroroot-ai/tenant-operator#76 Module 5 / issue #85.
// Structural fix: zeroroot-ai/tenant-operator#258.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// MigrationsTable is the name of the golang-migrate bookkeeping table
// used for this migration set. It is distinct from "schema_migrations"
// (used by the dataplane provisioner in the same gibson_platform DB) to
// avoid version-counter collision.
const MigrationsTable = "platform_op_schema_migrations"

//go:embed all:files
var platformFS embed.FS

// Run applies every embedded *.up.sql migration that has not been
// applied to the database described by dsn. golang-migrate's
// schema_migrations bookkeeping makes this idempotent — re-running on
// an up-to-date database is a no-op.
//
// dbName is used only for the database-name argument to
// migrate.NewWithInstance; the connection string in dsn determines
// which database is actually connected to. Pass an empty string and
// the runner derives it from dsn.
//
// Returns nil on success including ErrNoChange. Any other golang-
// migrate error (parse failure, SQL execution failure, dirty state)
// surfaces wrapped; the caller (cmd/main.go) is expected to fail the
// pod's readiness probe so the bad pod is visible in
// `kubectl get pod` rather than hidden inside a per-tenant saga.
func Run(ctx context.Context, dsn string) error {
	if dsn == "" {
		return errors.New("migrations: empty DSN")
	}

	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return fmt.Errorf("migrations: parse dsn: %w", err)
	}
	db := stdlib.OpenDB(*cfg)
	defer func() { _ = db.Close() }()

	// Use a short context just for the connectivity check; the actual
	// Up() call has its own internal timeout via lock-acquisition.
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("migrations: ping platform db: %w", err)
	}

	src, err := iofs.New(platformFS, "files")
	if err != nil {
		return fmt.Errorf("migrations: open embedded source: %w", err)
	}
	defer func() { _ = src.Close() }()

	dbName := cfg.Database
	if dbName == "" {
		return errors.New("migrations: dsn has no database name")
	}

	driver, err := migratepg.WithInstance(db, &migratepg.Config{
		DatabaseName:    dbName,
		MigrationsTable: MigrationsTable,
	})
	if err != nil {
		return fmt.Errorf("migrations: postgres driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, dbName, driver)
	if err != nil {
		return fmt.Errorf("migrations: migrate instance: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	return runUp(m)
}

// RunWithDB is the constructor-injection variant of Run for tests that
// already hold a *sql.DB they want to migrate. Production callers
// should use Run with the DSN — RunWithDB skips the connectivity check
// since the test fixture owns the connection lifecycle.
func RunWithDB(_ context.Context, db *sql.DB, dbName string) error {
	if db == nil {
		return errors.New("migrations: nil db")
	}
	if dbName == "" {
		return errors.New("migrations: dbName required")
	}
	src, err := iofs.New(platformFS, "files")
	if err != nil {
		return fmt.Errorf("migrations: open embedded source: %w", err)
	}
	defer func() { _ = src.Close() }()

	driver, err := migratepg.WithInstance(db, &migratepg.Config{
		DatabaseName:    dbName,
		MigrationsTable: MigrationsTable,
	})
	if err != nil {
		return fmt.Errorf("migrations: postgres driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, dbName, driver)
	if err != nil {
		return fmt.Errorf("migrations: migrate instance: %w", err)
	}
	defer func() { _, _ = m.Close() }()
	return runUp(m)
}

// runUp calls m.Up() and recovers from dirty migration state. If a pod
// is killed mid-migration, golang-migrate leaves schema_migrations with
// dirty=true. On the next startup m.Up() returns ErrDirty rather than
// running; we force back to version N-1 so the dirty migration can
// re-run from scratch. All our migrations use IF EXISTS / IF NOT EXISTS
// so re-running is always safe.
func runUp(m *migrate.Migrate) error {
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		var dirtyErr migrate.ErrDirty
		if errors.As(err, &dirtyErr) {
			// Force back to the last clean version so the dirty migration
			// re-runs from the beginning on retry. Migrations start at
			// version 1; version 0 does not exist in the source. When the
			// dirty version is 1 (the very first migration), we force to
			// -1 (NilVersion) so m.Up() treats the database as completely
			// uninitialized and re-runs from the first migration.
			prevVersion := dirtyErr.Version - 1
			if prevVersion <= 0 {
				prevVersion = -1 // database.NilVersion
			}
			if forceErr := m.Force(prevVersion); forceErr != nil {
				return fmt.Errorf("migrations: force to %d after dirty version %d: %w", prevVersion, dirtyErr.Version, forceErr)
			}
			if retryErr := m.Up(); retryErr != nil && !errors.Is(retryErr, migrate.ErrNoChange) {
				return fmt.Errorf("migrations: up after dirty recovery (version %d): %w", dirtyErr.Version, retryErr)
			}
			return nil
		}
		return fmt.Errorf("migrations: up: %w", err)
	}
	return nil
}

// EmbeddedFiles returns the names of all *.sql files bundled into the
// binary. Test-only — used by the embedding contract test to assert
// that adding a file under migrations/ at module-root level is also
// reflected here (would be a foot-gun otherwise — embed.FS only sees
// what //go:embed names).
func EmbeddedFiles() ([]string, error) {
	dirEntries, err := platformFS.ReadDir("files")
	if err != nil {
		return nil, fmt.Errorf("migrations: read embedded dir: %w", err)
	}
	names := make([]string, 0, len(dirEntries))
	for _, e := range dirEntries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
