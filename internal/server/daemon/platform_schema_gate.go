// Copyright 2026 Hack the Planet LLC
// Licensed under the Apache License, Version 2.0 (the "License").

// platform_schema_gate.go — startup migration runner and version gate for
// the dashboard Postgres (gibson_platform) database.
//
// Phase 6.1 of the deploy-architecture-refactor spec moves platform-DB
// migrations out of the Helm pre-install Job and into the daemon's own
// startup sequence. On every boot the daemon:
//
//  1. Calls pgmigrations.Stamp to seed schema_migrations on legacy DBs
//     that were previously bootstrapped by the Helm psql Job.
//  2. Runs all pending migrations via golang-migrate Up (idempotent).
//  3. Asserts the resulting version >= PlatformMaxVersion (assertPlatformSchemaVersion).
//
// The escape hatch SKIP_MIGRATIONS=true bypasses step 2 (and 3) for
// emergencies. In that case the daemon logs a warning and continues.
//
// On migration failure initPlatformPostgres returns a non-nil error that
// Start() propagates (gibson#246), so the daemon never boots with a partially
// initialized platform-postgres. The pod exits non-zero; Kubernetes restarts
// with exponential backoff.
//
// Spec: gibson-postgres-migrations, deploy-architecture-refactor Phase 6.1.

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"

	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"
)

// runPlatformMigrations applies all pending platform migrations against db
// using the embedded pgmigrations.Platform source. It is idempotent: when
// no migrations are pending, Up returns migrate.ErrNoChange and the
// function returns nil.
//
// If SKIP_MIGRATIONS=true, the function logs a warning and returns nil
// without touching the database (operator escape hatch for emergencies).
//
// On any other failure the error is returned as-is; callers should treat
// it as fatal.
func runPlatformMigrations(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}

	if os.Getenv("SKIP_MIGRATIONS") == "true" {
		logger.WarnContext(ctx, "platform migrations skipped (SKIP_MIGRATIONS=true)")
		return nil
	}

	// Seed schema_migrations for legacy DBs that were bootstrapped by the
	// Helm psql Job before this migration runner existed.
	if err := pgmigrations.Stamp(ctx, db, pgmigrations.KindPlatform); err != nil {
		return fmt.Errorf("runPlatformMigrations: stamp legacy state: %w", err)
	}

	src, err := pgmigrations.NewPlatformSource()
	if err != nil {
		return fmt.Errorf("runPlatformMigrations: build source: %w", err)
	}
	defer src.Close()

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil {
		return fmt.Errorf("runPlatformMigrations: postgres migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, "platform", driver)
	if err != nil {
		return fmt.Errorf("runPlatformMigrations: migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("runPlatformMigrations: apply: %w", err)
	}

	v, dirty, vErr := m.Version()
	if vErr != nil && !errors.Is(vErr, migrate.ErrNilVersion) {
		logger.WarnContext(ctx, "platform migrations: could not read version after up", "error", vErr)
	} else {
		logger.InfoContext(ctx, "platform migrations applied", "version", v, "dirty", dirty)
	}
	return nil
}

// assertPlatformSchemaVersion queries schema_migrations and refuses
// boot when the platform DB is older than this binary's embedded
// migration set or the table is dirty. Returns nil on success.
//
// Behavioural contract per spec design Component 7:
//
//   - schema_migrations table missing → error (run gibson-migrate
//     platform up).
//   - dirty=true → error (manual intervention; run gibson-migrate
//     platform force <N> after manual repair).
//   - version < embedded max → error (chart shipped a daemon image
//     newer than the platform-db-migrate Job applied).
//   - version >= embedded max AND clean → nil.
func assertPlatformSchemaVersion(ctx context.Context, db *sql.DB, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	want, err := pgmigrations.PlatformMaxVersion()
	if err != nil {
		return fmt.Errorf("read embedded PlatformMaxVersion: %w", err)
	}

	var version uint
	var dirty bool
	row := db.QueryRowContext(ctx,
		`SELECT version, dirty FROM schema_migrations LIMIT 1`,
	)
	if err := row.Scan(&version, &dirty); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("schema_migrations row missing — run gibson-migrate platform up; embedded version=%d", want)
		}
		return fmt.Errorf("schema_migrations table unavailable — run gibson-migrate platform up; embedded version=%d: %w", want, err)
	}
	if dirty {
		return fmt.Errorf("schema_migrations dirty at version=%d — manual repair required (gibson-migrate platform force <N>)", version)
	}
	if version < want {
		return fmt.Errorf("platform schema version=%d < required %d — run gibson-migrate platform up", version, want)
	}
	logger.Info("platform schema gate satisfied",
		"version", version,
		"required", want,
	)
	return nil
}
