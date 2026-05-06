// Copyright 2026 Zero Day AI.
// Licensed under the Apache License, Version 2.0 (the "License").

// platform_schema_gate.go — startup-gate that verifies the dashboard
// Postgres `schema_migrations.version` matches the embedded
// PlatformMaxVersion. Spec gibson-postgres-migrations Requirement 5.

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	pgmigrations "github.com/zero-day-ai/gibson/pkg/platform/migrations"
)

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
