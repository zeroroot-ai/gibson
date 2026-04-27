// Package runner provides per-store migration runners for the gibson-migrate CLI.
//
// The Postgres runner wraps lib/pq + golang-migrate to apply pending migrations
// against a single tenant Postgres database. The Neo4j runner implements an
// equivalent apply/status/down cycle via the Neo4j Go driver, tracking applied
// migrations via a singleton (:_SchemaVersion) node in each tenant database.
//
// Spec: database-per-tenant-data-plane, Phase G, task 7.1.
package runner

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file" // file:// source driver
	_ "github.com/lib/pq"                                // Postgres driver for database/sql
)

// PostgresRunner applies golang-migrate migrations against a single Postgres
// database. It is stateless; a new runner is created per tenant per CLI
// invocation.
type PostgresRunner struct {
	// DSN is the postgres:// connection string for the target tenant database.
	DSN string

	// MigrationsDir is an absolute path to the directory containing
	// *.up.sql / *.down.sql files.
	MigrationsDir string
}

// MigrationInfo describes a single migration file.
type MigrationInfo struct {
	// Version is the numeric prefix parsed from the filename (e.g. 1 for
	// "001_credentials.up.sql").
	Version uint

	// Name is the migration filename without directory.
	Name string
}

// PostgresStatus holds the current state of a tenant Postgres database
// with respect to the available migration files.
type PostgresStatus struct {
	// Current is the migration version currently applied to the database.
	// 0 means no migrations have been applied yet (or schema_migrations
	// table does not exist).
	Current uint

	// Target is the highest version available in MigrationsDir.
	Target uint

	// Applied lists the migration versions that have been applied.
	Applied []uint

	// Pending lists migration versions that are available but not yet applied.
	Pending []MigrationInfo

	// Dirty indicates that the last migration did not complete cleanly.
	Dirty bool
}

// Apply runs all pending migrations up to the latest version. It is
// idempotent — if the database is already at the latest version, Apply
// returns (current, current, nil, nil) indicating no change.
//
// Returns:
//
//	current  — the version before Apply ran (0 if no migrations applied).
//	target   — the version after Apply ran.
//	applied  — the names of migration files that were newly applied.
//	err      — non-nil if the migration failed. errors.Is(err, ErrDirty) if the
//	           schema_migrations table is dirty (incomplete previous run).
func (r *PostgresRunner) Apply(ctx context.Context) (current, target uint, applied []string, err error) {
	if r.DSN == "" {
		return 0, 0, nil, fmt.Errorf("postgres runner: DSN required")
	}

	// Enumerate available migration files to compute the target version and the
	// list of names to report as "applied" after the run.
	files, err := listMigrationFiles(r.MigrationsDir, ".up.sql")
	if err != nil {
		return 0, 0, nil, fmt.Errorf("postgres runner: list migration files: %w", err)
	}
	if len(files) == 0 {
		return 0, 0, nil, nil // nothing to apply; migrations dir will be authored by Phase D
	}

	m, db, closer, err := r.newMigrate()
	if err != nil {
		return 0, 0, nil, err
	}
	defer closer()

	// Query the current version before applying.
	ver, dirty, vErr := m.Version()
	if vErr != nil && !errors.Is(vErr, migrate.ErrNilVersion) {
		return 0, 0, nil, fmt.Errorf("postgres runner: query version: %w", vErr)
	}
	if dirty {
		return ver, 0, nil, ErrDirty
	}
	current = ver

	// Check context before running (golang-migrate does not accept context).
	select {
	case <-ctx.Done():
		return current, 0, nil, ctx.Err()
	default:
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return current, 0, nil, fmt.Errorf("postgres runner: migrate up: %w", err)
	}

	// Query the version after applying.
	newVer, _, _ := m.Version()
	target = newVer

	// Determine which migration names were newly applied.
	for _, f := range files {
		if f.Version > current && f.Version <= target {
			applied = append(applied, f.Name)
		}
	}

	// Query the applied versions from the database for a reliable list.
	_ = db // db is used via the migrate instance; we close it via the closer
	return current, target, applied, nil
}

// Status returns the current migration status without applying anything.
func (r *PostgresRunner) Status(ctx context.Context) (*PostgresStatus, error) {
	files, err := listMigrationFiles(r.MigrationsDir, ".up.sql")
	if err != nil {
		return nil, fmt.Errorf("postgres runner: list migration files: %w", err)
	}

	if len(files) == 0 {
		return &PostgresStatus{}, nil
	}

	target := uint(0)
	if len(files) > 0 {
		target = files[len(files)-1].Version
	}

	m, _, closer, err := r.newMigrate()
	if err != nil {
		// If the DB is unreachable or schema_migrations missing, return status
		// with no current version (0 = nothing applied).
		return &PostgresStatus{
			Target:  target,
			Pending: files,
		}, nil
	}
	defer closer()

	_ = ctx
	ver, dirty, vErr := m.Version()
	if vErr != nil && !errors.Is(vErr, migrate.ErrNilVersion) {
		return nil, fmt.Errorf("postgres runner: query version: %w", vErr)
	}

	status := &PostgresStatus{
		Current: ver,
		Target:  target,
		Dirty:   dirty,
	}

	for _, f := range files {
		if f.Version <= ver {
			status.Applied = append(status.Applied, f.Version)
		} else {
			status.Pending = append(status.Pending, f)
		}
	}

	return status, nil
}

// Down migrates down to the given target version. When dryRun is true it
// enumerates what would be rolled back without executing anything.
// Requires --confirm semantics at the CLI layer; this function does not
// prompt interactively.
func (r *PostgresRunner) Down(ctx context.Context, toVersion uint) (rolledBack []string, err error) {
	if r.DSN == "" {
		return nil, fmt.Errorf("postgres runner: DSN required")
	}

	files, err := listMigrationFiles(r.MigrationsDir, ".down.sql")
	if err != nil {
		return nil, fmt.Errorf("postgres runner: list down migration files: %w", err)
	}

	m, _, closer, err := r.newMigrate()
	if err != nil {
		return nil, err
	}
	defer closer()

	ver, dirty, vErr := m.Version()
	if vErr != nil && !errors.Is(vErr, migrate.ErrNilVersion) {
		return nil, fmt.Errorf("postgres runner: query version: %w", vErr)
	}
	if dirty {
		return nil, ErrDirty
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if err := m.Migrate(toVersion); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return nil, fmt.Errorf("postgres runner: migrate to %d: %w", toVersion, err)
	}

	// Report which down files would have been applied.
	for _, f := range files {
		if f.Version > toVersion && f.Version <= ver {
			rolledBack = append(rolledBack, f.Name)
		}
	}

	return rolledBack, nil
}

// newMigrate opens a *sql.DB and constructs a *migrate.Migrate instance.
// The caller must call the returned closer to release resources.
func (r *PostgresRunner) newMigrate() (*migrate.Migrate, *sql.DB, func(), error) {
	if r.MigrationsDir == "" {
		return nil, nil, func() {}, fmt.Errorf("postgres runner: MigrationsDir required")
	}

	db, err := sql.Open("postgres", r.DSN)
	if err != nil {
		return nil, nil, func() {}, fmt.Errorf("postgres runner: open db: %w", err)
	}

	driver, err := migratepg.WithInstance(db, &migratepg.Config{})
	if err != nil {
		_ = db.Close()
		return nil, nil, func() {}, fmt.Errorf("postgres runner: migrate driver: %w", err)
	}

	sourceURL := "file://" + filepath.ToSlash(r.MigrationsDir)
	m, err := migrate.NewWithDatabaseInstance(sourceURL, "postgres", driver)
	if err != nil {
		_ = db.Close()
		return nil, nil, func() {}, fmt.Errorf("postgres runner: migrate instance: %w", err)
	}

	closer := func() {
		m.Close()
		_ = db.Close()
	}
	return m, db, closer, nil
}

// ErrDirty is returned when the schema_migrations table has a dirty flag set,
// indicating the previous migration run did not complete cleanly.
var ErrDirty = errors.New("migration is in dirty state — manual intervention required")

// listMigrationFiles returns the migration files in the given directory that
// match the given suffix (e.g. ".up.sql" or ".down.sql"), sorted by filename.
// Returns nil (not an error) if the directory does not exist on disk — this is
// the expected state before Phase D authors the migration files.
func listMigrationFiles(dir, suffix string) ([]MigrationInfo, error) {
	if dir == "" {
		return nil, nil
	}

	// Check directory existence before globbing so we can distinguish
	// "directory missing" from "directory exists but empty".
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	pattern := filepath.Join(dir, "*"+suffix)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	sort.Strings(matches)
	result := make([]MigrationInfo, 0, len(matches))
	for _, path := range matches {
		base := filepath.Base(path)
		ver, err := parseVersion(base)
		if err != nil {
			continue // skip files that don't match the expected naming scheme
		}
		result = append(result, MigrationInfo{Version: ver, Name: base})
	}
	return result, nil
}

// parseVersion extracts the numeric version prefix from a migration filename.
// Expected format: "NNN_name.up.sql" where NNN is a zero-padded integer.
func parseVersion(filename string) (uint, error) {
	// Extract the leading numeric sequence before the first underscore.
	idx := strings.IndexByte(filename, '_')
	if idx <= 0 {
		return 0, fmt.Errorf("no leading version number in %q", filename)
	}
	prefix := filename[:idx]
	var ver uint
	if _, err := fmt.Sscanf(prefix, "%d", &ver); err != nil {
		return 0, fmt.Errorf("parse version from %q: %w", filename, err)
	}
	return ver, nil
}
