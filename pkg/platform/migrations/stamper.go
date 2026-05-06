// stamper.go — one-shot reconciler that detects existing kind / dev
// clusters whose schema was applied by hand-rolled `psql -f` (the
// pre-spec state) and stamps them with the correct
// schema_migrations row so subsequent golang-migrate up runs become
// no-ops instead of re-applying SQL that's already on disk.
//
// Spec: gibson-postgres-migrations Requirement 1.4 + design
// Component 4 + Error Scenarios 1, 2.

package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Kind selects which DB the stamper reconciles against.
type Kind string

const (
	// KindTenant — per-tenant Postgres database (`tenant_<slug>`).
	// Fingerprint table: `tenant_secrets`. Stamps to TenantMaxVersion()
	// when the fingerprint is present.
	KindTenant Kind = "tenant"

	// KindPlatform — dashboard / control-plane Postgres database.
	// Fingerprint table: `tenant_secrets_broker_config`. Stamps to
	// PlatformMaxVersion() when the fingerprint is present.
	KindPlatform Kind = "platform"
)

// Stamp inserts the appropriate schema_migrations row when the DB
// is detected to be in legacy-applied state (fingerprint table
// present but schema_migrations table absent). All other states
// are no-ops:
//
//   - schema_migrations exists already → return nil; golang-migrate
//     handles version reconciliation natively.
//   - schema_migrations absent AND fingerprint absent → fresh DB;
//     return nil; golang-migrate's first up will create the table.
//   - schema_migrations absent AND fingerprint present → CREATE the
//     table and INSERT one row stamping the appropriate version
//     (TenantMaxVersion() or PlatformMaxVersion()).
//
// The stamping write is wrapped in a single transaction.
//
// Stamp is idempotent and safe to call before every up. The first
// successful run creates schema_migrations; every subsequent run
// returns immediately on the schema_migrations existence check.
func Stamp(ctx context.Context, db *sql.DB, kind Kind) error {
	if db == nil {
		return errors.New("migrations.Stamp: nil *sql.DB")
	}
	exists, err := tableExists(ctx, db, "schema_migrations")
	if err != nil {
		return fmt.Errorf("migrations.Stamp: probe schema_migrations: %w", err)
	}
	if exists {
		return nil
	}

	fingerprint, version, err := fingerprintFor(kind)
	if err != nil {
		return err
	}
	hasFingerprint, err := tableExists(ctx, db, fingerprint)
	if err != nil {
		return fmt.Errorf("migrations.Stamp: probe fingerprint %s: %w", fingerprint, err)
	}
	if !hasFingerprint {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("migrations.Stamp: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("migrations.Stamp: create schema_migrations: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations(version, dirty) VALUES ($1, false)`, version,
	); err != nil {
		return fmt.Errorf("migrations.Stamp: insert version row: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("migrations.Stamp: commit: %w", err)
	}
	return nil
}

// schemaMigrationsDDL matches golang-migrate's exact table shape
// (per its postgres driver). Re-creating it here lets us stamp the
// version BEFORE golang-migrate ever opens the DB, while still
// being recognized as already-initialised on the next call.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version BIGINT NOT NULL,
  dirty   BOOLEAN NOT NULL,
  CONSTRAINT schema_migrations_pkey PRIMARY KEY (version)
)
`

// tableExists reports whether public.<name> exists in the connected
// database.
func tableExists(ctx context.Context, db *sql.DB, name string) (bool, error) {
	var present bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = $1
		)`, name).Scan(&present)
	if err != nil {
		return false, err
	}
	return present, nil
}

// fingerprintFor returns the (table-name, version) pair the stamper
// uses to decide what to stamp for a given Kind.
func fingerprintFor(kind Kind) (string, uint, error) {
	switch kind {
	case KindTenant:
		v, err := TenantMaxVersion()
		if err != nil {
			return "", 0, err
		}
		return "tenant_secrets", v, nil
	case KindPlatform:
		v, err := PlatformMaxVersion()
		if err != nil {
			return "", 0, err
		}
		return "tenant_secrets_broker_config", v, nil
	}
	return "", 0, fmt.Errorf("migrations.Stamp: unknown kind %q", kind)
}
