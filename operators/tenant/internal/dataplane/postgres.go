// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

package dataplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	migratepg "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	pdataplane "github.com/zeroroot-ai/gibson/pkg/platform/dataplane"
	pgmigrations "github.com/zeroroot-ai/gibson/pkg/platform/migrations"

	"github.com/zeroroot-ai/gibson/operators/tenant/internal/clients"
	vaultadmin "github.com/zeroroot-ai/gibson/operators/tenant/internal/clients/vault"
)

// transientCatalogSQLStates is the set of Postgres SQLSTATE codes that are
// retryable when raised by catalog-mutating operations (GRANT, REVOKE, ALTER
// ROLE on shared system catalogs like pg_authid). XX000 in particular surfaces
// as "tuple concurrently deleted" when two reconciles race on the same role
// row. See issue #48 + internal/metrics/observer.go isTransientPostgresError.
var transientCatalogSQLStates = map[string]struct{}{
	"XX000": {}, // internal_error / tuple concurrently deleted
	"40001": {}, // serialization_failure
	"40P01": {}, // deadlock_detected
}

// execWithCatalogRetry runs sql via conn.Exec with a small bounded retry loop
// for transient catalog errors. Attempts: 3 total, backoff 1s/2s/5s. Errors
// outside the transient set (or after the final attempt) propagate
// untouched. Returns the final error so callers can wrap it for context.
func execWithCatalogRetry(ctx context.Context, conn *pgx.Conn, stmt string) error {
	backoffs := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second}
	var lastErr error
	for i := range backoffs {
		_, err := conn.Exec(ctx, stmt)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isTransientCatalogErr(err) {
			return err
		}
		// Final attempt failed transiently — return without sleeping.
		if i == len(backoffs)-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoffs[i]):
		}
	}
	return lastErr
}

func isTransientCatalogErr(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		_, ok := transientCatalogSQLStates[pgErr.Code]
		return ok
	}
	return strings.Contains(err.Error(), "tuple concurrently deleted")
}

// PostgresConfig holds the admin connection details and migration source for
// the Postgres provisioner.
type PostgresConfig struct {
	// AdminDSN is the Postgres connection string for the admin role used to
	// CREATE/DROP tenant databases and roles (e.g. postgres://admin:pass@host/postgres).
	AdminDSN string

	// (MigrationsDir field removed — spec gibson-postgres-migrations
	// shifted per-tenant migrations onto the embedded source from
	// gibson/pkg/platform/migrations. The runner consumes Tenant
	// directly; there is no longer a filesystem path to configure.)

	// KEKDeriver derives per-tenant KEKs. In production this routes
	// through Vault transit so the master KEK never enters the operator
	// process; in dev mode it falls back to local HKDF. Required.
	KEKDeriver KEKDeriver

	// DefaultConnectionLimit is applied as ALTER ROLE ... CONNECTION LIMIT N
	// when provisioning. 0 means no limit (Postgres default -1).
	DefaultConnectionLimit int

	// VaultClient writes per-tenant Postgres credentials to
	// tenant/<id>/infra/postgres after a successful Provision so the
	// daemon's secrets broker can read them without deriving the
	// password locally. May be nil in dev / on-prem deployments where
	// Vault is not used; the credential write is then skipped.
	// Spec: tenant-provisioning-unification-phase2 Requirement 1.1.
	VaultClient vaultadmin.AdminClient

	// DevMode enables auto-recovery of dirty schema_migrations state
	// (issue #46). When a tenant DB's golang-migrate run aborts midway,
	// schema_migrations.dirty stays true and every subsequent Up()
	// returns `Dirty database version N`. With DevMode=true the
	// provisioner force-rolls the version back by one and re-applies
	// migrations so the saga converges automatically. With DevMode=false
	// (the default since the one-code-path epic deploy#205 hardcoded it)
	// it is a permanent failure surfaced via WrapPermanent so the saga
	// sets a recovery-required condition and a human runs the documented
	// recovery flow.
	//
	// The two paths exist because dirty state on a real tenant DB may
	// contain partially-applied user data; auto-clean there would
	// silently corrupt it. The field is retained as a guard for the
	// internal test fixtures only — the operator binary always sets it
	// to false.
	DevMode bool
}

// pgProvisioner provisions and deprovisions per-tenant Postgres databases.
type pgProvisioner struct {
	cfg PostgresConfig
}

// NewPostgresProvisioner constructs a Postgres provisioner. The admin
// connection is opened lazily (on first Provision/Deprovision call).
func NewPostgresProvisioner(cfg PostgresConfig) (*pgProvisioner, error) {
	if cfg.AdminDSN == "" {
		return nil, fmt.Errorf("dataplane/postgres: AdminDSN required")
	}
	if cfg.KEKDeriver == nil {
		return nil, fmt.Errorf("dataplane/postgres: KEKDeriver required")
	}
	return &pgProvisioner{cfg: cfg}, nil
}

// Provision creates the per-tenant Postgres database, applies all migrations,
// creates the per-tenant role with a derived password, and grants privileges.
// All steps are idempotent.
func (p *pgProvisioner) Provision(ctx context.Context, tenantID string) error {
	dbName, err := tenantDBName(tenantID)
	if err != nil {
		return err
	}
	roleName := dbName + "_app"

	// --- Step 1: connect as admin to the postgres default DB ---
	adminConn, err := pgx.Connect(ctx, p.cfg.AdminDSN)
	if err != nil {
		return fmt.Errorf("dataplane/postgres: admin connect: %w", err)
	}
	defer func() { _ = adminConn.Close(ctx) }()

	// --- Step 2: CREATE DATABASE IF NOT EXISTS (no native IF NOT EXISTS; use catalog check) ---
	var dbExists bool
	row := adminConn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbName)
	if err := row.Scan(&dbExists); err != nil {
		return fmt.Errorf("dataplane/postgres: check db exists: %w", err)
	}
	if !dbExists {
		// Use pgx.Identifier to safely quote the database name.
		createSQL := "CREATE DATABASE " + pgx.Identifier{dbName}.Sanitize()
		if _, err := adminConn.Exec(ctx, createSQL); err != nil {
			return fmt.Errorf("dataplane/postgres: create database %q: %w", dbName, err)
		}
	}

	// --- Step 3: derive role password from KEK ---
	password, err := tenantRolePasswordVia(ctx, p.cfg.KEKDeriver, tenantID)
	if err != nil {
		return err
	}

	// --- Step 4: CREATE ROLE IF NOT EXISTS with derived password ---
	var roleExists bool
	roleRow := adminConn.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname = $1)", roleName)
	if err := roleRow.Scan(&roleExists); err != nil {
		return fmt.Errorf("dataplane/postgres: check role exists: %w", err)
	}
	if !roleExists {
		// Build the SQL safely — role name is sanitized above, password must be
		// interpolated (pg does not support $1 for identifiers/passwords in CREATE ROLE).
		// We use pgx.Identifier for the role name and quote the password with
		// single-quote escaping. Since password is hex-encoded, no quoting is needed.
		roleSQL := fmt.Sprintf(
			"CREATE ROLE %s WITH LOGIN PASSWORD '%s'",
			pgx.Identifier{roleName}.Sanitize(),
			password,
		)
		if _, err := adminConn.Exec(ctx, roleSQL); err != nil {
			return fmt.Errorf("dataplane/postgres: create role %q: %w", roleName, err)
		}
	} else {
		// Role exists — update the password so rotation works.
		alterSQL := fmt.Sprintf(
			"ALTER ROLE %s WITH LOGIN PASSWORD '%s'",
			pgx.Identifier{roleName}.Sanitize(),
			password,
		)
		if _, err := adminConn.Exec(ctx, alterSQL); err != nil {
			return fmt.Errorf("dataplane/postgres: alter role %q: %w", roleName, err)
		}
	}

	// --- Step 5: apply per-tenant resource limit ---
	if p.cfg.DefaultConnectionLimit > 0 {
		limitSQL := fmt.Sprintf(
			"ALTER ROLE %s CONNECTION LIMIT %d",
			pgx.Identifier{roleName}.Sanitize(),
			p.cfg.DefaultConnectionLimit,
		)
		if _, err := adminConn.Exec(ctx, limitSQL); err != nil {
			return fmt.Errorf("dataplane/postgres: set connection limit: %w", err)
		}
	}

	// --- Step 6: GRANT CONNECT on the tenant DB to the role ---
	grantConnSQL := fmt.Sprintf(
		"GRANT CONNECT ON DATABASE %s TO %s",
		pgx.Identifier{dbName}.Sanitize(),
		pgx.Identifier{roleName}.Sanitize(),
	)
	// GRANT CONNECT touches pg_db_role_setting, which can XX000 ("tuple
	// concurrently deleted") under simultaneous reconciles on the same
	// tenant. execWithCatalogRetry transparently retries the documented
	// transient SQLSTATE classes with bounded backoff. (issue #48)
	if err := execWithCatalogRetry(ctx, adminConn, grantConnSQL); err != nil {
		return fmt.Errorf("dataplane/postgres: grant connect: %w", err)
	}

	// --- Step 7: connect to the tenant DB and apply grants + migrations ---
	tenantDSN, err := buildTenantAdminDSN(p.cfg.AdminDSN, dbName)
	if err != nil {
		return err
	}
	tenantConn, err := pgx.Connect(ctx, tenantDSN)
	if err != nil {
		return fmt.Errorf("dataplane/postgres: tenant db connect: %w", err)
	}
	defer func() { _ = tenantConn.Close(ctx) }()

	// Create the pg_trgm extension as admin BEFORE migrations run. Tenant
	// migration 003 builds a gin_trgm_ops trigram index on missions.name, which
	// requires pg_trgm. kind/CNPG inherits the extension from template1, but a
	// fresh Aurora/RDS tenant database does not, so without this the migration
	// failed ("operator class gin_trgm_ops does not exist") and left
	// golang-migrate dirty at version 3 — permanently blocking data-plane
	// provisioning for every tenant on Aurora (gibson#738). Creating it here on
	// the admin connection avoids any dependency on the per-tenant migration
	// role's privileges. Idempotent.
	if _, err := tenantConn.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_trgm"); err != nil {
		return fmt.Errorf("dataplane/postgres: create pg_trgm extension: %w", err)
	}

	// Grant USAGE on public schema and CRUD on all tables/sequences.
	schemaGrants := []string{
		fmt.Sprintf("GRANT USAGE ON SCHEMA public TO %s", pgx.Identifier{roleName}.Sanitize()),
		fmt.Sprintf("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO %s", pgx.Identifier{roleName}.Sanitize()),
		fmt.Sprintf("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO %s", pgx.Identifier{roleName}.Sanitize()),
		// Future tables/sequences — ALTER DEFAULT PRIVILEGES
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %s", pgx.Identifier{roleName}.Sanitize()),
		fmt.Sprintf("ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO %s", pgx.Identifier{roleName}.Sanitize()),
	}
	for _, grant := range schemaGrants {
		if _, err := tenantConn.Exec(ctx, grant); err != nil {
			return fmt.Errorf("dataplane/postgres: grant %q: %w", grant, err)
		}
	}

	// --- Step 8: run migrations ---
	if err := p.runMigrations(ctx, tenantDSN, dbName); err != nil {
		return fmt.Errorf("dataplane/postgres: migrations: %w", err)
	}

	// --- Step 9: write credentials to Vault ---
	// Per spec tenant-provisioning-unification-phase2 Requirement 1.1,
	// the daemon reads the per-tenant Postgres DSN from Vault rather
	// than constructing it locally via derivePostgresPassword. Skipped
	// when no Vault client is configured (dev / on-prem).
	if p.cfg.VaultClient != nil {
		if err := p.writeCredentialsToVault(ctx, tenantID, dbName, roleName, password); err != nil {
			return fmt.Errorf("dataplane/postgres: vault write: %w", err)
		}
	}

	return nil
}

// writeCredentialsToVault writes the canonical PostgresCredentials JSON
// to tenant/<id>/infra/postgres. The DSN is the libpq URL the daemon's
// pgxpool can dial unchanged. Idempotent: KV v2 upsert with same values
// is a no-op-equivalent.
func (p *pgProvisioner) writeCredentialsToVault(ctx context.Context, tenantID, dbName, roleName, password string) error {
	host, port, err := pgHostPortFromDSN(p.cfg.AdminDSN)
	if err != nil {
		return err
	}
	creds := pdataplane.PostgresCredentials{
		Host:     host,
		Port:     port,
		Database: dbName,
		Role:     roleName,
		Password: password,
		// Spec first-deploy-unblock-and-ha R7: sslmode=require, never disable.
		// The chart now provisions per-Postgres-alias TLS material via
		// cert-manager + ClusterIssuer, so every tenant role connects over TLS.
		DSN: fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=require", roleName, password, host, port, dbName),
	}
	return p.cfg.VaultClient.WriteInfraPostgres(ctx, tenantID, creds)
}

// pgHostPortFromDSN parses an admin DSN and returns its host + port.
// Used to populate PostgresCredentials.{Host,Port} for the Vault write.
func pgHostPortFromDSN(dsn string) (string, int, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return "", 0, fmt.Errorf("dataplane/postgres: parse admin DSN: %w", err)
	}
	port := int(cfg.Port)
	if port == 0 {
		port = 5432
	}
	return cfg.Host, port, nil
}

// Deprovision revokes access, drops the role, and drops the database.
// Idempotent — no-op if the database or role do not exist.
func (p *pgProvisioner) Deprovision(ctx context.Context, tenantID string) error {
	dbName, err := tenantDBName(tenantID)
	if err != nil {
		return err
	}
	roleName := dbName + "_app"

	adminConn, err := pgx.Connect(ctx, p.cfg.AdminDSN)
	if err != nil {
		return fmt.Errorf("dataplane/postgres: admin connect: %w", err)
	}
	defer func() { _ = adminConn.Close(ctx) }()

	// Revoke CONNECT so existing sessions are not replaced (idempotent).
	revokeSQL := fmt.Sprintf(
		"REVOKE CONNECT ON DATABASE %s FROM %s",
		pgx.Identifier{dbName}.Sanitize(),
		pgx.Identifier{roleName}.Sanitize(),
	)
	_, _ = adminConn.Exec(ctx, revokeSQL) // ignore: role/db may not exist

	// DROP DATABASE WITH (FORCE) terminates backend connections (Postgres 13+).
	// Use IF EXISTS for idempotency.
	dropDBSQL := fmt.Sprintf("DROP DATABASE IF EXISTS %s WITH (FORCE)", pgx.Identifier{dbName}.Sanitize())
	if _, err := adminConn.Exec(ctx, dropDBSQL); err != nil {
		// Fallback for Postgres < 13 that doesn't support WITH (FORCE).
		if strings.Contains(err.Error(), "syntax error") {
			dropDBSQL = fmt.Sprintf("DROP DATABASE IF EXISTS %s", pgx.Identifier{dbName}.Sanitize())
			if _, err2 := adminConn.Exec(ctx, dropDBSQL); err2 != nil {
				return fmt.Errorf("dataplane/postgres: drop database %q: %w", dbName, err2)
			}
		} else {
			return fmt.Errorf("dataplane/postgres: drop database %q: %w", dbName, err)
		}
	}

	// DROP ROLE IF EXISTS.
	dropRoleSQL := fmt.Sprintf("DROP ROLE IF EXISTS %s", pgx.Identifier{roleName}.Sanitize())
	if _, err := adminConn.Exec(ctx, dropRoleSQL); err != nil {
		return fmt.Errorf("dataplane/postgres: drop role %q: %w", roleName, err)
	}

	return nil
}

// runMigrations applies the embedded tenant migration set
// (gibson/pkg/platform/migrations.NewTenantSource) against the
// per-tenant DB, idempotent via golang-migrate's schema_migrations
// version table. Spec gibson-postgres-migrations Component 5.
//
// On clusters whose tenant DBs were created BEFORE this code path
// landed (legacy psql-applied schema), the embedded Stamp() helper
// inserts the appropriate schema_migrations row before the up
// pass so the migrator skips the already-applied SQL.
func (p *pgProvisioner) runMigrations(ctx context.Context, tenantDSN, dbName string) error {
	connConfig, err := pgx.ParseConfig(tenantDSN)
	if err != nil {
		return fmt.Errorf("parse tenant dsn: %w", err)
	}
	db := stdlib.OpenDB(*connConfig)
	defer func() { _ = db.Close() }()

	if err := pgmigrations.Stamp(ctx, db, pgmigrations.KindTenant); err != nil {
		return fmt.Errorf("stamp legacy state: %w", err)
	}

	src, err := pgmigrations.NewTenantSource()
	if err != nil {
		return fmt.Errorf("tenant migration source: %w", err)
	}
	defer func() { _ = src.Close() }()

	driver, err := migratepg.WithInstance(db, &migratepg.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		return fmt.Errorf("migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, dbName, driver)
	if err != nil {
		return fmt.Errorf("migrate instance: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		// golang-migrate sets schema_migrations.dirty=true when a
		// migration aborts midway and refuses every subsequent Up()
		// until an operator forces a version. Detect and either
		// auto-recover (dev) or surface a manual-recovery error
		// (prod). Spec issue #46.
		var dirty migrate.ErrDirty
		if errors.As(err, &dirty) {
			return p.recoverFromDirtyMigrations(m, dirty, dbName)
		}
		return fmt.Errorf("migrate up: %w", err)
	}
	return nil
}

// recoverFromDirtyMigrations handles a `schema_migrations.dirty=true`
// state encountered by m.Up(). In DevMode it force-rolls the version
// back by one and re-applies; in production it returns a permanent
// error so the saga sets the manual-recovery condition and stops
// retrying.
func (p *pgProvisioner) recoverFromDirtyMigrations(m *migrate.Migrate, dirty migrate.ErrDirty, dbName string) error {
	if !p.cfg.DevMode {
		// Production-safe path: do nothing automatically. A real tenant
		// DB may contain partially-applied user data; auto-clean here
		// could silently corrupt it. Surface as permanent so the saga
		// sets a DataPlaneNeedsManualRecovery condition; the operator
		// runs the documented recovery flow.
		return clients.WrapPermanent(fmt.Errorf(
			"dataplane/postgres: %q has dirty schema_migrations at version %d (manual recovery required — see runbook): %w",
			dbName, dirty.Version, dirty,
		))
	}

	// Dev path: roll back to the prior version and re-apply. dirty.Version
	// is the version that was partially applied when the previous run
	// aborted; force-rolling to dirty.Version-1 lets the embedded source
	// re-attempt N from a clean state.
	target := dirty.Version - 1
	if target < 0 {
		// Edge case: the very first migration (version 1) went dirty.
		// Force to the migrate "no version applied" sentinel so the
		// next Up() runs from scratch.
		target = database.NilVersion
	}
	if err := m.Force(target); err != nil {
		return fmt.Errorf("dataplane/postgres: dev-mode dirty recovery: force(%d): %w", target, err)
	}
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("dataplane/postgres: dev-mode dirty recovery: up after force(%d): %w", target, err)
	}
	return nil
}

// buildTenantAdminDSN replaces the database component in the admin DSN with
// the tenant database name, so the admin role connects to the tenant DB.
func buildTenantAdminDSN(adminDSN, dbName string) (string, error) {
	cfg, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		return "", fmt.Errorf("dataplane/postgres: parse admin DSN: %w", err)
	}
	cfg.Database = dbName
	// Rebuild a libpq-compatible connstring from the parsed config.
	dsn := buildDSN(cfg)
	return dsn, nil
}

// buildDSN reconstructs a simple postgres:// DSN from a pgx.ConnConfig.
func buildDSN(c *pgx.ConnConfig) string {
	var sb strings.Builder
	sb.WriteString("postgres://")
	if c.User != "" {
		sb.WriteString(c.User)
		if c.Password != "" {
			sb.WriteString(":")
			sb.WriteString(c.Password)
		}
		sb.WriteString("@")
	}
	sb.WriteString(c.Host)
	if c.Port != 0 {
		sb.WriteString(fmt.Sprintf(":%d", c.Port))
	}
	sb.WriteString("/")
	sb.WriteString(c.Database)
	// Spec first-deploy-unblock-and-ha R7: sslmode is hardcoded `require`.
	// The previous TLSConfig-conditional branch produced `disable` when no
	// explicit TLSConfig was supplied; that branch is removed entirely so
	// no DSN can downgrade to plaintext. Callers that need `verify-full`
	// against a chart-issued CA MUST set PGSSLMODE / PGSSLROOTCERT in the
	// consumer environment.
	sb.WriteString("?sslmode=require")
	_ = c.TLSConfig
	return sb.String()
}

// Ensure the stdlib import is not dead (used via stdlib.OpenDB).
var _ *sql.DB
