// Copyright 2026 Hack the Planet LLC
// Use of this source code is governed by the Elastic License 2.0
// that can be found in the LICENSE file in the repo root.

// Package postgres is platform-operator's internal PostgreSQL admin
// client. Owns the minimum API surface needed by PlatformBootstrap's
// postgres-bundle step: connect as superuser, ALTER DATABASE OWNER,
// GRANT USAGE+CREATE on public schema. Idempotent.
//
// Identifiers (database names, role names, schema names) are validated
// against a strict regex to defend against SQL injection — we cannot
// parameter-bind identifiers, only literal values.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"

	// Pure-Go postgres driver. Registered as "postgres" via init().
	_ "github.com/lib/pq"
)

var (
	ErrUnreachable    = errors.New("postgres: unreachable")
	ErrInvalidIdent   = errors.New("postgres: invalid identifier")
	ErrPermissionDeny = errors.New("postgres: permission denied")
)

// identRegex restricts identifiers to a-zA-Z0-9_, leading non-digit.
// Tight enough to defend against SQL injection on identifier paths
// where we have to interpolate (database, role, schema names).
var identRegex = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// Client is the postgres admin API surface.
type Client interface {
	// Ping verifies connectivity + superuser auth.
	Ping(ctx context.Context) error

	// EnsureDatabaseOwner runs `ALTER DATABASE <db> OWNER TO <owner>`
	// if the current owner doesn't match. Returns true when an ALTER
	// was issued; false when ownership was already correct.
	EnsureDatabaseOwner(ctx context.Context, db, owner string) (changed bool, err error)

	// EnsurePublicSchemaGrants grants USAGE + CREATE on the public schema
	// of `db` to each role in `grants`. Idempotent (GRANT is a no-op when
	// already granted, but we re-issue to keep the reconciler simple).
	// Connects to the target DB to issue schema-scoped grants.
	EnsurePublicSchemaGrants(ctx context.Context, db string, grants []string) error

	// Close releases the underlying connection pool.
	Close() error
}

// Config describes how the client connects.
type Config struct {
	Host     string
	Port     int32
	User     string
	Password string
	// SSLMode is "disable" / "require" / "verify-full". Defaults to
	// "require" if empty (CNPG defaults to enforcing TLS).
	SSLMode string
}

// New opens a connection pool to the management database "postgres" using
// the given superuser credentials. Returns ErrUnreachable on dial failure.
//
// The returned client multiplexes a small pool of connections; callers
// MUST call Close when done.
func New(ctx context.Context, cfg Config) (Client, error) {
	if cfg.Port == 0 {
		cfg.Port = 5432
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "require"
	}
	if cfg.User == "" {
		return nil, fmt.Errorf("postgres: empty user: %w", ErrInvalidIdent)
	}
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=%s connect_timeout=10",
		cfg.Host, cfg.Port, cfg.User, cfg.Password, cfg.SSLMode)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %v: %w", err, ErrUnreachable)
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	c := &pqClient{db: db, cfg: cfg}
	if err := c.Ping(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return c, nil
}

type pqClient struct {
	db  *sql.DB
	cfg Config
}

func (c *pqClient) Ping(ctx context.Context) error {
	if err := c.db.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres: ping: %v: %w", err, ErrUnreachable)
	}
	return nil
}

// EnsureDatabaseOwner implements Client.
//
// Two-phase: SELECT current owner from pg_database; ALTER only when the
// owner differs. The pg_roles join keeps us out of the OID weeds.
func (c *pqClient) EnsureDatabaseOwner(ctx context.Context, db, owner string) (bool, error) {
	if err := checkIdent("database", db); err != nil {
		return false, err
	}
	if err := checkIdent("owner", owner); err != nil {
		return false, err
	}
	var currentOwner string
	row := c.db.QueryRowContext(ctx, `
		SELECT pg_catalog.pg_get_userbyid(d.datdba)
		FROM pg_catalog.pg_database d
		WHERE d.datname = $1`, db)
	if err := row.Scan(&currentOwner); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("postgres: database %q not found", db)
		}
		return false, fmt.Errorf("postgres: lookup owner of %q: %w", db, err)
	}
	if currentOwner == owner {
		return false, nil
	}
	// Identifiers are validated above; safe to interpolate.
	stmt := fmt.Sprintf(`ALTER DATABASE %q OWNER TO %q`, db, owner)
	if _, err := c.db.ExecContext(ctx, stmt); err != nil {
		return false, wrapExecErr(err, stmt)
	}
	return true, nil
}

// EnsurePublicSchemaGrants implements Client.
//
// Opens a transient connection to the target DB (schema grants are
// per-database, not per-cluster), then issues GRANT USAGE + GRANT CREATE
// on schema public to each role.
func (c *pqClient) EnsurePublicSchemaGrants(ctx context.Context, db string, grants []string) error {
	if err := checkIdent("database", db); err != nil {
		return err
	}
	for _, r := range grants {
		if err := checkIdent("grant role", r); err != nil {
			return err
		}
	}
	if len(grants) == 0 {
		return nil
	}
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s connect_timeout=10",
		c.cfg.Host, c.cfg.Port, c.cfg.User, c.cfg.Password, db, c.cfg.SSLMode)
	target, err := sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("postgres: open %q: %v: %w", db, err, ErrUnreachable)
	}
	defer func() { _ = target.Close() }()
	if err := target.PingContext(ctx); err != nil {
		return fmt.Errorf("postgres: ping %q: %v: %w", db, err, ErrUnreachable)
	}
	for _, r := range grants {
		for _, verb := range []string{"USAGE", "CREATE"} {
			stmt := fmt.Sprintf(`GRANT %s ON SCHEMA public TO %q`, verb, r)
			if _, err := target.ExecContext(ctx, stmt); err != nil {
				return wrapExecErr(err, stmt)
			}
		}
	}
	return nil
}

func (c *pqClient) Close() error {
	return c.db.Close()
}

// checkIdent rejects identifiers that aren't safe to interpolate.
func checkIdent(kind, v string) error {
	if !identRegex.MatchString(v) {
		return fmt.Errorf("%s %q: %w", kind, v, ErrInvalidIdent)
	}
	return nil
}

// wrapExecErr classifies pq exec errors into our sentinels.
func wrapExecErr(err error, stmt string) error {
	if err == nil {
		return nil
	}
	// pq.Error carries an SQLSTATE; 42501 = insufficient_privilege.
	// We don't import pq.Error directly to keep this driver-agnostic in
	// shape; the error string carries enough signal for our Conditions.
	if errSQLState(err) == "42501" {
		return fmt.Errorf("postgres exec %q: %v: %w", stmt, err, ErrPermissionDeny)
	}
	return fmt.Errorf("postgres exec %q: %w", stmt, err)
}

// errSQLState extracts the 5-char SQLSTATE from a pq error string if
// present. The pq driver formats errors as: `pq: <message> (SQLSTATE
// <code>)` for some classes; for others the code is on the typed error.
// We do a substring scan to avoid a hard dep on the pq package surface.
func errSQLState(err error) string {
	type sqlStater interface{ SQLState() string }
	if s, ok := err.(sqlStater); ok {
		return s.SQLState()
	}
	return ""
}
