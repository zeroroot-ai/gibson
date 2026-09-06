// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The SQL seam.
//
// internal/infra/datapool is one of the few packages allowed to import a raw
// store client (forbid_raw_store_imports). Every other package reaches Postgres
// through a Conn — but "through a Conn" was only half true: a store still had
// to name pgx types to check for no rows, to spot a unique-constraint
// violation, or to hold a transaction. So each new store package landed on the
// allowlist, and the allowlist grew instead of shrinking.
//
// These four things are what a store actually needs, and none of them has to
// be a pgx type at the call site. A store that uses them imports no store
// client at all.

// ErrNoRows reports that a query that expected one row found none. It is the
// portable form of pgx.ErrNoRows: a store compares against it with errors.Is
// and never names the driver.
var ErrNoRows = errors.New("datapool: no rows in result set")

// ErrUniqueViolation reports that a write collided with a unique constraint.
// A store maps it to its own "already exists".
var ErrUniqueViolation = errors.New("datapool: unique constraint violation")

// Row is a single-row result. pgx.Row satisfies it.
type Row interface {
	Scan(dest ...any) error
}

// Rows is a multi-row result. pgx.Rows satisfies it.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close()
}

// SQL is what a store needs from a database handle: run a statement, read one
// row, read many. A Conn and a transaction both provide it, so a helper written
// against it works inside a transaction and outside one.
type SQL interface {
	// Exec runs a statement and reports how many rows it changed.
	Exec(ctx context.Context, sql string, args ...any) (int64, error)
	// QueryRow reads a single row. Scan returns ErrNoRows when there is none.
	QueryRow(ctx context.Context, sql string, args ...any) Row
	// Query reads many rows. The caller must Close them.
	Query(ctx context.Context, sql string, args ...any) (Rows, error)
}

// SQL returns the tenant's Postgres handle as the portable interface. It is
// valid only while the Conn is held.
func (c *Conn) SQL() SQL {
	return sqlHandle{q: c.Postgres}
}

// InTx runs fn inside a transaction on the tenant's Postgres, committing when
// fn returns nil and rolling back otherwise.
//
// A callback, not a returned handle: a transaction that a caller could forget
// to end is a connection that leaks and a lock that is never released, and the
// callback shape makes forgetting impossible.
func (c *Conn) InTx(ctx context.Context, fn func(SQL) error) error {
	tx, err := c.Postgres.Begin(ctx)
	if err != nil {
		return fmt.Errorf("datapool: begin transaction: %w", err)
	}
	if err := fn(sqlHandle{q: tx}); err != nil {
		// The rollback error is deliberately dropped: the caller's error is
		// what went wrong, and a rollback failure on an already-failed
		// transaction adds noise rather than information.
		_ = tx.Rollback(ctx)
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("datapool: commit transaction: %w", err)
	}
	return nil
}

// pgxQuerier is what pgxpool.Pool and pgx.Tx have in common.
type pgxQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// sqlHandle adapts a pgx querier to SQL, translating the driver's sentinels
// into this package's.
type sqlHandle struct{ q pgxQuerier }

func (h sqlHandle) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := h.q.Exec(ctx, sql, args...)
	if err != nil {
		return 0, translateSQLError(err)
	}
	return tag.RowsAffected(), nil
}

func (h sqlHandle) QueryRow(ctx context.Context, sql string, args ...any) Row {
	return sqlRow{row: h.q.QueryRow(ctx, sql, args...)}
}

func (h sqlHandle) Query(ctx context.Context, sql string, args ...any) (Rows, error) {
	rows, err := h.q.Query(ctx, sql, args...)
	if err != nil {
		return nil, translateSQLError(err)
	}
	return sqlRows{rows: rows}, nil
}

type sqlRow struct{ row pgx.Row }

func (r sqlRow) Scan(dest ...any) error { return translateSQLError(r.row.Scan(dest...)) }

type sqlRows struct{ rows pgx.Rows }

func (r sqlRows) Next() bool             { return r.rows.Next() }
func (r sqlRows) Scan(dest ...any) error { return translateSQLError(r.rows.Scan(dest...)) }
func (r sqlRows) Err() error             { return translateSQLError(r.rows.Err()) }
func (r sqlRows) Close()                 { r.rows.Close() }

// translateSQLError maps the driver's sentinels to this package's, so a caller
// can tell "no rows" and "already exists" apart without importing the driver.
// Anything else is returned unchanged: a store should see the real message.
func translateSQLError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pgx.ErrNoRows):
		return ErrNoRows
	case isPgUniqueViolation(err):
		return fmt.Errorf("%w: %w", ErrUniqueViolation, err)
	default:
		return err
	}
}

// isPgUniqueViolation reports whether err is SQLSTATE 23505.
func isPgUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
