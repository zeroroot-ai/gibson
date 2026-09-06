// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package datapool

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestTranslateSQLError maps the driver's sentinels to portable ones, which is
// what lets every store package reach Postgres without importing the driver.
func TestTranslateSQLError(t *testing.T) {
	if got := translateSQLError(nil); got != nil {
		t.Errorf("nil -> %v, want nil", got)
	}
	if got := translateSQLError(pgx.ErrNoRows); !errors.Is(got, ErrNoRows) {
		t.Errorf("no rows -> %v, want ErrNoRows", got)
	}
	unique := &pgconn.PgError{Code: "23505", Message: "duplicate key"}
	got := translateSQLError(unique)
	if !errors.Is(got, ErrUniqueViolation) {
		t.Errorf("23505 -> %v, want ErrUniqueViolation", got)
	}
	if !errors.Is(got, unique) {
		t.Error("the driver error must stay wrapped: a store should see the real message")
	}
	other := &pgconn.PgError{Code: "23503", Message: "foreign key"}
	if !errors.Is(translateSQLError(other), other) {
		t.Error("any other driver error is returned unchanged")
	}
	plain := errors.New("connection reset")
	if !errors.Is(translateSQLError(plain), plain) {
		t.Error("a non-driver error is returned unchanged")
	}
}

func TestIsPgUniqueViolation(t *testing.T) {
	if !isPgUniqueViolation(&pgconn.PgError{Code: "23505"}) {
		t.Error("23505 is a unique violation")
	}
	if isPgUniqueViolation(&pgconn.PgError{Code: "23503"}) {
		t.Error("23503 is not a unique violation")
	}
	if isPgUniqueViolation(errors.New("nope")) {
		t.Error("a plain error is not a unique violation")
	}
}

// The adapter tests below drive sqlHandle over a fake pgx querier. They cover
// the one thing the translation layer must get right: a driver sentinel that
// crosses the seam comes out as this package's, at every entry point, so a
// store that checks only these sentinels never sees a driver error by surprise.

type fakePgxQuerier struct {
	execErr  error
	execTag  pgconn.CommandTag
	rowErr   error
	queryErr error
	rows     *fakePgxRows
	lastSQL  string
}

func (f *fakePgxQuerier) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	f.lastSQL = sql
	return f.execTag, f.execErr
}

func (f *fakePgxQuerier) QueryRow(_ context.Context, sql string, _ ...any) pgx.Row {
	f.lastSQL = sql
	return fakePgxRow{err: f.rowErr}
}

func (f *fakePgxQuerier) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	f.lastSQL = sql
	if f.queryErr != nil {
		return nil, f.queryErr
	}
	return f.rows, nil
}

type fakePgxRow struct{ err error }

func (r fakePgxRow) Scan(...any) error { return r.err }

type fakePgxRows struct {
	remaining int
	scanErr   error
	err       error
	closed    bool
}

func (r *fakePgxRows) Close()                                       { r.closed = true }
func (r *fakePgxRows) Err() error                                   { return r.err }
func (r *fakePgxRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakePgxRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakePgxRows) Next() bool {
	if r.remaining == 0 {
		return false
	}
	r.remaining--
	return true
}
func (r *fakePgxRows) Scan(...any) error      { return r.scanErr }
func (r *fakePgxRows) Values() ([]any, error) { return nil, nil }
func (r *fakePgxRows) RawValues() [][]byte    { return nil }
func (r *fakePgxRows) Conn() *pgx.Conn        { return nil }

func TestSQLHandle_ExecReportsRowsAndTranslates(t *testing.T) {
	q := &fakePgxQuerier{execTag: pgconn.NewCommandTag("UPDATE 3")}
	h := sqlHandle{q: q}

	n, err := h.Exec(context.Background(), "UPDATE banks SET x = 1")
	if err != nil || n != 3 {
		t.Fatalf("Exec = %d, %v; want 3 rows and no error", n, err)
	}
	if q.lastSQL != "UPDATE banks SET x = 1" {
		t.Errorf("the statement must reach the driver unchanged, got %q", q.lastSQL)
	}

	q.execErr = &pgconn.PgError{Code: "23505"}
	if _, err := h.Exec(context.Background(), "INSERT"); !errors.Is(err, ErrUniqueViolation) {
		t.Fatalf("err = %v, want ErrUniqueViolation", err)
	}
}

func TestSQLHandle_QueryRowTranslatesNoRows(t *testing.T) {
	h := sqlHandle{q: &fakePgxQuerier{rowErr: pgx.ErrNoRows}}
	if err := h.QueryRow(context.Background(), "SELECT 1").Scan(); !errors.Is(err, ErrNoRows) {
		t.Fatalf("err = %v, want ErrNoRows", err)
	}
	h = sqlHandle{q: &fakePgxQuerier{}}
	if err := h.QueryRow(context.Background(), "SELECT 1").Scan(); err != nil {
		t.Fatalf("a row that scans cleanly must return nil, got %v", err)
	}
}

func TestSQLHandle_QueryTranslatesAtEveryStep(t *testing.T) {
	q := &fakePgxQuerier{rows: &fakePgxRows{remaining: 1, scanErr: pgx.ErrNoRows, err: pgx.ErrNoRows}}
	h := sqlHandle{q: q}

	rows, err := h.Query(context.Background(), "SELECT * FROM banks")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if !rows.Next() {
		t.Fatal("the first row must be readable")
	}
	if err := rows.Scan(); !errors.Is(err, ErrNoRows) {
		t.Errorf("Scan must translate: %v", err)
	}
	if err := rows.Err(); !errors.Is(err, ErrNoRows) {
		t.Errorf("Err must translate: %v", err)
	}
	if rows.Next() {
		t.Error("the rows are exhausted")
	}
	rows.Close()
	if !q.rows.closed {
		t.Error("Close must reach the driver, or a connection is held forever")
	}

	failing := sqlHandle{q: &fakePgxQuerier{queryErr: &pgconn.PgError{Code: "23505"}}}
	failedRows, err := failing.Query(context.Background(), "SELECT")
	if failedRows != nil {
		failedRows.Close()
	}
	if !errors.Is(err, ErrUniqueViolation) {
		t.Fatalf("a failed query must translate too: %v", err)
	}
}
