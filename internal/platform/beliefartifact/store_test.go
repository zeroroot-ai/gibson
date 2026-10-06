// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package beliefartifact

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestStore_Put(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db)
	ctx := context.Background()

	mock.ExpectQuery("COALESCE\\(MAX\\(version\\), 0\\) \\+ 1").
		WithArgs("acme", `{"a":1}`, `{"b":2}`).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(int64(1)))
	if v, err := store.Put(ctx, "acme", []byte(`{"a":1}`), []byte(`{"b":2}`)); err != nil || v != 1 {
		t.Fatalf("Put = %d, %v; want version 1", v, err)
	}
	for name, args := range map[string][2][]byte{
		"model is an array": {[]byte(`[1]`), []byte(`{}`)},
		"edges not JSON":    {[]byte(`{}`), []byte(`nope`)},
	} {
		if _, err := store.Put(ctx, "acme", args[0], args[1]); !errors.Is(err, ErrNotJSONObject) {
			t.Errorf("%s: err = %v, want ErrNotJSONObject", name, err)
		}
	}
	if _, err := store.Put(ctx, "", []byte(`{}`), []byte(`{}`)); err == nil {
		t.Error("an empty tenant was accepted")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestStore_Current(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db)
	ctx := context.Background()

	mock.ExpectQuery("state = 'current'").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"belief_model", "version"}).AddRow(`{"a":1}`, int64(2)))
	raw, v, found, err := store.Current(ctx, "acme")
	if err != nil || !found || v != 2 || string(raw) != `{"a":1}` {
		t.Fatalf("Current = %s, %d, %v, %v; want version 2", raw, v, found, err)
	}
	mock.ExpectQuery("state = 'current'").WillReturnError(sql.ErrNoRows)
	if _, _, found, err := store.Current(ctx, "acme"); err != nil || found {
		t.Fatalf("no current version: found %v, err %v", found, err)
	}
	mock.ExpectQuery("state = 'current'").WillReturnError(errors.New("db down"))
	if _, _, _, err := store.Current(ctx, "acme"); err == nil {
		t.Fatal("a database error was not returned")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestStore_Decide(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := NewStore(db)
	ctx := context.Background()
	accept := Verdict{Accepted: true, BrierCandidate: 0.1, BrierCurrent: 0.2, ScoredBets: 3}
	reject := Verdict{BrierCandidate: 0.3, BrierCurrent: 0.2, ScoredBets: 3}

	// Accepted: the current version is retired, then the candidate becomes current.
	mock.ExpectBegin()
	mock.ExpectExec("SET state = \\$2").WithArgs("acme", StateRetired, StateCurrent).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("SET    state = \\$3").WithArgs("acme", int64(2), StateCurrent, 0.1, 0.2, 3, StateCandidate).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.Decide(ctx, "acme", 2, accept); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Rejected: the current version is not touched.
	mock.ExpectBegin()
	mock.ExpectExec("SET    state = \\$3").WithArgs("acme", int64(3), StateRejected, 0.3, 0.2, 3, StateCandidate).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := store.Decide(ctx, "acme", 3, reject); err != nil {
		t.Fatalf("reject: %v", err)
	}

	// A version that is not a candidate is refused.
	mock.ExpectBegin()
	mock.ExpectExec("SET    state = \\$3").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectRollback()
	if err := store.Decide(ctx, "acme", 3, reject); !errors.Is(err, ErrNotACandidate) {
		t.Fatalf("second verdict: err %v, want ErrNotACandidate", err)
	}

	// Each database error is returned.
	mock.ExpectBegin().WillReturnError(errors.New("db down"))
	if err := store.Decide(ctx, "acme", 4, reject); err == nil {
		t.Fatal("begin error was not returned")
	}
	mock.ExpectBegin()
	mock.ExpectExec("SET state = \\$2").WillReturnError(errors.New("db down"))
	mock.ExpectRollback()
	if err := store.Decide(ctx, "acme", 4, accept); err == nil {
		t.Fatal("retire error was not returned")
	}
	mock.ExpectBegin()
	mock.ExpectExec("SET    state = \\$3").WillReturnError(errors.New("db down"))
	mock.ExpectRollback()
	if err := store.Decide(ctx, "acme", 4, reject); err == nil {
		t.Fatal("update error was not returned")
	}
	mock.ExpectBegin()
	mock.ExpectExec("SET    state = \\$3").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(errors.New("db down"))
	if err := store.Decide(ctx, "acme", 4, reject); err == nil {
		t.Fatal("commit error was not returned")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
