// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func producedStore(t *testing.T) (sqlProducedComponentStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlProducedComponentStore{db: db}, mock
}

func expectReserveLock(mock sqlmock.Sqlmock, count int) {
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WithArgs("acme").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT count\\(\\*\\) FROM produced_component").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(count))
}

// Reserve takes the tenant lock, counts the quota, and inserts the row in one
// transaction. The quota and a taken name are refused with their own errors,
// and the transaction rolls back.
func TestSQLProducedComponentStore_Reserve(t *testing.T) {
	ctx := context.Background()
	c := ProducedComponent{Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: testImage}

	t.Run("reserves under the quota", func(t *testing.T) {
		st, mock := producedStore(t)
		expectReserveLock(mock, 1)
		mock.ExpectExec("INSERT INTO produced_component").
			WithArgs("acme", "tool", "port-sniffer", "0.1.0", testImage, testProducer, testOwner).
			WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectCommit()
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("the quota is refused", func(t *testing.T) {
		st, mock := producedStore(t)
		expectReserveLock(mock, 5)
		mock.ExpectRollback()
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); !errors.Is(err, errProducedQuota) {
			t.Fatalf("Reserve over the quota: %v", err)
		}
	})
	t.Run("a taken name is refused", func(t *testing.T) {
		st, mock := producedStore(t)
		expectReserveLock(mock, 1)
		mock.ExpectExec("INSERT INTO produced_component").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectRollback()
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); !errors.Is(err, errProducedExists) {
			t.Fatalf("Reserve of a taken name: %v", err)
		}
	})
	t.Run("a database error is wrapped", func(t *testing.T) {
		st, mock := producedStore(t)
		mock.ExpectBegin().WillReturnError(errors.New("down"))
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); err == nil {
			t.Fatal("a failed begin must return an error")
		}
		st, mock = producedStore(t)
		expectReserveLock(mock, 1)
		mock.ExpectExec("INSERT INTO produced_component").WillReturnError(errors.New("down"))
		mock.ExpectRollback()
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); err == nil {
			t.Fatal("a failed insert must return an error")
		}
	})
}

// Bind records the principal of the row, and Release deletes a row that has
// no principal.
func TestSQLProducedComponentStore_BindAndRelease(t *testing.T) {
	ctx := context.Background()
	st, mock := producedStore(t)
	mock.ExpectExec("UPDATE produced_component SET principal_id").
		WithArgs("acme", "tool", "port-sniffer", "tool_principal:p1").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.Bind(ctx, "acme", "tool", "port-sniffer", "tool_principal:p1"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	mock.ExpectExec("DELETE FROM produced_component").
		WithArgs("acme", "tool", "port-sniffer").WillReturnResult(sqlmock.NewResult(0, 1))
	if err := st.Release(ctx, "acme", "tool", "port-sniffer"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	mock.ExpectExec("UPDATE produced_component SET principal_id").WillReturnError(errors.New("down"))
	if err := st.Bind(ctx, "acme", "tool", "x", "p"); err == nil {
		t.Fatal("a failed bind must return an error")
	}
	mock.ExpectExec("DELETE FROM produced_component").WillReturnError(errors.New("down"))
	if err := st.Release(ctx, "acme", "tool", "x"); err == nil {
		t.Fatal("a failed release must return an error")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

// WithProducedComponents wires the store and the quota, and leaves the store
// unset with no database.
func TestWithProducedComponents(t *testing.T) {
	s := &DaemonServer{}
	s.WithProducedComponents(nil, 3)
	if s.producedComponents != nil || s.producedComponentLimit != 3 {
		t.Fatalf("with no database: store = %v, limit = %d", s.producedComponents, s.producedComponentLimit)
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s.WithProducedComponents(db, 4)
	if s.producedComponents == nil || s.producedComponentLimit != 4 {
		t.Fatalf("with a database: store = %v, limit = %d", s.producedComponents, s.producedComponentLimit)
	}
}

// Each statement of the reservation reports its own failure.
func TestSQLProducedComponentStore_StatementErrors(t *testing.T) {
	ctx := context.Background()
	c := ProducedComponent{Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: testImage}
	down := errors.New("down")

	st, mock := producedStore(t)
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnError(down)
	mock.ExpectRollback()
	if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); !errors.Is(err, down) {
		t.Fatalf("a failed lock: %v", err)
	}

	st, mock = producedStore(t)
	mock.ExpectBegin()
	mock.ExpectExec("pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("SELECT count").WillReturnError(down)
	mock.ExpectRollback()
	if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); !errors.Is(err, down) {
		t.Fatalf("a failed count: %v", err)
	}

	st, mock = producedStore(t)
	expectReserveLock(mock, 1)
	mock.ExpectExec("INSERT INTO produced_component").WillReturnResult(sqlmock.NewErrorResult(down))
	mock.ExpectRollback()
	if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); !errors.Is(err, down) {
		t.Fatalf("a result with no row count: %v", err)
	}

	st, mock = producedStore(t)
	expectReserveLock(mock, 1)
	mock.ExpectExec("INSERT INTO produced_component").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit().WillReturnError(down)
	mock.ExpectRollback()
	if err := st.Reserve(ctx, "acme", testOwner, testProducer, c, 5); !errors.Is(err, down) {
		t.Fatalf("a failed commit: %v", err)
	}
}

// Each kind maps to its role and FGA type.
func TestProducedKind(t *testing.T) {
	for kind, want := range map[string]string{"agent": "agent_principal", "tool": "tool_principal", "plugin": "plugin_principal"} {
		if _, fgaType, err := producedKind(kind); err != nil || fgaType != want {
			t.Errorf("producedKind(%q) = %q, %v; want %q", kind, fgaType, err, want)
		}
	}
	if _, _, err := producedKind("connector"); err == nil {
		t.Error("an unknown kind must be refused")
	}
}
