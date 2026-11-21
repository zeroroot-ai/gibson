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

// Reserve inserts the row. A taken name is refused with its own error. There
// is no count limit.
func TestSQLProducedComponentStore_Reserve(t *testing.T) {
	ctx := context.Background()
	c := ProducedComponent{Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: testImage}

	t.Run("reserves a new name", func(t *testing.T) {
		st, mock := producedStore(t)
		mock.ExpectExec("INSERT INTO produced_component").
			WithArgs("acme", "tool", "port-sniffer", "0.1.0", testImage, testProducer, testOwner).
			WillReturnResult(sqlmock.NewResult(0, 1))
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a taken name is refused", func(t *testing.T) {
		st, mock := producedStore(t)
		mock.ExpectExec("INSERT INTO produced_component").WillReturnResult(sqlmock.NewResult(0, 0))
		if err := st.Reserve(ctx, "acme", testOwner, testProducer, c); !errors.Is(err, errProducedExists) {
			t.Fatalf("Reserve of a taken name: %v", err)
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

// WithProducedComponents wires the store, and leaves the store unset with no
// database.
func TestWithProducedComponents(t *testing.T) {
	s := &DaemonServer{}
	s.WithProducedComponents(nil)
	if s.producedComponents != nil {
		t.Fatalf("with no database: store = %v", s.producedComponents)
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s.WithProducedComponents(db)
	if s.producedComponents == nil {
		t.Fatal("with a database: store is nil")
	}
}

// Each failure of the reservation is wrapped.
func TestSQLProducedComponentStore_StatementErrors(t *testing.T) {
	ctx := context.Background()
	c := ProducedComponent{Kind: "tool", Name: "port-sniffer", Version: "0.1.0", Image: testImage}
	down := errors.New("down")

	st, mock := producedStore(t)
	mock.ExpectExec("INSERT INTO produced_component").WillReturnError(down)
	if err := st.Reserve(ctx, "acme", testOwner, testProducer, c); !errors.Is(err, down) {
		t.Fatalf("a failed insert: %v", err)
	}

	st, mock = producedStore(t)
	mock.ExpectExec("INSERT INTO produced_component").WillReturnResult(sqlmock.NewErrorResult(down))
	if err := st.Reserve(ctx, "acme", testOwner, testProducer, c); !errors.Is(err, down) {
		t.Fatalf("a result with no row count: %v", err)
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
