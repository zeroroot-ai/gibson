// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package daemon

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"github.com/zeroroot-ai/gibson/internal/server/admin"
)

// componentInstallRegistryReaderAdapter reads install metadata from the
// renamed component_install table (was plugin_install) with the renamed
// component_name column (was plugin_name). gibson renamed the table+column and
// these adapters now query the new names; a stale name would surface only at
// runtime as a Postgres "relation/column does not exist" error, so these
// tests pin the exact SQL and the row -> ComponentInstallInfo mapping.

// installReaderColumns mirrors the SELECT list of both ListAll and Get.
var installReaderColumns = []string{
	"id", "tenant_id", "component_name", "version", "declared_methods",
	"runtime_mode", "setec_required", "created_at",
}

func newMockReader(t *testing.T) (*componentInstallRegistryReaderAdapter, sqlmock.Sqlmock, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	return &componentInstallRegistryReaderAdapter{db: db}, mock, func() { _ = db.Close() }
}

func TestComponentInstallReader_ListAll_ReadsRenamedTable(t *testing.T) {
	adapter, mock, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	created := time.Now().UTC().Truncate(time.Second)

	// The query must hit component_install / component_name, not the old
	// plugin_install / plugin_name.
	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String()).
		WillReturnRows(sqlmock.NewRows(installReaderColumns).
			AddRow("inst-1", "acme", "scanner", "1.2.3", []byte(`["Run","Status"]`), "hosted", true, created).
			AddRow("inst-2", "acme", "reporter", "0.1.0", nil, "microvm", false, created))

	got, err := adapter.ListAll(context.Background(), tenant)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListAll returned %d rows, want 2", len(got))
	}
	if got[0].InstallID != "inst-1" || got[0].Name != "scanner" || got[0].Version != "1.2.3" {
		t.Fatalf("row 0 mapped wrong: %+v", got[0])
	}
	if got[0].RuntimeMode != "hosted" || !got[0].SetecRequired {
		t.Fatalf("row 0 runtime/setec mapped wrong: %+v", got[0])
	}
	if len(got[0].DeclaredMethods) != 2 || got[0].DeclaredMethods[0] != "Run" {
		t.Fatalf("row 0 declared methods mapped wrong: %+v", got[0].DeclaredMethods)
	}
	if got[0].Status != "serving" {
		t.Fatalf("row 0 status = %q, want serving", got[0].Status)
	}
	// A null declared_methods column yields a nil slice, not an error.
	if got[1].DeclaredMethods != nil {
		t.Fatalf("row 1 declared methods = %+v, want nil", got[1].DeclaredMethods)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestComponentInstallReader_ListAll_QueryError(t *testing.T) {
	adapter, mock, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	wantErr := errors.New("boom")
	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String()).
		WillReturnError(wantErr)

	if _, err := adapter.ListAll(context.Background(), tenant); err == nil {
		t.Fatal("ListAll: expected error on failed query, got nil")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestComponentInstallReader_Get_ReadsRenamedTable(t *testing.T) {
	adapter, mock, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	created := time.Now().UTC().Truncate(time.Second)

	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String(), "inst-9").
		WillReturnRows(sqlmock.NewRows(installReaderColumns).
			AddRow("inst-9", "acme", "scanner", "2.0.0", []byte(`["Run"]`), "hosted", false, created))

	got, err := adapter.Get(context.Background(), tenant, "inst-9")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.InstallID != "inst-9" || got.Name != "scanner" || got.Version != "2.0.0" {
		t.Fatalf("Get mapped wrong: %+v", got)
	}
	if got.Status != "serving" || len(got.DeclaredMethods) != 1 {
		t.Fatalf("Get status/methods mapped wrong: %+v", got)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestComponentInstallReader_Get_NotFound(t *testing.T) {
	adapter, mock, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String(), "missing").
		WillReturnError(sql.ErrNoRows)

	_, err := adapter.Get(context.Background(), tenant, "missing")
	if !errors.Is(err, admin.ErrInstallNotFound) {
		t.Fatalf("Get: expected ErrInstallNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestComponentInstallReader_Get_QueryError(t *testing.T) {
	adapter, mock, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String(), "inst-err").
		WillReturnError(errors.New("connection reset"))

	_, err := adapter.Get(context.Background(), tenant, "inst-err")
	if err == nil || errors.Is(err, admin.ErrInstallNotFound) {
		t.Fatalf("Get: expected a non-not-found error, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
