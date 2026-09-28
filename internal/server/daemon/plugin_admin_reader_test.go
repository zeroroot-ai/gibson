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
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/zeroroot-ai/gibson/internal/platform/component"
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
	"runtime_mode", "setec_required", "principal_ref", "created_at",
}

// newMockReader pairs the SQL mock with a miniredis the real install
// registry writes status into, so the status the reader reports is the one
// a heartbeat stored, not a constant.
func newMockReader(t *testing.T) (*componentInstallRegistryReaderAdapter, sqlmock.Sqlmock, component.ComponentInstallRegistry, func()) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	registry := component.NewPluginRegistry(nil, rdb, nil, nil)
	return &componentInstallRegistryReaderAdapter{db: db, redis: rdb}, mock, registry, func() { _ = db.Close() }
}

func TestComponentInstallReader_ListAll_ReadsRenamedTable(t *testing.T) {
	adapter, mock, registry, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	created := time.Now().UTC().Truncate(time.Second)

	// The query must hit component_install / component_name, not the old
	// plugin_install / plugin_name.
	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String()).
		WillReturnRows(sqlmock.NewRows(installReaderColumns).
			AddRow("inst-1", "acme", "scanner", "1.2.3", []byte(`["Run","Status"]`), "hosted", true, "plugin_principal:scanner", created).
			AddRow("inst-2", "acme", "reporter", "0.1.0", nil, "microvm", false, "", created))
	// inst-1 heartbeated degraded (a revoked secret, gibson#154); inst-2
	// never heartbeated on this daemon.
	if err := registry.Heartbeat(context.Background(), "inst-1", "10.0.0.7:50055", "degraded"); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

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
	if got[0].PrincipalRef != "plugin_principal:scanner" {
		t.Fatalf("row 0 principal = %q, want the registered plugin_principal", got[0].PrincipalRef)
	}
	if got[0].Status != "degraded" || got[0].Address != "10.0.0.7:50055" || got[0].LastHeartbeatAt.IsZero() {
		t.Fatalf("row 0 status must be what the plugin heartbeated: %+v", got[0])
	}
	// A null declared_methods column yields a nil slice, not an error.
	if got[1].DeclaredMethods != nil {
		t.Fatalf("row 1 declared methods = %+v, want nil", got[1].DeclaredMethods)
	}
	if got[1].Status != "unreachable" {
		t.Fatalf("row 1 status = %q, want unreachable for an install with no status key", got[1].Status)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestComponentInstallReader_ListAll_QueryError(t *testing.T) {
	adapter, mock, _, closeDB := newMockReader(t)
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
	adapter, mock, registry, closeDB := newMockReader(t)
	defer closeDB()

	tenant := mustTenant("acme")
	created := time.Now().UTC().Truncate(time.Second)

	mock.ExpectQuery("FROM\\s+component_install").
		WithArgs(tenant.String(), "inst-9").
		WillReturnRows(sqlmock.NewRows(installReaderColumns).
			AddRow("inst-9", "acme", "scanner", "2.0.0", []byte(`["Run"]`), "hosted", false, "plugin_principal:scanner", created))
	if err := registry.Heartbeat(context.Background(), "inst-9", "", "serving"); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	got, err := adapter.Get(context.Background(), tenant, "inst-9")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.InstallID != "inst-9" || got.Name != "scanner" || got.Version != "2.0.0" || got.PrincipalRef != "plugin_principal:scanner" {
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
	adapter, mock, _, closeDB := newMockReader(t)
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
	adapter, mock, _, closeDB := newMockReader(t)
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
