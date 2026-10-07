// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package tenantconnector

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockStore(t *testing.T) (*Store, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return NewStore(db), mock
}

func TestStore_Enable(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectExec("INSERT INTO tenant_connectors").WithArgs("acme", "gitlab").
		WillReturnResult(sqlmock.NewResult(0, 1))
	c, err := store.Enable(ctx, "acme", "gitlab")
	require.NoError(t, err)
	assert.Equal(t, Connector{TenantID: "acme", ConnectorID: "gitlab", Phase: PhasePending}, c)

	mock.ExpectExec("INSERT INTO tenant_connectors").WithArgs("acme", "gitlab").
		WillReturnResult(sqlmock.NewResult(0, 0))
	_, err = store.Enable(ctx, "acme", "gitlab")
	require.ErrorIs(t, err, ErrAlreadyEnabled)

	mock.ExpectExec("INSERT INTO tenant_connectors").WillReturnError(errors.New("db down"))
	_, err = store.Enable(ctx, "acme", "gitlab")
	require.Error(t, err)

	_, err = store.Enable(ctx, "", "gitlab")
	require.Error(t, err)
	_, err = store.Enable(ctx, "acme", "")
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_Adopt(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	// A row that exists is not an error: adopt is idempotent.
	mock.ExpectExec("ON CONFLICT").WithArgs("acme", "gitlab").WillReturnResult(sqlmock.NewResult(0, 0))
	require.NoError(t, store.Adopt(ctx, "acme", "gitlab"))
	mock.ExpectExec("INSERT INTO tenant_connectors").WillReturnError(errors.New("db down"))
	require.Error(t, store.Adopt(ctx, "acme", "gitlab"))
	require.Error(t, store.Adopt(ctx, "", "gitlab"))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_Disable(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectExec("DELETE FROM tenant_connectors").WithArgs("acme", "gitlab").
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, store.Disable(ctx, "acme", "gitlab"))

	mock.ExpectExec("DELETE FROM tenant_connectors").WithArgs("acme", "gitlab").
		WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, store.Disable(ctx, "acme", "gitlab"), ErrNotEnabled)
	require.Error(t, store.Disable(ctx, "acme", ""))
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_ListAndListAll(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)
	cols := []string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error"}

	mock.ExpectQuery("WHERE tenant_id = \\$1").WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(cols).AddRow("acme", "gitlab", "Ready", 12, ""))
	got, err := store.List(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, []Connector{{TenantID: "acme", ConnectorID: "gitlab", Phase: "Ready", DiscoveredTools: 12}}, got)

	mock.ExpectQuery("ORDER BY tenant_id, connector_id").
		WillReturnRows(sqlmock.NewRows(cols).
			AddRow("acme", "gitlab", "Pending", 0, "").
			AddRow("globex", "slack", "Failed", 0, "boom"))
	all, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, "boom", all[1].LastError)

	_, err = store.List(ctx, "")
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_ReportStatus(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectExec("UPDATE tenant_connectors").WithArgs("acme", "gitlab", "Ready", "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := store.ReportStatus(ctx, "acme", "gitlab", Status{Phase: "Ready"})
	require.NoError(t, err)
	assert.True(t, ok)

	mock.ExpectExec("UPDATE tenant_connectors").WillReturnResult(sqlmock.NewResult(0, 0))
	ok, err = store.ReportStatus(ctx, "acme", "gone", Status{Phase: "Ready"})
	require.NoError(t, err)
	assert.False(t, ok, "a report never creates a row")

	_, err = store.ReportStatus(ctx, "acme", "gitlab", Status{})
	require.Error(t, err, "a report with no phase must be refused")
	require.NoError(t, mock.ExpectationsWereMet())
}

var errDB = errors.New("db down")

// Each database failure returns an error and no result.
func TestStore_DatabaseFailures(t *testing.T) {
	ctx := context.Background()

	s, mock := newMockStore(t)
	mock.ExpectExec("INSERT INTO tenant_connectors").WillReturnError(errDB)
	if err := s.Adopt(ctx, "acme", "gitlab"); err == nil {
		t.Error("Adopt: insert failure returned no error")
	}
	mock.ExpectExec("INSERT INTO tenant_connectors").WillReturnResult(sqlmock.NewErrorResult(errDB))
	if err := s.Adopt(ctx, "acme", "gitlab"); err == nil {
		t.Error("Adopt: rows affected failure returned no error")
	}
	mock.ExpectExec("DELETE FROM tenant_connectors").WillReturnError(errDB)
	if err := s.Disable(ctx, "acme", "gitlab"); err == nil {
		t.Error("Disable: delete failure returned no error")
	}
	mock.ExpectExec("DELETE FROM tenant_connectors").WillReturnResult(sqlmock.NewErrorResult(errDB))
	if err := s.Disable(ctx, "acme", "gitlab"); err == nil {
		t.Error("Disable: rows affected failure returned no error")
	}
	mock.ExpectQuery("SELECT tenant_id").WillReturnError(errDB)
	if _, err := s.List(ctx, "acme"); err == nil {
		t.Error("List: query failure returned no error")
	}
	mock.ExpectQuery("SELECT tenant_id").WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow("acme"))
	if _, err := s.ListAll(ctx); err == nil {
		t.Error("ListAll: scan failure returned no error")
	}
	mock.ExpectQuery("SELECT tenant_id").WillReturnRows(
		sqlmock.NewRows([]string{"tenant_id", "connector_id", "phase", "discovered_tools", "last_error"}).
			AddRow("acme", "gitlab", "Ready", 1, "").RowError(0, errDB))
	if _, err := s.ListAll(ctx); err == nil {
		t.Error("ListAll: row failure returned no error")
	}
	if _, err := s.List(ctx, ""); err == nil {
		t.Error("List: no tenant returned no error")
	}
	if _, err := s.ReportStatus(ctx, "acme", "gitlab", Status{}); err == nil {
		t.Error("ReportStatus: no phase returned no error")
	}
	mock.ExpectExec("UPDATE tenant_connectors").WillReturnError(errDB)
	if _, err := s.ReportStatus(ctx, "acme", "gitlab", Status{Phase: "Ready"}); err == nil {
		t.Error("ReportStatus: update failure returned no error")
	}
	mock.ExpectExec("UPDATE tenant_connectors").WillReturnResult(sqlmock.NewErrorResult(errDB))
	if _, err := s.ReportStatus(ctx, "acme", "gitlab", Status{Phase: "Ready"}); err == nil {
		t.Error("ReportStatus: rows affected failure returned no error")
	}
}

// The daemon records the tool count of a connector. A report of the
// operator does not touch it (gibson#723).
func TestStore_SetDiscoveredTools(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectExec("UPDATE tenant_connectors\\s+SET\\s+discovered_tools = \\$3").
		WithArgs("acme", "gitlab", int32(7)).WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, store.SetDiscoveredTools(ctx, "acme", "gitlab", 7))

	mock.ExpectExec("UPDATE tenant_connectors").WillReturnError(errDB)
	require.ErrorIs(t, store.SetDiscoveredTools(ctx, "acme", "gitlab", 7), errDB)

	require.Error(t, store.SetDiscoveredTools(ctx, "", "gitlab", 7))
	require.NoError(t, mock.ExpectationsWereMet())
}
