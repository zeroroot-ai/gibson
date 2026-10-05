// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package catalogplugin

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

	mock.ExpectExec("INSERT INTO tenant_catalog_plugins").WithArgs("acme", "github").
		WillReturnResult(sqlmock.NewResult(0, 1))
	p, err := store.Enable(ctx, "acme", "github")
	require.NoError(t, err)
	assert.Equal(t, Plugin{TenantID: "acme", PluginID: "github", Phase: PhasePending}, p)

	mock.ExpectExec("INSERT INTO tenant_catalog_plugins").WithArgs("acme", "github").
		WillReturnResult(sqlmock.NewResult(0, 0))
	_, err = store.Enable(ctx, "acme", "github")
	require.ErrorIs(t, err, ErrAlreadyEnabled)

	mock.ExpectExec("INSERT INTO tenant_catalog_plugins").WillReturnError(errors.New("db down"))
	_, err = store.Enable(ctx, "acme", "github")
	require.Error(t, err)

	_, err = store.Enable(ctx, "", "github")
	require.Error(t, err, "an empty tenant must be refused")
	_, err = store.Enable(ctx, "acme", "")
	require.Error(t, err, "an empty plugin must be refused")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_Disable(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectExec("DELETE FROM tenant_catalog_plugins").WithArgs("acme", "github").
		WillReturnResult(sqlmock.NewResult(0, 1))
	require.NoError(t, store.Disable(ctx, "acme", "github"))

	mock.ExpectExec("DELETE FROM tenant_catalog_plugins").WithArgs("acme", "github").
		WillReturnResult(sqlmock.NewResult(0, 0))
	require.ErrorIs(t, store.Disable(ctx, "acme", "github"), ErrNotEnabled)

	mock.ExpectExec("DELETE FROM tenant_catalog_plugins").WillReturnError(errors.New("db down"))
	require.Error(t, store.Disable(ctx, "acme", "github"))

	require.Error(t, store.Disable(ctx, "", "github"))
	require.NoError(t, mock.ExpectationsWereMet())
}

// List always carries the tenant predicate: it is the isolation boundary.
func TestStore_List(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectQuery(`WHERE\s+tenant_id = \$1`).WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "plugin_id", "phase", "last_error"}).
			AddRow("acme", "github", "Ready", ""))
	got, err := store.List(ctx, "acme")
	require.NoError(t, err)
	assert.Equal(t, []Plugin{{TenantID: "acme", PluginID: "github", Phase: "Ready"}}, got)

	mock.ExpectQuery(`WHERE\s+tenant_id = \$1`).WillReturnError(errors.New("db down"))
	_, err = store.List(ctx, "acme")
	require.Error(t, err)

	_, err = store.List(ctx, "")
	require.Error(t, err, "a list with no tenant must be refused")
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestStore_ListAll(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectQuery("ORDER BY tenant_id, plugin_id").
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "plugin_id", "phase", "last_error"}).
			AddRow("acme", "github", "Ready", "").
			AddRow("globex", "github", PhasePending, ""))
	got, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "globex", got[1].TenantID)

	mock.ExpectQuery("ORDER BY tenant_id, plugin_id").WillReturnError(errors.New("db down"))
	_, err = store.ListAll(ctx)
	require.Error(t, err)
	require.NoError(t, mock.ExpectationsWereMet())
}

// A report updates a row a tenant made and never creates one.
func TestStore_ReportStatus(t *testing.T) {
	ctx := context.Background()
	store, mock := newMockStore(t)

	mock.ExpectExec("UPDATE tenant_catalog_plugins").WithArgs("acme", "github", "Degraded", "image pull failed").
		WillReturnResult(sqlmock.NewResult(0, 1))
	updated, err := store.ReportStatus(ctx, "acme", "github", "Degraded", "image pull failed")
	require.NoError(t, err)
	assert.True(t, updated)

	mock.ExpectExec("UPDATE tenant_catalog_plugins").WillReturnResult(sqlmock.NewResult(0, 0))
	updated, err = store.ReportStatus(ctx, "acme", "gitlab", "Ready", "")
	require.NoError(t, err)
	assert.False(t, updated, "a report for a pair no tenant enabled changes nothing")

	mock.ExpectExec("UPDATE tenant_catalog_plugins").WillReturnError(errors.New("db down"))
	_, err = store.ReportStatus(ctx, "acme", "github", "Ready", "")
	require.Error(t, err)

	_, err = store.ReportStatus(ctx, "acme", "github", "", "")
	require.Error(t, err, "an empty phase must be refused")
	require.NoError(t, mock.ExpectationsWereMet())
}
