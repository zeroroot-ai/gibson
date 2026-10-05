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

	mock.ExpectExec("UPDATE tenant_connectors").WithArgs("acme", "gitlab", "Ready", int32(7), "").
		WillReturnResult(sqlmock.NewResult(0, 1))
	ok, err := store.ReportStatus(ctx, "acme", "gitlab", Status{Phase: "Ready", DiscoveredTools: 7})
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
