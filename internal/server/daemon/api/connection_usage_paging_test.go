// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package api

import (
	"fmt"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	connectionv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/connection/v1"
)

// ListTenantUsage pages the tenants by tenant id with a keyset query. The
// walk gets a new tenant between the pages and sees each first tenant once.
func TestListTenantUsage_WalkWithTenantsBetweenPages(t *testing.T) {
	ctx := peerCtx(t, testActivationSVID)
	srv, mock := mockedConnectionServer(t)
	srv.budgetEnforcer = usageEnforcer{}

	rows := func(ids ...string) *sqlmock.Rows {
		r := sqlmock.NewRows([]string{"tenant_id"})
		for _, id := range ids {
			r.AddRow(id)
		}
		return r
	}
	const query = "SELECT tenant_id FROM tenant_status WHERE tenant_id > \\$1 ORDER BY tenant_id LIMIT \\$2"

	// Page 1: three rows come back for a page of two, so a page follows.
	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery(query).WithArgs("", 3).WillReturnRows(rows("a", "c", "e"))
	p1, err := srv.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{PageSize: 2})
	require.NoError(t, err)
	require.Len(t, p1.GetTenants(), 2)
	require.NotEmpty(t, p1.GetNextPageToken())

	// A tenant "b" arrives before the cursor and "f" after it. The cursor is "c".
	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery(query).WithArgs("c", 3).WillReturnRows(rows("e", "f"))
	p2, err := srv.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{PageSize: 2, PageToken: p1.GetNextPageToken()})
	require.NoError(t, err)
	require.Len(t, p2.GetTenants(), 2)
	assert.Empty(t, p2.GetNextPageToken(), "the last page has no token")

	seen := make([]string, 0, len(p1.GetTenants())+len(p2.GetTenants()))
	for _, tn := range append(p1.GetTenants(), p2.GetTenants()...) {
		seen = append(seen, tn.GetTenantId())
	}
	assert.Equal(t, []string{"a", "c", "e", "f"}, seen)
	require.NoError(t, mock.ExpectationsWereMet())
}

func TestListTenantUsage_RefusesAForgedToken(t *testing.T) {
	ctx := peerCtx(t, testActivationSVID)
	srv, _ := mockedConnectionServer(t)
	srv.budgetEnforcer = usageEnforcer{}
	_, err := srv.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{PageToken: "forged.token"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "err = %v", err)
}

func TestListTenantUsage_WithoutKeysTheListFails(t *testing.T) {
	ctx := peerCtx(t, testActivationSVID)
	srv, _ := mockedConnectionServer(t)
	srv.budgetEnforcer = usageEnforcer{}
	srv.WithPageKeys(nil)
	_, err := srv.ListTenantUsage(ctx, &connectionv1.ListTenantUsageRequest{})
	assert.Equal(t, codes.Internal, status.Code(err), fmt.Sprint(err))
}

func TestListTenantIDsAfter_ReportsAScanFailure(t *testing.T) {
	srv, mock := mockedConnectionServer(t)
	mock.ExpectQuery("SELECT tenant_id").WillReturnRows(sqlmock.NewRows([]string{"tenant_id", "x"}).AddRow("a", "b"))
	_, _, err := listTenantIDsAfter(peerCtx(t, testActivationSVID), srv.platformDB, "", 2)
	assert.Error(t, err)
}
