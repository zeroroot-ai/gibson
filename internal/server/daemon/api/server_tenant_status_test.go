// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// server_tenant_status_test.go — tests for the operator-reported tenant status
// read-back handlers (E9, gibson#948, dashboard#813).
// S5 (billing#3): SetTenantBillingActive invalidates the entitlements cache.
package api

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// fakeInvalidatingQuotaManager satisfies MissionQuotaChecker and records
// InvalidateCache calls so tests can assert the tenant was invalidated.
type fakeInvalidatingQuotaManager struct {
	invalidated atomic.Int64 // count of InvalidateCache calls
	lastTenant  atomic.Value // last tenant string passed to InvalidateCache
}

func (f *fakeInvalidatingQuotaManager) CheckMissionQuota(_ context.Context) error     { return nil }
func (f *fakeInvalidatingQuotaManager) CheckAgentQuota(_ context.Context) error       { return nil }
func (f *fakeInvalidatingQuotaManager) IncrementMissionCount(_ context.Context) error { return nil }
func (f *fakeInvalidatingQuotaManager) InvalidateCache(tenantID string) {
	f.lastTenant.Store(tenantID)
	f.invalidated.Add(1)
}

var errBoom = errors.New("boom")

func expectEnsureTenantStatusTable(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func TestReportTenantStatus_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestReportTenantStatus_NilDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestReportTenantStatus_Upserts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").
		WithArgs("acme", "Ready", true, "Ready", "Ready", "Provisioning", "acme-org").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{
		TenantId:       "acme",
		Phase:          "Ready",
		DataPlaneReady: true,
		StorePostgres:  "Ready",
		StoreRedis:     "Ready",
		StoreNeo4J:     "Provisioning",
		ZitadelOrgSlug: "acme-org",
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !resp.GetUpdated() {
		t.Errorf("expected updated=true on a changed upsert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestReportTenantStatus_EnsureTableError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").WillReturnError(errBoom)
	_, err = srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Internal)
}

func TestReportTenantStatus_UpsertError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	expectEnsureTenantStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").WillReturnError(errBoom)
	_, err = srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Internal)
}

func TestGetTenantProvisioningStatus_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.GetTenantProvisioningStatus(context.Background(), &tenantv1.GetTenantProvisioningStatusRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestGetTenantProvisioningStatus_NilDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.GetTenantProvisioningStatus(context.Background(), &tenantv1.GetTenantProvisioningStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestGetTenantProvisioningStatus_QueryError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT phase, data_plane_ready").WithArgs("acme").WillReturnError(errBoom)
	_, err = srv.GetTenantProvisioningStatus(context.Background(), &tenantv1.GetTenantProvisioningStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Internal)
}

func TestGetTenantProvisioningStatus_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectQuery("SELECT phase, data_plane_ready").
		WithArgs("ghost").
		WillReturnError(sql.ErrNoRows)

	resp, err := srv.GetTenantProvisioningStatus(context.Background(), &tenantv1.GetTenantProvisioningStatusRequest{TenantId: "ghost"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.GetFound() {
		t.Errorf("expected found=false for unknown slug")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestGetTenantProvisioningStatus_ReturnsSnapshot(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	rows := sqlmock.NewRows([]string{
		"phase", "data_plane_ready", "store_postgres", "store_redis", "store_neo4j",
		"zitadel_org_slug",
	}).AddRow("Provisioning", false, "Ready", "Provisioning", "", "acme-org")
	mock.ExpectQuery("SELECT phase, data_plane_ready").
		WithArgs("acme").
		WillReturnRows(rows)

	// This RPC serves the same coarse view to every caller — even the tenant
	// itself. The org slug is NOT served here (gibson#1339). See
	// tenant_status_gates_test.go for the full contract.
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetTenantProvisioningStatus(ctx, &tenantv1.GetTenantProvisioningStatusRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !resp.GetFound() || resp.GetPhase() != "Provisioning" || resp.GetDataPlaneReady() {
		t.Errorf("unexpected snapshot: %+v", resp)
	}
	if resp.GetStores().GetPostgres() != "Ready" || resp.GetStores().GetRedis() != "Provisioning" {
		t.Errorf("unexpected stores: %+v", resp.GetStores())
	}
	// The org-created edge is disclosed (the operator reported a non-empty
	// slug); the slug itself is not.
	if !resp.GetZitadelOrgReady() {
		t.Errorf("expected zitadel_org_ready=true when the operator reported an org slug")
	}
	if resp.GetZitadelOrgSlug() != "" {
		t.Errorf("the org slug must not be served by this RPC: %+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
