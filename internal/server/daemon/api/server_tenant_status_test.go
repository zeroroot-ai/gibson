// server_tenant_status_test.go — tests for the operator-reported tenant status
// read-back handlers (E9, gibson#948, dashboard#813).
package api

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

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

func TestReportTenantStatus_UpsertsAndEchoesBilling(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").
		WithArgs("acme", "Ready", true, "Ready", "Ready", "Provisioning", "acme-org", "cus_9").
		WillReturnResult(sqlmock.NewResult(0, 1))
	// Billing flag is read back after the upsert (operator stamps the annotation).
	mock.ExpectQuery("SELECT billing_active FROM tenant_status").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"billing_active"}).AddRow(true))

	resp, err := srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{
		TenantId:         "acme",
		Phase:            "Ready",
		DataPlaneReady:   true,
		StorePostgres:    "Ready",
		StoreRedis:       "Ready",
		StoreNeo4J:       "Provisioning",
		ZitadelOrgSlug:   "acme-org",
		StripeCustomerId: "cus_9",
	})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if !resp.GetUpdated() {
		t.Errorf("expected updated=true on a changed upsert")
	}
	if !resp.GetBillingActive() {
		t.Errorf("expected billing_active echoed back true")
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

func TestSetTenantBillingActive_NilDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.SetTenantBillingActive(context.Background(), &tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestSetTenantBillingActive_UpsertError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newPendingServer()
	srv.platformDB = db
	expectEnsureTenantStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").WillReturnError(errBoom)
	_, err = srv.SetTenantBillingActive(context.Background(), &tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})
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
		"zitadel_org_slug", "stripe_customer_id", "billing_active",
	}).AddRow("Provisioning", false, "Ready", "Provisioning", "", "acme-org", "cus_9", true)
	mock.ExpectQuery("SELECT phase, data_plane_ready").
		WithArgs("acme").
		WillReturnRows(rows)

	resp, err := srv.GetTenantProvisioningStatus(context.Background(), &tenantv1.GetTenantProvisioningStatusRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !resp.GetFound() || resp.GetPhase() != "Provisioning" || resp.GetDataPlaneReady() {
		t.Errorf("unexpected snapshot: %+v", resp)
	}
	if resp.GetStores().GetPostgres() != "Ready" || resp.GetStores().GetRedis() != "Provisioning" {
		t.Errorf("unexpected stores: %+v", resp.GetStores())
	}
	if resp.GetStripeCustomerId() != "cus_9" || !resp.GetBillingActive() || resp.GetZitadelOrgSlug() != "acme-org" {
		t.Errorf("unexpected fields: %+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestSetTenantBillingActive_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.SetTenantBillingActive(context.Background(), &tenantv1.SetTenantBillingActiveRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestSetTenantBillingActive_Upserts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTenantStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").
		WithArgs("acme", true).
		WillReturnResult(sqlmock.NewResult(1, 1))

	resp, err := srv.SetTenantBillingActive(context.Background(), &tenantv1.SetTenantBillingActiveRequest{TenantId: "acme", Active: true})
	if err != nil {
		t.Fatalf("set billing: %v", err)
	}
	if !resp.GetUpdated() {
		t.Errorf("expected updated=true on insert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
