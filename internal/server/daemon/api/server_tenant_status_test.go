// server_tenant_status_test.go — tests for the daemon-side tenant-status mirror
// (dashboard#855): ReportTenantStatus upsert, GetTenantProvisioningStatus
// (tenant-scoped, found / not-found), and CheckTenantSlugAvailable.
package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"os"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

func newStatusServer() *DaemonServer {
	return &DaemonServer{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

func expectEnsureStatusTable(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func errBoom() error { return errors.New("boom") }

// --- ReportTenantStatus ---

func TestReportTenantStatus_NilDB_Unavailable(t *testing.T) {
	srv := newStatusServer()
	srv.platformDB = nil
	_, err := srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestReportTenantStatus_MissingTenantID_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	_, err = srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestReportTenantStatus_Upserts(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").
		WithArgs("acme", "Ready", true, "org-123", true, false).
		WillReturnResult(sqlmock.NewResult(1, 1))

	_, err = srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{
		TenantId:       "acme",
		Phase:          "Ready",
		Ready:          true,
		ZitadelOrgId:   "org-123",
		DataPlaneReady: true,
	})
	if err != nil {
		t.Fatalf("report: %v", err)
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
	srv := newStatusServer()
	srv.platformDB = db
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_status").WillReturnError(errBoom())
	_, err = srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Internal)
}

func TestReportTenantStatus_UpsertError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	expectEnsureStatusTable(mock)
	mock.ExpectExec("INSERT INTO tenant_status").WillReturnError(errBoom())
	_, err = srv.ReportTenantStatus(context.Background(), &daemonoperatorv1.ReportTenantStatusRequest{
		TenantId: "acme", Phase: "Ready",
	})
	requireGRPCStatus(t, err, codes.Internal)
}

// --- GetTenantProvisioningStatus ---

func TestGetTenantProvisioningStatus_NoTenantContext_Unauthenticated(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	_, err = srv.GetTenantProvisioningStatus(context.Background(), &tenantv1.GetTenantProvisioningStatusRequest{})
	requireGRPCStatus(t, err, codes.Unauthenticated)
}

func TestGetTenantProvisioningStatus_ReturnsRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureStatusTable(mock)
	rows := sqlmock.NewRows([]string{"phase", "ready", "zitadel_org_id", "data_plane_ready", "owner_member_ready"}).
		AddRow("Ready", true, "org-123", true, true)
	mock.ExpectQuery("SELECT phase, ready, zitadel_org_id, data_plane_ready, owner_member_ready\\s+FROM tenant_status\\s+WHERE tenant_id = \\$1").
		WithArgs("acme").
		WillReturnRows(rows)

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetTenantProvisioningStatus(ctx, &tenantv1.GetTenantProvisioningStatusRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !resp.GetFound() {
		t.Fatalf("expected found=true")
	}
	if resp.GetPhase() != "Ready" || !resp.GetReady() || resp.GetZitadelOrgId() != "org-123" ||
		!resp.GetDataPlaneReady() || !resp.GetOwnerMemberReady() {
		t.Errorf("unexpected response: %+v", resp)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestGetTenantProvisioningStatus_NotReported_FoundFalse(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureStatusTable(mock)
	mock.ExpectQuery("SELECT phase, ready, zitadel_org_id, data_plane_ready, owner_member_ready").
		WithArgs("acme").
		WillReturnError(sql.ErrNoRows)

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	resp, err := srv.GetTenantProvisioningStatus(ctx, &tenantv1.GetTenantProvisioningStatusRequest{})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if resp.GetFound() {
		t.Errorf("expected found=false when operator has not reported")
	}
}

// TestGetTenantProvisioningStatus_TenantScoped_CannotReadOther asserts the read
// is keyed strictly on the CALLER tenant (resolved from context), so tenant A
// can only ever query its own row — the SQL is parameterised on the context
// tenant, never on a request-supplied id.
func TestGetTenantProvisioningStatus_TenantScoped_CannotReadOther(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureStatusTable(mock)
	// The query MUST be argued with the caller's tenant ("tenant-a"); sqlmock
	// fails the test if any other id is passed.
	mock.ExpectQuery("SELECT phase, ready, zitadel_org_id, data_plane_ready, owner_member_ready").
		WithArgs("tenant-a").
		WillReturnError(sql.ErrNoRows)

	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("tenant-a"))
	if _, err := srv.GetTenantProvisioningStatus(ctx, &tenantv1.GetTenantProvisioningStatusRequest{}); err != nil {
		t.Fatalf("get: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestGetTenantProvisioningStatus_NilDB_Unavailable(t *testing.T) {
	srv := newStatusServer()
	srv.platformDB = nil
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err := srv.GetTenantProvisioningStatus(ctx, &tenantv1.GetTenantProvisioningStatusRequest{})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestGetTenantProvisioningStatus_QueryError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	expectEnsureStatusTable(mock)
	mock.ExpectQuery("SELECT phase, ready, zitadel_org_id, data_plane_ready, owner_member_ready").
		WithArgs("acme").WillReturnError(errBoom())
	ctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	_, err = srv.GetTenantProvisioningStatus(ctx, &tenantv1.GetTenantProvisioningStatusRequest{})
	requireGRPCStatus(t, err, codes.Internal)
}

// --- CheckTenantSlugAvailable ---

func TestCheckTenantSlugAvailable_NilDB_Unavailable(t *testing.T) {
	srv := newStatusServer()
	srv.platformDB = nil
	_, err := srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: "acme"})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestCheckTenantSlugAvailable_PendingQueryError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM pending_tenant_provisioning WHERE tenant_id = \\$1\\)").
		WithArgs("acme").WillReturnError(errBoom())
	_, err = srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: "acme"})
	requireGRPCStatus(t, err, codes.Internal)
}

func TestCheckTenantSlugAvailable_StatusQueryError_Internal(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM pending_tenant_provisioning WHERE tenant_id = \\$1\\)").
		WithArgs("acme").WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	expectEnsureStatusTable(mock)
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM tenant_status WHERE tenant_id = \\$1\\)").
		WithArgs("acme").WillReturnError(errBoom())
	_, err = srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: "acme"})
	requireGRPCStatus(t, err, codes.Internal)
}

func TestCheckTenantSlugAvailable_MissingSlug_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	srv := newStatusServer()
	srv.platformDB = db
	_, err = srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestCheckTenantSlugAvailable_Taken_WhenPending(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureTable(mock) // pending_tenant_provisioning
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM pending_tenant_provisioning WHERE tenant_id = \\$1\\)").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	resp, err := srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: "acme"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if resp.GetAvailable() {
		t.Errorf("expected available=false when a pending-provisioning row exists")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestCheckTenantSlugAvailable_Available_WhenNeitherExists(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureTable(mock) // pending_tenant_provisioning
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM pending_tenant_provisioning WHERE tenant_id = \\$1\\)").
		WithArgs("freshslug").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	expectEnsureStatusTable(mock) // tenant_status
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM tenant_status WHERE tenant_id = \\$1\\)").
		WithArgs("freshslug").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))

	resp, err := srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: "freshslug"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !resp.GetAvailable() {
		t.Errorf("expected available=true when neither a pending nor a status row exists")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestCheckTenantSlugAvailable_Taken_WhenProvisioned(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	srv := newStatusServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM pending_tenant_provisioning WHERE tenant_id = \\$1\\)").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(false))
	expectEnsureStatusTable(mock)
	mock.ExpectQuery("SELECT EXISTS \\(SELECT 1 FROM tenant_status WHERE tenant_id = \\$1\\)").
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows([]string{"exists"}).AddRow(true))

	resp, err := srv.CheckTenantSlugAvailable(context.Background(), &tenantv1.CheckTenantSlugAvailableRequest{Slug: "acme"})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if resp.GetAvailable() {
		t.Errorf("expected available=false when a tenant_status row exists")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
