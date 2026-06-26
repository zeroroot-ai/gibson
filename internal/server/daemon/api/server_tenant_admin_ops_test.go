// server_tenant_admin_ops_test.go — tests for the operator-pull admin tenant
// CRUD queue handlers (gibson#964, enables dashboard#855).
package api

import (
	"context"
	"log/slog"
	"os"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func newAdminOpsServer() *DaemonServer {
	return &DaemonServer{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

func expectEnsureAdminOpsTable(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_admin_ops").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

// --- AdminProvisionTenant ---

func TestAdminProvisionTenant_NilDB_Unavailable(t *testing.T) {
	srv := newAdminOpsServer()
	srv.platformDB = nil
	_, err := srv.AdminProvisionTenant(context.Background(), &tenantv1.AdminProvisionTenantRequest{
		TenantId: "acme", DisplayName: "Acme", OwnerEmail: "o@acme.test",
	})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestAdminProvisionTenant_MissingFields_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	for _, req := range []*tenantv1.AdminProvisionTenantRequest{
		{DisplayName: "Acme", OwnerEmail: "o@acme.test"}, // no tenant_id
		{TenantId: "acme", OwnerEmail: "o@acme.test"},    // no display_name
		{TenantId: "acme", DisplayName: "Acme"},          // no owner_email
	} {
		_, err := srv.AdminProvisionTenant(context.Background(), req)
		requireGRPCStatus(t, err, codes.InvalidArgument)
	}
}

func TestAdminProvisionTenant_RecordsOp_DefaultsTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	// Empty tier defaults to "team"; op_id is a generated UUID (any value).
	mock.ExpectExec("INSERT INTO tenant_admin_ops").
		WithArgs(sqlmock.AnyArg(), "acme", "Acme Inc", "owner@acme.test", "team").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.AdminProvisionTenant(context.Background(), &tenantv1.AdminProvisionTenantRequest{
		TenantId: "acme", DisplayName: "Acme Inc", OwnerEmail: "owner@acme.test",
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if resp.GetOpId() == "" {
		t.Errorf("expected non-empty op_id on fresh provision")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestAdminProvisionTenant_IdempotentDedup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	// WHERE NOT EXISTS matched an already-pending provision → 0 rows affected.
	mock.ExpectExec("INSERT INTO tenant_admin_ops").
		WithArgs(sqlmock.AnyArg(), "acme", "Acme Inc", "owner@acme.test", "org").
		WillReturnResult(sqlmock.NewResult(0, 0))

	resp, err := srv.AdminProvisionTenant(context.Background(), &tenantv1.AdminProvisionTenantRequest{
		TenantId: "acme", DisplayName: "Acme Inc", OwnerEmail: "owner@acme.test", Tier: "org",
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if resp.GetOpId() != "" {
		t.Errorf("expected empty op_id on idempotent de-dup, got %q", resp.GetOpId())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// --- AdminUpdateTenant ---

func TestAdminUpdateTenant_NoFieldsSet_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db
	_, err = srv.AdminUpdateTenant(context.Background(), &tenantv1.AdminUpdateTenantRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestAdminUpdateTenant_RecordsOp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	// tier-only update: tier="org" tier_set=true, display_name="" display_name_set=false.
	mock.ExpectExec("INSERT INTO tenant_admin_ops").
		WithArgs(sqlmock.AnyArg(), "acme", "", false, "org", true).
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.AdminUpdateTenant(context.Background(), &tenantv1.AdminUpdateTenantRequest{
		TenantId: "acme", Tier: "org", TierSet: true,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if resp.GetOpId() == "" {
		t.Errorf("expected non-empty op_id")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// --- AdminDeleteTenant ---

func TestAdminDeleteTenant_MissingTenantID_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db
	_, err = srv.AdminDeleteTenant(context.Background(), &tenantv1.AdminDeleteTenantRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestAdminDeleteTenant_RecordsOp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	mock.ExpectExec("INSERT INTO tenant_admin_ops").
		WithArgs(sqlmock.AnyArg(), "acme").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.AdminDeleteTenant(context.Background(), &tenantv1.AdminDeleteTenantRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if resp.GetOpId() == "" {
		t.Errorf("expected non-empty op_id")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// --- ListPendingTenantOps ---

func TestListPendingTenantOps_NilDB_Unavailable(t *testing.T) {
	srv := newAdminOpsServer()
	srv.platformDB = nil
	_, err := srv.ListPendingTenantOps(context.Background(), &daemonoperatorv1.ListPendingTenantOpsRequest{})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestListPendingTenantOps_ReturnsRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	rows := sqlmock.NewRows([]string{"op_id", "tenant_id", "op_type", "display_name", "display_name_set", "owner_email", "tier", "tier_set"}).
		AddRow("op-1", "acme", "provision", "Acme Inc", true, "o@acme.test", "team", true).
		AddRow("op-2", "globex", "delete", "", false, "", "", false)
	mock.ExpectQuery("SELECT op_id, tenant_id, op_type, display_name, display_name_set, owner_email, tier, tier_set\\s+FROM tenant_admin_ops").
		WillReturnRows(rows)

	resp, err := srv.ListPendingTenantOps(context.Background(), &daemonoperatorv1.ListPendingTenantOpsRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetOps()) != 2 {
		t.Fatalf("expected 2 ops, got %d", len(resp.GetOps()))
	}
	first := resp.GetOps()[0]
	if first.GetOpId() != "op-1" || first.GetOpType() != "provision" || first.GetTier() != "team" || !first.GetTierSet() {
		t.Errorf("unexpected first op: %+v", first)
	}
	if resp.GetOps()[1].GetOpType() != "delete" || resp.GetOps()[1].GetDisplayNameSet() {
		t.Errorf("unexpected second op: %+v", resp.GetOps()[1])
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

// --- AckTenantOp ---

func TestAckTenantOp_MissingOpID_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db
	_, err = srv.AckTenantOp(context.Background(), &daemonoperatorv1.AckTenantOpRequest{OpId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestAckTenantOp_MarksDone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	mock.ExpectExec("UPDATE tenant_admin_ops").
		WithArgs("op-1").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.AckTenantOp(context.Background(), &daemonoperatorv1.AckTenantOpRequest{OpId: "op-1"})
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if !resp.GetAcked() {
		t.Errorf("expected acked=true when a row transitioned to done")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestAckTenantOp_UnknownOrAlreadyDone_NoOp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newAdminOpsServer()
	srv.platformDB = db

	expectEnsureAdminOpsTable(mock)
	mock.ExpectExec("UPDATE tenant_admin_ops").
		WithArgs("ghost").
		WillReturnResult(sqlmock.NewResult(0, 0))

	resp, err := srv.AckTenantOp(context.Background(), &daemonoperatorv1.AckTenantOpRequest{OpId: "ghost"})
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if resp.GetAcked() {
		t.Errorf("expected acked=false for unknown/already-done op")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
