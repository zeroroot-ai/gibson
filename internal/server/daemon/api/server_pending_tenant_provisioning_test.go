// server_pending_tenant_provisioning_test.go — tests for the operator-pull
// tenant-provisioning queue handlers (E9, gibson#948).
package api

import (
	"context"
	"log/slog"
	"os"
	"testing"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

func newPendingServer() *DaemonServer {
	return &DaemonServer{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

// expectEnsureTable matches the CREATE TABLE IF NOT EXISTS guard that every
// handler runs before its real query.
func expectEnsureTable(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS pending_tenant_provisioning").
		WillReturnResult(sqlmock.NewResult(0, 0))
}

func TestEnqueuePendingTenantProvisioning_NilDB_NoError(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	enq, err := srv.enqueuePendingTenantProvisioning(context.Background(), &daemonoperatorv1.PendingTenant{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if enq {
		t.Errorf("expected enqueued=false when no platform DB configured")
	}
}

func TestEnqueuePendingTenantProvisioning_InsertsRow(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("INSERT INTO pending_tenant_provisioning").
		WithArgs("acme", "u-1", "owner@acme.test", "Acme Inc", "team", "cus_123").
		WillReturnResult(sqlmock.NewResult(1, 1))

	enq, err := srv.enqueuePendingTenantProvisioning(context.Background(), &daemonoperatorv1.PendingTenant{
		TenantId:         "acme",
		OwnerUserId:      "u-1",
		OwnerEmail:       "owner@acme.test",
		WorkspaceName:    "Acme Inc",
		Tier:             "team",
		StripeCustomerId: "cus_123",
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if !enq {
		t.Errorf("expected enqueued=true on fresh insert")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestEnqueuePendingTenantProvisioning_IdempotentConflict(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	// ON CONFLICT DO NOTHING → 0 rows affected on a retry of the same tenant.
	mock.ExpectExec("INSERT INTO pending_tenant_provisioning").
		WithArgs("acme", "u-1", "owner@acme.test", "Acme Inc", "team", "").
		WillReturnResult(sqlmock.NewResult(0, 0))

	enq, err := srv.enqueuePendingTenantProvisioning(context.Background(), &daemonoperatorv1.PendingTenant{
		TenantId:      "acme",
		OwnerUserId:   "u-1",
		OwnerEmail:    "owner@acme.test",
		WorkspaceName: "Acme Inc",
		Tier:          "team",
	})
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if enq {
		t.Errorf("expected enqueued=false on conflict (idempotent retry)")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestListPendingTenantProvisioning_NilDB_Unavailable(t *testing.T) {
	srv := newPendingServer()
	srv.platformDB = nil
	_, err := srv.ListPendingTenantProvisioning(context.Background(), &daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestListPendingTenantProvisioning_ReturnsRows(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	rows := sqlmock.NewRows([]string{"tenant_id", "owner_user_id", "owner_email", "workspace_name", "tier", "stripe_customer_id"}).
		AddRow("acme", "u-1", "owner@acme.test", "Acme Inc", "team", "cus_123").
		AddRow("globex", "u-2", "ceo@globex.test", "Globex", "org", "")
	mock.ExpectQuery("SELECT tenant_id, owner_user_id, owner_email, workspace_name, tier, stripe_customer_id\\s+FROM pending_tenant_provisioning").
		WillReturnRows(rows)

	resp, err := srv.ListPendingTenantProvisioning(context.Background(), &daemonoperatorv1.ListPendingTenantProvisioningRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(resp.GetPending()) != 2 {
		t.Fatalf("expected 2 pending rows, got %d", len(resp.GetPending()))
	}
	first := resp.GetPending()[0]
	if first.GetTenantId() != "acme" || first.GetTier() != "team" || first.GetStripeCustomerId() != "cus_123" {
		t.Errorf("unexpected first row: %+v", first)
	}
	if resp.GetPending()[1].GetStripeCustomerId() != "" {
		t.Errorf("expected empty stripe customer on second row")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}

func TestAckTenantProvisioned_MissingTenantID_InvalidArgument(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	srv := newPendingServer()
	srv.platformDB = db
	_, err = srv.AckTenantProvisioned(context.Background(), &daemonoperatorv1.AckTenantProvisionedRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestAckTenantProvisioned_MarksDone(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	mock.ExpectExec("UPDATE pending_tenant_provisioning").
		WithArgs("acme").
		WillReturnResult(sqlmock.NewResult(0, 1))

	resp, err := srv.AckTenantProvisioned(context.Background(), &daemonoperatorv1.AckTenantProvisionedRequest{TenantId: "acme"})
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

func TestAckTenantProvisioned_UnknownOrAlreadyDone_NoOp(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := newPendingServer()
	srv.platformDB = db

	expectEnsureTable(mock)
	// WHERE status <> 'done' matches nothing → 0 rows affected.
	mock.ExpectExec("UPDATE pending_tenant_provisioning").
		WithArgs("ghost").
		WillReturnResult(sqlmock.NewResult(0, 0))

	resp, err := srv.AckTenantProvisioned(context.Background(), &daemonoperatorv1.AckTenantProvisionedRequest{TenantId: "ghost"})
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if resp.GetAcked() {
		t.Errorf("expected acked=false for unknown/already-done tenant")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("expectations: %v", err)
	}
}
