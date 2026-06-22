package api

import (
	"context"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/daemon/api/gibson/daemon/operator/v1"
)

// Regression for gibson#558: UpsertTenantQuota must persist plan_id so the
// billing page shows the plan name instead of "No plan assigned".
func TestUpsertTenantQuota_WritesPlanID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	// ensureTenantQuotasTable: CREATE + three forward-compat ALTERs (missions, plan_id, connectors).
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	// The upsert binds plan_id as the 5th positional arg (after the connector budget).
	mock.ExpectQuery("INSERT INTO tenant_quotas").
		WithArgs("t1", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "team").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	s := &DaemonServer{platformDB: db}
	resp, err := s.UpsertTenantQuota(context.Background(), &daemonoperatorv1.UpsertTenantQuotaRequest{
		TenantId:           "t1",
		ConcurrentMissions: 10,
		ConcurrentAgents:   100,
		PlanId:             "team",
	})
	if err != nil {
		t.Fatalf("UpsertTenantQuota: %v", err)
	}
	if resp.GetUpdatedAt() == "" {
		t.Fatal("expected non-empty updated_at")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("plan_id not bound as expected: %v", err)
	}
}

// Empty plan_id (tenant not yet on a named plan) still upserts cleanly.
func TestUpsertTenantQuota_EmptyPlanIDOK(t *testing.T) {
	db, mock, _ := sqlmock.New()
	defer db.Close()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("ALTER TABLE tenant_quotas").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("INSERT INTO tenant_quotas").
		WithArgs("t2", sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), "").
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(time.Now()))

	s := &DaemonServer{platformDB: db}
	if _, err := s.UpsertTenantQuota(context.Background(), &daemonoperatorv1.UpsertTenantQuotaRequest{
		TenantId: "t2", ConcurrentMissions: 1, ConcurrentAgents: 1,
	}); err != nil {
		t.Fatalf("UpsertTenantQuota empty plan: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("expectations: %v", err)
	}
}
