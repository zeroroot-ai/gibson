// server_quota_test.go — tests for the GetTenantQuota and
// GetTenantQuotaUsage handlers post spec plans-and-quotas-simplification.
package api

import (
	"context"
	"log/slog"
	"os"
	"regexp"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

func newQuotaTestServer() *DaemonServer {
	return &DaemonServer{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

func TestGetTenantQuota_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newQuotaTestServer()
	_, err := srv.GetTenantQuota(context.Background(), &tenantv1.GetTenantQuotaRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestGetTenantQuota_NilPlatformDB_ReturnsZeroLimits(t *testing.T) {
	srv := newQuotaTestServer()
	srv.platformDB = nil
	resp, err := srv.GetTenantQuota(context.Background(), &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetConcurrentMissions() != 0 || resp.GetConcurrentAgents() != 0 {
		t.Errorf("expected zero limits when platformDB is nil, got %+v", resp)
	}
}

func TestGetTenantQuotaUsage_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newQuotaTestServer()
	_, err := srv.GetTenantQuotaUsage(context.Background(), &tenantv1.GetTenantQuotaUsageRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestGetTenantQuotaUsage_NilQuotaManager_Unavailable(t *testing.T) {
	srv := newQuotaTestServer()
	srv.quotaManager = nil
	_, err := srv.GetTenantQuotaUsage(context.Background(), &tenantv1.GetTenantQuotaUsageRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Unavailable)
}

type fakeQuotaUsageReader struct {
	missions, agents int64
}

func (f *fakeQuotaUsageReader) ReadActiveCounters(_ context.Context, _ string) (int64, int64, error) {
	return f.missions, f.agents, nil
}
func (f *fakeQuotaUsageReader) CheckMissionQuota(_ context.Context) error     { return nil }
func (f *fakeQuotaUsageReader) CheckAgentQuota(_ context.Context) error       { return nil }
func (f *fakeQuotaUsageReader) IncrementMissionCount(_ context.Context) error { return nil }
func (f *fakeQuotaUsageReader) InvalidateCache(_ string)                      {}

func TestGetTenantQuotaUsage_ReturnsCounterValues(t *testing.T) {
	srv := newQuotaTestServer()
	srv.quotaManager = &fakeQuotaUsageReader{missions: 4, agents: 9}
	resp, err := srv.GetTenantQuotaUsage(context.Background(), &tenantv1.GetTenantQuotaUsageRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetMissionsActive() != 4 {
		t.Errorf("missions: got %d, want 4", resp.GetMissionsActive())
	}
	if resp.GetAgentsActive() != 9 {
		t.Errorf("agents: got %d, want 9", resp.GetAgentsActive())
	}
}

func requireGRPCStatus(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected gRPC %s, got nil", want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %T %v", err, err)
	}
	if st.Code() != want {
		t.Fatalf("expected gRPC code %s, got %s (%v)", want, st.Code(), err)
	}
}

// ---------------------------------------------------------------------------
// readTenantQuotasRow — unit tests (sqlmock)
// ---------------------------------------------------------------------------

func TestReadTenantQuotasRow_WithPlanId(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	cols := []string{"concurrent_missions", "concurrent_agents", "updated_at", "plan_id"}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT")).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(cols).AddRow(int32(10), int32(50), now, "enterprise"))

	row, err := readTenantQuotasRow(context.Background(), db, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row == nil {
		t.Fatal("expected non-nil row")
	}
	if row.planId != "enterprise" {
		t.Errorf("plan_id: got %q, want %q", row.planId, "enterprise")
	}
	if row.concurrentMissions != 10 {
		t.Errorf("concurrent_missions: got %d, want 10", row.concurrentMissions)
	}
	if row.concurrentAgents != 50 {
		t.Errorf("concurrent_agents: got %d, want 50", row.concurrentAgents)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestReadTenantQuotasRow_EmptyPlanId(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	now := time.Now().UTC().Truncate(time.Second)
	cols := []string{"concurrent_missions", "concurrent_agents", "updated_at", "plan_id"}
	// COALESCE returns "" when plan_id column is NULL or absent.
	mock.ExpectQuery(regexp.QuoteMeta("SELECT")).
		WithArgs("acme").
		WillReturnRows(sqlmock.NewRows(cols).AddRow(int32(5), int32(20), now, ""))

	row, err := readTenantQuotasRow(context.Background(), db, "acme")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row == nil {
		t.Fatal("expected non-nil row")
	}
	if row.planId != "" {
		t.Errorf("plan_id: got %q, want empty string", row.planId)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestReadTenantQuotasRow_NoRow_ReturnsNil(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer db.Close()

	cols := []string{"concurrent_missions", "concurrent_agents", "updated_at", "plan_id"}
	mock.ExpectQuery(regexp.QuoteMeta("SELECT")).
		WithArgs("unknown").
		WillReturnRows(sqlmock.NewRows(cols))

	row, err := readTenantQuotasRow(context.Background(), db, "unknown")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if row != nil {
		t.Errorf("expected nil row for missing tenant, got %+v", row)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unmet sqlmock expectations: %v", err)
	}
}

func TestGetTenantQuota_NilPlatformDB_PlanIdEmpty(t *testing.T) {
	srv := newQuotaTestServer()
	srv.platformDB = nil
	resp, err := srv.GetTenantQuota(context.Background(), &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetPlanId() != "" {
		t.Errorf("plan_id: got %q, want empty when platformDB is nil", resp.GetPlanId())
	}
}
