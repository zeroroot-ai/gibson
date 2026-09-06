// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"github.com/zeroroot-ai/sdk/auth"
)

func newQuotaTestServer() *DaemonServer {
	return &DaemonServer{
		logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})),
	}
}

// quotaAdminSubject is the caller identity used by the GetTenantQuota tests
// that must pass requireTenantAdmin's FGA Check.
const quotaAdminSubject = "quota-admin"

// newQuotaTestServerWithAdmin wires a fakeAuthorizer granting
// quotaAdminSubject the admin relation on tenant "acme", so
// GetTenantQuota's requireTenantAdmin gate (server_audit.go, now fail-closed
// when unwired) actually passes instead of erroring Unavailable.
func newQuotaTestServerWithAdmin() *DaemonServer {
	srv := newQuotaTestServer()
	srv.WithAuthorizer(newFakeAuthorizer().allow("user:"+quotaAdminSubject, "admin", "tenant:acme"))
	return srv
}

func TestGetTenantQuota_MissingTenantID_InvalidArgument(t *testing.T) {
	srv := newQuotaTestServer()
	_, err := srv.GetTenantQuota(context.Background(), &tenantv1.GetTenantQuotaRequest{TenantId: ""})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestGetTenantQuota_NilPlatformDB_ReturnsZeroLimits(t *testing.T) {
	srv := newQuotaTestServerWithAdmin()
	srv.platformDB = nil
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: quotaAdminSubject})
	resp, err := srv.GetTenantQuota(ctx, &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetConcurrentMissions() != 0 || resp.GetConcurrentAgents() != 0 {
		t.Errorf("expected zero limits when platformDB is nil, got %+v", resp)
	}
}

// TestGetTenantQuota_NoAuthorizer_Unavailable pins the requireTenantAdmin fix
// (server_audit.go): with no authorizer wired at all, GetTenantQuota must
// refuse with Unavailable rather than silently serving the request — the
// bug this same handler's suppression comment ("fails closed") previously
// misdescribed.
func TestGetTenantQuota_NoAuthorizer_Unavailable(t *testing.T) {
	srv := newQuotaTestServer() // authorizer intentionally left nil
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: quotaAdminSubject})
	_, err := srv.GetTenantQuota(ctx, &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.Unavailable)
}

func TestGetTenantQuotaUsage_MissingTenantInContext_InvalidArgument(t *testing.T) {
	srv := newQuotaTestServer()
	// A tenant_id on the request must not stand in for the authenticated tenant.
	_, err := srv.GetTenantQuotaUsage(context.Background(), &tenantv1.GetTenantQuotaUsageRequest{TenantId: "acme"})
	requireGRPCStatus(t, err, codes.InvalidArgument)
}

func TestGetTenantQuotaUsage_NilQuotaManager_Unavailable(t *testing.T) {
	srv := newQuotaTestServer()
	srv.quotaManager = nil
	_, err := srv.GetTenantQuotaUsage(tenantAndSubjectCtx("acme", "u1"), &tenantv1.GetTenantQuotaUsageRequest{})
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
	resp, err := srv.GetTenantQuotaUsage(tenantAndSubjectCtx("acme", "u1"), &tenantv1.GetTenantQuotaUsageRequest{})
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
	srv := newQuotaTestServerWithAdmin()
	srv.platformDB = nil
	ctx := auth.WithIdentity(context.Background(), auth.Identity{Subject: quotaAdminSubject})
	resp, err := srv.GetTenantQuota(ctx, &tenantv1.GetTenantQuotaRequest{TenantId: "acme"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.GetPlanId() != "" {
		t.Errorf("plan_id: got %q, want empty when platformDB is nil", resp.GetPlanId())
	}
}
