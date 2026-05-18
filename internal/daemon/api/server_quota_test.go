// server_quota_test.go — tests for the GetTenantQuota and
// GetTenantQuotaUsage handlers post spec plans-and-quotas-simplification.
package api

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/gibson/internal/daemon/api/gibson/tenant/v1"
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
