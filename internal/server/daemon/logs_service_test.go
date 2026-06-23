package daemon

import (
	"context"
	"testing"

	"github.com/zeroroot-ai/gibson/internal/platform/observability/lokilogs"
	logspb "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/logs/v1"
	"github.com/zeroroot-ai/sdk/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeLogsQuerier records the tenant it was asked to query for and returns a
// canned entry tagged with that tenant, so a test can prove the handler scopes
// by the daemon-derived tenant and never by a client-supplied value.
type fakeLogsQuerier struct {
	missionTenant string
	daemonTenant  string
}

func (f *fakeLogsQuerier) QueryMissionLogs(_ context.Context, q lokilogs.MissionQuery) ([]lokilogs.Entry, error) {
	f.missionTenant = q.TenantID
	return []lokilogs.Entry{{UnixNanos: 1, Line: "mission line", Labels: map[string]string{"tenant_id": q.TenantID}}}, nil
}

func (f *fakeLogsQuerier) QueryDaemonLogs(_ context.Context, q lokilogs.DaemonQuery) ([]lokilogs.Entry, error) {
	f.daemonTenant = q.TenantID
	return []lokilogs.Entry{{UnixNanos: 2, Line: "daemon line", Labels: map[string]string{"tenant_id": q.TenantID, "level": q.Level}}}, nil
}

// TestLogsService_TenantScopedRead: the handler derives the tenant from context
// and passes it to the querier; a request with no tenant is PermissionDenied.
func TestLogsService_TenantScopedRead(t *testing.T) {
	fake := &fakeLogsQuerier{}
	srv := NewLogsServer(fake, nil)

	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	resp, err := srv.QueryMissionLogs(tctx, &logspb.QueryMissionLogsRequest{MissionId: "m1"})
	if err != nil {
		t.Fatalf("QueryMissionLogs: %v", err)
	}
	if len(resp.GetEntries()) != 1 || resp.Entries[0].Line != "mission line" {
		t.Fatalf("unexpected entries: %+v", resp.GetEntries())
	}
	// The querier must have been scoped to the caller's tenant — derived
	// server-side, never supplied by the client.
	if fake.missionTenant != "acme" {
		t.Fatalf("mission query tenant = %q, want acme", fake.missionTenant)
	}

	dResp, err := srv.QueryDaemonLogs(tctx, &logspb.QueryDaemonLogsRequest{Level: logspb.LogLevel_LOG_LEVEL_ERROR})
	if err != nil {
		t.Fatalf("QueryDaemonLogs: %v", err)
	}
	if len(dResp.GetEntries()) != 1 {
		t.Fatalf("unexpected daemon entries: %+v", dResp.GetEntries())
	}
	if fake.daemonTenant != "acme" {
		t.Fatalf("daemon query tenant = %q, want acme", fake.daemonTenant)
	}

	// No tenant in context -> PermissionDenied (both RPCs).
	if _, err := srv.QueryMissionLogs(context.Background(), &logspb.QueryMissionLogsRequest{MissionId: "m1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("QueryMissionLogs without tenant: want PermissionDenied, got %v", err)
	}
	if _, err := srv.QueryDaemonLogs(context.Background(), &logspb.QueryDaemonLogsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("QueryDaemonLogs without tenant: want PermissionDenied, got %v", err)
	}
}

// TestLogsService_CannotReadAnotherTenant: a caller authenticated as tenant A
// can never cause the backing query to run scoped to tenant B. The tenant fed
// to Loki is exactly the context tenant, regardless of request fields.
func TestLogsService_CannotReadAnotherTenant(t *testing.T) {
	fake := &fakeLogsQuerier{}
	srv := NewLogsServer(fake, nil)

	// Caller is tenant "alpha".
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("alpha"))

	resp, err := srv.QueryMissionLogs(tctx, &logspb.QueryMissionLogsRequest{MissionId: "victim-mission"})
	if err != nil {
		t.Fatalf("QueryMissionLogs: %v", err)
	}
	// The query was scoped to alpha — not to any other tenant — and the returned
	// entry's tenant_id label reflects alpha.
	if fake.missionTenant != "alpha" {
		t.Fatalf("query escaped tenant scope: scoped to %q, want alpha", fake.missionTenant)
	}
	if got := resp.Entries[0].Labels["tenant_id"]; got != "alpha" {
		t.Fatalf("returned entry tenant_id = %q, want alpha", got)
	}
}

// TestLogsService_MissionIDRequired: QueryMissionLogs rejects an empty mission_id.
func TestLogsService_MissionIDRequired(t *testing.T) {
	srv := NewLogsServer(&fakeLogsQuerier{}, nil)
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))
	if _, err := srv.QueryMissionLogs(tctx, &logspb.QueryMissionLogsRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for empty mission_id, got %v", err)
	}
}

// TestLogsService_BackendUnavailable: when the querier reports Loki unavailable
// the handler returns codes.Unavailable (the dashboard degrades cleanly).
func TestLogsService_BackendUnavailable(t *testing.T) {
	srv := NewLogsServer(unavailableLogsQuerier{}, nil)
	tctx := auth.WithTenant(context.Background(), auth.MustNewTenantID("acme"))

	if _, err := srv.QueryMissionLogs(tctx, &logspb.QueryMissionLogsRequest{MissionId: "m1"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
	if _, err := srv.QueryDaemonLogs(tctx, &logspb.QueryDaemonLogsRequest{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}
