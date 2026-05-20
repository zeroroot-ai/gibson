// Package api — server_quota.go
//
// Quota RPC handlers, post spec plans-and-quotas-simplification:
//   - GetTenantQuota:      reads the tenant_quotas Postgres row (limits).
//   - GetTenantQuotaUsage: reads the Redis :active counters (live usage).
//
// The legacy SetTenantQuota RPC + Redis quota:config JSON store + memory
// enforcement (CheckMemoryQuota / quota:memory:used_mb) are deleted; the
// only writer for tenant quotas is the operator's UpsertTenantQuota RPC,
// which writes Postgres directly.
package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zero-day-ai/platform-sdk/gen/gibson/tenant/v1"
	"github.com/zero-day-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// GetTenantQuota — limits (Postgres)
// ---------------------------------------------------------------------------

// GetTenantQuota retrieves the configured quota limits for a tenant.
// Returns zero values for any quota not explicitly set; 0 = unlimited
// (existing convention, applied by callers that interpret the response).
func (s *DaemonServer) GetTenantQuota(ctx context.Context, req *tenantv1.GetTenantQuotaRequest) (*tenantv1.GetTenantQuotaResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	if err := s.requireTenantAdmin(ctx, tenantID); err != nil {
		return nil, err
	}

	resp := &tenantv1.GetTenantQuotaResponse{}
	if db := s.platformDB; db != nil {
		row, err := readTenantQuotasRow(ctx, db, tenantID)
		if err != nil {
			s.logger.WarnContext(ctx, "GetTenantQuota: postgres read failed (returning zero limits)",
				slog.String("tenant_id", tenantID),
				slog.String("error", err.Error()),
			)
		} else if row != nil {
			resp.ConcurrentMissions = row.concurrentMissions
			resp.ConcurrentAgents = row.concurrentAgents
			resp.UpdatedAt = row.updatedAt
		}
	}
	return resp, nil
}

type tenantQuotaRow struct {
	concurrentMissions int32
	concurrentAgents   int32
	updatedAt          string
}

// readTenantQuotasRow loads the tenant_quotas row for a tenant. Returns
// (nil, nil) when the row is absent.
func readTenantQuotasRow(ctx context.Context, db *sql.DB, tenantID string) (*tenantQuotaRow, error) {
	const q = `
		SELECT concurrent_missions, concurrent_agents, updated_at
		FROM tenant_quotas
		WHERE tenant_id = $1
	`
	var r tenantQuotaRow
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, q, tenantID).Scan(
		&r.concurrentMissions,
		&r.concurrentAgents,
		&updatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.updatedAt = updatedAt.UTC().Format(time.RFC3339Nano)
	return &r, nil
}

// ---------------------------------------------------------------------------
// GetTenantQuotaUsage — live counters (Redis)
// ---------------------------------------------------------------------------

// quotaUsageReader is the narrow interface GetTenantQuotaUsage uses to read
// the live :active counters. *component.QuotaManager.ReadActiveCounters
// satisfies it; nil disables the RPC.
type quotaUsageReader interface {
	ReadActiveCounters(ctx context.Context, tenant string) (missions, agents int64, err error)
}

// GetTenantQuotaUsage returns the live counter values (current usage)
// for the two enforced quotas. Cheap (single MGET-equivalent through the
// tenant-scoped store); intended for the dashboard's in-app quota UX.
//
// Spec plans-and-quotas-simplification R9.B.
func (s *DaemonServer) GetTenantQuotaUsage(ctx context.Context, req *tenantv1.GetTenantQuotaUsageRequest) (*tenantv1.GetTenantQuotaUsageResponse, error) {
	tenantID := req.GetTenantId()
	if tenantID == "" {
		tenantID = auth.TenantStringFromContext(ctx)
	}
	if tenantID == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	// FGA member relation enforced by the auth interceptor (proto annotation
	// `relation: "member"`) — no re-check needed here.

	reader, ok := s.quotaManager.(quotaUsageReader)
	if !ok || reader == nil {
		return nil, status_grpc.Error(codes.Unavailable, "quota usage reader not configured")
	}
	missions, agents, err := reader.ReadActiveCounters(ctx, tenantID)
	if err != nil {
		s.logger.WarnContext(ctx, "GetTenantQuotaUsage: read failed (returning zeros)",
			slog.String("tenant_id", tenantID),
			slog.String("error", err.Error()),
		)
	}
	return &tenantv1.GetTenantQuotaUsageResponse{
		MissionsActive: missions,
		AgentsActive:   agents,
	}, nil
}
