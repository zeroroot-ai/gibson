// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_quota.go
//
// Quota RPC handlers. The daemon enforces no plan quota and keeps no quota
// counter. These two RPCs stay until the dashboard stops the calls, and
// gibson#1530 deletes them with the tenant_quotas table.
//   - GetTenantQuota:      reports the stored tenant_quotas row. No code
//     enforces it.
//   - GetTenantQuotaUsage: reports zero, because no counter exists.
package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	status_grpc "google.golang.org/grpc/status"

	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ---------------------------------------------------------------------------
// GetTenantQuota — limits (Postgres)
// ---------------------------------------------------------------------------

// GetTenantQuota reports the stored tenant_quotas row of a tenant. The daemon
// enforces none of these values.
//
// gibsoncheck:allow tenant-from-request — guarded by requireTenantAdmin(ctx, tenantID) below,
// which FGA-Checks the caller's subject against the supplied tenant, so a foreign tenant id
// fails closed.
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
			resp.PlanId = row.planId
		}
	}
	return resp, nil
}

type tenantQuotaRow struct {
	concurrentMissions int32
	concurrentAgents   int32
	updatedAt          string
	planId             string
}

// readTenantQuotasRow loads the tenant_quotas row for a tenant. Returns
// (nil, nil) when the row is absent.
//
// plan_id is read via COALESCE so the query degrades gracefully when the
// column has not yet been added by the tenant-operator migration (returns
// empty string in that case).
func readTenantQuotasRow(ctx context.Context, db *sql.DB, tenantID string) (*tenantQuotaRow, error) {
	const q = `
		SELECT concurrent_missions, concurrent_agents, updated_at,
		       COALESCE(plan_id, '') AS plan_id
		FROM tenant_quotas
		WHERE tenant_id = $1
	`
	var r tenantQuotaRow
	var updatedAt time.Time
	err := db.QueryRowContext(ctx, q, tenantID).Scan(
		&r.concurrentMissions,
		&r.concurrentAgents,
		&updatedAt,
		&r.planId,
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
// GetTenantQuotaUsage
// ---------------------------------------------------------------------------

// GetTenantQuotaUsage reports zero for each counter. The daemon counts no
// missions and no agents for a plan, so there is no usage to report. The RPC
// stays until gibson#1530 deletes it.
func (s *DaemonServer) GetTenantQuotaUsage(ctx context.Context, _ *tenantv1.GetTenantQuotaUsageRequest) (*tenantv1.GetTenantQuotaUsageResponse, error) {
	if auth.TenantStringFromContext(ctx) == "" {
		return nil, status_grpc.Error(codes.InvalidArgument, "tenant_id is required")
	}
	return &tenantv1.GetTenantQuotaUsageResponse{}, nil
}
