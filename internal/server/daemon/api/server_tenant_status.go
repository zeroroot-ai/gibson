// Package api — server_tenant_status.go
//
// Daemon-side mirror of the Tenant CR's provisioning status (zero-kubeconfig,
// dashboard#855). The dashboard's signup + tenant-status surfaces need the
// Tenant CR's provisioning status (phase, zitadelOrgID, data-plane readiness,
// owner-member readiness), but the daemon cannot read Kubernetes (ADR-0023).
//
// The tenant-operator — the sole K8s actor — reports the Tenant CR's aggregate
// status into the platform Postgres (tenant_status, migration 017) via
// DaemonOperatorService.ReportTenantStatus. The daemon serves it back to the
// dashboard via TenantService.GetTenantProvisioningStatus and
// SignupService.CheckTenantSlugAvailable. The daemon never touches Kubernetes —
// it only reads/writes its own Postgres mirror.
package api

import (
	"context"
	"database/sql"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// tenantStatusRow models the tenant_status row (migration 017). Kept file-local,
// mirroring the pending_tenant_provisioning handlers which scan straight into
// the generated proto type — there is no separate store package.
type tenantStatusRow struct {
	Phase            string
	Ready            bool
	ZitadelOrgID     string
	DataPlaneReady   bool
	OwnerMemberReady bool
}

// ReportTenantStatus upserts the daemon's mirror of a Tenant CR's aggregate
// provisioning status. Operator-only (platform_operator on system_tenant,
// enforced by ext-authz). The daemon never reads Kubernetes here — the operator
// owns the Tenant CR and pushes its observable status in. Idempotent upsert
// keyed on tenant_id.
func (s *DaemonServer) ReportTenantStatus(ctx context.Context, req *daemonoperatorv1.ReportTenantStatusRequest) (*daemonoperatorv1.ReportTenantStatusResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Errorf(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id required")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		INSERT INTO tenant_status
			(tenant_id, phase, ready, zitadel_org_id, data_plane_ready, owner_member_ready, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			phase            = EXCLUDED.phase,
			ready            = EXCLUDED.ready,
			zitadel_org_id   = EXCLUDED.zitadel_org_id,
			data_plane_ready = EXCLUDED.data_plane_ready,
			-- owner_member_ready is monotonic: once the founding-owner
			-- TenantMember reaches Active it never regresses. The Tenant
			-- reconcile reports it false (it is not its concern); the
			-- owner-member path reports it true. OR-ing preserves a prior
			-- true so the Tenant reconcile cannot clobber it back to false.
			owner_member_ready = tenant_status.owner_member_ready OR EXCLUDED.owner_member_ready,
			updated_at       = NOW()
	`
	if _, err := db.ExecContext(ctx, q,
		req.GetTenantId(), req.GetPhase(), req.GetReady(),
		req.GetZitadelOrgId(), req.GetDataPlaneReady(), req.GetOwnerMemberReady(),
	); err != nil {
		return nil, status.Errorf(codes.Internal, "upsert tenant_status: %v", err)
	}
	return &daemonoperatorv1.ReportTenantStatusResponse{}, nil
}

// getTenantStatus reads the mirrored status row for a tenant. Returns
// (nil, nil) when no row exists yet (the operator has not reported) so the
// caller can report found=false.
func (s *DaemonServer) getTenantStatus(ctx context.Context, db *sql.DB, tenantID string) (*tenantStatusRow, error) {
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, fmt.Errorf("ensure table: %w", err)
	}
	const q = `
		SELECT phase, ready, zitadel_org_id, data_plane_ready, owner_member_ready
		FROM tenant_status
		WHERE tenant_id = $1
	`
	var row tenantStatusRow
	err := db.QueryRowContext(ctx, q, tenantID).Scan(
		&row.Phase, &row.Ready, &row.ZitadelOrgID, &row.DataPlaneReady, &row.OwnerMemberReady,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query tenant_status: %w", err)
	}
	return &row, nil
}

// tenantStatusExists reports whether a tenant_status row exists for a slug —
// the provisioned-tenant half of the slug-availability check.
func (s *DaemonServer) tenantStatusExists(ctx context.Context, db *sql.DB, tenantID string) (bool, error) {
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return false, fmt.Errorf("ensure table: %w", err)
	}
	const q = `SELECT EXISTS (SELECT 1 FROM tenant_status WHERE tenant_id = $1)`
	var exists bool
	if err := db.QueryRowContext(ctx, q, tenantID).Scan(&exists); err != nil {
		return false, fmt.Errorf("query tenant_status exists: %w", err)
	}
	return exists, nil
}

// ensureTenantStatusTable creates tenant_status if it does not yet exist.
// Mirrors ensurePendingTenantProvisioningTable: migration 017 is authoritative,
// but this keeps the RPCs working on a freshly-pointed DB before migrations run.
func ensureTenantStatusTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS tenant_status (
			tenant_id          TEXT PRIMARY KEY,
			phase              TEXT NOT NULL DEFAULT '',
			ready              BOOLEAN NOT NULL DEFAULT FALSE,
			zitadel_org_id     TEXT NOT NULL DEFAULT '',
			data_plane_ready   BOOLEAN NOT NULL DEFAULT FALSE,
			owner_member_ready BOOLEAN NOT NULL DEFAULT FALSE,
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create tenant_status: %w", err)
	}
	return nil
}
