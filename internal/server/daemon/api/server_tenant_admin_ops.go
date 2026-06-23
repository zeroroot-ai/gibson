// Package api — server_tenant_admin_ops.go
//
// Operator-pull admin tenant CRUD (gibson#964, enables dashboard#855).
//
// dashboard#855 removes the dashboard's last Kubernetes consumer — the admin
// CRD tool (app/actions/crd/tenant.ts) that let a platform admin
// provision/update/delete a tenant by writing the Tenant CR directly from the
// web tier. This file is the daemon side of the replacement:
//
//   - AdminTenantService (dashboard-facing) records the admin's intent in the
//     platform Postgres tenant_admin_ops queue (migration 018). Cross-tenant
//     platform-admin only (platform_operator USER, enforced by ext-authz).
//   - DaemonOperatorService.ListPendingTenantOps / AckTenantOp (operator-facing)
//     let the tenant-operator drain the queue. The operator applies each op to
//     the Tenant CR (create / patch spec / delete) and acks.
//
// ADR-0023: the daemon never touches Kubernetes. These handlers only read/write
// the platform Postgres queue; every Tenant-CR mutation happens in the operator
// (which holds tenants create/update/delete RBAC). This mirrors the self-serve
// operator-pull provisioning path (server_pending_tenant_provisioning.go,
// gibson#948/#949) for the admin CRUD operations.
package api

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// defaultProvisionTier mirrors the dashboard's provisionTenantAction default
// (`parsed.data.tier ?? 'team'`): an empty tier on provision becomes "team".
const defaultProvisionTier = "team"

// --- AdminTenantService (dashboard-facing) -------------------------------

// AdminProvisionTenant records intent to create a new tenant. Replaces the
// dashboard provisionTenantAction's applyTenant() Tenant-CR create. The operator
// drains the queue and creates the Tenant CR. Cross-tenant platform-admin only
// (ext-authz enforces platform_operator USER).
//
// Idempotent on tenant_id: if a provision op is already pending for this slug,
// the insert is a no-op and op_id is empty — a double-submit cannot enqueue two
// provisions (and even if it did, the operator's existence check would make the
// second create a no-op).
func (s *DaemonServer) AdminProvisionTenant(ctx context.Context, req *tenantv1.AdminProvisionTenantRequest) (*tenantv1.AdminProvisionTenantResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if req.GetDisplayName() == "" {
		return nil, status.Error(codes.InvalidArgument, "display_name required")
	}
	if req.GetOwnerEmail() == "" {
		return nil, status.Error(codes.InvalidArgument, "owner_email required")
	}
	if err := ensureTenantAdminOpsTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	tier := req.GetTier()
	if tier == "" {
		tier = defaultProvisionTier
	}
	opID := uuid.NewString()
	const q = `
		INSERT INTO tenant_admin_ops
			(op_id, tenant_id, op_type, display_name, display_name_set, owner_email, tier, tier_set, status, created_at, updated_at)
		SELECT $1, $2, 'provision', $3, TRUE, $4, $5, TRUE, 'pending', NOW(), NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant_admin_ops
			WHERE tenant_id = $2 AND op_type = 'provision' AND status = 'pending'
		)
	`
	res, err := db.ExecContext(ctx, q, opID, req.GetTenantId(), req.GetDisplayName(), req.GetOwnerEmail(), tier)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "insert tenant_admin_ops: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		// A provision op was already pending — idempotent de-dup.
		return &tenantv1.AdminProvisionTenantResponse{}, nil
	}
	return &tenantv1.AdminProvisionTenantResponse{OpId: opID}, nil
}

// AdminUpdateTenant records intent to patch a tenant's tier and/or display name.
// Replaces the dashboard updateTenantAction's patchTenant({spec}). At least one
// of tier_set / display_name_set must be true. The operator patches the marked
// fields on Tenant.spec; unset fields are left untouched.
func (s *DaemonServer) AdminUpdateTenant(ctx context.Context, req *tenantv1.AdminUpdateTenantRequest) (*tenantv1.AdminUpdateTenantResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if !req.GetTierSet() && !req.GetDisplayNameSet() {
		return nil, status.Error(codes.InvalidArgument, "at least one of tier or display_name must be set")
	}
	if err := ensureTenantAdminOpsTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	opID := uuid.NewString()
	const q = `
		INSERT INTO tenant_admin_ops
			(op_id, tenant_id, op_type, display_name, display_name_set, owner_email, tier, tier_set, status, created_at, updated_at)
		VALUES ($1, $2, 'update', $3, $4, '', $5, $6, 'pending', NOW(), NOW())
	`
	if _, err := db.ExecContext(ctx, q,
		opID, req.GetTenantId(), req.GetDisplayName(), req.GetDisplayNameSet(), req.GetTier(), req.GetTierSet(),
	); err != nil {
		return nil, status.Errorf(codes.Internal, "insert tenant_admin_ops: %v", err)
	}
	return &tenantv1.AdminUpdateTenantResponse{OpId: opID}, nil
}

// AdminDeleteTenant records intent to delete a tenant. Replaces the dashboard
// deleteTenantAction's deleteTenant() Tenant-CR delete. The operator deletes the
// Tenant CR, which triggers the existing finalizer teardown — the daemon does not
// delete any tenant data itself.
//
// Idempotent on tenant_id: if a delete op is already pending for this slug, the
// insert is a no-op and op_id is empty.
func (s *DaemonServer) AdminDeleteTenant(ctx context.Context, req *tenantv1.AdminDeleteTenantRequest) (*tenantv1.AdminDeleteTenantResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if err := ensureTenantAdminOpsTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	opID := uuid.NewString()
	const q = `
		INSERT INTO tenant_admin_ops
			(op_id, tenant_id, op_type, display_name, display_name_set, owner_email, tier, tier_set, status, created_at, updated_at)
		SELECT $1, $2, 'delete', '', FALSE, '', '', FALSE, 'pending', NOW(), NOW()
		WHERE NOT EXISTS (
			SELECT 1 FROM tenant_admin_ops
			WHERE tenant_id = $2 AND op_type = 'delete' AND status = 'pending'
		)
	`
	res, err := db.ExecContext(ctx, q, opID, req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "insert tenant_admin_ops: %v", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return &tenantv1.AdminDeleteTenantResponse{}, nil
	}
	return &tenantv1.AdminDeleteTenantResponse{OpId: opID}, nil
}

// --- DaemonOperatorService (operator-facing) -----------------------------

// ListPendingTenantOps returns the queue of admin tenant ops awaiting
// application to the Tenant CR (status=pending), in created_at order so a
// tenant's ops apply in sequence. Operator-only (platform_operator on
// system_tenant, enforced by ext-authz). The daemon never reads Kubernetes here.
func (s *DaemonServer) ListPendingTenantOps(ctx context.Context, _ *daemonoperatorv1.ListPendingTenantOpsRequest) (*daemonoperatorv1.ListPendingTenantOpsResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantAdminOpsTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		SELECT op_id, tenant_id, op_type, display_name, display_name_set, owner_email, tier, tier_set
		FROM tenant_admin_ops
		WHERE status = 'pending'
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query tenant_admin_ops: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := &daemonoperatorv1.ListPendingTenantOpsResponse{}
	for rows.Next() {
		var op daemonoperatorv1.TenantOp
		if err := rows.Scan(
			&op.OpId, &op.TenantId, &op.OpType, &op.DisplayName,
			&op.DisplayNameSet, &op.OwnerEmail, &op.Tier, &op.TierSet,
		); err != nil {
			return nil, status.Errorf(codes.Internal, "scan tenant_admin_op row: %v", err)
		}
		out.Ops = append(out.Ops, &op)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "iterate tenant_admin_op rows: %v", err)
	}
	return out, nil
}

// AckTenantOp marks a pending admin-op record done after the operator has applied
// it to the Tenant CR. Operator-only. Idempotent: acking an unknown or
// already-done op_id returns acked=false with no error.
func (s *DaemonServer) AckTenantOp(ctx context.Context, req *daemonoperatorv1.AckTenantOpRequest) (*daemonoperatorv1.AckTenantOpResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetOpId() == "" {
		return nil, status.Error(codes.InvalidArgument, "op_id required")
	}
	if err := ensureTenantAdminOpsTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		UPDATE tenant_admin_ops
		SET status = 'done', updated_at = NOW()
		WHERE op_id = $1 AND status <> 'done'
	`
	res, err := db.ExecContext(ctx, q, req.GetOpId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update tenant_admin_ops: %v", err)
	}
	n, _ := res.RowsAffected()
	return &daemonoperatorv1.AckTenantOpResponse{Acked: n > 0}, nil
}

// ensureTenantAdminOpsTable creates tenant_admin_ops if it does not yet exist.
// Mirrors ensurePendingTenantProvisioningTable: migration 018 is authoritative,
// but this keeps the RPCs working on a freshly-pointed DB before migrations run.
func ensureTenantAdminOpsTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS tenant_admin_ops (
			op_id              TEXT PRIMARY KEY,
			tenant_id          TEXT NOT NULL,
			op_type            TEXT NOT NULL
				CONSTRAINT tenant_admin_ops_op_type_check
				CHECK (op_type IN ('provision', 'update', 'delete')),
			display_name       TEXT NOT NULL DEFAULT '',
			display_name_set   BOOLEAN NOT NULL DEFAULT FALSE,
			owner_email        TEXT NOT NULL DEFAULT '',
			tier               TEXT NOT NULL DEFAULT '',
			tier_set           BOOLEAN NOT NULL DEFAULT FALSE,
			status             TEXT NOT NULL DEFAULT 'pending'
				CONSTRAINT tenant_admin_ops_status_check
				CHECK (status IN ('pending', 'done')),
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create tenant_admin_ops: %w", err)
	}
	return nil
}
