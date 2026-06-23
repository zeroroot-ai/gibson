// Package api — server_pending_tenant_provisioning.go
//
// Operator-pull tenant provisioning (E9, gibson#948, enables dashboard#813).
//
// The daemon owns a pending-provisioning queue in the platform Postgres
// (pending_tenant_provisioning, migration 016). The Signup handler enqueues one
// row per self-serve signup once it has provisioned the founding-owner Zitadel
// user (gibson#812). The tenant-operator drains the queue via
// ListPendingTenantProvisioning, creates the Tenant CR for each pending record
// (the same spec the dashboard used to write), and acks each via
// AckTenantProvisioned.
//
// ADR-0023: the daemon never touches Kubernetes. These handlers only read/write
// the platform Postgres queue; the operator (which holds `tenants` create RBAC)
// owns all Tenant-CR creation.
package api

import (
	"context"
	"database/sql"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// enqueuePendingTenantProvisioning records a tenant awaiting Tenant-CR creation.
// Called by the Signup handler after the founding-owner Zitadel user is
// provisioned. Idempotent on tenant_id: a retry that re-enqueues the same
// tenant leaves an existing (possibly already-claimed/done) row untouched,
// mirroring the already_existed handling in the owner-provisioning path —
// re-creating it would risk re-provisioning a tenant the operator already built.
//
// Returns (false, nil) when no platform DB is configured: enqueue is best-effort
// in dev/kind where Postgres may be absent, and the caller logs rather than
// failing the signup.
func (s *DaemonServer) enqueuePendingTenantProvisioning(ctx context.Context, p *daemonoperatorv1.PendingTenant) (bool, error) {
	db := s.entitlementsDB()
	if db == nil {
		return false, nil
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return false, fmt.Errorf("ensure table: %w", err)
	}
	const q = `
		INSERT INTO pending_tenant_provisioning
			(tenant_id, owner_user_id, owner_email, workspace_name, tier, stripe_customer_id, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, 'pending', NOW(), NOW())
		ON CONFLICT (tenant_id) DO NOTHING
	`
	res, err := db.ExecContext(ctx, q,
		p.GetTenantId(), p.GetOwnerUserId(), p.GetOwnerEmail(),
		p.GetWorkspaceName(), p.GetTier(), p.GetStripeCustomerId(),
	)
	if err != nil {
		return false, fmt.Errorf("insert pending_tenant_provisioning: %w", err)
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ListPendingTenantProvisioning returns the queue of tenants awaiting Tenant-CR
// creation (status=pending). Operator-only (platform_operator on system_tenant,
// enforced by ext-authz). The daemon never reads Kubernetes here — it only
// returns queue rows for the operator to act on.
func (s *DaemonServer) ListPendingTenantProvisioning(ctx context.Context, _ *daemonoperatorv1.ListPendingTenantProvisioningRequest) (*daemonoperatorv1.ListPendingTenantProvisioningResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		SELECT tenant_id, owner_user_id, owner_email, workspace_name, tier, stripe_customer_id
		FROM pending_tenant_provisioning
		WHERE status = 'pending'
		ORDER BY created_at ASC
	`
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query pending_tenant_provisioning: %v", err)
	}
	defer func() { _ = rows.Close() }()

	out := &daemonoperatorv1.ListPendingTenantProvisioningResponse{}
	for rows.Next() {
		var p daemonoperatorv1.PendingTenant
		if err := rows.Scan(
			&p.TenantId, &p.OwnerUserId, &p.OwnerEmail,
			&p.WorkspaceName, &p.Tier, &p.StripeCustomerId,
		); err != nil {
			return nil, status.Errorf(codes.Internal, "scan pending row: %v", err)
		}
		out.Pending = append(out.Pending, &p)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "iterate pending rows: %v", err)
	}
	return out, nil
}

// AckTenantProvisioned marks a pending record done after the operator has
// ensured the Tenant CR exists. Operator-only. Idempotent: acking an unknown or
// already-done tenant_id returns acked=false with no error.
func (s *DaemonServer) AckTenantProvisioned(ctx context.Context, req *daemonoperatorv1.AckTenantProvisionedRequest) (*daemonoperatorv1.AckTenantProvisionedResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		UPDATE pending_tenant_provisioning
		SET status = 'done', updated_at = NOW()
		WHERE tenant_id = $1 AND status <> 'done'
	`
	res, err := db.ExecContext(ctx, q, req.GetTenantId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update pending_tenant_provisioning: %v", err)
	}
	n, _ := res.RowsAffected()
	return &daemonoperatorv1.AckTenantProvisionedResponse{Acked: n > 0}, nil
}

// pendingTenantExists reports whether a pending_tenant_provisioning row exists
// for a slug, in ANY status (pending/claimed/done) — all three mean a self-serve
// signup has claimed the slug. The in-flight half of CheckTenantSlugAvailable
// (dashboard#855), so a slug is unavailable the moment Signup enqueues it, even
// before the operator creates the Tenant CR or reports tenant_status.
func (s *DaemonServer) pendingTenantExists(ctx context.Context, db *sql.DB, tenantID string) (bool, error) {
	if err := ensurePendingTenantProvisioningTable(ctx, db); err != nil {
		return false, fmt.Errorf("ensure table: %w", err)
	}
	const q = `SELECT EXISTS (SELECT 1 FROM pending_tenant_provisioning WHERE tenant_id = $1)`
	var exists bool
	if err := db.QueryRowContext(ctx, q, tenantID).Scan(&exists); err != nil {
		return false, fmt.Errorf("query pending_tenant_provisioning exists: %w", err)
	}
	return exists, nil
}

// ensurePendingTenantProvisioningTable creates pending_tenant_provisioning if it
// does not yet exist. Mirrors ensureTenantZitadelOrgsTable: migration 016 is
// authoritative, but this keeps the RPC working on a freshly-pointed DB before
// migrations run.
func ensurePendingTenantProvisioningTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS pending_tenant_provisioning (
			tenant_id          TEXT PRIMARY KEY,
			owner_user_id      TEXT NOT NULL DEFAULT '',
			owner_email        TEXT NOT NULL,
			workspace_name     TEXT NOT NULL,
			tier               TEXT NOT NULL,
			stripe_customer_id TEXT NOT NULL DEFAULT '',
			status             TEXT NOT NULL DEFAULT 'pending'
				CONSTRAINT pending_tenant_provisioning_status_check
				CHECK (status IN ('pending', 'claimed', 'done')),
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create pending_tenant_provisioning: %w", err)
	}
	return nil
}
