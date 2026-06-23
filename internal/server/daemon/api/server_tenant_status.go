// Package api — server_tenant_status.go
//
// Operator-reported tenant status read-back (E9, gibson#948, enables
// dashboard#813).
//
// The dashboard used to read the Tenant CR's status directly (data-plane
// provisioning progress, billing customer id, phase) to drive its onboarding /
// signup-status / billing surfaces, and to patch the billing-active annotation
// from the Stripe webhook. To take all Kubernetes access off the web tier
// (dashboard#813) those reads/writes move here:
//
//   - The tenant-operator REPORTS the observed Tenant CR status into the
//     platform Postgres (tenant_status, migration 017) via
//     DaemonOperatorService.ReportTenantStatus (operator-only).
//   - The dashboard READS it back via
//     gibson.tenant.v1.TenantProvisioningService.GetTenantProvisioningStatus
//     and records billing-active via SetTenantBillingActive (both
//     unauthenticated, Envoy-gated to the dashboard workload).
//
// ADR-0023: the daemon never touches Kubernetes — it only reads/writes the
// platform Postgres here. The operator is the sole source of the status
// snapshot; billing_active is owned by the dashboard webhook and the two writers
// never clobber each other (ReportTenantStatus never touches billing_active;
// SetTenantBillingActive only touches billing_active).
package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
)

// ReportTenantStatus upserts the operator-observed Tenant CR status snapshot.
// Operator-only (platform_operator on system_tenant, enforced by the SPIFFE
// peer allowlist + ext-authz). Idempotent: re-reporting an unchanged status is a
// no-op (updated=false). Never writes billing_active — that column is owned by
// the dashboard webhook via SetTenantBillingActive.
func (s *DaemonServer) ReportTenantStatus(ctx context.Context, req *daemonoperatorv1.ReportTenantStatusRequest) (*daemonoperatorv1.ReportTenantStatusResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id required")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Errorf(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	// ON CONFLICT DO UPDATE guarded by IS DISTINCT FROM so an unchanged
	// reconcile (the common case — the operator reports every pass) does not
	// churn the row, and updated reflects a genuine change.
	const q = `
		INSERT INTO tenant_status
			(tenant_id, phase, data_plane_ready, store_postgres, store_redis, store_neo4j, zitadel_org_slug, stripe_customer_id, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			phase              = EXCLUDED.phase,
			data_plane_ready   = EXCLUDED.data_plane_ready,
			store_postgres     = EXCLUDED.store_postgres,
			store_redis        = EXCLUDED.store_redis,
			store_neo4j        = EXCLUDED.store_neo4j,
			zitadel_org_slug   = EXCLUDED.zitadel_org_slug,
			stripe_customer_id = EXCLUDED.stripe_customer_id,
			updated_at         = NOW()
		WHERE tenant_status.phase              IS DISTINCT FROM EXCLUDED.phase
		   OR tenant_status.data_plane_ready   IS DISTINCT FROM EXCLUDED.data_plane_ready
		   OR tenant_status.store_postgres     IS DISTINCT FROM EXCLUDED.store_postgres
		   OR tenant_status.store_redis        IS DISTINCT FROM EXCLUDED.store_redis
		   OR tenant_status.store_neo4j        IS DISTINCT FROM EXCLUDED.store_neo4j
		   OR tenant_status.zitadel_org_slug   IS DISTINCT FROM EXCLUDED.zitadel_org_slug
		   OR tenant_status.stripe_customer_id IS DISTINCT FROM EXCLUDED.stripe_customer_id
	`
	res, err := db.ExecContext(ctx, q,
		req.GetTenantId(), req.GetPhase(), req.GetDataPlaneReady(),
		req.GetStorePostgres(), req.GetStoreRedis(), req.GetStoreNeo4J(),
		req.GetZitadelOrgSlug(), req.GetStripeCustomerId(),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "upsert tenant_status: %v", err)
	}
	n, _ := res.RowsAffected()

	// Echo the dashboard-owned billing_active back so the operator can stamp the
	// billing-active CR annotation in the same reconcile pass. Read after the
	// upsert (the IS DISTINCT FROM guard may have skipped the UPDATE, so a
	// RETURNING clause would not fire on a no-op).
	var billingActive bool
	if err := db.QueryRowContext(ctx,
		`SELECT billing_active FROM tenant_status WHERE tenant_id = $1`,
		req.GetTenantId(),
	).Scan(&billingActive); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, status.Errorf(codes.Internal, "read billing_active: %v", err)
	}
	return &daemonoperatorv1.ReportTenantStatusResponse{
		Updated:       n > 0,
		BillingActive: billingActive,
	}, nil
}

// GetTenantProvisioningStatus returns the operator-reported provisioning status
// for a tenant slug. Unauthenticated (pre-membership signup polling / slug
// availability). Returns found=false for an unknown slug rather than NOT_FOUND
// so the dashboard can use it as an existence check.
func (s *DaemonServer) GetTenantProvisioningStatus(ctx context.Context, req *tenantv1.GetTenantProvisioningStatusRequest) (*tenantv1.GetTenantProvisioningStatusResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id required")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Errorf(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		SELECT phase, data_plane_ready, store_postgres, store_redis, store_neo4j,
		       zitadel_org_slug, stripe_customer_id, billing_active
		FROM tenant_status
		WHERE tenant_id = $1
	`
	var (
		phase, storePG, storeRedis, storeNeo4j, orgSlug, stripeID string
		dataPlaneReady, billingActive                             bool
	)
	err := db.QueryRowContext(ctx, q, req.GetTenantId()).Scan(
		&phase, &dataPlaneReady, &storePG, &storeRedis, &storeNeo4j,
		&orgSlug, &stripeID, &billingActive,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return &tenantv1.GetTenantProvisioningStatusResponse{Found: false}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query tenant_status: %v", err)
	}
	return &tenantv1.GetTenantProvisioningStatusResponse{
		Found:          true,
		Phase:          phase,
		DataPlaneReady: dataPlaneReady,
		Stores: &tenantv1.TenantDataPlaneStoreStatus{
			Postgres: storePG,
			Redis:    storeRedis,
			Neo4J:    storeNeo4j,
		},
		ZitadelOrgSlug:   orgSlug,
		StripeCustomerId: stripeID,
		BillingActive:    billingActive,
	}, nil
}

// SetTenantBillingActive records a tenant's billing-active state (the Stripe
// webhook path). Unauthenticated; Envoy gates the daemon to the dashboard
// workload. Idempotent: setting the same value is a no-op (updated=false). Only
// touches billing_active so it never clobbers the operator's status snapshot;
// inserts a billing-only row if the operator has not reported yet.
func (s *DaemonServer) SetTenantBillingActive(ctx context.Context, req *tenantv1.SetTenantBillingActiveRequest) (*tenantv1.SetTenantBillingActiveResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id required")
	}
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Errorf(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		INSERT INTO tenant_status (tenant_id, billing_active, created_at, updated_at)
		VALUES ($1, $2, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			billing_active = EXCLUDED.billing_active,
			updated_at     = NOW()
		WHERE tenant_status.billing_active IS DISTINCT FROM EXCLUDED.billing_active
	`
	res, err := db.ExecContext(ctx, q, req.GetTenantId(), req.GetActive())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "upsert tenant_status billing_active: %v", err)
	}
	n, _ := res.RowsAffected()
	return &tenantv1.SetTenantBillingActiveResponse{Updated: n > 0}, nil
}

// ensureTenantStatusTable creates tenant_status if it does not yet exist.
// Mirrors ensurePendingTenantProvisioningTable: migration 017 is authoritative,
// but this keeps the RPCs working on a freshly-pointed DB before migrations run.
func ensureTenantStatusTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS tenant_status (
			tenant_id          TEXT PRIMARY KEY,
			phase              TEXT NOT NULL DEFAULT '',
			data_plane_ready   BOOLEAN NOT NULL DEFAULT FALSE,
			store_postgres     TEXT NOT NULL DEFAULT '',
			store_redis        TEXT NOT NULL DEFAULT '',
			store_neo4j        TEXT NOT NULL DEFAULT '',
			zitadel_org_slug   TEXT NOT NULL DEFAULT '',
			stripe_customer_id TEXT NOT NULL DEFAULT '',
			billing_active     BOOLEAN NOT NULL DEFAULT FALSE,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create tenant_status: %w", err)
	}
	return nil
}
