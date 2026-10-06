// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_tenant_status.go
//
// Operator-reported tenant status read-back (E9, gibson#948, enables
// dashboard#813).
//
// The dashboard used to read the Tenant CR's status directly (data-plane
// provisioning progress, phase) to drive its onboarding and signup-status
// surfaces. To take all Kubernetes access off the web tier (dashboard#813)
// those reads move here:
//
//   - The tenant-operator REPORTS the observed Tenant CR status into the
//     platform Postgres (tenant_status, migration 017) via
//     DaemonOperatorService.ReportTenantStatus (operator-only).
//   - The dashboard READS it back via
//     gibson.tenant.v1.TenantProvisioningService.GetTenantProvisioningStatus
//     (unauthenticated, coarse progress only).
//
// ADR-0023: the daemon never touches Kubernetes — it only reads/writes the
// platform Postgres here. The operator is the sole source of the status
// snapshot. The activation column of the same row has its own writer,
// ConnectionPointService.SetTenantActivation, and ReportTenantStatus never
// touches it.
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
// no-op (updated=false). Never writes the activation column.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist. The operator reports status
// for every tenant by design.
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
			(tenant_id, phase, data_plane_ready, store_postgres, store_redis, store_neo4j, zitadel_org_slug, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			phase              = EXCLUDED.phase,
			data_plane_ready   = EXCLUDED.data_plane_ready,
			store_postgres     = EXCLUDED.store_postgres,
			store_redis        = EXCLUDED.store_redis,
			store_neo4j        = EXCLUDED.store_neo4j,
			zitadel_org_slug   = EXCLUDED.zitadel_org_slug,
			updated_at         = NOW()
		WHERE tenant_status.phase              IS DISTINCT FROM EXCLUDED.phase
		   OR tenant_status.data_plane_ready   IS DISTINCT FROM EXCLUDED.data_plane_ready
		   OR tenant_status.store_postgres     IS DISTINCT FROM EXCLUDED.store_postgres
		   OR tenant_status.store_redis        IS DISTINCT FROM EXCLUDED.store_redis
		   OR tenant_status.store_neo4j        IS DISTINCT FROM EXCLUDED.store_neo4j
		   OR tenant_status.zitadel_org_slug   IS DISTINCT FROM EXCLUDED.zitadel_org_slug
	`
	res, err := db.ExecContext(ctx, q,
		req.GetTenantId(), req.GetPhase(), req.GetDataPlaneReady(),
		req.GetStorePostgres(), req.GetStoreRedis(), req.GetStoreNeo4J(),
		req.GetZitadelOrgSlug(),
	)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "upsert tenant_status: %v", err)
	}
	n, _ := res.RowsAffected()
	s.welcomeOwnerIfReady(ctx, db, req.GetTenantId(), req.GetPhase(), req.GetDataPlaneReady())
	return &daemonoperatorv1.ReportTenantStatusResponse{Updated: n > 0}, nil
}

// GetTenantProvisioningStatus returns the operator-reported provisioning status
// for a tenant slug. Returns found=false for an unknown slug rather than
// NOT_FOUND so the caller can use it as an existence check.
//
// # Coarse, unauthenticated-by-design (gibson#1230, gibson#1339)
//
// The RPC stays reachable without a principal — signup-status polling and
// slug-availability run BEFORE any tenant or membership exists, so there is no
// identity to check. It therefore serves the SAME coarse view to every caller:
// existence plus the provisioning progress the public signup page renders —
// found, phase, data_plane_ready, per-store states, zitadel_org_ready. None of
// those name a tenant in another system or expose commercial state.
//
// The cross-tenant identifier zitadel_org_slug is NOT served here
// (gibson#1230, gibson#1339).
//
// zitadel_org_ready exists because the org-created edge is the signal the signup
// poller waits on; it used to read that edge off the org SLUG being non-empty,
// so withholding the slug would have cost the poller its early exit and turned
// successful signups into "we'll email you" timeouts. The boolean carries the
// edge without the identifier.
//
// gibsoncheck:allow tenant-from-request — the request's tenant_id only SELECTs
// which row's coarse, non-sensitive progress to return (existence + phase +
// stores + zitadel_org_ready). This RPC discloses no identifier to anyone, so a caller naming any slug — its own or another's — learns
// only whether that slug is provisioned and how far, which is exactly the
// slug-availability / signup-progress signal the RPC exists to serve. There is
// nothing cross-tenant-sensitive for a tenant gate to protect here.
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
	// Select only the coarse columns this RPC serves. The org SLUG is read only
	// to derive the non-identifying zitadel_org_ready edge; it is not returned.
	const q = `
		SELECT phase, data_plane_ready, store_postgres, store_redis, store_neo4j,
		       zitadel_org_slug
		FROM tenant_status
		WHERE tenant_id = $1
	`
	var (
		phase, storePG, storeRedis, storeNeo4j, orgSlug string
		dataPlaneReady                                  bool
	)
	err := db.QueryRowContext(ctx, q, req.GetTenantId()).Scan(
		&phase, &dataPlaneReady, &storePG, &storeRedis, &storeNeo4j, &orgSlug,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return &tenantv1.GetTenantProvisioningStatusResponse{Found: false}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query tenant_status: %v", err)
	}
	// This RPC is intentionally unauthenticated (signup polling, slug
	// availability run before any principal exists), so ext-authz never resolves
	// a caller tenant for it (skipTenantResolution) — there is no identity to
	// authorise a cross-tenant disclosure against. It therefore serves ONLY
	// existence and coarse provisioning progress.
	//
	// The cross-tenant identifier zitadel_org_slug is deliberately NOT
	// populated here (gibson#1230, gibson#1339).
	resp := &tenantv1.GetTenantProvisioningStatusResponse{
		Found:          true,
		Phase:          phase,
		DataPlaneReady: dataPlaneReady,
		Stores: &tenantv1.TenantDataPlaneStoreStatus{
			Postgres: storePG,
			Redis:    storeRedis,
			Neo4J:    storeNeo4j,
		},
		// zitadel_org_ready is the org-created EDGE — coarse progress of the same
		// class as phase/data_plane_ready/stores, and the signal the signup
		// poller waits on. It names nothing and is safe to disclose anonymously;
		// the org SLUG it is derived from is not returned here (gibson#1339).
		ZitadelOrgReady: orgSlug != "",
	}
	return resp, nil
}

// ensureTenantStatusTable creates tenant_status if it does not yet exist.
// Mirrors ensurePendingTenantProvisioningTable: migrations 017 and 033 are
// authoritative,
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
			activation         TEXT NOT NULL DEFAULT 'active'
				CONSTRAINT tenant_status_activation_check
				CHECK (activation IN ('active', 'suspended')),
			created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create tenant_status: %w", err)
	}
	return nil
}
