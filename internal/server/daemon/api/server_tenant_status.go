// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
	tenantv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/tenant/v1"
	"github.com/zeroroot-ai/sdk/auth"
)

// ReportTenantStatus upserts the operator-observed Tenant CR status snapshot.
// Operator-only (platform_operator on system_tenant, enforced by the SPIFFE
// peer allowlist + ext-authz). Idempotent: re-reporting an unchanged status is a
// no-op (updated=false). Never writes billing_active — that column is owned by
// the dashboard webhook via SetTenantBillingActive.
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
// The cross-tenant identifiers and billing state (zitadel_org_slug,
// stripe_customer_id, billing_active) are NOT served here. gibson#1230 first
// tried to gate them behind an in-handler "same authenticated tenant" check, but
// that allow-branch was unreachable for every caller — ext-authz never resolves
// a tenant on an unauthenticated-mode RPC, so even the tenant's own billing
// portal was blinded (gibson#1339). Those reads moved to rule-mode RPCs:
// TenantService.GetTenantBilling (own tenant) and
// AdminTenantService.AdminGetTenantBilling (cross-tenant, platform_operator).
//
// zitadel_org_ready exists because the org-created edge is the signal the signup
// poller waits on; it used to read that edge off the org SLUG being non-empty,
// so withholding the slug would have cost the poller its early exit and turned
// successful signups into "we'll email you" timeouts. The boolean carries the
// edge without the identifier.
//
// gibsoncheck:allow tenant-from-request — the request's tenant_id only SELECTs
// which row's coarse, non-sensitive progress to return (existence + phase +
// stores + zitadel_org_ready). This RPC discloses no identifier and no billing
// state to anyone, so a caller naming any slug — its own or another's — learns
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
	// Select only the coarse columns this RPC serves. The identifier and billing
	// columns (stripe_customer_id, billing_active) are deliberately not read here
	// — they are served by readTenantBilling via the rule-mode billing RPCs. The
	// org SLUG is read only to derive the non-identifying zitadel_org_ready edge;
	// it is not returned.
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
	// The cross-tenant identifiers and billing state (zitadel_org_slug,
	// stripe_customer_id, billing_active) are deliberately NOT populated here.
	// gibson#1230 first tried to gate them behind an in-handler "same
	// authenticated tenant" check, but that allow-branch was unreachable for
	// EVERY caller (including the tenant's own billing portal) because ext-authz
	// leaves the tenant empty on an unauthenticated-mode RPC — gibson#1339. Those
	// fields now live on the rule-mode RPCs TenantService.GetTenantBilling (own
	// tenant) and AdminTenantService.AdminGetTenantBilling (cross-tenant), where
	// ext-authz + FGA authorise the caller before the handler runs.
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

// readTenantBilling returns the billing identifiers recorded for tenantID:
// found=false (no error) when the tenant has no tenant_status row yet.
//
// It is shared by the own-tenant (TenantService.GetTenantBilling) and the
// cross-tenant (AdminTenantService.AdminGetTenantBilling) billing reads. The
// caller's authorization to read tenantID is enforced UPSTREAM by ext-authz
// (rule-mode: tenant_from_identity `admin` for the own-tenant RPC,
// platform_operator on system_tenant for the admin RPC) — never here. This
// helper takes an already-authorised tenant string and performs no gate of its
// own, which is why it reads no request field.
func (s *DaemonServer) readTenantBilling(ctx context.Context, tenantID string) (found bool, stripeCustomerID string, billingActive bool, zitadelOrgSlug string, err error) {
	db := s.entitlementsDB()
	if db == nil {
		return false, "", false, "", status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if err := ensureTenantStatusTable(ctx, db); err != nil {
		return false, "", false, "", status.Errorf(codes.Internal, "ensure table: %v", err)
	}
	const q = `
		SELECT stripe_customer_id, billing_active, zitadel_org_slug
		FROM tenant_status
		WHERE tenant_id = $1
	`
	var (
		stripeID, orgSlug string
		active            bool
	)
	scanErr := db.QueryRowContext(ctx, q, tenantID).Scan(&stripeID, &active, &orgSlug)
	if errors.Is(scanErr, sql.ErrNoRows) {
		return false, "", false, "", nil
	}
	if scanErr != nil {
		return false, "", false, "", status.Errorf(codes.Internal, "query tenant_status billing: %v", scanErr)
	}
	return true, stripeID, active, orgSlug, nil
}

// GetTenantBilling returns the CALLING tenant's own billing identifiers
// (stripe_customer_id, billing_active, zitadel_org_slug) for the billing-portal
// surface (dashboard#1016).
//
// Rule-mode (tenant_from_identity `admin`): ext-authz resolves the caller's
// tenant and authorises `admin` on it BEFORE this handler runs, so the tenant
// is taken from the authenticated context and never from the request — there is
// no request tenant_id to spoof. This is the own-tenant replacement for the
// billing fields that GetTenantProvisioningStatus can no longer serve
// (gibson#1339).
func (s *DaemonServer) GetTenantBilling(ctx context.Context, _ *tenantv1.GetTenantBillingRequest) (*tenantv1.GetTenantBillingResponse, error) {
	tenant, ok := auth.TenantFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.PermissionDenied, "no tenant in context")
	}
	found, stripeID, active, orgSlug, err := s.readTenantBilling(ctx, tenant.String())
	if err != nil {
		return nil, err
	}
	return &tenantv1.GetTenantBillingResponse{
		Found:            found,
		StripeCustomerId: stripeID,
		BillingActive:    active,
		ZitadelOrgSlug:   orgSlug,
	}, nil
}

// AdminGetTenantBilling returns ANY tenant's billing identifiers for the
// platform-operator admin surfaces (the trial-extension tool, dashboard#1016).
// A genuine CROSS-tenant read: a staff operator acting on an arbitrary tenant.
//
// gibsoncheck:allow tenant-from-request — AdminTenantService: platform_operator on
// system_tenant at ext-authz (registry rule), enforced before this handler runs.
// Naming another tenant is the whole point of this cross-tenant admin surface.
func (s *DaemonServer) AdminGetTenantBilling(ctx context.Context, req *tenantv1.AdminGetTenantBillingRequest) (*tenantv1.AdminGetTenantBillingResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	found, stripeID, active, orgSlug, err := s.readTenantBilling(ctx, req.GetTenantId())
	if err != nil {
		return nil, err
	}
	return &tenantv1.AdminGetTenantBillingResponse{
		Found:            found,
		StripeCustomerId: stripeID,
		BillingActive:    active,
		ZitadelOrgSlug:   orgSlug,
	}, nil
}

// SetTenantBillingActive records a tenant's billing-active state (the Stripe
// webhook path). Idempotent: setting the same value is a no-op (updated=false).
// Only touches billing_active so it never clobbers the operator's status
// snapshot; inserts a billing-only row if the operator has not reported yet.
//
// # Authentication (gibson#1230)
//
// The caller must present a fresh HMAC assertion over exactly this tenant_id
// and active value, signed with the deployment's billing-webhook secret. The
// mechanism and the reason a SPIFFE peer policy cannot serve here are in
// billing_webhook_auth.go. Before this gate the write was protected only by
// Envoy routing, so any caller reaching that route could flip billing_active
// for any tenant_id — and billing_active now gates paid-tier provisioning
// (ListPendingTenantProvisioning), so a forged write buys a tenant.
//
// gibsoncheck:allow tenant-from-request — GUARD: authorizeBillingWebhook
// (billing_webhook_auth.go), called before any database access below. The request's
// tenant_id names the row to write and is UNTRUSTED, but it is bound into the HMAC
// assertion that guard verifies, so a caller can only write the tenant_id it holds a
// valid, unexpired signature for. Cross-tenant is the intended semantic for the webhook:
// one signer legitimately records billing for every tenant.
func (s *DaemonServer) SetTenantBillingActive(ctx context.Context, req *tenantv1.SetTenantBillingActiveRequest) (*tenantv1.SetTenantBillingActiveResponse, error) {
	if req.GetTenantId() == "" {
		return nil, status.Errorf(codes.InvalidArgument, "tenant_id required")
	}
	// Authenticate BEFORE touching the database: an unauthenticated caller must
	// not be able to create tables, probe for tenants, or measure timing.
	if err := s.authorizeBillingWebhook(ctx, req.GetTenantId(), req.GetActive(), time.Now()); err != nil {
		return nil, err
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

	// Invalidate the entitlements cache for this tenant immediately so the
	// next quota check reflects the updated subscription state rather than
	// waiting up to 60 s for the TTL to expire naturally. The call is safe to
	// make even when active did not change (n == 0): cache invalidation is
	// always idempotent and never errors. When quotaManager is nil (tests or
	// a daemon wired without one) the call is skipped; when the underlying
	// provider has no per-tenant cache (UnlimitedProvider) the call is a
	// harmless no-op inside QuotaManager.InvalidateCache.
	if s.quotaManager != nil {
		s.quotaManager.InvalidateCache(req.GetTenantId())
	}

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
