// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

// Package api — server_tenant_zitadel_org.go
//
// SetTenantZitadelOrg (gibson#621): the operator seeds the daemon's
// tenant -> Zitadel-org-id mapping at standup. The daemon persists it in the
// platform Postgres (tenant_zitadel_orgs, migration 006) so
// gibson.tenant.v1.MembershipService can write the Zitadel half of human
// membership (org member add/remove) without reading Kubernetes (ADR-0023).
package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/gibson/internal/server/daemon/api/gibson/daemon/operator/v1"
)

// envIDPZitadelOrgID is the platform org's Zitadel org id (the same env var
// idp_init.go reads as envZitadelOrgID). The Platform owner and the service
// accounts live there; mapping it to a tenant would give them a tenant
// (ADR-0093 decision 4).
const envIDPZitadelOrgID = "GIBSON_IDP_ZITADEL_ORG_ID"

// SetTenantZitadelOrg upserts the tenant -> Zitadel-org-id mapping. Operator-only
// (platform_operator on system_tenant, enforced by ext-authz). Idempotent:
// re-seeding the same value is a no-op; a changed org id overwrites.
//
// gibsoncheck:allow tenant-from-request — DaemonOperatorService: platform_operator on
// system_tenant at ext-authz, plus the SPIFFE peer allowlist. The operator seeds this
// mapping for every tenant.
func (s *DaemonServer) SetTenantZitadelOrg(ctx context.Context, req *daemonoperatorv1.SetTenantZitadelOrgRequest) (*daemonoperatorv1.SetTenantZitadelOrgResponse, error) {
	db := s.entitlementsDB()
	if db == nil {
		return nil, status.Error(codes.Unavailable, "platform Postgres not configured")
	}
	if req.GetTenantId() == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id required")
	}
	if req.GetZitadelOrgId() == "" {
		// Reject rather than persist a half-mapping the membership write would
		// then silently skip.
		return nil, status.Error(codes.InvalidArgument, "zitadel_org_id required")
	}
	if platformOrg := os.Getenv(envIDPZitadelOrgID); platformOrg != "" && req.GetZitadelOrgId() == platformOrg {
		// Refuse a mapping that cannot be right (ADR-0093 decision 4): the
		// Platform owner and the service accounts live in the platform org.
		return nil, status.Error(codes.InvalidArgument, "zitadel_org_id is the platform org, not a tenant org")
	}
	if err := ensureTenantZitadelOrgsTable(ctx, db); err != nil {
		return nil, status.Errorf(codes.Internal, "ensure table: %v", err)
	}

	const q = `
		INSERT INTO tenant_zitadel_orgs (tenant_id, zitadel_org_id, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			zitadel_org_id = EXCLUDED.zitadel_org_id,
			updated_at = NOW()
	`
	if _, err := db.ExecContext(ctx, q, req.GetTenantId(), req.GetZitadelOrgId()); err != nil {
		if isPgUniqueViolation(err) {
			// The unique index (migration 027) makes one org map to at most
			// one tenant. A second tenant claiming an already-mapped org
			// would make ext-authz's org->tenant lookup ambiguous.
			return nil, status.Errorf(codes.FailedPrecondition,
				"zitadel_org_id %s is already mapped to a different tenant", req.GetZitadelOrgId())
		}
		return nil, status.Errorf(codes.Internal, "upsert tenant_zitadel_orgs: %v", err)
	}
	return &daemonoperatorv1.SetTenantZitadelOrgResponse{}, nil
}

// isPgUniqueViolation reports whether err is a Postgres unique constraint
// violation (SQLSTATE 23505).
func isPgUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	type pgError interface{ SQLState() string }
	var pe pgError
	if errors.As(err, &pe) {
		return pe.SQLState() == "23505"
	}
	return false
}

// ensureTenantZitadelOrgsTable creates tenant_zitadel_orgs (and its
// org-uniqueness index) if they do not yet exist. Mirrors
// ensureTenantQuotasTable: migrations 006 and 027 are authoritative, but this
// keeps the RPC working on a freshly-pointed DB before migrations run.
func ensureTenantZitadelOrgsTable(ctx context.Context, db *sql.DB) error {
	const create = `
		CREATE TABLE IF NOT EXISTS tenant_zitadel_orgs (
			tenant_id      TEXT PRIMARY KEY,
			zitadel_org_id TEXT NOT NULL,
			updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`
	if _, err := db.ExecContext(ctx, create); err != nil {
		return fmt.Errorf("create tenant_zitadel_orgs: %w", err)
	}
	const uniq = `
		CREATE UNIQUE INDEX IF NOT EXISTS tenant_zitadel_orgs_org_uidx
			ON tenant_zitadel_orgs (zitadel_org_id)
	`
	if _, err := db.ExecContext(ctx, uniq); err != nil {
		return fmt.Errorf("create tenant_zitadel_orgs_org_uidx: %w", err)
	}
	return nil
}

// ZitadelOrgResolver is a Postgres-backed resolver of the tenant -> Zitadel-org
// mapping. It structurally satisfies the resolver interface that
// internal/admin's TenantAdminServer consumes, letting MembershipService read
// the org id seeded by SetTenantZitadelOrg.
type ZitadelOrgResolver struct {
	db *sql.DB
}

// NewZitadelOrgResolver builds a resolver over the platform Postgres handle.
func NewZitadelOrgResolver(db *sql.DB) *ZitadelOrgResolver {
	return &ZitadelOrgResolver{db: db}
}

// ZitadelOrgID returns the org id seeded for the tenant, or ("", nil) when
// unmapped or when no DB is configured (the caller skips the Zitadel half).
func (r *ZitadelOrgResolver) ZitadelOrgID(ctx context.Context, tenantID string) (string, error) {
	if r == nil || r.db == nil {
		return "", nil
	}
	return readTenantZitadelOrgID(ctx, r.db, tenantID)
}

// readTenantZitadelOrgID returns the Zitadel org id seeded for a tenant, or
// ("", nil) when no mapping exists (the membership write then skips the Zitadel
// half rather than failing — the operator backfill/reconcile converges it).
func readTenantZitadelOrgID(ctx context.Context, db *sql.DB, tenantID string) (string, error) {
	const q = `SELECT zitadel_org_id FROM tenant_zitadel_orgs WHERE tenant_id = $1`
	var orgID string
	switch err := db.QueryRowContext(ctx, q, tenantID).Scan(&orgID); {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("read tenant_zitadel_orgs: %w", err)
	default:
		return orgID, nil
	}
}

// TenantForOrg returns the tenant mapped to zitadelOrgID, or ("", nil) when
// the org maps to no tenant. This is the reverse lookup of ZitadelOrgID: the
// daemon's org-tenant route (org_tenant_route.go) calls it so ext-authz can
// resolve a signed-in person's tenant from their token's verified Zitadel
// org (ADR-0093 decision 4), never from a client-supplied header.
func (r *ZitadelOrgResolver) TenantForOrg(ctx context.Context, zitadelOrgID string) (string, error) {
	if r == nil || r.db == nil {
		return "", nil
	}
	return readTenantForZitadelOrg(ctx, r.db, zitadelOrgID)
}

// readTenantForZitadelOrg returns the tenant id mapped to this Zitadel org,
// or ("", nil) when no mapping exists.
func readTenantForZitadelOrg(ctx context.Context, db *sql.DB, zitadelOrgID string) (string, error) {
	const q = `SELECT tenant_id FROM tenant_zitadel_orgs WHERE zitadel_org_id = $1`
	var tenantID string
	switch err := db.QueryRowContext(ctx, q, zitadelOrgID).Scan(&tenantID); {
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("read tenant_zitadel_orgs by org: %w", err)
	default:
		return tenantID, nil
	}
}
