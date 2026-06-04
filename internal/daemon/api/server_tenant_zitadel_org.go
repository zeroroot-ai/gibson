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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	daemonoperatorv1 "github.com/zeroroot-ai/platform-sdk/gen/gibson/daemon/operator/v1"
)

// SetTenantZitadelOrg upserts the tenant -> Zitadel-org-id mapping. Operator-only
// (platform_operator on system_tenant, enforced by ext-authz). Idempotent:
// re-seeding the same value is a no-op; a changed org id overwrites.
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
		return nil, status.Errorf(codes.Internal, "upsert tenant_zitadel_orgs: %v", err)
	}
	return &daemonoperatorv1.SetTenantZitadelOrgResponse{}, nil
}

// ensureTenantZitadelOrgsTable creates tenant_zitadel_orgs if it does not yet
// exist. Mirrors ensureTenantQuotasTable: the migration (006) is authoritative,
// but this keeps the RPC working on a freshly-pointed DB before migrations run.
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
