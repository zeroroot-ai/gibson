-- 006_tenant_zitadel_orgs.up.sql
--
-- gibson#621: the daemon's MembershipService writes the Zitadel half of human
-- membership (org member add/remove) for granular member operations, so the
-- dashboard can stop writing TenantMember CRs (ADR-0044). The daemon cannot
-- read Kubernetes (ADR-0023), so it cannot resolve a tenant's per-tenant
-- Zitadel org id from Tenant.Status.ZitadelOrgID. The tenant-operator — the
-- lifecycle coordinator that provisions the org at standup — seeds the
-- tenant -> org mapping into the daemon via
-- DaemonOperatorService.SetTenantZitadelOrg, persisted here.
--
-- tenant_id is TEXT (slug), consistent with tenant_quotas (003) and the
-- TEXT-not-UUID precedent (004). Idempotent — IF NOT EXISTS.

CREATE TABLE IF NOT EXISTS tenant_zitadel_orgs (
    tenant_id      TEXT PRIMARY KEY,
    zitadel_org_id TEXT NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
