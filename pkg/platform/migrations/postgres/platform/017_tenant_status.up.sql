-- 017_tenant_status.up.sql
--
-- tenant_status is the daemon-owned, operator-reported snapshot of each
-- Tenant CR's provisioning status (E9, gibson#948, enables dashboard#813).
--
-- Once the dashboard stops touching Kubernetes it can no longer read the Tenant
-- CR status to drive onboarding / signup-status / billing surfaces, and the
-- daemon cannot read the CR either (ADR-0023). Instead the tenant-operator —
-- the one component that watches Tenant CRs — REPORTS the observed status into
-- this table via DaemonOperatorService.ReportTenantStatus, and the daemon
-- serves it back to the dashboard via
-- gibson.tenant.v1.TenantProvisioningService.GetTenantProvisioningStatus.
--
-- Lives in the PLATFORM (control-plane) Postgres alongside
-- pending_tenant_provisioning (migration 016): it is keyed by the tenant slug
-- and read before per-tenant resources exist.
--
-- tenant_id is the PRIMARY KEY so ReportTenantStatus is a simple idempotent
-- upsert (ON CONFLICT (tenant_id) DO UPDATE).
--
-- billing_active is owned by the dashboard billing webhook
-- (TenantProvisioningService.SetTenantBillingActive), NOT by the operator's
-- ReportTenantStatus — so its upsert must not clobber this column. The operator
-- reads it back to stamp the gibson.zeroroot.ai/billing-active CR annotation the
-- saga waits on.
CREATE TABLE IF NOT EXISTS tenant_status (
    -- tenant_id is the deterministic tenant slug (Tenant CR name).
    tenant_id          TEXT PRIMARY KEY,

    -- phase mirrors Tenant.status.phase
    -- (Pending/Provisioning/Ready/Failed/Terminating/Terminated). Empty until
    -- the operator first reports.
    phase              TEXT NOT NULL DEFAULT '',

    -- data_plane_ready mirrors Tenant.status.dataPlane.ready — the gate the
    -- daemon uses before serving tenant data and the signal onboarding polls.
    data_plane_ready   BOOLEAN NOT NULL DEFAULT FALSE,

    -- store_* are the per-store state strings from
    -- status.dataPlane.stores for the onboarding-progress UI.
    store_postgres     TEXT NOT NULL DEFAULT '',
    store_redis        TEXT NOT NULL DEFAULT '',
    store_neo4j        TEXT NOT NULL DEFAULT '',

    -- zitadel_org_slug mirrors status.zitadelOrgSlug (per-tenant org login slug).
    zitadel_org_slug   TEXT NOT NULL DEFAULT '',

    -- stripe_customer_id mirrors status.billing.customerId (billing-portal link).
    stripe_customer_id TEXT NOT NULL DEFAULT '',

    -- billing_active is recorded by the dashboard billing webhook, NOT the
    -- operator status report. Default FALSE so a row created by the operator's
    -- first ReportTenantStatus starts billing-inactive until the webhook fires.
    billing_active     BOOLEAN NOT NULL DEFAULT FALSE,

    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
