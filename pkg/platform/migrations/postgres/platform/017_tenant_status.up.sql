-- 017_tenant_status.up.sql
--
-- Daemon-side mirror of the Tenant CR's provisioning status (zero-kubeconfig,
-- dashboard#855). The daemon cannot read Kubernetes (ADR-0023), so the
-- tenant-operator's Tenant reconcile reports the Tenant CR's aggregate status
-- here via DaemonOperatorService.ReportTenantStatus. The dashboard's signup +
-- tenant-status surfaces then read it from the daemon
-- (TenantService.GetTenantProvisioningStatus) instead of opening a K8s channel.
--
-- One row per tenant, keyed by the tenant slug (= Tenant CR metadata.name).
-- Upserted whenever the operator observes an aggregate-status change. Fields
-- mirror exactly what the dashboard status routes consume:
--   - phase            ← Tenant.Status.Phase (Pending/Provisioning/Ready/Failed/…)
--   - ready            ← phase == Ready (the data plane + children all converged)
--   - zitadel_org_id   ← Tenant.Status.ZitadelOrgID (waitForTenantReady gate)
--   - data_plane_ready ← Tenant.Status.DataPlane.Ready
--   - owner_member_ready ← founding-owner TenantMember reached phase Active
CREATE TABLE IF NOT EXISTS tenant_status (
    tenant_id          TEXT PRIMARY KEY,
    phase              TEXT NOT NULL DEFAULT '',
    ready              BOOLEAN NOT NULL DEFAULT FALSE,
    zitadel_org_id     TEXT NOT NULL DEFAULT '',
    data_plane_ready   BOOLEAN NOT NULL DEFAULT FALSE,
    owner_member_ready BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
