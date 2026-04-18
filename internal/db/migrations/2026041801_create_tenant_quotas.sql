-- Spec: agent-authoring-and-tenant-entitlements task 20
--
-- Per-tenant runtime quota record written by the tenant-operator
-- (DaemonAdminService.UpsertTenantQuota) from the canonical plan registry
-- and read by the daemon at mission dispatch time to enforce concurrent-
-- agent / storage / sandbox-launch limits.
--
-- Values encode -1 as "unlimited / fair-use" — callers enforcing runtime
-- limits MUST treat -1 as "no enforcement." All columns are NOT NULL;
-- tenant-operator reconcile always writes a complete row via UPSERT.
--
-- This migration is idempotent. The handler in
-- core/gibson/internal/daemon/api/server_entitlements.go also carries a
-- CREATE TABLE IF NOT EXISTS fallback for deployments that haven't applied
-- this migration (dev/kind clusters); schema-managed environments should
-- still apply this file as the authoritative source.

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id                   TEXT        PRIMARY KEY,
    seats                       INTEGER     NOT NULL,
    concurrent_agents           INTEGER     NOT NULL,
    storage_gb                  INTEGER     NOT NULL,
    retention_days              INTEGER     NOT NULL,
    sandbox_launches_per_month  INTEGER     NOT NULL,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE tenant_quotas IS
    'Per-tenant runtime quota record. Written by tenant-operator from the plan registry; read by daemon at mission dispatch.';
COMMENT ON COLUMN tenant_quotas.seats IS
    'Max users in tenant; -1 = unlimited.';
COMMENT ON COLUMN tenant_quotas.concurrent_agents IS
    'Max agents running simultaneously; -1 = unlimited.';
COMMENT ON COLUMN tenant_quotas.storage_gb IS
    'GraphRAG/workspace storage budget in GB; -1 = unlimited.';
COMMENT ON COLUMN tenant_quotas.retention_days IS
    'Audit/mission-history retention window; -1 = unlimited.';
COMMENT ON COLUMN tenant_quotas.sandbox_launches_per_month IS
    'Setec microVM launches per month; -1 = unlimited / fair-use.';
