-- 003_tenant_quotas_simplify.up.sql
--
-- Spec plans-and-quotas-simplification (R3 / Phase 3).
--
-- Reduces tenant_quotas to the two enforced quotas. Drops the legacy
-- columns (seats / storage_gb / retention_days / sandbox_launches_per_month)
-- and adds concurrent_missions. Idempotent — IF NOT EXISTS / IF EXISTS
-- guards make this safe to re-run on clusters that already had
-- ensureTenantQuotasTable converge them on the new shape.

CREATE TABLE IF NOT EXISTS tenant_quotas (
    tenant_id           TEXT PRIMARY KEY,
    concurrent_missions INT NOT NULL DEFAULT 0,
    concurrent_agents   INT NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS concurrent_missions INT NOT NULL DEFAULT 0;
ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS concurrent_agents INT NOT NULL DEFAULT 0;
ALTER TABLE tenant_quotas DROP COLUMN IF EXISTS seats;
ALTER TABLE tenant_quotas DROP COLUMN IF EXISTS storage_gb;
ALTER TABLE tenant_quotas DROP COLUMN IF EXISTS retention_days;
ALTER TABLE tenant_quotas DROP COLUMN IF EXISTS sandbox_launches_per_month;
