-- 003_tenant_quotas_simplify.down.sql
--
-- Restores the legacy column shape on tenant_quotas. Defaults are
-- zero — the legacy data is gone after the up migration drops it,
-- this only re-creates the columns so a rollback compiles.

ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS seats INT NOT NULL DEFAULT 0;
ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS storage_gb INT NOT NULL DEFAULT 0;
ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS retention_days INT NOT NULL DEFAULT 0;
ALTER TABLE tenant_quotas ADD COLUMN IF NOT EXISTS sandbox_launches_per_month INT NOT NULL DEFAULT 0;
