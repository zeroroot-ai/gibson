-- 050_drop_plan_tier_columns.down.sql
--
-- Adds the tier columns again. The values are gone, so each row gets the
-- empty tier, which means no plan.
ALTER TABLE pending_tenant_provisioning ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT '';
ALTER TABLE tenant_admin_ops ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT '';
ALTER TABLE tenant_admin_ops ADD COLUMN IF NOT EXISTS tier_set BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE signup_verification ADD COLUMN IF NOT EXISTS tier TEXT NOT NULL DEFAULT '';
