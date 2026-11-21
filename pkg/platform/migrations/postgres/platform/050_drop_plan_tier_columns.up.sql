-- 050_drop_plan_tier_columns.up.sql
--
-- The product has no plan (gibson#1525). After gibson#1531, no code reads or
-- writes a tier. Migration 016 made pending_tenant_provisioning.tier, 018 made
-- tenant_admin_ops.tier and tenant_admin_ops.tier_set, and 021 made
-- signup_verification.tier.
ALTER TABLE pending_tenant_provisioning DROP COLUMN IF EXISTS tier;
ALTER TABLE tenant_admin_ops DROP COLUMN IF EXISTS tier;
ALTER TABLE tenant_admin_ops DROP COLUMN IF EXISTS tier_set;
ALTER TABLE signup_verification DROP COLUMN IF EXISTS tier;
