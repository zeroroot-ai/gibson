-- rollback for 005_add_plan_id_to_tenant_quotas.
ALTER TABLE tenant_quotas DROP COLUMN IF EXISTS plan_id;
