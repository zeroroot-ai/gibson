-- 016_pending_tenant_provisioning.down.sql
DROP INDEX IF EXISTS pending_tenant_provisioning_pending_idx;
DROP TABLE IF EXISTS pending_tenant_provisioning;
