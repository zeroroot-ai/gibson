-- 018_tenant_admin_ops.down.sql
DROP INDEX IF EXISTS tenant_admin_ops_pending_idx;
DROP TABLE IF EXISTS tenant_admin_ops;
