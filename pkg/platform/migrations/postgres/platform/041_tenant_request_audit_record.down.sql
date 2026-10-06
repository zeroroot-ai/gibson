ALTER TABLE tenant_admin_ops DROP COLUMN IF EXISTS audit_record_id;
ALTER TABLE pending_tenant_provisioning DROP COLUMN IF EXISTS audit_record_id;
