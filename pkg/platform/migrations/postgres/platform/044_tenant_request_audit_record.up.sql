-- gibson#583: each tenant queue entry carries the id of the daemon audit
-- record of the human request behind it. The tenant-operator stamps the id on
-- the Tenant as the gibson.zeroroot.ai/correlation-id annotation, and each
-- operator audit record of that tenant carries it. An empty id means no human
-- request is behind the entry (for example the first-tenant seed).
ALTER TABLE pending_tenant_provisioning
    ADD COLUMN IF NOT EXISTS audit_record_id TEXT NOT NULL DEFAULT '';
ALTER TABLE tenant_admin_ops
    ADD COLUMN IF NOT EXISTS audit_record_id TEXT NOT NULL DEFAULT '';
