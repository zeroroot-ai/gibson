-- rollback for 025_add_concurrent_connectors_to_tenant_quotas.
ALTER TABLE tenant_quotas DROP COLUMN IF EXISTS concurrent_connectors;
