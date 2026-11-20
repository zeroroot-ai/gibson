-- 049_drop_tenant_quotas.up.sql
--
-- The product is open source, so it has no plan quotas (gibson#1525). No
-- code reads or writes tenant_quotas after gibson#1530, which removed the
-- UpsertTenantQuota RPC. Migrations 003, 005 and 025 made the table.
DROP TABLE IF EXISTS tenant_quotas;
