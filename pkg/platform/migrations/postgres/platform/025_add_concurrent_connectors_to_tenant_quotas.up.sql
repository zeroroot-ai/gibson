-- 025_add_concurrent_connectors_to_tenant_quotas.up.sql
--
-- Adds concurrent_connectors to tenant_quotas: the plan-tier budget of hosted
-- MCP connector instances (ADR-0047 facet 3), read by the entitlements
-- provider on every Limits call alongside concurrent_missions and
-- concurrent_agents.
--
-- The column existed only in ensureTenantQuotasTable, the ALTER that runs
-- inside UpsertTenantQuota. A database that had run the migration set and not
-- yet taken an upsert failed every entitlements read with
-- `column "concurrent_connectors" does not exist`, and every RPC that checks a
-- ceiling (CreateBank among them) answered PermissionDenied for every tenant
-- (gibson#13, run 35439708012). The migration set is the authoritative schema,
-- so the column lives here, with its table (see 005 for why not in a
-- tenant-operator migration).
--
-- Idempotent — ADD COLUMN IF NOT EXISTS, so it is safe on a database the
-- upsert path already converged.
ALTER TABLE tenant_quotas
  ADD COLUMN IF NOT EXISTS concurrent_connectors INT NOT NULL DEFAULT 0;
