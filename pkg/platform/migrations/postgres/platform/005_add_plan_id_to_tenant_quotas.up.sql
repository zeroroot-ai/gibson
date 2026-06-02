-- 005_add_plan_id_to_tenant_quotas.up.sql
--
-- Adds plan_id to tenant_quotas so each row records which Gibson plan the
-- tenant was on at the time of the last UpsertTenantQuota call (written by the
-- tenant-operator's EntitlementsGRPCClient alongside concurrent_missions /
-- concurrent_agents).
--
-- This column lives with its TABLE. The daemon owns tenant_quotas (created in
-- 003_tenant_quotas_simplify), so the schema for it is migrated here — NOT in a
-- tenant-operator migration. A tenant-operator migration that ALTERed this
-- table deadlocked bringup: the daemon's StatefulSet gates on the tenant-
-- operator being Ready, but the tenant-operator's migration needed this daemon-
-- owned table, which the (not-yet-started) daemon would create. See
-- tenant-operator#316.
--
-- Idempotent — ADD COLUMN IF NOT EXISTS, so it is safe whether or not the
-- (now-removed) tenant-operator migration had already added the column.
ALTER TABLE tenant_quotas
  ADD COLUMN IF NOT EXISTS plan_id TEXT NOT NULL DEFAULT '';
