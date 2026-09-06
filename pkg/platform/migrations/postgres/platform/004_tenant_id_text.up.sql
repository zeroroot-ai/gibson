-- gibson#99: tenant_id columns must be TEXT, not UUID.
--
-- The SDK's auth.TenantID is documented to accept slugs, UUIDs, ULIDs,
-- and account identifiers from upstream IdPs (see
-- core/sdk/auth/tenantid.go — the validation regex permits a leading
-- lowercase letter followed by [a-z0-9_-]+, which excludes UUIDs but
-- accepts every non-UUID slug Gibson assigns at signup). Application
-- code uniformly passes tenant.String() — a sealed validated slug —
-- to every storage layer.
--
-- Two earlier migrations declared tenant_id as UUID NOT NULL:
--
--   001_tenant_secrets_broker_config — PRIMARY KEY (tenant_id)
--   002_plugin_install                — part of UNIQUE (tenant_id, …)
--
-- That left the column rejecting every non-UUID-shaped slug with
-- SQLSTATE 22P02 ("invalid input syntax for type uuid"), e.g.:
--
--   configstore: query tenant jasdklfjl:
--     ERROR: invalid input syntax for type uuid: "jasdklfjl"
--
-- Migration 003_tenant_quotas_simplify chose TEXT PRIMARY KEY correctly;
-- this migration aligns 001 and 002 with that precedent.
--
-- Casting UUID → TEXT is loss-free: any rows currently in either table
-- (rare in dev, none in prod yet) keep their canonical 36-char dashed
-- representation via the explicit USING tenant_id::text cast.
-- The unique constraints and indexes that reference tenant_id rebuild
-- transparently on the column-type change.

ALTER TABLE tenant_secrets_broker_config
    ALTER COLUMN tenant_id TYPE TEXT USING tenant_id::text;

ALTER TABLE plugin_install
    ALTER COLUMN tenant_id TYPE TEXT USING tenant_id::text;
