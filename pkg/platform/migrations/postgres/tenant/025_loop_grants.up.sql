-- 025_loop_grants.up.sql
--
-- Loop grants of one tenant (gibson#1612).
--
-- loop_grants - one row for each catalog agent whose bank members may call the
--               tools of the connectors that the tenant enabled. The row names
--               the tool classes and the harness calls, and the admin who gave
--               the grant. The check at call time reads the tool class of a
--               connector from its catalog manifest, never from this row.
--
-- This table lives in the PER-TENANT database, so there is no tenant_id column:
-- the database is the tenant scope (migration 007).

CREATE TABLE IF NOT EXISTS loop_grants (
    agent_name    TEXT        PRIMARY KEY,
    id            TEXT        NOT NULL UNIQUE,
    tool_classes  TEXT[]      NOT NULL DEFAULT '{}',
    harness_calls TEXT[]      NOT NULL DEFAULT '{}',
    grantor       TEXT        NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
