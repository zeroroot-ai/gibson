-- 025_loop_grants.up.sql
--
-- Loop grants of one tenant (gibson#1612).
--
-- loop_grants - one row for each bank member that a tenant admin gave a loop
--               grant. The row is bound to the member identity, which is the
--               bank member id, and so to the tenant by this database. It names
--               the tool classes and the harness calls, and the admin who gave
--               the grant. agent_name is the catalog agent of the member. The
--               manifest of that agent limits the classes of the grant. The check
--               at call time reads the tool class of a connector from its catalog
--               manifest, never from this row.
--
-- This table lives in the PER-TENANT database, so there is no tenant_id column:
-- the database is the tenant scope (migration 007).

CREATE TABLE IF NOT EXISTS loop_grants (
    member_id     TEXT        PRIMARY KEY,
    id            TEXT        NOT NULL UNIQUE,
    agent_name    TEXT        NOT NULL,
    tool_classes  TEXT[]      NOT NULL DEFAULT '{}',
    harness_calls TEXT[]      NOT NULL DEFAULT '{}',
    grantor       TEXT        NOT NULL,
    granted_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
