-- 020_outside_agents.up.sql
--
-- Outside agents of one tenant (epic gibson#1366, gibson#1403).
--
-- outside_agents — one row for each A2A agent that runs outside Gibson. The row
--                  holds the HTTPS URL of its A2A endpoint and the NAME of the
--                  tenant secret for its credential. It never holds a credential
--                  value. The grant to a mission lives in FGA, not here.
--
-- This table lives in the PER-TENANT database, so there is no tenant_id column:
-- the database is the tenant scope (migration 007).

CREATE TABLE IF NOT EXISTS outside_agents (
    name              TEXT        PRIMARY KEY,
    a2a_url           TEXT        NOT NULL,
    credential_secret TEXT        NOT NULL DEFAULT '',
    description       TEXT        NOT NULL DEFAULT '',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
