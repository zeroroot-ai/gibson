-- 022_inbound_missions.up.sql
--
-- Mission definitions that a tenant published for inbound A2A calls (epic
-- gibson#1367, gibson#1408).
--
-- inbound_missions — one row for each agent name that an outside A2A client may
--                    call. The row names the mission definition, and it holds
--                    the target IDs that a tenant admin approved. The grant to
--                    a caller identity lives in FGA, not here.
--
-- This table lives in the PER-TENANT database, so there is no tenant_id column:
-- the database is the tenant scope (migration 007).

CREATE TABLE IF NOT EXISTS inbound_missions (
    agent                 TEXT        PRIMARY KEY,
    mission_definition_id TEXT        NOT NULL,
    -- definition_hash is the hash of the definition at publish. A call starts a
    -- mission only while the definition still has this hash.
    definition_hash       TEXT        NOT NULL,
    target_ids            TEXT        NOT NULL,
    -- target_hashes is a JSON object, target id to the hash of the target at
    -- publish. A call starts a mission only while each of its targets has its hash.
    target_hashes         TEXT        NOT NULL,
    published_by          TEXT        NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
