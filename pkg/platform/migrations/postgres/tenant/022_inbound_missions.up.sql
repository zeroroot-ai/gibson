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
    -- publication_id is new for each publication of the agent name. The count of
    -- open tasks is by publication, so the open tasks of an old publication do not
    -- count against a new publication of the same name.
    publication_id        TEXT        NOT NULL,
    mission_definition_id TEXT        NOT NULL,
    -- definition_hash is the hash of the definition at publish. A call starts a
    -- mission only while the definition still has this hash.
    definition_hash       TEXT        NOT NULL,
    target_ids            TEXT        NOT NULL,
    -- target_hashes is a JSON object, target id to the hash of the target at
    -- publish. A call starts a mission only while each of its targets has its hash.
    target_hashes         TEXT        NOT NULL,
    -- max_active_missions is the most inbound missions of this publication that
    -- run or wait at one time. The admin sets it at publish. It has no default.
    max_active_missions   INT         NOT NULL CHECK (max_active_missions > 0),
    published_by          TEXT        NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- inbound_tasks — one row for each inbound mission, from the moment a message
-- reserves a place for it. The row holds the caller that started the mission, so
-- every replica finds the Task of a caller from the row. A row with finished_at
-- NULL counts against max_active_missions. The reservation locks the row of the
-- publication in inbound_missions, so parallel messages and more than one replica
-- cannot go over the limit. The row stays after an unpublish, so the caller can
-- still read its own missions. A cancel needs the live grant to the agent.
CREATE TABLE IF NOT EXISTS inbound_tasks (
    slot        TEXT        PRIMARY KEY,
    agent       TEXT        NOT NULL,
    publication_id TEXT     NOT NULL,
    owner       TEXT        NOT NULL,
    -- mission_id is set when the reservation is made. The mission record takes this
    -- ID, so a running mission always has its row.
    mission_id  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS inbound_tasks_mission_idx ON inbound_tasks (mission_id);
CREATE INDEX IF NOT EXISTS inbound_tasks_open_idx ON inbound_tasks (publication_id) WHERE finished_at IS NULL;
