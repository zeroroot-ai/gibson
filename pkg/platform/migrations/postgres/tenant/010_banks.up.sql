-- 010_banks.up.sql
--
-- Banks of always-on coding agents and their members (ADR-0019, gibson#1708).
--
-- banks         — the declarative pool: owner, desired count, login shape, policies.
-- bank_members  — one row per running member, with the status it last reported.
--
-- These tables live in the PER-TENANT database, so there is no tenant_id
-- column: the database is the tenant scope, the same way provider_configs is
-- scoped (migration 007).

CREATE TABLE IF NOT EXISTS banks (
    id                   TEXT        PRIMARY KEY,
    name                 TEXT        NOT NULL UNIQUE,
    -- owner_kind is 'user' or 'tenant'. A person owns a bank that signs in on
    -- their subscription; the tenant owns a bank that runs on the tenant
    -- provider configuration.
    owner_kind           TEXT        NOT NULL,
    owner_id             TEXT        NOT NULL,
    desired_count        INTEGER     NOT NULL DEFAULT 0,
    login_shape          TEXT        NOT NULL,
    provider_config_name TEXT        NOT NULL DEFAULT '',
    agent_name           TEXT        NOT NULL DEFAULT 'claude',
    model                TEXT        NOT NULL DEFAULT '',
    max_jobs_in_flight   INTEGER     NOT NULL DEFAULT 1,
    -- A job with no input for this many seconds closes with verdict
    -- ABANDONED. Zero means the daemon default.
    stale_limit_seconds  BIGINT      NOT NULL DEFAULT 0,
    spill_policy         TEXT        NOT NULL DEFAULT 'queue',
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bank_members (
    id             TEXT        PRIMARY KEY,
    bank_id        TEXT        NOT NULL REFERENCES banks(id) ON DELETE CASCADE,
    mission_id     TEXT        NOT NULL DEFAULT '',
    mission_run_id TEXT        NOT NULL DEFAULT '',
    agent_run_id   TEXT        NOT NULL DEFAULT '',
    sandbox_id     TEXT        NOT NULL DEFAULT '',
    state          TEXT        NOT NULL,
    jobs_in_flight INTEGER     NOT NULL DEFAULT 0,
    job_cap        INTEGER     NOT NULL DEFAULT 1,
    active_job_ids TEXT[]      NOT NULL DEFAULT '{}',
    claude_version TEXT        NOT NULL DEFAULT '',
    last_heartbeat TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS bank_members_bank_id_idx ON bank_members (bank_id);

-- A member callback names no member: the daemon resolves it from the mission
-- run on the verified grant, so that lookup is on the request path of every
-- callback a member makes.
CREATE UNIQUE INDEX IF NOT EXISTS bank_members_mission_run_idx
    ON bank_members (mission_run_id)
    WHERE mission_run_id <> '';
