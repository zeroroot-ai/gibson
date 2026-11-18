-- 017_agent_skills.up.sql
--
-- Agent Skills of one tenant (epic gibson#1364).
--
-- agent_skills               — one row for each published version, keyed by the
--                              digest of its OCI image. A new publish of a name
--                              adds a row and moves the current flag. An old
--                              digest stays readable.
-- agent_skill_files          — the files of one version. A load reads these rows
--                              and never the registry, so a version stays
--                              readable when the registry loses it.
-- agent_skill_mission_pins   — the digest that one mission uses for one name.
--                              The first load in a mission writes it. A later
--                              publish does not change it.
--
-- These tables live in the PER-TENANT database, so there is no tenant_id
-- column: the database is the tenant scope (migration 007).

CREATE TABLE IF NOT EXISTS agent_skills (
    digest         TEXT        PRIMARY KEY,
    name           TEXT        NOT NULL,
    reference      TEXT        NOT NULL,
    description    TEXT        NOT NULL,
    license        TEXT        NOT NULL DEFAULT '',
    compatibility  TEXT        NOT NULL DEFAULT '',
    metadata_json  TEXT        NOT NULL DEFAULT '{}',
    allowed_tools  TEXT[]      NOT NULL DEFAULT '{}',
    published_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_current     BOOLEAN     NOT NULL DEFAULT false,
    -- source is 'tenant' for a version that the tenant published and 'shared'
    -- for a copy of a Shared Agent Skill of the operator.
    source         TEXT        NOT NULL DEFAULT 'tenant' CHECK (source IN ('tenant', 'shared'))
);

CREATE INDEX IF NOT EXISTS agent_skills_name_idx ON agent_skills (name, published_at DESC);

-- At most one current version for each name.
CREATE UNIQUE INDEX IF NOT EXISTS agent_skills_current_idx
    ON agent_skills (name)
    WHERE is_current;

CREATE TABLE IF NOT EXISTS agent_skill_files (
    digest  TEXT  NOT NULL REFERENCES agent_skills(digest) ON DELETE CASCADE,
    path    TEXT  NOT NULL,
    content BYTEA NOT NULL,
    sha256  TEXT  NOT NULL,
    PRIMARY KEY (digest, path)
);

CREATE TABLE IF NOT EXISTS agent_skill_mission_pins (
    mission_id TEXT        NOT NULL,
    name       TEXT        NOT NULL,
    digest     TEXT        NOT NULL REFERENCES agent_skills(digest) ON DELETE CASCADE,
    pinned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (mission_id, name)
);
