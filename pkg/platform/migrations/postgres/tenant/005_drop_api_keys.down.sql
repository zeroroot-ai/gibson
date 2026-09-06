-- Migration 005 down: Recreate api_keys table (empty) for rollback.
-- Recreates the original schema so that a same-release rollback (helm rollback)
-- does not leave the schema in an inconsistent state. No data is restored;
-- the rollback target would need to restart the daemon to re-seed.
-- Spec: agent-service-credentials Requirement 10.7 / NFR Reliability.

CREATE TABLE IF NOT EXISTS api_keys (
    key_id        TEXT PRIMARY KEY,
    tenant_id     TEXT NOT NULL,
    key_hash      TEXT NOT NULL,
    name          TEXT,
    created_by    TEXT,
    allowed_kinds TEXT[] NOT NULL DEFAULT '{}',
    allowed_names TEXT[] NOT NULL DEFAULT '{}',
    capabilities  TEXT[] NOT NULL DEFAULT '{}',
    status        TEXT NOT NULL DEFAULT 'active',
    max_uses      INTEGER,
    use_count     INTEGER NOT NULL DEFAULT 0,
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
