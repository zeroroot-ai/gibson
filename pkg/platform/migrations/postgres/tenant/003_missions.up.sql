-- Phase D, Task 4.8: per-tenant missions table.
-- No tenant_id column — the tenant is implied by which database this table lives in.
-- Missions are stored as JSON documents in the document column for flexibility.

CREATE TABLE IF NOT EXISTS missions (
    id          UUID        PRIMARY KEY,
    name        TEXT        NOT NULL,
    status      TEXT        NOT NULL DEFAULT 'pending',
    document    JSONB       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index to support listing by status.
CREATE INDEX IF NOT EXISTS missions_status_idx ON missions (status);

-- Index to support listing by name.
CREATE INDEX IF NOT EXISTS missions_name_idx ON missions (name);

-- Index to support full-text search on mission name.
CREATE INDEX IF NOT EXISTS missions_name_trgm_idx ON missions USING gin (name gin_trgm_ops);

COMMENT ON TABLE missions IS 'Tenant-scoped mission records. One row per mission instance. No tenant_id — isolation is by database.';
COMMENT ON COLUMN missions.id IS 'Mission UUID, globally unique.';
COMMENT ON COLUMN missions.name IS 'Human-readable mission name.';
COMMENT ON COLUMN missions.status IS 'Lifecycle state: pending, running, paused, completed, failed, cancelled.';
COMMENT ON COLUMN missions.document IS 'Full mission JSON document.';
